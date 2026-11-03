"""Iterative, cancellable directory walker and the in-memory size index.

Design notes:

* Traversal is iterative (an explicit stack), so a deep tree cannot exhaust the
  interpreter stack.
* On POSIX every directory is opened with O_NOFOLLOW and walked relative to its
  descriptor, so a folder swapped for a symlink mid-scan cannot redirect the
  walk outside the tree the user chose.
* Windows has no descriptor-relative opens. There we re-check after the walk
  that the root is still the directory we started from, and refuse to publish
  otherwise.
* Top-level entries are split across a small thread pool; files are handled
  inline by the producer, because a Future per file costs more than the stat.
"""

import ctypes
import heapq
import os
import stat
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from . import native
from . import paths
from . import platform as osplat

# ---- Tuning ----------------------------------------------------------------
SEND_DEPTH = 7          # ring levels of data sent per request
MAX_CHILDREN = 80       # max children kept per node (rest aggregated)
MAX_SEND_NODES = 2500   # global budget for one transport payload
MIN_FRACTION = 0.003    # children below this share of the parent are aggregated
WORKERS = 2 if osplat.IS_MAC else max(4, os.cpu_count() or 4)
MAX_JSON_BODY = 64 * 1024
MAX_ENTRIES = 0         # optional explicit cap; the default is memory-guarded
MAX_MEMORY_MB = 0       # automatic: 25% of RAM, clamped to 512 MiB - 4 GiB
PREVIEW_INTERVAL = 10

# Set from the CLI and injected into the page.
START_PATH = "~"
READ_ONLY = False

# ---- Index -----------------------------------------------------------------
# INDEX maps a directory path -> its node. Nodes are plain dicts shared with
# the tree the UI walks, so every mutation happens under INDEX_LOCK.
INDEX = {}
INDEX_LOCK = threading.RLock()
OPERATION_LOCK = threading.Lock()


def _basename(path):
    return os.path.basename(path.rstrip("/\\")) or path


if osplat.IS_WIN:
    def _alloc(st, path=None):
        """Allocated bytes on disk.

        Windows has no st_blocks, so ask the filesystem.
        GetCompressedFileSizeW returns the bytes actually allocated, which is
        what makes sparse and compressed files look smaller than their size --
        the behaviour macOS gets from st_blocks.
        """
        if path and not stat.S_ISLNK(st.st_mode):
            # GetCompressedFileSizeW follows reparse points, so a link would
            # report its target's allocation; a link's own size is st_size.
            high = ctypes.c_ulong(0)
            low = ctypes.windll.kernel32.GetCompressedFileSizeW(str(path), ctypes.byref(high))
            if low != 0xFFFFFFFF or ctypes.windll.kernel32.GetLastError() == 0:
                return (high.value << 32) | low
        return st.st_size
else:
    def _alloc(st, path=None):
        """Allocated bytes: st_blocks is in 512-byte units on POSIX."""
        blocks = getattr(st, "st_blocks", None)
        return st.st_size if blocks is None else blocks * 512


def _node(path, st, is_dir, identity=True):
    node = {"name": _basename(path), "path": path, "dir": is_dir,
            "size": 0 if is_dir else _alloc(st, path),
            "mtime": 0 if is_dir else int(st.st_mtime)}
    if identity:
        node["_identity"] = paths.make_identity(st)
    if is_dir:
        node.update(children=[], skipped=0, skipped_sample=[])
    return node


def _skip(node, path):
    node["skipped"] += 1
    if len(node["skipped_sample"]) < 15:
        node["skipped_sample"].append(path)


def _add(parent, child):
    parent["size"] += child["size"]
    parent["mtime"] = max(parent["mtime"], child["mtime"])
    if child.get("skipped"):
        parent["skipped"] += child["skipped"]
        room = 15 - len(parent["skipped_sample"])
        parent["skipped_sample"].extend(child["skipped_sample"][:max(0, room)])


def _preview_item(node, scanning=False):
    return {**{k: node[k] for k in ("name", "path", "dir", "size", "mtime")},
            "preview": True, "trashable": False, "scanning": scanning}


# ---- Live progress ---------------------------------------------------------
class ScanProgress:
    """Cheap counters plus bounded summaries; never snapshots a full tree."""

    def __init__(self, max_entries=None, max_memory_mb=None):
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.entries = 0
        self.bytes = 0
        self.started = time.monotonic()
        self.finished = None
        self._observed = (0, 0)
        self._last_progress_time = self.started
        self._io_paths = {}
        self.max_entries = MAX_ENTRIES if max_entries is None else max_entries
        memory_mb = MAX_MEMORY_MB if max_memory_mb is None else max_memory_mb
        validate_limits(self.max_entries, memory_mb)
        self.max_memory_mb = memory_mb or native.automatic_memory_mb()
        self.resident_bytes = None
        self._baseline_bytes = native.resident_bytes() or 0
        self.failure = None
        self._memory_lock = threading.Lock()
        self._last_memory_check = float("-inf")
        self.path = None
        self.active = {}
        self.largest = []
        self.sequence = 0
        self.completed = 0
        self._preview_lock = threading.Lock()
        self._preview_time = float("-inf")
        self._preview_cache = None
        self._root_index = None
        self._worker_indexes = {}
        self._folder_previews = OrderedDict()

    # -- cancellation and limits --
    def check(self):
        if self.failure:
            # Store only scalars: keeping an exception traceback here would
            # retain the whole failed multi-million-entry tree.
            raise paths.ScanLimitError(*self.failure)
        if self.cancel.is_set():
            raise paths.ScanCancelled("Scan cancelled; the previous results are unchanged.")

    def record(self, size=0):
        self.check()
        with self.lock:
            self.entries += 1
            self.bytes += size
            if self.max_entries and self.entries > self.max_entries:
                self.failure = (f"Scan reached its {self.max_entries:,}-entry limit. "
                                "Retry with a higher limit.", "entry_limit")
                self.cancel.set()
                raise paths.ScanLimitError(*self.failure)
            check_memory = self.entries % 4096 == 0
        if check_memory:
            self._check_memory()

    def _check_memory(self):
        if not self._memory_lock.acquire(blocking=False):
            return
        try:
            now = time.monotonic()
            if now - self._last_memory_check < 0.5:
                return
            self._last_memory_check = now
            resident = native.resident_bytes()
            with self.lock:
                self.resident_bytes = resident
                # The budget covers what *this scan* added, not the whole
                # process: an embedder (tests, an IDE) already holds memory and
                # would otherwise fail every scan. Fall back to an estimate
                # when the OS cannot report usage.
                if resident is not None:
                    used = max(0, resident - self._baseline_bytes)
                else:
                    used = self.entries * 1536
                if used > self.max_memory_mb * 1024 * 1024:
                    self.failure = (f"Scan reached its {self.max_memory_mb:,} MiB memory "
                                    "budget. Retry with more memory or scan a smaller folder.",
                                    "memory_limit")
                    self.cancel.set()
                    raise paths.ScanLimitError(*self.failure)
        finally:
            self._memory_lock.release()

    # -- live bookkeeping --
    def begin_branch(self, path):
        with self.lock:
            self.active[path] = {"name": _basename(path), "path": path, "dir": True,
                                 "size": 0, "mtime": 0}
            self._io_paths[path] = path

    def reading_directory(self, branch, path):
        with self.lock:
            if path is None:
                self._io_paths.pop(branch, None)
            else:
                self._io_paths[branch] = path

    def finish(self):
        with self.lock:
            if self.finished is None:
                self.finished = time.monotonic()
            self._io_paths.clear()

    def _keep_largest(self, node):  # caller owns self.lock
        self.completed += 1
        if len(self.largest) < MAX_CHILDREN or node["size"] > self.largest[0][0]:
            self.sequence += 1
            item = (node["size"], self.sequence, _preview_item(node))
            if len(self.largest) < MAX_CHILDREN:
                heapq.heappush(self.largest, item)
            else:
                heapq.heapreplace(self.largest, item)

    def add_file(self, node):
        with self.lock:
            self.bytes += node["size"]
            self._keep_largest(node)

    def add_allocated(self, size, branch=None):
        with self.lock:
            self.bytes += size
            if branch in self.active:
                self.active[branch]["size"] += size

    def finish_branch(self, path, node=None):
        with self.lock:
            self.active.pop(path, None)
            self._io_paths.pop(path, None)
            self._worker_indexes.pop(path, None)
            if node is not None:
                self._keep_largest(node)

    def attach_index(self, path, index):
        with self.lock:
            self._worker_indexes[path] = index

    def release_indexes(self):
        # A failed scan must not keep its private tree alive through a job.
        with self.lock:
            self._root_index = None
            self._worker_indexes.clear()

    # -- previews --
    def _folder_preview(self, path, now):
        if not isinstance(path, str) or "\0" in path or not os.path.isabs(path):
            raise ValueError("A valid absolute folder path is required.")
        path = os.path.normpath(path)
        if not self.path or not osplat.inside(path, self.path):
            raise ValueError("Folder is outside the running scan.")
        cached = self._folder_previews.get(path)
        if cached and now - cached[0] < PREVIEW_INTERVAL:
            self._folder_previews.move_to_end(path)
            return cached[1]
        with self.lock:
            node = self._root_index.get(path) if self._root_index is not None else None
            if node is None:
                for index in self._worker_indexes.values():
                    node = index.get(path)
                    if node is not None:
                        break
            if node is None:
                node = self.active.get(path)
            entries = self.entries
        if node is None:
            raise ValueError("This folder has not been visited yet. Wait for the next chart update.")
        # Only this folder's immediate children are inspected, on demand. Copy
        # the append-only list so a worker extending it cannot corrupt iteration.
        kids = node.get("children", [])[:]
        largest, total = [], 0
        for sequence, child in enumerate(kids):
            size = child["size"]
            total += size
            if len(largest) < MAX_CHILDREN or size > largest[0][0]:
                item = _preview_item(child, child["dir"] and not child.get("_complete", False))
                item["size"] = size
                candidate = (size, sequence, item)
                if len(largest) < MAX_CHILDREN:
                    heapq.heappush(largest, candidate)
                else:
                    heapq.heapreplace(largest, candidate)
        children = [item[2] for item in sorted(largest, reverse=True)]
        remainder = len(kids) - len(children)
        if remainder:
            children.append({"name": f"({remainder} other scanned items)", "path": "", "dir": False,
                             "size": total - sum(c["size"] for c in children), "mtime": 0,
                             "other": True, "preview": True, "trashable": False})
        root = {**_preview_item(node, not node.get("_complete", False)), "children": children,
                "size": total, "entries": entries}
        self._folder_previews[path] = (now, root)
        if len(self._folder_previews) > 4:
            self._folder_previews.popitem(last=False)
        return root

    def preview(self, path=None):
        # Tabs share one cache; each build copies at most 80 + 2*workers
        # summaries no matter how many entries were visited.
        with self._preview_lock:
            now = time.monotonic()
            if path is not None and path != self.path:
                return self._folder_preview(path, now)
            if self._preview_cache is not None and now - self._preview_time < PREVIEW_INTERVAL:
                return self._preview_cache
            with self.lock:
                if not self.path:
                    return None
                items = [item[2] for item in self.largest]
                items.extend(_preview_item(node, True) for node in self.active.values())
                kids = heapq.nlargest(MAX_CHILDREN, items, key=lambda c: c["size"])
                remainder = max(0, self.bytes - sum(c["size"] for c in kids))
                other_count = self.completed + len(self.active) - len(kids)
                if other_count:
                    kids.append({"name": f"({other_count} other scanned items)", "path": "",
                                 "dir": False, "size": remainder, "mtime": 0, "other": True,
                                 "preview": True, "trashable": False})
                root = {"name": _basename(self.path), "path": self.path, "dir": True,
                        "size": self.bytes, "mtime": 0, "preview": True, "trashable": False,
                        "children": kids, "entries": self.entries}
            self._preview_cache, self._preview_time = root, now
            return root

    def snapshot(self):
        with self.lock:
            now = time.monotonic()
            observed = (self.entries, self.bytes)
            if observed != self._observed:
                self._observed = observed
                self._last_progress_time = now
            idle = 0 if self.finished is not None else round(now - self._last_progress_time, 1)
            return {"entries": self.entries, "bytes": self.bytes,
                    "elapsed": round((self.finished if self.finished is not None
                                      else now) - self.started, 1),
                    "idle_seconds": idle,
                    "waiting_paths": list(self._io_paths.values())[:4] if idle >= 10 else [],
                    "cancel_requested": self.cancel.is_set(),
                    "max_entries": self.max_entries,
                    "max_memory_mb": self.max_memory_mb,
                    "resident_bytes": self.resident_bytes}


def validate_limits(max_entries, max_memory_mb):
    if type(max_entries) is not int or not (max_entries == 0 or 1 <= max_entries <= 1_000_000_000):
        raise ValueError("max_entries must be 0 (automatic) or an integer from 1 to 1,000,000,000.")
    if type(max_memory_mb) is not int or not (max_memory_mb == 0 or 64 <= max_memory_mb <= 1_048_576):
        raise ValueError("max_memory_mb must be 0 (automatic) or an integer from 64 to 1,048,576.")


# ---- Traversal -------------------------------------------------------------
_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
              | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))


def _open_directory(path):
    """Open a directory without following links anywhere in its prefix.

    POSIX only: Windows has no descriptor-relative opens, so callers check
    osplat.IS_POSIX first.
    """
    if hasattr(os, "O_NOFOLLOW_ANY"):
        return os.open(path, (_DIR_FLAGS & ~os.O_NOFOLLOW) | os.O_NOFOLLOW_ANY)
    fd = os.open(os.sep, _DIR_FLAGS)
    try:
        for part in path.split(os.sep):
            if part:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _pop_directory(stack, node, progress, branch):
    """Close a finished directory and fold its totals into its parent."""
    _, parent_fd, iterator = stack.pop()
    iterator.close()
    os.close(parent_fd)
    node["_complete"] = True
    if stack:
        _add(stack[-1][0], node)
        progress.reading_directory(branch, stack[-1][0]["path"])


def _walk_dir(path, index, progress=None, fd=None, branch=None):
    """Iterative DFS from an open descriptor; never follows directory links.

    Keeps at most one iterator and descriptor per depth. Unreadable folders and
    vanishing entries are recorded as skips instead of aborting the scan.
    """
    progress = progress or ScanProgress()
    fd = _open_directory(path) if fd is None else fd
    try:
        root = _node(path, os.fstat(fd), True)
        progress.reading_directory(branch or path, path)
        iterator = os.scandir(fd)
    except BaseException:
        os.close(fd)
        raise
    index[path] = root
    stack = [(root, fd, iterator)]
    pending_bytes = 0
    try:
        while stack:
            progress.check()
            node, parent_fd, iterator = stack[-1]
            try:
                entry = next(iterator)
            except StopIteration:
                _pop_directory(stack, node, progress, branch or path)
                continue
            except OSError:
                _skip(node, node["path"])
                _pop_directory(stack, node, progress, branch or path)
                continue
            child_path = os.path.join(node["path"], entry.name)
            progress.record()
            child_fd = None
            try:
                if entry.is_dir(follow_symlinks=False):
                    if paths.excluded(child_path):
                        _skip(node, f"Excluded by --exclude: {child_path}")
                        continue
                    progress.reading_directory(branch or path, child_path)
                    child_fd = os.open(entry.name, _DIR_FLAGS, dir_fd=parent_fd)
                    child = _node(child_path, os.fstat(child_fd), True)
                    child_it = os.scandir(child_fd)
                    node["children"].append(child)
                    index[child_path] = child
                    stack.append((child, child_fd, child_it))
                    child_fd = None  # ownership moved to the stack
                else:
                    st = _entry_stat(entry)
                    if stat.S_ISDIR(st.st_mode):  # became a directory mid-scan
                        _skip(node, child_path)
                        continue
                    child = _node(child_path, st, False)
                    node["children"].append(child)
                    _add(node, child)
                    pending_bytes += child["size"]
                    if pending_bytes >= 1024 * 1024:
                        progress.add_allocated(pending_bytes, branch)
                        pending_bytes = 0
            except OSError:
                _skip(node, child_path)
            finally:
                if child_fd is not None:
                    os.close(child_fd)
    finally:
        progress.add_allocated(pending_bytes, branch)
        progress.reading_directory(branch or path, None)
        for _, open_fd, open_it in reversed(stack):
            open_it.close()
            os.close(open_fd)
    return root


def _walk_dir_win(path, index, progress=None, branch=None):
    """Iterative DFS for Windows, where descriptor-relative opens do not exist.

    Links and junctions are counted as leaves and never followed. Because
    Windows has no O_NOFOLLOW, the caller re-checks the root's identity after
    the walk and refuses to publish results if it changed.

    Each stack frame holds the directory *and its pending entries*, so a
    descent never re-reads the parent (which would re-walk its siblings).
    """
    progress = progress or ScanProgress()
    root = _node(path, os.stat(path, follow_symlinks=False), True)
    progress.reading_directory(branch or path, path)
    index[path] = root
    stack = [(root, _entries(root, progress))]
    while stack:
        progress.check()
        node, pending = stack[-1]
        if not pending:
            stack.pop()
            node["_complete"] = True
            if stack:
                _add(stack[-1][0], node)
                progress.reading_directory(branch or path, stack[-1][0]["path"])
            continue
        entry = pending.popleft()
        progress.record()
        child_path = entry.path
        try:
            if _is_real_dir(entry):
                if paths.excluded(child_path):
                    _skip(node, f"Excluded by --exclude: {child_path}")
                    continue
                child = _node(child_path, _entry_stat(entry), True)
                node["children"].append(child)
                index[child_path] = child
                progress.reading_directory(branch or path, child_path)
                stack.append((child, _entries(child, progress)))
                continue
            child = _leaf(entry)
            if child is None:
                _skip(node, child_path)
                continue
            node["children"].append(child)
            _add(node, child)
            progress.add_allocated(child["size"], branch)
        except OSError:
            _skip(node, child_path)
    progress.reading_directory(branch or path, None)
    return root


def _entries(node, progress):
    """The directory's entries as a queue; unreadable folders become a skip."""
    try:
        return deque(os.scandir(node["path"]))
    except OSError:
        _skip(node, node["path"])
        return deque()

def _is_real_dir(entry):
    """True only for a real directory; links and junctions count as leaves."""
    if not entry.is_dir(follow_symlinks=False):
        return False
    if osplat.IS_WIN:
        return not entry.is_symlink() and not os.path.islink(entry.path)
    return True


def _leaf(entry):
    """A file or link node, or None if the entry turned out to be a directory."""
    if _is_real_dir(entry):
        return None
    return _node(entry.path, _entry_stat(entry), False)


def _entry_stat(entry):
    """Stat an entry with device/inode filled in.

    Windows' scandir fills st_dev and st_ino with 0; only a real stat() gets
    the NTFS file index. Those fields are the item identity used to reject a
    stale delete, so the extra call is required there. POSIX keeps the cached
    stat, which is free on macOS and already carries the inode.
    """
    st = entry.stat(follow_symlinks=False)
    if osplat.IS_WIN and (st.st_dev == 0 or st.st_ino == 0 or entry.is_symlink()):
        # A link's cached stat reports its target's size, so re-stat it.
        return os.stat(entry.path, follow_symlinks=False)
    return st


def _scan_tree(path, progress):
    """Walk `path`, parallelizing across its immediate children."""
    with progress.lock:
        progress.path = path
    root = _node(path, os.stat(path, follow_symlinks=False), True)
    merged = {path: root}
    with progress.lock:
        progress._root_index = merged

    def work(name):
        progress.check()
        child_path = os.path.join(path, name)
        idx = {}
        progress.attach_index(child_path, idx)
        try:
            if osplat.IS_POSIX:
                child_fd = os.open(name, _DIR_FLAGS, dir_fd=root_fd)
                child = _walk_dir(child_path, idx, progress=progress, fd=child_fd,
                                  branch=child_path)
            else:
                child = _walk_dir_win(child_path, idx, progress=progress, branch=child_path)
            return child, idx, None
        except OSError:
            return None, idx, child_path

    def collect(done):
        for future in done:
            child, idx, error_path = future.result()
            if child is not None:
                root["children"].append(child)
                _add(root, child)
                merged.update(idx)
                progress.finish_branch(child["path"], child)
            if error_path:
                _skip(root, error_path)
                progress.finish_branch(error_path)

    root_fd = _open_directory(path) if osplat.IS_POSIX else None
    try:
        with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="diskclean-scan") as pool:
            pending = set()
            try:
                with os.scandir(root_fd if root_fd is not None else path) as entries:
                    for entry in entries:
                        progress.record()
                        # Files need one cached stat, not a Future and a thread
                        # handoff. Only directory subtrees enter the pool.
                        if not _is_real_dir(entry):
                            try:
                                child = _leaf(entry)
                            except OSError:
                                _skip(root, entry.path)
                                continue
                            if child is None:
                                _skip(root, entry.path)
                                continue
                            root["children"].append(child)
                            _add(root, child)
                            progress.add_file(child)
                            continue
                        if paths.excluded(entry.path):
                            _skip(root, f"Excluded by --exclude: {entry.path}")
                            continue
                        progress.begin_branch(entry.path)
                        pending.add(pool.submit(work, entry.name))
                        if len(pending) >= WORKERS * 2:
                            done, pending = wait(pending, return_when=FIRST_COMPLETED)
                            collect(done)
                while pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    collect(done)
            except BaseException:
                progress.cancel.set()
                for future in pending:
                    future.cancel()
                raise
        progress.check()
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return root, merged


# ---- Commit ----------------------------------------------------------------
def _recalculate(node):
    kids = node.get("children", [])
    node["size"] = sum(c["size"] for c in kids)
    node["mtime"] = max((c["mtime"] for c in kids), default=0)
    # Keep this folder's own errors, recompute the ones inherited from children.
    local = node.get("_local_skipped", 0)
    samples = list(node.get("_local_samples", []))
    node["skipped"] = local + sum(c.get("skipped", 0) for c in kids)
    for child in kids:
        samples.extend(child.get("skipped_sample", [])[:max(0, 15 - len(samples))])
    node["skipped_sample"] = samples[:15]


def _commit(path, root, merged):
    # Remember each folder's own errors so later refreshes can recompute
    # disclosure without double-counting children.
    for node in merged.values():
        node["_local_skipped"] = node.get("skipped", 0) - sum(
            c.get("skipped", 0) for c in node.get("children", []))
        inherited = {p for c in node.get("children", []) for p in c.get("skipped_sample", [])}
        node["_local_samples"] = [p for p in node.get("skipped_sample", []) if p not in inherited]
    with INDEX_LOCK:
        for existing in [k for k in INDEX if osplat.inside(k, path)]:
            del INDEX[existing]
        # Key every entry through osplat.key() so the browser's casing and the
        # on-disk casing address the same node (Windows is case-insensitive).
        INDEX.update({osplat.key(k): v for k, v in merged.items()})
        parent_path = os.path.dirname(path)
        parent = INDEX.get(osplat.key(parent_path))
        if parent and parent_path != path:
            parent["children"] = [root if c["path"] == path else c for c in parent["children"]]
        while parent and parent_path != path:
            parent.pop("_sorted", None)
            _recalculate(parent)
            path, parent_path = parent_path, os.path.dirname(parent_path)
            parent = INDEX.get(osplat.key(parent_path))


def _perform_scan(path, register_root, progress):
    path = osplat.normalize(path)
    if paths.excluded(path):
        raise ValueError("This folder is excluded by --exclude. "
                         "Choose a different folder or restart without that exclusion.")
    root, merged = _scan_tree(path, progress)
    # Refuse to publish results for a root that was replaced during the walk.
    try:
        now = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"The folder could not be re-read after the scan: {exc.strerror or exc}") from exc
    if paths.make_identity(now)[:3] != root["_identity"][:3]:
        raise ValueError("The folder changed during the scan. Please scan again.")
    progress.check()
    _commit(path, root, merged)
    if register_root:
        # A new root replaces the session tree, which bounds long-lived memory.
        paths.clear_scan_roots()
        paths.register_scan_root(path)
    return root


def scan(path, register_root=False, progress=None):
    """Scan `path` and publish it to INDEX. Returns the root node."""
    if not OPERATION_LOCK.acquire(blocking=False):
        raise paths.BusyError("A scan or Trash operation is already running.")
    try:
        progress = progress or ScanProgress()
        result = _perform_scan(path, register_root, progress)
        if register_root:
            # A new root replaces the session tree. Compare against the
            # normalized path the index is actually keyed by.
            with INDEX_LOCK:
                for existing in [k for k in INDEX if not osplat.inside(k, result["path"])]:
                    del INDEX[existing]
        return result
    finally:
        if progress is not None:
            progress.release_indexes()
        OPERATION_LOCK.release()


def rescan(path):
    """Refresh helper: a rescan is a full scan of the subtree."""
    return scan(path)


# ---- Queries ---------------------------------------------------------------
def _summary(node):
    result = {k: node[k] for k in ("name", "path", "size", "dir", "mtime")}
    if "_identity" in node:
        result["revision"] = paths.revision(node["_identity"])
    result["trashable"] = not READ_ONLY and paths.is_trashable(node["path"])
    if node.get("dir"):
        result["count"] = len(node.get("children", []))
    return result


def prune(node, depth=0, budget=None):
    """Bound transport size by depth, branching *and* total nodes.

    Totals stay exact: aggregated children are grouped in an "other" node whose
    size is the remainder, so sums always match the parent.
    """
    budget = [MAX_SEND_NODES] if budget is None else budget
    budget[0] -= 1
    out = _summary(node)
    if node.get("skipped"):
        out["skipped"] = node["skipped"]
        out["skipped_sample"] = node.get("skipped_sample", [])
    if not node["dir"]:
        return out
    kids = node.get("children", [])
    if depth >= SEND_DEPTH or budget[0] <= 1:
        out["more"] = bool(kids)
        return out
    # Reserve room for this level's aggregate before descending.
    budget[0] -= 1
    largest = heapq.nlargest(MAX_CHILDREN, kids, key=lambda c: (c["size"], c["name"]))
    kept, included = [], set()
    for child in largest:
        if child["size"] < node["size"] * MIN_FRACTION or budget[0] < 1:
            continue
        kept.append(prune(child, depth + 1, budget))
        included.add(child["path"])
    others = len(kids) - len(included)
    if others:
        kept.append({"name": f"({others} small items)", "path": "",
                     "size": node["size"] - sum(c["size"] for c in kept),
                     "dir": False, "other": True, "mtime": 0, "count": others})
    else:
        budget[0] += 1
    out["children"] = kept
    return out


def get_subtree(path):
    path = osplat.normalize(path)
    with INDEX_LOCK:
        node = INDEX.get(osplat.key(path))
    if node is None:
        raise ValueError("Folder is not in the current scan. Scan it first.")
    return prune(node)


def list_children(path, query="", offset=0, limit=100):
    path = osplat.normalize(path)
    if not isinstance(query, str) or len(query) > 256 or offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid search or page size.")
    with INDEX_LOCK:
        node = INDEX.get(osplat.key(path))
        if node is None:
            raise ValueError("Folder is not in the current scan.")
        # Cache the sorted order once per committed tree; pages reuse it.
        if "_sorted" not in node:
            node["_sorted"] = sorted(node.get("children", []),
                                     key=lambda c: (-c["size"], c["name"]))
        matches = node["_sorted"]
        if query:
            folded = query.casefold()
            matches = [c for c in matches if folded in c["name"].casefold()]
        return {"items": [_summary(c) for c in matches[offset:offset + limit]],
                "total": len(matches), "offset": offset}


def _indexed_item(path):
    with INDEX_LOCK:
        node = INDEX.get(osplat.key(path))
        if node is not None:
            return node
        parent = INDEX.get(osplat.key(os.path.dirname(path)))
        return next((c for c in parent["children"] if c["path"] == path), None) if parent else None


def remove_from_index(path):
    """Drop a trashed item and its descendants, then fix ancestor totals."""
    path = osplat.resolve_prefix(path)
    with INDEX_LOCK:
        for existing in [k for k in INDEX if osplat.inside(k, path)]:
            del INDEX[existing]
        parent_path = os.path.dirname(path)
        parent = INDEX.get(osplat.key(parent_path))
        if parent:
            # Child paths carry the on-disk casing; compare case-insensitively.
            folded = osplat.fold(path)
            parent["children"] = [c for c in parent["children"]
                                  if osplat.fold(c["path"]) != folded]
        while parent:
            parent.pop("_sorted", None)
            _recalculate(parent)
            next_path = os.path.dirname(parent_path)
            if next_path == parent_path:
                break
            parent_path, parent = next_path, INDEX.get(osplat.key(next_path))


# ---- Delete ----------------------------------------------------------------
def move_to_trash(path, revision=None):
    """Validate, re-verify the selection, then hand off to the OS Trash."""
    if READ_ONLY:
        return False, "Trash is disabled in read-only mode."
    if not OPERATION_LOCK.acquire(blocking=False):
        return False, "A scan or Trash operation is already running. Please wait."
    try:
        target, reason = paths.validate_trash_target(path)
        if reason:
            return False, reason
        node = _indexed_item(target)
        if node is None or not revision or revision != paths.revision(node["_identity"]):
            return False, "Selection is stale. Refresh the folder and select the item again."
        expected = node["_identity"]

        # Re-check identity immediately before the path-based native call; no
        # OS lets us make this check atomic with the move, so keep the window small.
        if osplat.IS_POSIX:
            parent_fd = _open_directory(os.path.dirname(target))
            try:
                current = os.stat(os.path.basename(target), dir_fd=parent_fd,
                                  follow_symlinks=False)
            finally:
                os.close(parent_fd)
        else:
            current = os.stat(target, follow_symlinks=False)
        if paths.make_identity(current) != expected:
            return False, "The item changed since the scan. Refresh before moving it to Trash."

        check, reason = paths.validate_trash_target(target)
        if reason or check != target:
            return False, reason or "The path changed. Refresh and try again."

        ok, message = native.trash(target)
        if not ok:
            return False, message
        remove_from_index(target)
        return True, f"Moved to {trash_name()}. Restore it from there if needed."
    except OSError as exc:
        return False, str(exc)
    finally:
        OPERATION_LOCK.release()


def trash_name():
    return "Trash" if not osplat.IS_WIN else "Recycle Bin"


def reveal(path):
    """Reveal `path` in the OS file manager."""
    if not isinstance(path, str) or not path or "\0" in path:
        return False, "Path does not exist."
    return native.reveal(os.path.abspath(path))
