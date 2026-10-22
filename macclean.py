#!/usr/bin/env python3
"""MacClean: an offline, loopback-only disk analyzer for Python 3.10+."""

import argparse
import ctypes
from collections import OrderedDict
from functools import lru_cache
import hashlib
import heapq
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0.0"
SEND_DEPTH = 7
MAX_CHILDREN = 80
MAX_SEND_NODES = 2500
MIN_FRACTION = 0.003
WORKERS = 2
MAX_JSON_BODY = 64 * 1024
MAX_ENTRIES = 0  # optional explicit cap; default scans are guarded by memory
MAX_MEMORY_MB = 0  # automatic: 25% of physical RAM, between 512 MiB and 4 GiB
PREVIEW_INTERVAL = 10
START_PATH = "~"
READ_ONLY = False
EXCLUDE_PATHS = ()
SESSION_TOKEN = secrets.token_urlsafe(32)
ALLOWED_HOSTS = set()
SCAN_ROOTS = set()
SCAN_ROOTS_LOCK = threading.Lock()
INDEX = {}
INDEX_LOCK = threading.RLock()
# All scans and Trash operations use this lock; reads see only committed trees.
OPERATION_LOCK = threading.Lock()
_HOME = os.path.realpath(os.path.expanduser("~"))
PROTECTED_EXACT = {
    "/", "/System", "/Library", "/Applications", "/Users", "/Users/Shared",
    "/private", "/usr", "/bin", "/sbin", "/opt", "/cores", "/Volumes",
    "/etc", "/var", "/tmp", "/dev", "/Network", _HOME,
    *(os.path.join(_HOME, n) for n in ("Library", "Desktop", "Documents", "Downloads")),
}
PROTECTED_EXACT |= {os.path.realpath(p) for p in PROTECTED_EXACT}


class BusyError(Exception):
    pass


class ScanCancelled(Exception):
    pass


class ScanLimitError(Exception):
    def __init__(self, message, kind="entry_limit", limit=None):
        super().__init__(message)
        self.kind = kind
        self.limit = limit


def normalize_path(path):
    if not isinstance(path, str) or not path or "\0" in path:
        raise ValueError("A non-empty folder path without NUL characters is required.")
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def _inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _excluded(path):
    return any(_inside(path, root) for root in EXCLUDE_PATHS)


def protected_reason(path):
    if path in PROTECTED_EXACT:
        return "a protected system, home, or top-level folder"
    if _inside(path, "/System"):
        return "a macOS system folder"
    if path.startswith("/Volumes/") and path.count("/") == 2:
        return "a mounted volume root"
    if _inside(_HOME, path):
        return "a folder that contains your Home folder"
    return None


def validate_trash_target(path):
    if not isinstance(path, str) or not path or "\0" in path:
        return None, "No valid path given."
    abspath = os.path.abspath(os.path.expanduser(path))
    target = os.path.join(os.path.realpath(os.path.dirname(abspath)), os.path.basename(abspath))
    if not os.path.lexists(target):
        return None, "Path does not exist."
    with SCAN_ROOTS_LOCK:
        roots = set(SCAN_ROOTS)
    # A root remains protected even when another scanned root contains it.
    if target in roots:
        return None, "Refusing: the scanned folder itself is protected."
    if not any(_inside(target, root) for root in roots):
        return None, "Refusing: item is outside the folder you scanned."
    reason = protected_reason(target)
    if not os.path.islink(target) and os.path.ismount(target):
        reason = "a mounted volume root"
    if reason:
        return None, f"Refusing to delete {reason}."
    return target, None


def _alloc(st):
    blocks = getattr(st, "st_blocks", None)
    return max(0, st.st_size if blocks is None else blocks * 512)


def _basename(path):
    return os.path.basename(path.rstrip("/")) or path


def _identity(st):
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_mtime_ns, st.st_ctime_ns)


def _revision(identity):
    return hashlib.sha256(repr(identity).encode("ascii")).hexdigest()[:24]


def _node(path, st, is_dir):
    return {"name": _basename(path), "path": path, "dir": is_dir,
            "size": 0 if is_dir else _alloc(st), "mtime": 0 if is_dir else int(st.st_mtime),
            "_identity": _identity(st),
            **({"children": [], "skipped": 0, "skipped_sample": []} if is_dir else {})}


def _skip(node, path):
    node["skipped"] += 1
    if len(node["skipped_sample"]) < 15:
        node["skipped_sample"].append(path)


def _add(parent, child):
    parent["size"] += child["size"]
    parent["mtime"] = max(parent["mtime"], child["mtime"])
    if child.get("skipped"):
        parent["skipped"] += child["skipped"]
        parent["skipped_sample"].extend(child["skipped_sample"][:15 - len(parent["skipped_sample"])])


def _automatic_memory_mb():
    try:
        physical_mb = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // (1024 * 1024)
        return max(512, min(4096, physical_mb // 4))
    except (ValueError, OSError):
        return 1024


@lru_cache(maxsize=1)
def _mac_memory_reader():
    # proc_taskinfo from Apple's sys/proc_info.h: six uint64s, twelve int32s.
    # Querying our own process avoids spawning ps or using a peak-RSS counter.
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    reader = library.proc_pidinfo
    reader.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    reader.restype = ctypes.c_int
    return reader


def _resident_bytes():
    try:
        if sys.platform == "darwin":
            data = (ctypes.c_uint64 * 12)()  # sizeof(proc_taskinfo) == 96
            if _mac_memory_reader()(os.getpid(), 4, 0, data, ctypes.sizeof(data)) == ctypes.sizeof(data):
                return data[1]
        elif sys.platform.startswith("linux"):
            return int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError, IndexError):
        pass
    return None


def _validate_scan_limits(max_entries, max_memory_mb):
    if type(max_entries) is not int or not 0 <= max_entries <= 1_000_000_000:
        raise ValueError("max_entries must be an integer from 0 to 1,000,000,000 (0 means no entry cap).")
    if type(max_memory_mb) is not int or not (max_memory_mb == 0 or 64 <= max_memory_mb <= 1_048_576):
        raise ValueError("max_memory_mb must be 0 (automatic) or an integer from 64 to 1,048,576.")


def _preview_item(node, scanning=False):
    return {**{k: node[k] for k in ("name", "path", "dir", "size", "mtime")},
            "preview": True, "trashable": False, "scanning": scanning}


class ScanProgress:
    """Cheap counters plus bounded top-level summaries; never snapshot a full tree."""
    def __init__(self, max_entries=None, max_memory_mb=None):
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.entries = 0
        self.bytes = 0
        self.started = time.monotonic()
        self.finished = None
        self._observed_progress = (0, 0)
        self._last_progress_time = self.started
        self._io_paths = {}
        self.max_entries = MAX_ENTRIES if max_entries is None else max_entries
        memory_mb = MAX_MEMORY_MB if max_memory_mb is None else max_memory_mb
        _validate_scan_limits(self.max_entries, memory_mb)
        self.max_memory_mb = memory_mb or _automatic_memory_mb()
        self.resident_bytes = None
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

    def check(self):
        if self.failure:
            # Store only scalar failure data: retaining an exception traceback
            # here would keep the failed multi-million-entry tree alive.
            raise ScanLimitError(*self.failure)
        if self.cancel.is_set():
            raise ScanCancelled("Scan cancelled; the previous results are unchanged.")

    def record(self, size=0):
        self.check()
        with self.lock:
            self.entries += 1
            self.bytes += size
            if self.max_entries and self.entries > self.max_entries:
                self.failure = (f"Scan reached its {self.max_entries:,}-entry limit. Retry with a higher limit.", "entry_limit", self.max_entries)
                self.cancel.set()
                raise ScanLimitError(*self.failure)
            check_memory = self.entries % 4096 == 0
        if check_memory:
            self._check_memory()

    def _check_memory(self):
        if not self._memory_lock.acquire(blocking=False):
            return
        try:
            now = time.monotonic()
            if now - self._last_memory_check < .5:
                return
            self._last_memory_check = now
            resident = _resident_bytes()
            with self.lock:
                self.resident_bytes = resident
                # If OS accounting is unavailable, keep an estimated guard.
                used = resident if resident is not None else self.entries * 1536
                if used > self.max_memory_mb * 1024 * 1024:
                    self.failure = (
                        f"Scan reached its {self.max_memory_mb:,} MiB memory budget. Retry with more memory or scan a smaller folder.",
                        "memory_limit", self.max_memory_mb)
                    self.cancel.set()
                    raise ScanLimitError(*self.failure)
        finally:
            self._memory_lock.release()

    def begin_branch(self, path):
        with self.lock:
            self.active[path] = {"name": _basename(path), "path": path, "dir": True, "size": 0, "mtime": 0}
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

    def _keep_largest(self, node):
        # Caller owns self.lock. Reject most files without copying a summary.
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

    def _folder_preview(self, path, now):
        if not isinstance(path, str) or "\0" in path or not os.path.isabs(path):
            raise ValueError("A valid absolute folder path is required.")
        path = os.path.normpath(path)
        if not self.path or not _inside(path, self.path):
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
        # the append-only list to avoid iterating a list a worker is extending.
        # Scalar sizes can be partial; no private node is exposed or modified.
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
        # Multiple tabs share a cache; each build copies at most 80 + 2*workers
        # summaries, regardless of how many millions of entries were visited.
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
                    kids.append({"name": f"({other_count} other scanned items)", "path": "", "dir": False,
                                 "size": remainder, "mtime": 0, "other": True, "preview": True, "trashable": False})
                root = {"name": _basename(self.path), "path": self.path, "dir": True, "size": self.bytes,
                        "mtime": 0, "preview": True, "trashable": False, "children": kids, "entries": self.entries}
            self._preview_cache, self._preview_time = root, now
            return root

    def snapshot(self):
        with self.lock:
            now = time.monotonic()
            observed = (self.entries, self.bytes)
            if observed != self._observed_progress:
                self._observed_progress = observed
                self._last_progress_time = now
            idle = 0 if self.finished is not None else round(now - self._last_progress_time, 1)
            return {"entries": self.entries, "bytes": self.bytes,
                    "elapsed": round((self.finished if self.finished is not None else now) - self.started, 1),
                    "idle_seconds": idle, "waiting_paths": list(self._io_paths.values())[:4] if idle >= 10 else [],
                    "cancel_requested": self.cancel.is_set(),
                    "max_entries": self.max_entries, "max_memory_mb": self.max_memory_mb,
                    "resident_bytes": self.resident_bytes}


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_directory(path):
    """Open every component without following links, including changed prefixes."""
    if hasattr(os, "O_NOFOLLOW_ANY"):
        return os.open(path, (_DIR_FLAGS & ~os.O_NOFOLLOW) | os.O_NOFOLLOW_ANY)
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in path.split("/"):
            if part:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _walk_dir(path, index, skipped=None, name=None, progress=None, fd=None, branch=None):
    """Iterative descriptor-relative DFS; never follows directory symlinks.

    At most one iterator and descriptor per depth are retained. FD exhaustion,
    unreadable directories and disappearing entries are disclosed as skips.
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
                iterator.close()
                os.close(parent_fd)
                stack.pop()
                node["_complete"] = True
                if stack:
                    _add(stack[-1][0], node)
                    progress.reading_directory(branch or path, stack[-1][0]["path"])
                continue
            except OSError:
                _skip(node, node["path"])
                iterator.close()
                os.close(parent_fd)
                stack.pop()
                node["_complete"] = True
                if stack:
                    _add(stack[-1][0], node)
                    progress.reading_directory(branch or path, stack[-1][0]["path"])
                continue
            child_path = os.path.join(node["path"], entry.name)
            progress.record()
            child_fd = None
            try:
                if entry.is_dir(follow_symlinks=False):
                    if _excluded(child_path):
                        _skip(node, f"Excluded by --exclude: {child_path}")
                        continue
                    progress.reading_directory(branch or path, child_path)
                    child_fd = os.open(entry.name, _DIR_FLAGS, dir_fd=parent_fd)
                    child = _node(child_path, os.fstat(child_fd), True)
                    child_it = os.scandir(child_fd)
                    node["children"].append(child)
                    index[child_path] = child
                    stack.append((child, child_fd, child_it))
                    child_fd = None  # ownership transferred to stack
                else:
                    st = entry.stat(follow_symlinks=False)
                    # A directory replacing a file is skipped until the next scan.
                    if stat.S_ISDIR(st.st_mode):
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
    if skipped is not None:
        skipped.extend(root["skipped_sample"])
    return root


def _scan_tree(path, progress):
    with progress.lock:
        progress.path = path
    fd = _open_directory(path)
    try:
        root = _node(path, os.fstat(fd), True)
    except BaseException:
        os.close(fd)
        raise
    merged = {path: root}
    with progress.lock:
        progress._root_index = merged

    def work(name):
        progress.check()
        child_path = os.path.join(path, name)
        idx = {}
        progress.attach_index(child_path, idx)
        child_fd = None
        try:
            child_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
            owned_fd, child_fd = child_fd, None
            child = _walk_dir(child_path, idx, progress=progress, fd=owned_fd, branch=child_path)
            return child, idx, None
        except OSError:
            return None, idx, child_path
        finally:
            if child_fd is not None:
                os.close(child_fd)

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

    try:
        # The producer never queues the entire top-level directory in memory.
        with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="macclean-scan") as pool:
            pending = set()
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        progress.record()
                        # Files need one cached stat, not a Future and a thread
                        # handoff. Only directory subtrees enter the worker pool.
                        try:
                            if not entry.is_dir(follow_symlinks=False):
                                st = entry.stat(follow_symlinks=False)
                                if stat.S_ISDIR(st.st_mode):
                                    _skip(root, os.path.join(path, entry.name))
                                    continue
                                child = _node(os.path.join(path, entry.name), st, False)
                                root["children"].append(child)
                                _add(root, child)
                                progress.add_file(child)
                                continue
                        except OSError:
                            _skip(root, os.path.join(path, entry.name))
                            continue
                        if _excluded(os.path.join(path, entry.name)):
                            _skip(root, f"Excluded by --exclude: {os.path.join(path, entry.name)}")
                            continue
                        progress.begin_branch(os.path.join(path, entry.name))
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
        os.close(fd)
    return root, merged


def _recalculate(node):
    kids = node.get("children", [])
    node["size"] = sum(c["size"] for c in kids)
    node["mtime"] = max((c["mtime"] for c in kids), default=0)
    # Preserve local errors, but replace errors inherited from refreshed children.
    local = node.get("_local_skipped", 0)
    samples = list(node.get("_local_samples", []))
    node["skipped"] = local + sum(c.get("skipped", 0) for c in kids)
    for child in kids:
        samples.extend(child.get("skipped_sample", [])[:15 - len(samples)])
    node["skipped_sample"] = samples[:15]


def _commit(path, root, merged):
    # Remember own errors so subsequent refresh/removal can recompute disclosure.
    for node in merged.values():
        node["_local_skipped"] = node["skipped"] - sum(c.get("skipped", 0) for c in node["children"])
        inherited = {p for c in node["children"] for p in c.get("skipped_sample", [])}
        node["_local_samples"] = [p for p in node["skipped_sample"] if p not in inherited]
    with INDEX_LOCK:
        for key in [k for k in INDEX if _inside(k, path)]:
            del INDEX[key]
        INDEX.update(merged)
        parent_path = os.path.dirname(path)
        parent = INDEX.get(parent_path)
        if parent and parent_path != path:
            parent["children"] = [root if c["path"] == path else c for c in parent["children"]]
        while parent and parent_path != path:
            parent.pop("_sorted", None)
            _recalculate(parent)
            path, parent_path = parent_path, os.path.dirname(parent_path)
            parent = INDEX.get(parent_path)


def _perform_scan(path, register_root, progress):
    path = normalize_path(path)
    if _excluded(path):
        raise ValueError("This folder is excluded by --exclude. Choose a different folder or restart without that exclusion.")
    root, merged = _scan_tree(path, progress)
    # Do not commit results for a root replaced while scanning.
    now = os.stat(path, follow_symlinks=False)
    if _identity(now)[:3] != root["_identity"][:3]:
        raise ValueError("The folder changed during the scan. Please scan again.")
    progress.check()
    _commit(path, root, merged)
    if register_root:
        with SCAN_ROOTS_LOCK:
            # A new root replaces the session tree, bounding long-lived memory.
            SCAN_ROOTS.clear()
            SCAN_ROOTS.add(path)
    return root


def scan(path, register_root=False, progress=None):
    if not OPERATION_LOCK.acquire(blocking=False):
        raise BusyError("A scan or Trash operation is already running.")
    try:
        progress = progress or ScanProgress()
        # Full scans replace the previous session only after successful traversal.
        result = _perform_scan(path, register_root, progress)
        if register_root:
            with INDEX_LOCK:
                for key in [k for k in INDEX if not _inside(k, result["path"])]:
                    del INDEX[key]
        return result
    finally:
        if progress is not None:
            progress.release_indexes()
        OPERATION_LOCK.release()


def rescan(path):
    return scan(path)


def _summary(node):
    result = {k: node[k] for k in ("name", "path", "size", "dir", "mtime")}
    if "_identity" in node:
        result["revision"] = _revision(node["_identity"])
    result["trashable"] = (not READ_ONLY and sys.platform == "darwin"
                          and node["path"] not in SCAN_ROOTS and not protected_reason(node["path"]))
    if node.get("dir"):
        result["count"] = len(node.get("children", []))
    return result


def prune(node, depth=0, budget=None):
    """Bound total transport size as well as depth/branching; keep totals exact."""
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
        kept.append({"name": f"({others} small items)", "path": "", "size": node["size"] - sum(c["size"] for c in kept),
                     "dir": False, "other": True, "mtime": 0, "count": others})
    else:
        budget[0] += 1
    out["children"] = kept
    return out


def get_subtree(path):
    path = normalize_path(path)
    with INDEX_LOCK:
        if path not in INDEX:
            raise ValueError("Folder is not in the current scan. Scan it first.")
        return prune(INDEX[path])


def list_children(path, query="", offset=0, limit=100):
    path = normalize_path(path)
    if not isinstance(query, str) or len(query) > 256 or offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid search or page size.")
    with INDEX_LOCK:
        if path not in INDEX:
            raise ValueError("Folder is not in the current scan.")
        node = INDEX[path]
        # Cache sorted references once per committed tree; pages reuse the ordering.
        if "_sorted" not in node:
            node["_sorted"] = sorted(node["children"], key=lambda c: (-c["size"], c["name"]))
        matches = node["_sorted"]
        if query:
            matches = [c for c in matches if query.casefold() in c["name"].casefold()]
        return {"items": [_summary(c) for c in matches[offset:offset + limit]],
                "total": len(matches), "offset": offset}


def remove_from_index(path):
    with INDEX_LOCK:
        for key in [k for k in INDEX if _inside(k, path)]:
            del INDEX[key]
        parent_path = os.path.dirname(path)
        parent = INDEX.get(parent_path)
        if parent:
            parent["children"] = [c for c in parent["children"] if c["path"] != path]
        while parent:
            parent.pop("_sorted", None)
            _recalculate(parent)
            next_path = os.path.dirname(parent_path)
            if next_path == parent_path:
                break
            parent_path, parent = next_path, INDEX.get(next_path)


def _indexed_item(path):
    node = INDEX.get(path)
    if node is not None:
        return node
    parent = INDEX.get(os.path.dirname(path))
    return next((c for c in parent["children"] if c["path"] == path), None) if parent else None


_TRASH_JXA = '''ObjC.import("Foundation");
function run(argv) {
  var url = $.NSURL.fileURLWithPath(argv[0]);
  var destination = $();
  var err = $();
  if (!$.NSFileManager.defaultManager.trashItemAtURLResultingItemURLError(url, destination, err)) {
    throw new Error(ObjC.unwrap(err.localizedDescription));
  }
  return JSON.stringify({path: ObjC.unwrap(destination.path)});
}'''


def reveal_in_finder(path):
    if sys.platform != "darwin":
        return False, "Reveal in Finder requires macOS."
    if not isinstance(path, str) or not path or "\0" in path or not os.path.lexists(path):
        return False, "Path does not exist."
    try:
        # Always reveal rather than launching executables or opening file contents.
        result = subprocess.run(["/usr/bin/open", "-R", os.path.abspath(path)], capture_output=True, text=True, timeout=15)
        return (True, "ok") if result.returncode == 0 else (False, result.stderr.strip() or "Could not reveal in Finder.")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def move_to_trash(path, revision=None):
    if READ_ONLY:
        return False, "Trash is disabled in read-only mode."
    if not OPERATION_LOCK.acquire(blocking=False):
        return False, "A scan or Trash operation is running. Please wait."
    try:
        target, reason = validate_trash_target(path)
        if reason:
            return False, reason
        with INDEX_LOCK:
            node = _indexed_item(target)
            if node is None or not revision or revision != _revision(node["_identity"]):
                return False, "Selection is stale. Refresh the folder and select the item again."
            expected = node["_identity"]
        if sys.platform != "darwin":
            return False, "Move to Trash requires macOS."
        # Re-open prefixes without symlinks and check identity immediately before
        # the native path-based call. Foundation cannot make this check atomic.
        parent_fd = _open_directory(os.path.dirname(target))
        try:
            current = os.stat(os.path.basename(target), dir_fd=parent_fd, follow_symlinks=False)
            if _identity(current) != expected:
                return False, "The item changed since the scan. Refresh before moving it to Trash."
            check, reason = validate_trash_target(target)
            if reason or check != target:
                return False, reason or "The path changed. Refresh and try again."
            result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", "-e", _TRASH_JXA, target],
                                    capture_output=True, text=True, timeout=30)
        finally:
            os.close(parent_fd)
        if result.returncode:
            return False, result.stderr.strip() or "Could not move the item to Trash."
        remove_from_index(target)
        return True, "Moved to Trash. Restore it from Finder’s Trash if needed."
    except subprocess.TimeoutExpired:
        return False, "Trash operation timed out; its outcome is unknown. Check Finder and refresh before retrying."
    except OSError as exc:
        return False, str(exc)
    finally:
        OPERATION_LOCK.release()


class ScanJobs:
    """One background scan with bounded history and an explicit commit boundary."""
    def __init__(self):
        self.lock = threading.Lock()
        self.job = None
        self.thread = None

    def start(self, path, refresh=False, max_entries=None, max_memory_mb=None):
        path = normalize_path(path)
        progress = ScanProgress(max_entries, max_memory_mb)
        if refresh:
            with INDEX_LOCK:
                if path not in INDEX:
                    raise ValueError("Folder is not in the current scan.")
        if not OPERATION_LOCK.acquire(blocking=False):
            raise BusyError("A scan or Trash operation is already running.")
        job = {"id": secrets.token_urlsafe(12), "path": path, "state": "running", "progress": progress,
               "refresh": refresh}
        with self.lock:
            self.job = job

        def run():
            try:
                root = _perform_scan(path, not refresh, progress)
                if not refresh:
                    with INDEX_LOCK:
                        for key in [k for k in INDEX if not _inside(k, path)]:
                            del INDEX[key]
                with self.lock:
                    job.update(state="done", origin=path)
            except ScanLimitError as exc:
                retry_entries = min(1_000_000_000, max(progress.max_entries + 1, progress.max_entries * 2)) if exc.kind == "entry_limit" else progress.max_entries
                retry_memory = min(1_048_576, progress.max_memory_mb * 2) if exc.kind == "memory_limit" else progress.max_memory_mb
                with self.lock:
                    job.update(state="error", error=str(exc), limit_kind=exc.kind,
                               retry={"max_entries": retry_entries, "max_memory_mb": retry_memory})
            except ScanCancelled as exc:
                with self.lock:
                    job.update(state="cancelled", error=str(exc))
            except (OSError, ValueError) as exc:
                with self.lock:
                    job.update(state="error", error=str(exc))
            except Exception:
                with self.lock:
                    job.update(state="error", error="Scan failed unexpectedly. Please try a smaller folder.")
            finally:
                progress.finish()
                progress.release_indexes()
                OPERATION_LOCK.release()

        self.thread = threading.Thread(target=run, name="macclean-job", daemon=True)
        try:
            self.thread.start()
        except BaseException:
            OPERATION_LOCK.release()
            raise
        return self.status(job["id"])

    def status(self, job_id=None):
        with self.lock:
            if self.job is None and job_id is None:
                return {"state": "idle", "cached_origin": None}
            if self.job is None or (job_id is not None and self.job["id"] != job_id):
                raise ValueError("Unknown scan. It may have been replaced by another browser tab.")
            result = {k: v for k, v in self.job.items() if k != "progress"}
            result.update(self.job["progress"].snapshot())
            with SCAN_ROOTS_LOCK:
                result["cached_origin"] = next(iter(SCAN_ROOTS), None)
            return result

    def cancel(self, job_id):
        with self.lock:
            if self.job is None or self.job["id"] != job_id:
                raise ValueError("Unknown scan.")
            if self.job["state"] == "running":
                self.job["progress"].cancel.set()
        return self.status(job_id)

    def preview(self, job_id, path=None):
        with self.lock:
            if self.job is None or self.job["id"] != job_id:
                raise ValueError("Unknown scan.")
            job = self.job
            if job["state"] != "running":
                return {"root": None, "state": job["state"]}
        # Do not hold the jobs lock while inspecting a focused folder's children:
        # cancellation and status polling should remain responsive.
        root = job["progress"].preview(path)
        with self.lock:
            if self.job is not job:
                raise ValueError("Unknown scan.")
            return {"root": root, "state": job["state"]}

    def close(self):
        with self.lock:
            if self.job:
                self.job["progress"].cancel.set()
        if self.thread:
            self.thread.join(timeout=5)


JOBS = ScanJobs()


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(24)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "MacClean/" + VERSION

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def end_headers(self):
        nonce = getattr(self, "_csp_nonce", "")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; "
                         f"script-src 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                         "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        super().end_headers()

    def _send(self, body, content_type, code=200):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8", code)

    def _error(self, message, code=400):
        self._json({"ok": False, "error": message, "message": message}, code)

    def _same_origin(self):
        origin = self.headers.get("Origin")
        return (not origin or origin == "http://" + self.headers.get("Host", "")) and self.headers.get("Sec-Fetch-Site") != "cross-site"

    def _has_token(self):
        token = self.headers.get("X-MacClean-Token", "")
        return (token.isascii() and secrets.compare_digest(token, SESSION_TOKEN)
                and self.headers.get("Host", "") in ALLOWED_HOSTS and self._same_origin())

    def do_GET(self):
        if self.headers.get("Host", "") not in ALLOWED_HOSTS or not self._same_origin():
            self._error("Unauthorized host or origin.", 403)
            return
        u = urlparse(self.path)
        if u.path == "/":
            self._csp_nonce = secrets.token_urlsafe(16)
            self._send(render_page(self._csp_nonce).encode("utf-8"), "text/html; charset=utf-8")
            return
        if not self._has_token():
            self._error("Unauthorized.", 403)
            return
        q = parse_qs(u.query)
        try:
            if u.path == "/api/status":
                self._json(JOBS.status(q.get("id", [None])[0]))
            elif u.path == "/api/preview":
                self._json(JOBS.preview(q.get("id", [""])[0], q.get("path", [None])[0]))
            elif u.path == "/api/subtree":
                self._json({"root": get_subtree(q.get("path", [""])[0])})
            elif u.path == "/api/children":
                self._json(list_children(q.get("path", [""])[0], q.get("q", [""])[0],
                                         int(q.get("offset", ["0"])[0]), int(q.get("limit", ["100"])[0])))
            elif u.path == "/api/scan":
                self._error("Use POST /api/scan to start a scan.", 405)
            else:
                self._error("Not found.", 404)
        except (OSError, ValueError) as exc:
            self._error(str(exc))

    def _read_json_body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported.")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json.")
        if len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("A single Content-Length is required.")
        try:
            length = int(self.headers["Content-Length"])
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if length < 0:
            raise ValueError("Invalid Content-Length.")
        if length > MAX_JSON_BODY:
            raise ValueError("Request body too large.")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete request body.")
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ValueError("Invalid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object.")
        # Reject lone Unicode surrogates from JSON before passing paths to OS APIs.
        for key in ("path", "id", "revision"):
            if key in data and not isinstance(data[key], str):
                raise ValueError(f"{key} must be a string.")
            if isinstance(data.get(key), str):
                try:
                    os.fsencode(data[key])
                except UnicodeEncodeError as exc:
                    raise ValueError(f"Invalid characters in {key}.") from exc
        return data

    def do_POST(self):
        if not self._has_token():
            self._error("Unauthorized.", 403)
            return
        u = urlparse(self.path)
        if u.path not in ("/api/scan", "/api/cancel", "/api/trash", "/api/reveal"):
            self._error("Not found.", 404)
            return
        try:
            data = self._read_json_body()
            if u.path == "/api/cancel":
                self._json(JOBS.cancel(data.get("id")))
                return
            path = data.get("path")
            if not isinstance(path, str) or not path or "\0" in path:
                raise ValueError("A valid path string is required.")
            if u.path == "/api/scan":
                refresh = data.get("refresh", False)
                if not isinstance(refresh, bool):
                    raise ValueError("refresh must be a boolean.")
                limits = {key: data[key] for key in ("max_entries", "max_memory_mb") if key in data}
                if any(value is None for value in limits.values()):
                    raise ValueError("Scan limits must be integers.")
                self._json(JOBS.start(path, refresh, **limits), 202)
            elif u.path == "/api/trash":
                ok, message = move_to_trash(path, data.get("revision"))
                self._json({"ok": ok, "message": message}, 200 if ok else 400)
            else:
                ok, message = reveal_in_finder(path)
                self._json({"ok": ok, "message": message}, 200 if ok else 400)
        except BusyError as exc:
            self._error(str(exc), 409)
        except (OSError, ValueError) as exc:
            self._error(str(exc), 413 if "too large" in str(exc) else 400)


PAGE = Path(__file__).with_suffix(".html").read_text(encoding="utf-8")


def _js_literal(value):
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_page(csp_nonce=""):
    # Replace template tokens in a single pass: path text cannot inject tokens.
    import re
    values = {"START_PATH": START_PATH, "TOKEN": SESSION_TOKEN,
              "READ_ONLY": READ_ONLY or sys.platform != "darwin", "CSP_NONCE": csp_nonce}
    return re.sub(r"__(START_PATH|TOKEN|READ_ONLY|CSP_NONCE)__",
                  lambda m: _js_literal(values[m[1]])[1:-1] if m[1] == "CSP_NONCE" else _js_literal(values[m[1]]), PAGE)


def main(argv=None):
    global START_PATH, ALLOWED_HOSTS, READ_ONLY, WORKERS, MAX_ENTRIES, MAX_MEMORY_MB, EXCLUDE_PATHS
    ap = argparse.ArgumentParser(description="Analyze disk usage in an offline browser UI. Nothing is permanently deleted.")
    ap.add_argument("path", nargs="?", default="~", help="folder to scan (default: home)")
    ap.add_argument("--port", type=int, default=8765, help="loopback port (default: 8765; 0 chooses a free port)")
    ap.add_argument("--no-open", action="store_true", help="do not open the browser automatically")
    ap.add_argument("--read-only", action="store_true", help="disable all Move to Trash actions")
    ap.add_argument("--exclude", action="append", default=[], metavar="FOLDER",
                    help="skip a folder and its descendants (repeatable; useful for stalled cloud-provider folders)")
    ap.add_argument("--workers", type=int, default=WORKERS, help="scan threads, 1–32 (default: %(default)s)")
    ap.add_argument("--max-entries", type=int, default=MAX_ENTRIES, help="optional entry limit (default: 0, no entry cap)")
    ap.add_argument("--max-memory-mb", type=int, default=MAX_MEMORY_MB,
                    help="process memory budget in MiB (default: 0, automatic based on RAM)")
    ap.add_argument("--version", action="version", version="MacClean " + VERSION)
    args = ap.parse_args(argv)
    if not 0 <= args.port <= 65535:
        ap.error("--port must be between 0 and 65535")
    if not 1 <= args.workers <= 32:
        ap.error("--workers must be between 1 and 32")
    try:
        _validate_scan_limits(args.max_entries, args.max_memory_mb)
    except ValueError as exc:
        ap.error(str(exc))
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        ap.error("Run MacClean as your normal user, without sudo.")
    START_PATH = normalize_path(args.path)
    if not os.path.isdir(START_PATH):
        ap.error(f"Not a folder: {START_PATH}")
    READ_ONLY, WORKERS, MAX_ENTRIES = args.read_only, args.workers, args.max_entries
    MAX_MEMORY_MB = args.max_memory_mb
    EXCLUDE_PATHS = tuple(normalize_path(path) for path in args.exclude)
    try:
        server = LocalServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        ap.exit(1, f"Cannot start MacClean: {exc}. Try --port 0 for a free port.\n")
    port = server.server_address[1]
    ALLOWED_HOSTS = {f"127.0.0.1:{port}", f"localhost:{port}"}
    url = f"http://127.0.0.1:{port}/"
    print(f"MacClean {VERSION} running at {url}", flush=True)
    print(f"Starting folder: {START_PATH}")
    if READ_ONLY or sys.platform != "darwin":
        print("Read-only mode: Move to Trash is disabled.")
    print("Press Ctrl+C to stop.", flush=True)
    if not args.no_open:
        timer = threading.Timer(0.3, lambda: webbrowser.open(url))
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nMacClean stopped.")
    finally:
        JOBS.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
