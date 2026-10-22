#!/usr/bin/env python3
"""
MacWinClean — an interactive folder size analyzer for macOS and Windows.

Usage:
    python3 macwinclean.py [PATH] [--port N] [--no-open]

Scans PATH (default: your home folder), then opens an interactive
sunburst in your browser. Click rings to dive in, select anything and
move it to the Trash (recoverable) to reclaim space.

Pure standard library. No build step, no internet required.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.setrecursionlimit(100_000)

# ---- Platform ---------------------------------------------------------------
IS_MAC = sys.platform == "darwin"
IS_WIN = os.name == "nt"
IS_POSIX = not IS_WIN
PLATFORM = "mac" if IS_MAC else "win" if IS_WIN else "other"
# Name of the OS file manager, used in UI labels.
FILE_MANAGER = "Finder" if IS_MAC else "Explorer" if IS_WIN else "Files"


def _norm(p):
    """Normalize a path for comparison (case-insensitive on Windows)."""
    return os.path.normcase(os.path.abspath(p))

# ---- Tuning -----------------------------------------------------------------
SEND_DEPTH = 7        # how many ring-levels of data to send per request
MAX_CHILDREN = 80     # max children kept per node (rest aggregated)
MIN_FRACTION = 0.003  # children smaller than this fraction of parent are aggregated
WORKERS = max(4, (os.cpu_count() or 4) * 2)
MAX_JSON_BODY = 64 * 1024

START_PATH = "~"  # set from CLI, injected into the page

# ---- Security ---------------------------------------------------------------
# A deletion-capable local server needs to defend against CSRF / drive-by
# requests from other pages in the browser. We require a per-process random
# token on every API request, enforce same-origin on POST, only ever act
# on paths *inside* a folder the user actually scanned, and never delete
# protected system/home/app roots.
SESSION_TOKEN = secrets.token_urlsafe(24)
ALLOWED_HOSTS = set()        # {"127.0.0.1:PORT", "localhost:PORT"}; filled at startup
SCAN_ROOTS = set()           # realpaths the user explicitly scanned (delete allowlist)
SCAN_ROOTS_LOCK = threading.Lock()

# Folders we will never move to Trash even if they sit inside a scanned root.
_HOME = os.path.realpath(os.path.expanduser("~"))


def _build_protected():
    home = _HOME
    common = {home,
              os.path.join(home, "Desktop"),
              os.path.join(home, "Documents"),
              os.path.join(home, "Downloads")}
    if IS_WIN:
        env = os.environ
        drive = env.get("SystemDrive", "C:") + os.sep
        common |= {
            env.get("SystemRoot", r"C:\Windows"),
            env.get("ProgramFiles", r"C:\Program Files"),
            env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            env.get("ProgramData", r"C:\ProgramData"),
            os.path.join(drive, "Users"),
            os.path.join(drive, "Users", "Public"),
            os.path.join(home, "AppData"),
        }
    else:
        common |= {
            "/", "/System", "/Library", "/Applications", "/Users", "/Users/Shared",
            "/private", "/usr", "/bin", "/sbin", "/opt", "/cores", "/Volumes",
            "/etc", "/var", "/tmp", "/dev", "/Network",
            os.path.join(home, "Library"),
        }
    return {_norm(p) for p in common}


PROTECTED_EXACT = _build_protected()


def protected_reason(realpath):
    """Return a human reason if `realpath` must never be trashed, else None."""
    rp = _norm(realpath)
    if rp in PROTECTED_EXACT:
        return "a protected system, home, or top-level folder"

    if IS_WIN:
        _drive, tail = os.path.splitdrive(realpath)
        if tail in ("", os.sep, "/"):
            return "a drive root"
        sysroot = _norm(os.environ.get("SystemRoot", r"C:\Windows"))
        if rp == sysroot or rp.startswith(sysroot + os.sep):
            return "a Windows system folder"
    else:
        if realpath == "/System" or realpath.startswith("/System/"):
            return "a macOS system folder"
        # /Volumes/<name> (a mounted volume root) but not items inside it
        if realpath.startswith("/Volumes/") and realpath.count("/") == 2:
            return "a mounted volume root"

    # any ancestor of the home folder (e.g. /Users or C:\Users)
    home = _norm(_HOME)
    if rp == home or home.startswith(rp + os.sep):
        return "a folder that contains your Home folder"
    return None


def validate_trash_target(path):
    """Return (target, None) if `path` is safe to Trash, else (None, reason).

    `target` is the selected item *itself*: we resolve symlinks in the path
    prefix (so a link in the prefix can't smuggle the location outside the
    allowlist) but keep the final component as-is. That means selecting a
    symlink trashes the link, never the file it points at.
    """
    if not path:
        return None, "No path given."
    abspath = os.path.abspath(os.path.expanduser(path))
    parent = os.path.realpath(os.path.dirname(abspath))
    target = os.path.join(parent, os.path.basename(abspath))
    if not os.path.lexists(target):  # lexists: a dangling symlink still counts
        return None, "Path does not exist."

    with SCAN_ROOTS_LOCK:
        roots = set(SCAN_ROOTS)
    inside = False
    for root in roots:
        try:
            if target != root and os.path.commonpath([target, root]) == root:
                inside = True
                break
        except ValueError:
            continue  # different drive / not comparable
    if not inside:
        return None, "Refusing: item is outside the folder you scanned."

    reason = protected_reason(target)
    if reason:
        return None, f"Refusing to delete {reason}."
    return target, None


# ---- Scanner ----------------------------------------------------------------
# A node is a dict: {name, path, size, dir, children?}.  `children` only on dirs.
# `size` is the ALLOCATED size estimate (st_blocks*512) — much closer to real
# disk usage than apparent size (st_size) for APFS compression and sparse
# files. It is an *estimate*, not exact uniquely-reclaimable bytes: hard links
# are counted once per link and APFS clones / shared extents are counted in
# full for each path, so deleting one copy may free less than shown.
# INDEX maps a directory path -> its node, so drill-down/trash are O(1).
INDEX = {}
INDEX_LOCK = threading.Lock()


def _alloc(st):
    """Allocated bytes on disk. st_blocks is in 512-byte units (POSIX)."""
    blocks = getattr(st, "st_blocks", None)
    if blocks is None:  # not available on this platform; fall back
        return st.st_size
    return blocks * 512


def _basename(path):
    return os.path.basename(path.rstrip("/\\")) or path


# ---- Live scan progress -----------------------------------------------------
# The scanner publishes running counters (items + bytes seen, and how many of
# the top-level entries have finished) so the browser can show a progress bar
# by polling /api/scan/progress while the scan request is still in flight.
class ScanProgress:
    def __init__(self):
        self.lock = threading.Lock()
        self.items = 0
        self.bytes = 0
        self.done_top = 0
        self.total_top = 0
        self.active = True
        self.finished = False

    def add(self, items, nbytes):
        with self.lock:
            self.items += items
            self.bytes += nbytes

    def tick_top(self):
        with self.lock:
            self.done_top += 1

    def set_total_top(self, n):
        with self.lock:
            self.total_top = n

    def finish(self):
        with self.lock:
            self.active = False
            self.finished = True

    def snapshot(self):
        with self.lock:
            return {"active": self.active, "finished": self.finished,
                    "items": self.items, "bytes": self.bytes,
                    "doneTop": self.done_top, "totalTop": self.total_top}


_PROGRESS_LOCK = threading.Lock()
_CURRENT_PROGRESS = None


def new_progress():
    global _CURRENT_PROGRESS
    p = ScanProgress()
    with _PROGRESS_LOCK:
        _CURRENT_PROGRESS = p
    return p


def progress_snapshot():
    with _PROGRESS_LOCK:
        p = _CURRENT_PROGRESS
    if p is None:
        return {"active": False, "finished": True, "items": 0, "bytes": 0,
                "doneTop": 0, "totalTop": 0}
    return p.snapshot()


def _walk_dir(path, index, skipped, progress=None, name=None):
    """Recursively build a node for directory `path`.

    Uses scandir's cached entry metadata: `entry.is_dir`/`is_symlink` come
    from the dirent type (no syscall on macOS), and only *files* get a single
    `stat` for their size — directories are never stat'd, we sum their kids.
    Nodes are written into the local `index` dict (merged under the lock later).
    Directories we can't read are appended to `skipped` so the UI can disclose
    that the totals are incomplete.
    """
    total = 0
    newest = 0  # most recent mtime among descendants — drives the Age heatmap
    leaf_bytes = 0
    children = []
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    if e.is_symlink():
                        # Count the link itself as a leaf, never follow it.
                        st = e.stat(follow_symlinks=False)
                        child = {"name": e.name, "path": e.path,
                                 "size": _alloc(st), "dir": False, "mtime": int(st.st_mtime)}
                    elif e.is_dir(follow_symlinks=False):
                        child = _walk_dir(e.path, index, skipped, progress, e.name)
                    else:
                        st = e.stat(follow_symlinks=False)
                        child = {"name": e.name, "path": e.path,
                                 "size": _alloc(st), "dir": False, "mtime": int(st.st_mtime)}
                except OSError:
                    skipped.append(e.path)
                    continue
                children.append(child)
                total += child["size"]
                if not child["dir"]:
                    leaf_bytes += child["size"]
                if child.get("mtime", 0) > newest:
                    newest = child["mtime"]
    except PermissionError:
        skipped.append(path)
    except OSError:
        skipped.append(path)

    # Flush once per directory (not per file) to keep lock traffic low while
    # still updating the bar continuously. Each node is counted by its parent,
    # so summing direct children across all dirs counts every node exactly once.
    if progress is not None:
        progress.add(len(children), leaf_bytes)

    node = {"name": name or _basename(path), "path": path, "size": total,
            "dir": True, "children": children, "mtime": newest}
    index[path] = node
    return node


def scan(path, register_root=False, progress=None):
    """Scan `path`, parallelizing across its top-level entries for speed.

    Each top-level subtree is walked in its own thread into a private index,
    so threads never contend on the lock during the heavy traversal; the
    per-thread indexes are merged once at the end.

    If `register_root` is set the resolved path is added to the delete
    allowlist (only items inside a scanned root may be trashed). If `progress`
    is given it is updated live so a UI can show a progress bar.
    """
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(path):
        raise NotADirectoryError(f"Not a folder: {path}")

    children, merged, skipped = [], {}, []
    try:
        with os.scandir(path) as it:
            top = list(it)
    except (PermissionError, OSError):
        top = []
        skipped.append(path)

    if progress is not None:
        progress.set_total_top(len(top))

    def work(e):
        idx, skipped = {}, []
        try:
            if e.is_symlink() or not e.is_dir(follow_symlinks=False):
                st = e.stat(follow_symlinks=False)
                node = {"name": e.name, "path": e.path,
                        "size": _alloc(st), "dir": False, "mtime": int(st.st_mtime)}
            else:
                node = _walk_dir(e.path, idx, skipped, progress, e.name)
        except OSError:
            skipped.append(e.path)
            return None, idx, skipped
        return node, idx, skipped

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for node, idx, sk in pool.map(work, top):
            skipped.extend(sk)
            if progress is not None:
                progress.tick_top()
                # Count the top-level entry itself (its descendants were
                # already counted inside _walk_dir).
                progress.add(1, node["size"] if node and not node["dir"] else 0)
            if node:
                children.append(node)
                merged.update(idx)

    total = sum(c["size"] for c in children)
    newest = max((c.get("mtime", 0) for c in children), default=0)
    node = {"name": _basename(path), "path": path, "size": total, "dir": True,
            "children": children, "mtime": newest, "skipped": len(skipped),
            "skipped_sample": skipped[:15]}
    merged[path] = node
    with INDEX_LOCK:
        # Drop any stale entries from a previous scan of this same subtree
        # (folders that have since been deleted) before merging fresh ones.
        prefix = path.rstrip("/") + "/"
        for k in [k for k in INDEX if k == path or k.startswith(prefix)]:
            del INDEX[k]
        INDEX.update(merged)
        INDEX[path] = node
    if register_root:
        with SCAN_ROOTS_LOCK:
            SCAN_ROOTS.add(os.path.realpath(path))
    return node


def rescan(path, progress=None):
    """Re-scan a single folder in place and correct ancestor sizes.

    Used by the Refresh button so the current folder reflects on-disk changes
    (e.g. files you deleted in Finder) without re-scanning everything.
    """
    path = os.path.abspath(os.path.expanduser(path))
    with INDEX_LOCK:
        old = INDEX.get(path)
        old_size = old["size"] if old else None

    fresh = scan(path, progress=progress)  # rebuilds INDEX entries for this subtree

    with INDEX_LOCK:
        # Relink the parent's child entry to the fresh node so navigating up
        # shows the new size (scan() replaced INDEX[path] but not the parent's
        # reference into it).
        parent = INDEX.get(os.path.dirname(path))
        if parent:
            kids = parent.get("children", [])
            for i, c in enumerate(kids):
                if c["path"] == path:
                    kids[i] = fresh
                    break
        if old_size is not None and fresh["size"] != old_size:
            delta = fresh["size"] - old_size
            cur = os.path.dirname(path)
            while True:
                p = INDEX.get(cur)
                if p:
                    p["size"] = max(0, p["size"] + delta)
                nxt = os.path.dirname(cur)
                if nxt == cur:
                    break
                cur = nxt
    return fresh


def prune(node, depth=0):
    """Trim a node for transport: cap depth, aggregate tiny children."""
    out = {"name": node["name"], "path": node["path"], "size": node["size"],
           "dir": node["dir"], "mtime": node.get("mtime", 0)}
    if depth == 0 and node.get("skipped"):
        out["skipped"] = node["skipped"]
        out["skipped_sample"] = node.get("skipped_sample", [])
    if not node.get("dir"):
        return out

    kids = node.get("children") or []
    if depth >= SEND_DEPTH:
        # Boundary: don't send children, but flag that more exists to drill into.
        out["more"] = bool(kids)
        return out

    kids = sorted(kids, key=lambda c: c["size"], reverse=True)
    threshold = node["size"] * MIN_FRACTION
    kept, other_size, other_count = [], 0, 0
    for c in kids:
        if c["size"] >= threshold and len(kept) < MAX_CHILDREN:
            kept.append(prune(c, depth + 1))
        else:
            other_size += c["size"]
            other_count += 1
    if other_size > 0:
        kept.append({
            "name": f"({other_count} small item{'s' if other_count != 1 else ''})",
            "path": "", "size": other_size, "dir": False, "other": True,
        })
    out["children"] = kept
    return out


def get_subtree(path):
    """Return a pruned subtree for `path`, scanning fresh if not yet indexed."""
    with INDEX_LOCK:
        node = INDEX.get(path)
    if node is None:
        node = scan(path)
    return prune(node)


def remove_from_index(path):
    """After trashing `path`, drop it (and any descendants) from the cached
    tree and fix ancestor sizes so the UI stays consistent without a rescan."""
    with INDEX_LOCK:
        node = INDEX.get(path)
        size = None
        if node is not None:
            size = node["size"]
        else:
            # Not directly indexed (a file): find its size via the parent's
            # child entry so we can correct ancestor totals.
            parent = INDEX.get(os.path.dirname(path))
            if parent:
                for c in parent.get("children", []):
                    if c["path"] == path:
                        size = c["size"]
                        break

        # Purge the node and every indexed descendant (prevents stale entries
        # and unbounded memory growth across deletes).
        prefix = path.rstrip("/") + "/"
        for k in [k for k in INDEX if k == path or k.startswith(prefix)]:
            del INDEX[k]

        if size is None:
            return  # couldn't determine size; at least the index is clean

        cur = os.path.dirname(path)
        first = True
        while True:
            p = INDEX.get(cur)
            if p:
                p["size"] = max(0, p["size"] - size)
                if first:
                    p["children"] = [c for c in p.get("children", []) if c["path"] != path]
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
            first = False


# ---- Reveal in the OS file manager ------------------------------------------
def reveal_path(path):
    """Open a folder, or reveal+select a file in its containing folder."""
    if not path or not os.path.exists(path):
        return False, "Path does not exist."
    try:
        if IS_MAC:
            args = ["open", path] if os.path.isdir(path) else ["open", "-R", path]
        elif IS_WIN:
            # explorer returns nonzero even on success, so don't check its code.
            args = ["explorer", path] if os.path.isdir(path) else ["explorer", "/select,", path]
            subprocess.run(args, timeout=15)
            return True, "ok"
        else:  # Linux / other: open the folder containing the item.
            folder = path if os.path.isdir(path) else os.path.dirname(path)
            args = ["xdg-open", folder]
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return False, (r.stderr.strip() or f"Could not open in {FILE_MANAGER}.")
        return True, "ok"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


# ---- Move to Trash / Recycle Bin (recoverable) ------------------------------
# macOS: NSFileManager.trashItemAtURL via JXA — moves the item itself (with
# Put-Back support) and does NOT follow a final symlink (`fileURLWithPath`
# operates on the given path), so selecting a symlink trashes the link, not its
# target. No Finder Automation permission needed.
_TRASH_JXA = (
    'ObjC.import("Foundation");\n'
    'function run(argv){\n'
    '  var url = $.NSURL.fileURLWithPath(argv[0]);\n'
    '  var err = $();\n'
    '  var ok = $.NSFileManager.defaultManager'
    '.trashItemAtURLResultingItemURLError(url, null, err);\n'
    '  if(!ok){ throw new Error(err.localizedDescription.js); }\n'
    '  return "ok";\n'
    '}'
)

# Windows: Microsoft.VisualBasic FileSystem.DeleteFile/DeleteDirectory with
# SendToRecycleBin. The path is passed via an env var (not interpolated into
# the script) so it can't break out or inject PowerShell.
_TRASH_PS = (
    "Add-Type -AssemblyName Microsoft.VisualBasic;"
    "$p = $env:MACWINCLEAN_TRASH_PATH;"
    "if (Test-Path -LiteralPath $p -PathType Container) {"
    "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory("
    "$p,'OnlyErrorDialogs','SendToRecycleBin') } else {"
    "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile("
    "$p,'OnlyErrorDialogs','SendToRecycleBin') }"
)


def _trash_mac(target):
    r = subprocess.run(["osascript", "-l", "JavaScript", "-e", _TRASH_JXA, target],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return False, (r.stderr.strip() or "Could not move the item to the Trash.")
    return True, "ok"


def _trash_windows(target):
    env = os.environ.copy()
    env["MACWINCLEAN_TRASH_PATH"] = target
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _TRASH_PS],
        capture_output=True, text=True, timeout=30, env=env,
    )
    if r.returncode != 0:
        return False, (r.stderr.strip() or "Could not move the item to the Recycle Bin.")
    return True, "ok"


def _trash_posix(target):
    # Best effort on Linux/other via the freedesktop trash (GNOME's gio).
    try:
        r = subprocess.run(["gio", "trash", "--", target],
                           capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return False, "No Trash backend available (install glib's `gio`)."
    if r.returncode != 0:
        return False, (r.stderr.strip() or "Could not move the item to the Trash.")
    return True, "ok"


def move_to_trash(path):
    # Server-side guard: only trash items inside a scanned root, never a
    # protected folder. Never trust the client to have checked.
    target, reason = validate_trash_target(path)
    if reason:
        return False, reason
    try:
        if IS_MAC:
            ok, msg = _trash_mac(target)
        elif IS_WIN:
            ok, msg = _trash_windows(target)
        else:
            ok, msg = _trash_posix(target)
        if not ok:
            return False, msg
        # Keep the in-memory tree consistent. INDEX keys are abspaths from the
        # scan; update both the original selection and the resolved target.
        abspath = os.path.abspath(os.path.expanduser(path))
        remove_from_index(abspath)
        if target != abspath:
            remove_from_index(target)
        return True, "ok"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


# ---- HTTP server ------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def end_headers(self):
        nonce = getattr(self, "_csp_nonce", None)
        script_src = f"'self' 'nonce-{nonce}'" if nonce else "'self'"
        csp = (
            "default-src 'self'; "
            f"script-src {script_src}; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'none'"
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", csp)
        super().end_headers()

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _has_token(self):
        """Constant header check: the per-process token must be present.

        Custom headers can't be sent cross-origin without a CORS preflight we
        never grant, so this also blocks drive-by GETs from other web pages.
        """
        token = self.headers.get("X-MacWinClean-Token", "")
        return (secrets.compare_digest(token, SESSION_TOKEN)
                and self.headers.get("Host", "") in ALLOWED_HOSTS)

    def _authorized_mutation(self):
        """True only for same-origin POSTs bearing the session token (anti-CSRF)."""
        if not self._has_token():
            return False
        # A browser sets Origin on fetch POSTs; if present it must be ours.
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc not in ALLOWED_HOSTS:
            return False
        return True

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path == "/":
            self._csp_nonce = secrets.token_urlsafe(16)
            body = render_page(self._csp_nonce).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # All API endpoints mutate state (scan registers a delete-allowlist
        # root; subtree?fresh rescans) or do disk-heavy work, so they require
        # the session token even on GET — a random web page can't supply it.
        if u.path in ("/api/scan", "/api/subtree", "/api/scan/progress"):
            if not self._has_token():
                self._json({"error": "Unauthorized."}, 403)
                return

        if u.path == "/api/scan/progress":
            self._json(progress_snapshot())
            return

        if u.path == "/api/scan":
            path = (q.get("path") or [os.path.expanduser("~")])[0]
            prog = new_progress()
            try:
                node = scan(path, register_root=True, progress=prog)
            except Exception as e:  # noqa: BLE001
                self._json({"error": str(e)}, 400)
                return
            finally:
                prog.finish()
            self._json({"root": prune(node), "origin": node["path"]})
            return

        if u.path == "/api/subtree":
            path = (q.get("path") or [""])[0]
            fresh = (q.get("fresh") or ["0"])[0] == "1"
            prog = new_progress() if fresh else None
            try:
                node = rescan(path, progress=prog) if fresh else None
                self._json({"root": prune(node) if node else get_subtree(path)})
            except Exception as e:  # noqa: BLE001
                self._json({"error": str(e)}, 400)
            finally:
                if prog is not None:
                    prog.finish()
            return

        self.send_error(404)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if length < 0:
            raise ValueError("Invalid Content-Length.")
        if length > MAX_JSON_BODY:
            raise ValueError("Request body too large.")
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON.") from exc

    def do_POST(self):
        u = urlparse(self.path)
        if u.path not in ("/api/trash", "/api/reveal"):
            self.send_error(404)
            return
        if not self._authorized_mutation():
            self._json({"ok": False, "message": "Unauthorized."}, 403)
            return
        try:
            data = self._read_json_body()
        except ValueError as e:
            code = 413 if "too large" in str(e) else 400
            self._json({"ok": False, "message": str(e)}, code)
            return
        if u.path == "/api/trash":
            ok, msg = move_to_trash(data.get("path", ""))
        else:
            ok, msg = reveal_path(data.get("path", ""))
        self._json({"ok": ok, "message": msg}, 200 if ok else 400)


# ---- Front-end (self-contained: no CDN, vanilla SVG sunburst) ---------------
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MacWinClean</title>
<style nonce="__CSP_NONCE__">
  :root{
    --bg:#0e1117; --panel:#171c26; --panel2:#1f2632; --line:#2a3340;
    --txt:#e6edf3; --dim:#8b97a7; --accent:#4da3ff; --danger:#ff5d5d;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{background:var(--bg);color:var(--txt);font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,Arial,sans-serif;display:flex;flex-direction:column}
  header{display:flex;gap:8px;align-items:center;padding:10px 14px;background:var(--panel);border-bottom:1px solid var(--line)}
  header .logo{font-weight:700;letter-spacing:.3px;margin-right:6px}
  header .logo b{color:var(--accent)}
  input[type=text]{flex:0 1 420px;background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:7px 10px;border-radius:8px;font-size:13px}
  button{background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:7px 12px;border-radius:8px;cursor:pointer;font-size:13px}
  button:hover{border-color:var(--accent)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#06223f;font-weight:600}
  button.danger{background:var(--danger);border-color:var(--danger);color:#3a0000;font-weight:600}
  .chip{padding:5px 10px;font-size:12px;color:var(--dim)}
  .chip:hover{color:var(--txt)}
  main{flex:1;display:flex;min-height:0}
  #chart{flex:1;display:flex;align-items:center;justify-content:center;position:relative;min-width:0}
  #crumbs{position:absolute;top:12px;left:14px;right:14px;display:flex;flex-wrap:wrap;gap:4px;align-items:center;color:var(--dim);font-size:12px}
  #crumbs a{color:var(--accent);cursor:pointer;text-decoration:none}
  #crumbs a:hover{text-decoration:underline}
  #crumbs span.sep{color:var(--line)}
  aside{width:330px;flex:none;background:var(--panel);border-left:1px solid var(--line);padding:16px;overflow:auto;display:flex;flex-direction:column;gap:14px}
  .card{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px}
  .sel-name{font-size:15px;font-weight:600;word-break:break-all}
  .sel-path{color:var(--dim);font-size:11px;word-break:break-all;margin-top:4px}
  .sel-size{font-size:26px;font-weight:700;margin-top:8px}
  .sel-meta{color:var(--dim);font-size:12px;margin-top:2px}
  .actions{display:flex;gap:8px;margin-top:12px}
  .actions button{flex:1}
  h3{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);font-weight:600}
  .list{display:flex;flex-direction:column;gap:2px}
  .row{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:7px;cursor:pointer}
  .row:hover{background:var(--panel2)}
  .row .sw{width:10px;height:10px;border-radius:3px;flex:none}
  .row .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .row .sz{color:var(--dim);font-variant-numeric:tabular-nums}
  .row .bar{height:3px;border-radius:2px;margin-top:3px;background:var(--accent);opacity:.5}
  .row .nmwrap{flex:1;min-width:0}
  #status{position:absolute;bottom:12px;left:14px;color:var(--dim);font-size:12px}
  .overlay{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(14,17,23,.7);font-size:15px;color:var(--dim);z-index:5}
  .scanbox{width:360px;max-width:72%;text-align:center}
  .scan-title{font-size:15px;color:var(--txt);margin-bottom:12px;word-break:break-all}
  .bar-track{height:9px;background:var(--panel2);border:1px solid var(--line);border-radius:6px;overflow:hidden}
  .bar-fill{height:100%;width:0;background:linear-gradient(90deg,var(--accent),#7ec8ff);border-radius:6px;transition:width .2s ease}
  .bar-fill.indet{width:34%;animation:indet 1.1s ease-in-out infinite}
  @keyframes indet{0%{margin-left:-34%}100%{margin-left:100%}}
  .scan-stats{margin-top:10px;color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums}
  svg path{cursor:pointer;transition:opacity .08s}
  .center-label{pointer-events:none}
  .empty{color:var(--dim)}
  select{background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:6px 8px;border-radius:8px;font-size:13px;cursor:pointer}
  select:hover{border-color:var(--accent)}
  label.ctl{display:flex;align-items:center;gap:6px;color:var(--dim);font-size:12px;margin-left:4px}
  #legend{position:absolute;bottom:11px;right:14px;display:none;align-items:center;gap:8px;color:var(--dim);font-size:11px;background:rgba(23,28,38,.78);padding:5px 9px;border-radius:8px}
  #legend .grad{width:130px;height:9px;border-radius:5px;border:1px solid var(--line)}
</style>
</head>
<body>
<header>
  <div class="logo"><b>MacWin</b>Clean</div>
  <input id="path" type="text" placeholder="/Users/you/Documents" spellcheck="false">
  <button class="primary" id="scan">Scan</button>
  <button id="refresh" title="Re-scan the current folder from disk">↻ Refresh</button>
  <label class="ctl">Color
    <select id="colorMode" title="How to color the chart">
      <option value="folder">Folder</option>
      <option value="cleanup">Cleanup likelihood</option>
      <option value="age">Age (last modified)</option>
    </select>
  </label>
  <span class="chip" data-go="~">Home</span>
  <span class="chip" data-go="~/Downloads">Downloads</span>
  <span class="chip" data-go="~/Documents">Documents</span>
  <span class="chip" data-go="~/Desktop">Desktop</span>
  <span class="chip" data-go="__CACHE_PATH__">Caches</span>
</header>
<main>
  <div id="chart">
    <div id="crumbs"></div>
    <svg id="svg"></svg>
    <div id="status"></div>
    <div id="legend"></div>
    <div class="overlay" id="overlay">Enter a folder and press Scan.</div>
  </div>
  <aside>
    <div class="card" id="selcard">
      <div class="sel-name" id="selName">Nothing selected</div>
      <div class="sel-path" id="selPath"></div>
      <div class="sel-size" id="selSize"></div>
      <div class="sel-meta" id="selMeta"></div>
      <div class="actions">
        <button id="zoomBtn" style="display:none">Open ↘</button>
        <button id="finderBtn" style="display:none" data-fm="Reveal in %s">Reveal in Finder</button>
        <button class="danger" id="trashBtn" style="display:none">Move to Trash</button>
      </div>
    </div>
    <div class="card">
      <h3>Contents (largest first)</h3>
      <div class="list" id="list"><div class="empty">—</div></div>
    </div>
  </aside>
</main>
<script nonce="__CSP_NONCE__">
const HOME = location.search; // unused; kept for clarity
const $ = s => document.querySelector(s);
const svg = $('#svg');
const SVGNS = 'http://www.w3.org/2000/svg';

let origin = '';        // originally scanned root path
let viewRoot = null;    // node currently at center
let viewPath = '';      // its path
let selected = null;    // selected node
let arcs = [];          // laid-out arcs currently drawn
const HOLE = 78, RINGS = 7;

function fmt(n){
  if(n < 1024) return n + ' B';
  const u = ['KB','MB','GB','TB','PB']; let i=-1; let v=n;
  do { v/=1024; i++; } while(v>=1024 && i<u.length-1);
  return (v>=100?v.toFixed(0):v>=10?v.toFixed(1):v.toFixed(2)) + ' ' + u[i];
}
function colorFor(hue, depth){
  const light = Math.max(34, 64 - depth*6);
  const sat = depth===0 ? 0 : 48;
  return `hsl(${hue|0} ${sat}% ${light}%)`;
}

// ---- color modes -----------------------------------------------------------
let colorMode = 'folder';           // 'folder' | 'cleanup' | 'age'
let ageRange = {min:0, max:1};      // mtime range over the visible arcs

function ext(name){ const i=name.lastIndexOf('.'); return i>0 ? name.slice(i+1).toLowerCase() : ''; }

// Substrings that strongly suggest disposable/regenerable data.
const JUNK_PATH = ['/node_modules/','/caches/','/cache/','/.cache/','/logs/',
  'deriveddata','/.trash/','__pycache__','/.gradle/','/pods/','/.cocoapods/',
  '/build/','/dist/','/.next/','/.nuxt/','/.venv/','/venv/','/.tox/',
  '/.pytest_cache/','/tmp/','/temp/','/.npm/','/.yarn/','/target/',
  // Windows
  '/appdata/local/temp/','/windows/temp/','/$recycle.bin/',
  '/appdata/local/microsoft/windows/inetcache/','/appdata/local/crashdumps/'];
const JUNK_EXT = new Set(['log','tmp','temp','cache','crash','dmp','part','download','o','pyc','class']);
const ARCHIVE_EXT = new Set(['dmg','pkg','iso','zip','tar','gz','tgz','bz2','rar','7z']);
const IMPORTANT_EXT = new Set(['py','js','ts','jsx','tsx','swift','java','kt','c','h','cpp','cc','hpp','go','rs','rb','php','sh','html','css','scss','vue',
  'pdf','doc','docx','xls','xlsx','ppt','pptx','key','pages','numbers','txt','md','rtf','csv',
  'jpg','jpeg','png','heic','gif','tiff','raw','cr2','nef','psd','ai','sketch','mov','mp4','m4v','avi','mkv','wav','aiff','flac','mp3','m4a',
  'sqlite','db','sql']);
const IMPORTANT_PATH = ['/documents/','/desktop/','/pictures/','/movies/','/music/'];

// 0 = likely important (keep / red) … 1 = likely junk (clean / green).
function junkScore(node){
  const p = (node.path||'').toLowerCase().replace(/\\/g,'/') + '/';
  const name = node.name||'', e = ext(name);
  let s = 0.45, strong = false;
  for(const k of JUNK_PATH){ if(p.includes(k)){ s = 0.92; strong = true; break; } }
  if(!strong){
    if(name === '.DS_Store' || name.startsWith('._')){ s = 0.9; }
    else if(JUNK_EXT.has(e)){ s = 0.85; }
    else if(ARCHIVE_EXT.has(e)){ s = p.includes('/downloads/') ? 0.8 : 0.6; }
    else if(IMPORTANT_EXT.has(e)){ s = 0.15; }
    else { for(const k of IMPORTANT_PATH){ if(p.includes(k)){ s = 0.3; break; } } }
  }
  // Stale things are likelier disposable; freshly-touched things less so.
  if(node.mtime){
    const days = (Date.now()/1000 - node.mtime)/86400;
    if(days > 365) s += 0.12; else if(days < 7) s -= 0.12;
  }
  return Math.max(0, Math.min(1, s));
}

function heat(hue, depth){
  const light = Math.max(34, 50 - depth*2);
  return `hsl(${hue|0} 60% ${light}%)`;
}
function ageHue(mtime){
  if(!mtime) return null;
  const {min,max} = ageRange;
  const norm = max>min ? (mtime-min)/(max-min) : 1;  // 0 old … 1 recent
  return 120*(1-norm);                                // old→green, recent→red
}
// Color for a node at a given ring depth under the active mode.
function nodeColor(node, depth){
  if(node.other) return 'hsl(220 6% 34%)';
  if(colorMode==='cleanup') return heat(120*junkScore(node), depth);
  if(colorMode==='age'){ const h = ageHue(node.mtime); return h==null ? 'hsl(0 0% 32%)' : heat(h, depth); }
  return null; // folder mode handled by caller (needs the laid-out hue)
}

function computeAgeRange(){
  let min = Infinity, max = -Infinity;
  for(const a of arcs){
    if(a.center || a.node.other || !a.node.mtime) continue;
    if(a.node.mtime < min) min = a.node.mtime;
    if(a.node.mtime > max) max = a.node.mtime;
  }
  ageRange = (min===Infinity) ? {min:0, max:1} : {min, max};
}

function recolor(){ render(); renderList(); }

function relTime(mtime){
  if(!mtime) return '';
  const d = Math.floor((Date.now()/1000 - mtime)/86400);
  if(d <= 0) return 'today';
  if(d === 1) return 'yesterday';
  if(d < 30) return d + ' days ago';
  if(d < 365){ const m = Math.round(d/30); return m + (m===1?' month':' months') + ' ago'; }
  const y = (d/365); return (y<2 ? '1 year' : Math.round(y)+' years') + ' ago';
}

function updateLegend(){
  const el = $('#legend');
  if(colorMode==='folder'){ el.style.display='none'; return; }
  el.style.display='flex';
  if(colorMode==='cleanup'){
    el.innerHTML = '<span>Important</span>'
      + '<span class="grad" style="background:linear-gradient(to right,'
      + 'hsl(0 60% 46%),hsl(60 60% 46%),hsl(120 60% 42%))"></span>'
      + '<span>Likely junk</span>';
  } else {
    el.innerHTML = '<span>Old</span>'
      + '<span class="grad" style="background:linear-gradient(to right,'
      + 'hsl(120 60% 42%),hsl(60 60% 46%),hsl(0 60% 46%))"></span>'
      + '<span>Recent</span>';
  }
}

async function api(url, opts){
  opts = opts || {};
  // Token on every request (GET included): scan/subtree mutate server state,
  // and the token keeps other web pages from driving this localhost server.
  opts.headers = Object.assign({}, opts.headers, {'X-MacWinClean-Token': TOKEN});
  const r = await fetch(url, opts);
  return r.json();
}

// ---- scan progress ---------------------------------------------------------
let pollTimer = null, polling = false;
function showScan(title){
  const o = $('#overlay');
  o.innerHTML = '<div class="scanbox"><div class="scan-title">' + escapeHtml(title) + '</div>'
    + '<div class="bar-track"><div class="bar-fill indet" id="barFill"></div></div>'
    + '<div class="scan-stats" id="scanStats">Starting…</div></div>';
  o.style.display = 'flex';
}
function updateScanUI(p){
  if(p.finished) return;  // ignore a stale snapshot from a previous scan
  const fill = $('#barFill');
  if(fill && p.totalTop > 0){
    fill.classList.remove('indet');
    fill.style.width = Math.min(100, Math.round(p.doneTop / p.totalTop * 100)) + '%';
  }
  const st = $('#scanStats');
  if(st) st.textContent = p.items.toLocaleString() + ' items · ' + fmt(p.bytes) + ' scanned';
}
function startPoll(){
  stopPoll();
  pollTimer = setInterval(async () => {
    if(polling) return;
    polling = true;
    try { updateScanUI(await api('/api/scan/progress')); }
    catch(e){ /* ignore transient errors */ }
    finally { polling = false; }
  }, 150);
}
function stopPoll(){ if(pollTimer){ clearInterval(pollTimer); pollTimer = null; } }

async function doScan(path){
  showScan('Scanning ' + path + ' …');
  startPoll();
  let d;
  try { d = await api('/api/scan?path=' + encodeURIComponent(path)); }
  finally { stopPoll(); }
  if(d.error){ overlay('Error: ' + d.error); return; }
  origin = d.origin;
  setRoot(d.root);
  hideOverlay();
}

async function navigate(path){
  if(path === viewPath) return;
  overlay('Loading …');
  const d = await api('/api/subtree?path=' + encodeURIComponent(path));
  if(d.error){ overlay('Error: ' + d.error); return; }
  setRoot(d.root);
  hideOverlay();
}

function setRoot(node){
  viewRoot = node; viewPath = node.path;
  selected = node;
  render();
  refreshSelection(node, null);
  renderList();
  renderCrumbs();
  let st = fmt(node.size) + ' on disk (allocated est.)';
  const note = 'Allocated size estimate (st_blocks). Hard links and APFS '
    + 'clones/shared extents are not deduped, so freed space may be less.';
  if(node.skipped){
    st += '  ·  ⚠ ' + node.skipped + " folder" + (node.skipped===1?'':'s')
        + " couldn't be read (permission denied) — totals may be low";
    $('#status').title = note + '\n\nUnreadable:\n' + (node.skipped_sample||[]).join('\n')
        + (node.skipped > (node.skipped_sample||[]).length ? '\n…' : '');
  } else {
    $('#status').title = note;
  }
  $('#status').textContent = st;
}

// ---- layout ----------------------------------------------------------------
function layout(){
  arcs = [];
  const W = svg.clientWidth, H = svg.clientHeight;
  const cx = W/2, cy = H/2;
  const maxR = Math.max(60, Math.min(W, H)/2 - 24);
  const rw = (maxR - HOLE) / RINGS;

  // center disk
  arcs.push({node:viewRoot, depth:0, a0:0, a1:Math.PI*2, r0:0, r1:HOLE,
             cx, cy, hue:0, center:true});

  function recurse(node, depth, a0, a1, hue){
    if(depth > RINGS) return;
    const kids = node.children;
    if(!kids || !kids.length) return;
    const span = a1 - a0;
    const total = node.size || kids.reduce((s,c)=>s+c.size,0) || 1;
    let acc = a0;
    kids.forEach((c, i) => {
      const frac = c.size / total;
      const ca0 = acc, ca1 = acc + span*frac;
      acc = ca1;
      if(ca1 - ca0 < 0.0015) return; // too thin to see/click
      const h = depth===0 ? (i/kids.length*360) : hue;
      const r0 = HOLE + (depth)*rw, r1 = HOLE + (depth+1)*rw;
      arcs.push({node:c, depth:depth+1, a0:ca0, a1:ca1, r0, r1, cx, cy, hue:h});
      if(c.dir && !c.other) recurse(c, depth+1, ca0, ca1, h);
    });
  }
  recurse(viewRoot, 0, 0, Math.PI*2, 0);
}

function arcPath(a){
  const {cx,cy,r0,r1} = a;
  // angles measured clockwise from top (-90deg)
  const a0 = a.a0 - Math.PI/2, a1 = a.a1 - Math.PI/2;
  const x = (r,ang)=>cx + r*Math.cos(ang);
  const y = (r,ang)=>cy + r*Math.sin(ang);
  const large = (a.a1 - a.a0) > Math.PI ? 1 : 0;
  if(r0 <= 0){ // full disk / pie
    if(a.a1 - a.a0 >= Math.PI*2 - 1e-6){
      return `M ${cx-r1} ${cy} a ${r1} ${r1} 0 1 0 ${r1*2} 0 a ${r1} ${r1} 0 1 0 ${-r1*2} 0`;
    }
    return `M ${cx} ${cy} L ${x(r1,a0)} ${y(r1,a0)} A ${r1} ${r1} 0 ${large} 1 ${x(r1,a1)} ${y(r1,a1)} Z`;
  }
  return `M ${x(r0,a0)} ${y(r0,a0)} L ${x(r1,a0)} ${y(r1,a0)} `
       + `A ${r1} ${r1} 0 ${large} 1 ${x(r1,a1)} ${y(r1,a1)} `
       + `L ${x(r0,a1)} ${y(r0,a1)} `
       + `A ${r0} ${r0} 0 ${large} 0 ${x(r0,a0)} ${y(r0,a0)} Z`;
}

function render(){
  layout();
  if(colorMode==='age') computeAgeRange();
  updateLegend();
  const W = svg.clientWidth, H = svg.clientHeight;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  while(svg.firstChild) svg.removeChild(svg.firstChild);

  arcs.forEach(a => {
    const p = document.createElementNS(SVGNS, 'path');
    p.setAttribute('d', arcPath(a));
    const fill = a.center ? 'var(--panel2)'
               : (nodeColor(a.node, a.depth) || colorFor(a.hue, a.depth));
    p.setAttribute('fill', fill);
    p.setAttribute('stroke', 'var(--bg)');
    p.setAttribute('stroke-width', a.center ? '0' : '1');
    p._a = a;
    p.addEventListener('mouseenter', () => { refreshSelection(a.node, a); hi(a); });
    p.addEventListener('mouseleave', () => unhi());
    p.addEventListener('click', () => { selected = a.node; refreshSelection(a.node, a); markList(); });
    p.addEventListener('contextmenu', (ev) => {
      ev.preventDefault();
      if(a.center){ reveal(viewRoot); return; }
      selected = a.node; refreshSelection(a.node, a); reveal(a.node);
    });
    p.addEventListener('dblclick', () => {
      if(a.center){ goUp(); return; }
      if(a.node.dir && !a.node.other) navigate(a.node.path);
    });
    svg.appendChild(p);
  });

  // center label
  const cx = W/2, cy = H/2;
  const t1 = document.createElementNS(SVGNS,'text');
  t1.setAttribute('x',cx); t1.setAttribute('y',cy-6);
  t1.setAttribute('text-anchor','middle'); t1.setAttribute('class','center-label');
  t1.setAttribute('fill','var(--txt)'); t1.setAttribute('font-size','15'); t1.setAttribute('font-weight','600');
  t1.textContent = trim(viewRoot.name, 18);
  const t2 = document.createElementNS(SVGNS,'text');
  t2.setAttribute('x',cx); t2.setAttribute('y',cy+14);
  t2.setAttribute('text-anchor','middle'); t2.setAttribute('class','center-label');
  t2.setAttribute('fill','var(--dim)'); t2.setAttribute('font-size','12');
  t2.textContent = fmt(viewRoot.size) + (origin!==viewPath ? '  ·  ↑ up' : '');
  svg.appendChild(t1); svg.appendChild(t2);
}

function hi(a){
  for(const p of svg.querySelectorAll('path')){
    if(p._a.center) continue;
    p.style.opacity = (p._a === a) ? '1' : '0.32';
  }
}
function unhi(){ for(const p of svg.querySelectorAll('path')) p.style.opacity='1'; }

function trim(s,n){ return s.length>n ? s.slice(0,n-1)+'…' : s; }

function goUp(){
  if(viewPath === origin) return;
  const i = viewPath.replace(/[\/\\]+$/,'').search(/[\/\\][^\/\\]*$/);
  let parent = i > 0 ? viewPath.slice(0, i) : origin;
  if(!parent.startsWith(origin)) parent = origin;
  navigate(parent);
}

// ---- selection panel -------------------------------------------------------
function refreshSelection(node, arc){
  $('#selName').textContent = node.name;
  $('#selPath').textContent = node.path || '';
  $('#selSize').textContent = fmt(node.size);
  const pct = viewRoot.size ? (node.size/viewRoot.size*100) : 0;
  let meta = (node===viewRoot ? 'current folder' :
      `${pct.toFixed(1)}% of ${trim(viewRoot.name,20)}  ·  ${node.dir?'folder':'file'}`);
  if(!node.other && node.mtime) meta += `  ·  modified ${relTime(node.mtime)}`;
  if(!node.other && node.path){
    const s = junkScore(node);
    if(s >= 0.75) meta += '  ·  🟢 likely safe to clean';
    else if(s <= 0.25) meta += '  ·  🔴 looks important';
  }
  $('#selMeta').textContent = meta;
  const zb = $('#zoomBtn'), tb = $('#trashBtn'), fb = $('#finderBtn');
  if(node.dir && !node.other && node!==viewRoot){
    zb.style.display=''; zb.onclick=()=>navigate(node.path);
  } else zb.style.display='none';
  if(node.path && !node.other){
    fb.style.display=''; fb.onclick=()=>reveal(node);
  } else fb.style.display='none';
  // Never offer to trash the centered/scan-root folder itself (also enforced
  // server-side). Only real items strictly inside the scanned tree.
  if(node.path && !node.other && node!==viewRoot && node.path!==origin){
    tb.style.display=''; tb.onclick=()=>trash(node);
  } else tb.style.display='none';
}

async function reveal(node){
  if(!node || !node.path) return;
  const r = await api('/api/reveal', {method:'POST', headers:{'Content-Type':'application/json'},
                       body: JSON.stringify({path: node.path})});
  if(!r.ok) alert('Could not open in ' + FILE_MANAGER + ':\n' + r.message);
}

async function trash(node){
  if(!node.path) return;
  if(!confirm(`Move to Trash?\n\n${node.path}\n${fmt(node.size)}\n\n(You can restore it from the Trash.)`)) return;
  const r = await api('/api/trash', {method:'POST', headers:{'Content-Type':'application/json'},
                       body: JSON.stringify({path: node.path})});
  if(!r.ok){ alert('Could not move to Trash:\n' + r.message); return; }
  // refresh current view from server (sizes already corrected server-side)
  navigateForce(viewPath);
}
async function navigateForce(path){
  const d = await api('/api/subtree?path=' + encodeURIComponent(path));
  if(!d.error) setRoot(d.root);
}

// ---- contents list ---------------------------------------------------------
let listRows = [];
function renderList(){
  const el = $('#list'); el.innerHTML=''; listRows=[];
  const kids = (viewRoot.children||[]).slice().sort((a,b)=>b.size-a.size);
  if(!kids.length){ el.innerHTML='<div class="empty">empty</div>'; return; }
  const max = kids[0].size || 1;
  kids.forEach((c,i)=>{
    const sw = c.other ? 'var(--line)'
             : (nodeColor(c, 1) || colorFor(i/kids.length*360, 1));
    const row = document.createElement('div'); row.className='row';
    row.innerHTML = `<span class="sw" style="background:${sw}"></span>
      <div class="nmwrap"><div class="nm">${escapeHtml(c.name)}</div>
      <div class="bar" style="width:${Math.max(4,(c.size/max*100))}%"></div></div>
      <span class="sz">${fmt(c.size)}</span>`;
    row.addEventListener('click', ()=>{ selected=c; refreshSelection(c,null); });
    row.addEventListener('contextmenu', (ev)=>{ ev.preventDefault(); selected=c; refreshSelection(c,null); reveal(c); });
    row.addEventListener('dblclick', ()=>{ if(c.dir && !c.other) navigate(c.path); });
    el.appendChild(row); listRows.push({el:row, node:c});
  });
}
function markList(){ /* hook for highlight if desired */ }
function escapeHtml(s){ return s.replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// ---- breadcrumbs -----------------------------------------------------------
function renderCrumbs(){
  const el = $('#crumbs'); el.innerHTML='';
  const rel = viewPath.startsWith(origin) ? viewPath.slice(origin.length) : '';
  const parts = rel.split(/[\/\\]/).filter(Boolean);
  const mk = (label, path) => {
    const a = document.createElement('a'); a.textContent=label;
    a.onclick=()=>navigate(path); return a;
  };
  el.appendChild(mk(origin, origin));
  let cur = origin;
  parts.forEach(p=>{
    cur = cur.replace(/[\/\\]$/,'') + SEP + p;
    const sep=document.createElement('span'); sep.className='sep'; sep.textContent=' › ';
    el.appendChild(sep); el.appendChild(mk(p, cur));
  });
}

// ---- overlay / events ------------------------------------------------------
function overlay(msg){ const o=$('#overlay'); o.textContent=msg; o.style.display='flex'; }
function hideOverlay(){ $('#overlay').style.display='none'; }

$('#scan').addEventListener('click', ()=>{ const v=$('#path').value.trim(); if(v) doScan(v); });
$('#refresh').addEventListener('click', async ()=>{
  if(!viewPath) return;
  showScan('Refreshing ' + viewRoot.name + ' …');
  startPoll();
  let d;
  try { d = await api('/api/subtree?fresh=1&path=' + encodeURIComponent(viewPath)); }
  finally { stopPoll(); }
  if(d.error){ overlay('Error: ' + d.error); return; }
  setRoot(d.root); hideOverlay();
});
$('#path').addEventListener('keydown', e=>{ if(e.key==='Enter'){ const v=$('#path').value.trim(); if(v) doScan(v);} });
$('#colorMode').addEventListener('change', e=>{ colorMode = e.target.value; if(viewRoot) recolor(); });
document.querySelectorAll('.chip').forEach(c=>c.addEventListener('click', ()=>{
  const v=c.dataset.go; $('#path').value=v; doScan(v);
}));
window.addEventListener('resize', ()=>{ if(viewRoot) render(); });

// boot
const START = __START_PATH__;
const TOKEN = __TOKEN__;
const SEP = __SEP__;                 // OS path separator ('/' or '\\')
const PLATFORM = __PLATFORM__;       // 'mac' | 'win' | 'other'
const FILE_MANAGER = __FILE_MANAGER__;
document.querySelectorAll('[data-fm]').forEach(el => {
  el.textContent = el.dataset.fm.replace('%s', FILE_MANAGER);
});
$('#path').value = START;
doScan(START);
</script>
</body>
</html>
"""


def _js_literal(value):
    """Serialize a Python value as a safe inline-JS literal.

    json.dumps handles quoting/escaping; we additionally neutralize the few
    sequences that could otherwise break out of a <script> block or start an
    HTML comment, so a folder path like `</script>` is inert.
    """
    s = json.dumps(value)
    return (s.replace('<', '\\u003c').replace('>', '\\u003e')
             .replace('&', '\\u0026'))


def _cache_shortcut():
    if IS_MAC:
        return "~/Library/Caches"
    if IS_WIN:
        return os.environ.get("LOCALAPPDATA", r"~\AppData\Local")
    return "~/.cache"


def render_page(csp_nonce=""):
    return (PAGE
            .replace("__START_PATH__", _js_literal(START_PATH or "~"))
            .replace("__TOKEN__", _js_literal(SESSION_TOKEN))
            .replace("__SEP__", _js_literal(os.sep))
            .replace("__PLATFORM__", _js_literal(PLATFORM))
            .replace("__FILE_MANAGER__", _js_literal(FILE_MANAGER))
            .replace("__CACHE_PATH__", html_attr(_cache_shortcut()))
            .replace("__CSP_NONCE__", _js_literal(csp_nonce)[1:-1]))


def html_attr(value):
    """Escape a string for use inside a double-quoted HTML attribute."""
    return (value.replace("&", "&amp;").replace('"', "&quot;")
                 .replace("<", "&lt;").replace(">", "&gt;"))


def main():
    ap = argparse.ArgumentParser(description="Interactive folder size analyzer.")
    ap.add_argument("path", nargs="?", default="~", help="folder to scan (default: home)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    args = ap.parse_args()

    global START_PATH, ALLOWED_HOSTS
    START_PATH = args.path
    ALLOWED_HOSTS = {f"127.0.0.1:{args.port}", f"localhost:{args.port}"}
    url = f"http://127.0.0.1:{args.port}/"
    # Bind to loopback only; deletion is gated by a per-process token + origin.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"MacWinClean running at {url}")
    print(f"Scanning starts at: {os.path.abspath(os.path.expanduser(args.path))}")
    print("Press Ctrl+C to stop.")
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        server.shutdown()


if __name__ == "__main__":
    main()
