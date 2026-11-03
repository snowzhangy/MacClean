"""Which paths may be deleted, and how we prove that a selection is current.

A deletion-capable local server has to defend against three different mistakes:

1. a cross-site request driving the API (handled in `server`),
2. a request naming a path the user never scanned or a system folder, and
3. deleting a *different* item than the one the user was looking at because the
   folder changed between the scan and the click (stale selection).

This module owns (2) and (3): the scanned-root allowlist, the protected-folder
rules, and per-item revisions.
"""

import hashlib
import os
import stat
import threading

from . import platform as osplat


class BusyError(Exception):
    """Another scan or delete is already running."""


class ScanCancelled(Exception):
    """The user cancelled the scan; previous results are unchanged."""


class ScanLimitError(Exception):
    """A scan exceeded its entry or memory budget."""

    def __init__(self, message, kind):
        super().__init__(message)
        self.kind = kind  # "entry_limit" | "memory_limit"


# ---- Scanned-root allowlist -------------------------------------------------
# Only items *inside* a folder the user actually scanned may be trashed. The
# set holds normalized absolute paths; the lock guards concurrent scans.
SCAN_ROOTS = set()
SCAN_ROOTS_LOCK = threading.Lock()


def register_scan_root(path):
    """Allow deletions inside `path` (called when a full scan succeeds)."""
    with SCAN_ROOTS_LOCK:
        SCAN_ROOTS.add(osplat.normalize(path))


def scan_roots():
    with SCAN_ROOTS_LOCK:
        return {osplat.fold(root) for root in SCAN_ROOTS}


def cached_origin():
    """The most recently scanned root, for reconnecting browsers."""
    with SCAN_ROOTS_LOCK:
        return next(iter(SCAN_ROOTS), None)


def clear_scan_roots():
    with SCAN_ROOTS_LOCK:
        SCAN_ROOTS.clear()


# ---- Protected folders ------------------------------------------------------
# Folders we never trash, even when they sit inside a scanned root. Keeping a
# whole Home folder *and* its Documents/Downloads protects the two cases a user
# is most likely to hit by accident.
def _build_protected():
    home = osplat.HOME
    common = {home,
              os.path.join(home, "Desktop"),
              os.path.join(home, "Documents"),
              os.path.join(home, "Downloads"),
              os.path.join(home, "Music"),
              os.path.join(home, "Pictures"),
              os.path.join(home, "Videos")}
    if osplat.IS_WIN:
        env = os.environ
        users = os.path.join(osplat.ROOT_DIR, "Users")
        common |= {
            env.get("SystemRoot", os.path.join(osplat.ROOT_DIR, "Windows")),
            osplat.ROOT_DIR,
            env.get("ProgramFiles", os.path.join(osplat.ROOT_DIR, "Program Files")),
            env.get("ProgramFiles(x86)", os.path.join(osplat.ROOT_DIR, "Program Files (x86)")),
            env.get("ProgramData", os.path.join(osplat.ROOT_DIR, "ProgramData")),
            users,
            os.path.join(users, "Public"),
            os.path.join(home, "AppData"),
        }
    else:
        common |= {
            "/", "/System", "/Library", "/Applications", "/Users", "/Users/Shared",
            "/private", "/usr", "/bin", "/sbin", "/opt", "/cores", "/Volumes",
            "/etc", "/var", "/tmp", "/dev", "/Network",
            os.path.join(home, "Library"),
        }
    return {osplat.fold(p) for p in common}


PROTECTED_EXACT = _build_protected()


def protected_reason(path):
    """Return a human reason if `path` must never be trashed, else None."""
    folded = osplat.fold(path)
    if folded in PROTECTED_EXACT:
        return "a protected system, home, or top-level folder"

    if osplat.IS_WIN:
        if osplat.is_drive_root(path):
            return "a drive root"
        sysroot = osplat.fold(os.environ.get("SystemRoot",
                                            os.path.join(osplat.ROOT_DIR, "Windows")))
        if folded == sysroot or folded.startswith(sysroot + os.sep):
            return "a Windows system folder"
        # System folders that live next to SystemRoot on the same drive.
        for sibling in ("$Recycle.Bin", "System Volume Information", "Recovery"):
            sibling_path = osplat.fold(os.path.join(osplat.ROOT_DIR, sibling))
            if folded == sibling_path or folded.startswith(sibling_path + os.sep):
                return "a Windows system folder"
    else:
        if path == "/System" or path.startswith("/System/"):
            return "a system folder"
        # /Volumes/<name> (a mounted volume root) but not items inside it.
        if path.startswith("/Volumes/") and path.count("/") == 2:
            return "a mounted volume root"

    # Any ancestor of the home folder (e.g. /Users or C:\Users).
    home = osplat.fold(osplat.HOME)
    if folded == home or home.startswith(folded + os.sep):
        return "a folder that contains your Home folder"
    return None


# ---- Exclusions -------------------------------------------------------------
EXCLUDE_PATHS = ()


def set_excludes(paths):
    """Folders never opened by the scanner (e.g. a stalled cloud Trash)."""
    global EXCLUDE_PATHS
    EXCLUDE_PATHS = tuple(osplat.fold(p) for p in paths)


def excluded(path):
    folded = os.path.normcase(path)
    return any(osplat.inside(folded, root) for root in EXCLUDE_PATHS)


# ---- Revisions --------------------------------------------------------------
def make_identity(st):
    """A tuple that changes when the item at a path is replaced or modified.

    (device, inode, file type, mtime) plus ctime on POSIX. Windows reports
    st_ino/st_dev from the NTFS file index and ns timestamps, so the same
    check works there -- but st_ctime on Windows is *creation* time, not
    metadata-change time, and comparing it would reject perfectly valid
    deletes, so it is left out.
    """
    identity = (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode),
                getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
    if not osplat.IS_WIN:
        identity += (getattr(st, "st_ctime_ns", int(st.st_ctime * 1e9)),)
    return identity


def revision(identity_tuple):
    """Short, stable hash the browser echoes back when it deletes."""
    return hashlib.sha256(repr(identity_tuple).encode("ascii", "replace")).hexdigest()[:24]


def validate_trash_target(path):
    """Return (target, None) if `path` is safe to Trash, else (None, reason).

    `target` is the selected item *itself*: symlinks in the path prefix are
    resolved (so a link cannot smuggle the location outside the allowlist) but
    the final component is kept as-is. Selecting a symlink trashes the link,
    never the file it points at.
    """
    if not path:
        return None, "No path given."
    if "\0" in path:
        return None, "Invalid path."

    abspath = os.path.abspath(os.path.expanduser(path))
    parent = os.path.realpath(os.path.dirname(abspath))
    target = os.path.join(parent, os.path.basename(abspath))
    if not os.path.lexists(target):  # lexists: a dangling symlink still counts
        return None, "Path does not exist."

    roots = scan_roots()
    if os.path.islink(target):
        # A link may point anywhere, so judge it by its own location only.
        candidates = [target]
    else:
        candidates = [osplat.normalize(target)]
    if not any(_belongs_to_scan(c, roots) for c in candidates):
        return None, "Refusing: item is outside the folder you scanned."

    reason = protected_reason(target)
    if reason:
        return None, f"Refusing to delete {reason}."
    return target, None


def _belongs_to_scan(path, roots):
    folded = osplat.fold(path)
    return any(osplat.strictly_inside(folded, root) for root in roots)


def is_trashable(path, roots=None):
    """Cheap check used to mark nodes in the UI as deletable."""
    roots = scan_roots() if roots is None else roots
    if not path:
        return False
    folded = osplat.fold(path)
    return (any(osplat.strictly_inside(folded, root) for root in roots)
            and protected_reason(path) is None)
