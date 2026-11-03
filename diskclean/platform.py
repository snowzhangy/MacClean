"""OS identity, path normalization, and per-platform defaults.

Everything that differs between macOS, Windows and Linux lives here or in
`native`, so the scanner and server stay platform-agnostic.
"""

import os
import sys

IS_MAC = sys.platform == "darwin"
IS_WIN = os.name == "nt"
IS_POSIX = not IS_WIN

# "mac" | "win" | "linux" -- drives UI labels and defaults.
PLATFORM = "mac" if IS_MAC else "win" if IS_WIN else "linux"

# Name of the OS file manager, shown in UI labels ("Reveal in Finder").
FILE_MANAGER = "Finder" if IS_MAC else "Explorer" if IS_WIN else "Files"

# Top-level hierarchy root: "/" on POSIX, "C:\\" on Windows.
#
# On Windows this is derived from SystemRoot, not from the cwd's drive: a shell
# launched from D:\\ must not move the OS-folder protections to D:\\. Never
# "\\\\": that is the network/UNC root, not a local volume.
if IS_WIN:
    ROOT_DIR = os.path.splitdrive(os.environ.get("SystemRoot", r"C:\Windows"))[0] + os.sep
    if ROOT_DIR == os.sep:  # SystemRoot unset or malformed; use the cwd drive
        ROOT_DIR = os.path.splitdrive(os.path.abspath(os.sep))[0] + os.sep or "C:" + os.sep
else:
    ROOT_DIR = "/"

HOME = os.path.realpath(os.path.expanduser("~"))


def normalize(path):
    """Absolute, expanded path -- the canonical form stored in the index.

    realpath() resolves symlinks and Windows 8.3 short names (YZZZZZ~1), so one
    folder always maps to one key no matter how the user typed it or how the
    browser echoed it back.
    """
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def key(path):
    """Index key: normalized, and case-folded on Windows.

    Windows paths are case-insensitive, so `c:\\Users\\Me` and `C:\\Users\\me`
    must address the same entry. macOS *can* be case-sensitive, so POSIX keeps
    the original case here and folds only where a comparison needs it.
    """
    normalized = normalize(path)
    return os.path.normcase(normalized) if IS_WIN else normalized


def resolve_prefix(path):
    """Resolve links in the parent chain but keep the final component as-is.

    realpath() would follow a selected symlink to its target; here the item
    itself stays the item, so a link can be trashed without touching what it
    points at.
    """
    absolute = os.path.abspath(os.path.expanduser(path))
    return os.path.join(os.path.realpath(os.path.dirname(absolute)),
                        os.path.basename(absolute))


def fold(path):
    """Case- and prefix-normalized absolute path, for security comparisons."""
    return os.path.normcase(resolve_prefix(path))


def inside(path, root):
    """True if `path` is `root` itself or lies underneath it.

    realpath() on the *prefix* (not the final component) resolves Windows 8.3
    short names and links in the parent chain, while a selected symlink is
    judged by its own location rather than its target.
    """
    path, root = os.path.normcase(resolve_prefix(path)), os.path.normcase(resolve_prefix(root))
    if path == root:
        return True
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives / not comparable
        return False


def strictly_inside(path, root):
    """True if `path` lies underneath `root` (not `root` itself)."""
    path, root = os.path.normcase(resolve_prefix(path)), os.path.normcase(resolve_prefix(root))
    return path != root and inside(path, root)


def is_drive_root(path):
    """True for a Windows volume root ("C:\\", "D:\\") or a UNC share root."""
    if not IS_WIN:
        return path.rstrip("/") == ""
    drive, tail = os.path.splitdrive(path)
    return (bool(drive) or path.startswith(os.sep)) and not tail.strip("/\\")


def join(base, *parts):
    """Join path fragments using `base`'s own separator style.

    The UI sends paths built on the client; joining with os.sep keeps entries
    created here consistent with what scandir reports.
    """
    return os.path.join(base, *parts)
