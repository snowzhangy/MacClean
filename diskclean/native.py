"""Native integration: Trash/Recycle Bin, reveal-in-file-manager, memory.

Every OS-specific subprocess call in the program lives here. Nothing deletes
permanently: macOS uses NSFileManager's trashItemAtURL, Windows uses the shell's
SendToRecycleBin, and Linux uses the freedesktop trash through gio.
"""

import ctypes
import ctypes.wintypes
import os
import shutil
import subprocess
import sys

from . import platform as osplat


# ---- Trash / Recycle Bin ----------------------------------------------------
# macOS: JXA so the path is an argv element, never interpolated into script
# source. NSFileManager trashes the given URL itself (no link following), and
# needs no Finder Automation permission.
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

# Windows: the path travels in an environment variable, so it cannot break out
# of the PowerShell source or inject a command.
_TRASH_PS = (
    "Add-Type -AssemblyName Microsoft.VisualBasic;"
    "$p = $env:DISKCLEAN_TRASH_PATH;"
    "if (Test-Path -LiteralPath $p -PathType Container) {"
    "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory("
    "$p,'OnlyErrorDialogs','SendToRecycleBin') } else {"
    "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile("
    "$p,'OnlyErrorDialogs','SendToRecycleBin') }"
)


def _trash_mac(target):
    result = subprocess.run(["osascript", "-l", "JavaScript", "-e", _TRASH_JXA, target],
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return False, (result.stderr.strip() or "Could not move the item to the Trash.")
    return True, "ok"


def _powershell():
    """Prefer PowerShell 7 where present, else Windows PowerShell."""
    for name in ("pwsh", "powershell.exe"):
        if shutil.which(name):
            return name
    return "powershell.exe"


def _trash_windows(target):
    env = os.environ.copy()
    env["DISKCLEAN_TRASH_PATH"] = target
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", _TRASH_PS],
        capture_output=True, text=True, timeout=30, env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        return False, (result.stderr.strip() or "Could not move the item to the Recycle Bin.")
    return True, "ok"


def _trash_linux(target):
    try:
        result = subprocess.run(["gio", "trash", "--", target],
                                capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return False, "No Trash backend available (install glib's `gio`)."
    if result.returncode != 0:
        return False, (result.stderr.strip() or "Could not move the item to the Trash.")
    return True, "ok"


def trash(target):
    """Move `target` to the OS Trash. Returns (ok, message)."""
    if osplat.IS_MAC:
        return _trash_mac(target)
    if osplat.IS_WIN:
        return _trash_windows(target)
    return _trash_linux(target)


# ---- Reveal in the OS file manager ------------------------------------------
def reveal(path):
    """Open a folder, or reveal and select a file in its containing folder."""
    if not path or not os.path.exists(path):
        return False, "Path does not exist."
    try:
        if osplat.IS_MAC:
            args = ["open", path] if os.path.isdir(path) else ["open", "-R", path]
            result = subprocess.run(args, timeout=15)
            if result.returncode != 0:
                return False, "Finder could not reveal that item."
            return True, "ok"
        if osplat.IS_WIN:
            # explorer.exe returns exit code 1 even when it succeeds, so the
            # return code carries no information here.
            args = ["explorer", path] if os.path.isdir(path) else ["explorer", "/select,", path]
            subprocess.run(args, timeout=15)
            return True, "ok"
        # Linux / other: open the containing folder.
        folder = path if os.path.isdir(path) else os.path.dirname(path)
        result = subprocess.run(["xdg-open", folder], timeout=15)
        return (result.returncode == 0), "ok" if result.returncode == 0 else "Could not open the file manager."
    except FileNotFoundError:
        return False, f"{osplat.FILE_MANAGER} is not available on this system."
    except subprocess.TimeoutExpired:
        return False, "The file manager did not respond."
    except OSError as exc:
        return False, str(exc)


# ---- Default shortcuts ------------------------------------------------------
def cache_shortcut():
    """The 'Caches' shortcut target for this OS."""
    if osplat.IS_MAC:
        return os.path.join(osplat.HOME, "Library", "Caches")
    if osplat.IS_WIN:
        return os.environ.get("LOCALAPPDATA") or os.path.join(osplat.HOME, "AppData", "Local")
    return os.path.join(osplat.HOME, ".cache")


# ---- Memory accounting ------------------------------------------------------
def automatic_memory_mb():
    """Default scan memory budget: a quarter of RAM, clamped to 512 MiB - 4 GiB."""
    physical = None
    if osplat.IS_WIN:
        class _Status(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.wintypes.DWORD),
                        ("dwMemoryLoad", ctypes.wintypes.DWORD),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = _Status()
        status.dwLength = ctypes.sizeof(_Status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            physical = status.ullTotalPhys // (1024 * 1024)
    elif hasattr(os, "sysconf"):
        try:
            physical = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // (1024 * 1024)
        except (ValueError, OSError):
            physical = None
    if not physical:
        return 1024
    return max(512, min(4096, physical // 4))


def resident_bytes():
    """Current process RSS in bytes, or None when the platform cannot say."""
    if osplat.IS_WIN:
        if _psapi is None:
            return None
        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if _psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return int(counters.WorkingSetSize)
        return None
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # macOS reports bytes, Linux reports kibibytes.
        return int(peak if sys.platform == "darwin" else peak * 1024)
    except (ImportError, OSError):
        return None


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", ctypes.wintypes.DWORD),
                ("PageFaultCount", ctypes.wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


# Declare the prototypes: without them ctypes assumes C int, which truncates
# the 64-bit process handle on x64 and makes the call fail silently.
if osplat.IS_WIN:
    try:
        _psapi = ctypes.WinDLL("psapi", use_last_error=True)
        _psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
            ctypes.wintypes.DWORD]
        _psapi.GetProcessMemoryInfo.restype = ctypes.wintypes.BOOL
    except (OSError, AttributeError):
        _psapi = None
else:
    _psapi = None
