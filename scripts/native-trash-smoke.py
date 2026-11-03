#!/usr/bin/env python3
"""Opt-in macOS test: Trash and immediately restore only generated fixtures.

    python scripts/native-trash-smoke.py

Run as your normal user (not root). Every fixture is created here and restored
afterwards; the user's Trash is never enumerated or emptied.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from diskclean import native


def _unique_name(root, stem):
    # The Trash keeps a moved item under its own name; a unique stem keeps the
    # restore exact even when older copies exist.
    return f"{stem}-{os.getpid()}-{int(time.time())}"


def main():
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise SystemExit("Run this test on macOS as your normal user.")
    with tempfile.TemporaryDirectory(prefix="diskclean-native-trash-") as temp:
        root = Path(temp).resolve()
        target = root / "target.txt"
        target.write_text("The symlink target must remain untouched.")

        regular = root / _unique_name(root, "regular.txt")
        regular.write_text("Generated DiskClean smoke fixture.")
        link = root / _unique_name(root, "link")
        link.symlink_to(target)

        for item in (regular, link):
            identity = os.lstat(item).st_ino
            result = subprocess.run(
                ["/usr/bin/osascript", "-l", "JavaScript", "-e", native._TRASH_JXA, str(item)],
                capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(f"Native Trash failed: {result.stderr.strip()}; "
                                   f"fixture still present: {os.path.lexists(item)}")
            trashed = Path(json.loads(result.stdout)["path"])
            try:
                assert not os.path.lexists(item), "Selected item was not moved"
                assert os.lstat(trashed).st_ino == identity, "Native Trash moved a different item"
                assert target.read_text() == "The symlink target must remain untouched."
                if item == link:
                    assert trashed.is_symlink(), "Native Trash followed the final symlink"
            finally:
                # Restore exactly what the native call returned; never list Trash.
                if os.path.lexists(trashed):
                    if os.path.lexists(item):
                        raise RuntimeError(f"Cannot restore without overwriting: {trashed} -> {item}")
                    os.rename(trashed, item)
            assert os.lstat(item).st_ino == identity
        print("Native Trash smoke passed: regular file and final symlink moved and "
              "restored; the symlink target was unchanged.")


if __name__ == "__main__":
    main()
