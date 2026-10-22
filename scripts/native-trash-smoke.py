#!/usr/bin/env python3
"""Opt-in macOS test: Trash and immediately restore only generated fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import macclean


def main():
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise SystemExit("Run this test on macOS as your normal user.")
    with tempfile.TemporaryDirectory(prefix="macclean-native-trash-") as temp:
        root = Path(temp).resolve()
        target = root / "target.txt"
        target.write_text("The symlink target must remain untouched.")
        regular = root / (root.name + "-regular.txt")
        regular.write_text("Generated MacClean smoke fixture.")
        link = root / (root.name + "-link")
        link.symlink_to(target)
        for item in (regular, link):
            identity = os.lstat(item).st_ino
            result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", "-e", macclean._TRASH_JXA, str(item)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(f"Native Trash failed: {result.stderr.strip()}; fixture still present: {os.path.lexists(item)}")
            trashed = Path(json.loads(result.stdout)["path"])
            try:
                assert not os.path.lexists(item), "Selected item was not moved"
                assert os.lstat(trashed).st_ino == identity, "Native Trash moved a different item"
                assert target.read_text() == "The symlink target must remain untouched."
                if item == link:
                    assert trashed.is_symlink(), "Native Trash followed the final symlink"
            finally:
                # Restore the exact native-returned item; never enumerate Trash.
                if os.path.lexists(trashed):
                    if os.path.lexists(item):
                        raise RuntimeError(f"Cannot restore without overwriting: {trashed} -> {item}")
                    os.rename(trashed, item)
            assert os.lstat(item).st_ino == identity
        print("Native Trash smoke passed: regular file and final symlink moved and restored; target unchanged.")


if __name__ == "__main__":
    main()
