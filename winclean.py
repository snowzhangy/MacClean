#!/usr/bin/env python3
"""DiskClean for Windows: scan any folder, explore it in the browser, and move
selected items to the Recycle Bin (recoverable) -- nothing is deleted
permanently.

  python winclean.py                    # scan your home folder
  python winclean.py %USERPROFILE%\\Downloads
  python winclean.py C:\\ --port 9000 --no-open

The same program runs on macOS and Linux as cleaner.py; this entry point is
provided so the Windows workflow has a name of its own.
"""

import sys

from diskclean import cli


def main(argv=None):
    if sys.platform != "win32":
        sys.stderr.write("winclean.py is the Windows entry point. "
                         "On macOS or Linux run cleaner.py instead.\n")
        return 2
    return cli.main(argv, prog="winclean.py")


if __name__ == "__main__":
    sys.exit(main())
