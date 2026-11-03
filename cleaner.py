#!/usr/bin/env python3
"""DiskClean: an offline, loopback-only disk usage analyzer.

Scans a folder, draws an interactive sunburst in your browser, and moves
selected items to the OS Trash / Recycle Bin (recoverable). Python standard
library only: no packages, build step, account, or internet connection.

  python cleaner.py                     # scan your home folder
  python cleaner.py ~/Downloads
  python cleaner.py ~/Downloads --read-only
  python cleaner.py . --port 0 --no-open
  python cleaner.py ~ --exclude ~/Library/CloudStorage/YourDrive/.Trash

On Windows you can also use winclean.py, which is the same program.
"""

import sys

from diskclean import cli


def main(argv=None):
    return cli.main(argv, prog="cleaner.py")


if __name__ == "__main__":
    sys.exit(main())
