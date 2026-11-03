"""DiskClean: an offline, loopback-only folder size analyzer for macOS, Windows and Linux.

The package is split so each concern can be tested on its own:

    platform   OS identity, path normalization, per-OS defaults
    paths      protection rules, scanned-root allowlist, delete validation
    scanner    iterative, cancellable directory walker plus the in-memory index
    native     Trash/Recycle Bin, reveal-in-file-manager, memory accounting
    server     loopback HTTP server, request validation and the JSON API

Entry points (cleaner.py, winclean.py) only parse arguments and start the
server, so every platform runs the same code path.
"""

__version__ = "2.0.0"
