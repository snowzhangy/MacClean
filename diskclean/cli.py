"""Shared command-line front end used by every entry point."""

import argparse
import os
import sys
import threading
import webbrowser

from . import native
from . import paths
from . import platform as osplat
from . import scanner
from . import server


def build_parser(prog, description):
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument("path", nargs="?", default="~", help="folder to scan (default: home)")
    parser.add_argument("--port", type=int, default=8765,
                        help="loopback port (default: 8765; 0 chooses a free port)")
    parser.add_argument("--no-open", action="store_true", help="do not open the browser")
    parser.add_argument("--read-only", action="store_true",
                        help=f"disable all Move to {scanner.trash_name()} actions")
    parser.add_argument("--exclude", action="append", default=[], metavar="FOLDER",
                        help="skip a folder and its descendants (repeatable; useful for "
                             "stalled cloud-provider folders)")
    parser.add_argument("--workers", type=int, default=scanner.WORKERS,
                        help="scan threads, 1-32 (default: %(default)s)")
    parser.add_argument("--max-entries", type=int, default=scanner.MAX_ENTRIES,
                        help="optional entry limit (default: 0, no entry cap)")
    parser.add_argument("--max-memory-mb", type=int, default=scanner.MAX_MEMORY_MB,
                        help="process memory budget in MiB (default: 0, automatic from RAM)")
    parser.add_argument("--version", action="version", version=f"DiskClean {prog}")
    return parser


def main(argv=None, prog="cleaner.py"):
    parser = build_parser(prog, "Analyze disk usage in an offline browser UI. "
                               "Nothing is permanently deleted.")
    args = parser.parse_args(argv)

    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    if not 1 <= args.workers <= 32:
        parser.error("--workers must be between 1 and 32")
    try:
        scanner.validate_limits(args.max_entries, args.max_memory_mb)
    except ValueError as exc:
        parser.error(str(exc))
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        parser.error("Run DiskClean as your normal user, without sudo.")

    start = osplat.normalize(args.path)
    if not os.path.isdir(start):
        parser.error(f"Not a folder: {start}")

    scanner.START_PATH = start
    scanner.READ_ONLY = args.read_only
    scanner.WORKERS = args.workers
    scanner.MAX_ENTRIES = args.max_entries
    scanner.MAX_MEMORY_MB = args.max_memory_mb
    paths.set_excludes(osplat.normalize(p) for p in args.exclude)

    try:
        httpd = server.LocalServer(("127.0.0.1", args.port), server.Handler)
    except OSError as exc:
        parser.exit(1, f"Cannot start DiskClean: {exc}. Try --port 0 for a free port.\n")
    port = httpd.server_address[1]
    server.ALLOWED_HOSTS = {f"127.0.0.1:{port}", f"localhost:{port}"}
    url = f"http://127.0.0.1:{port}/"

    print(f"DiskClean running at {url}", flush=True)
    print(f"Starting folder: {start}")
    if scanner.READ_ONLY:
        print(f"Read-only mode: Move to {scanner.trash_name()} is disabled.")
    print(f"Default memory budget: {native.automatic_memory_mb()} MiB")
    print("Press Ctrl+C to stop.", flush=True)

    if not args.no_open:
        timer = threading.Timer(0.3, lambda: webbrowser.open(url))
        timer.daemon = True
        timer.start()
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nDiskClean stopped.")
    finally:
        server.JOBS.close()
        httpd.server_close()
    return 0
