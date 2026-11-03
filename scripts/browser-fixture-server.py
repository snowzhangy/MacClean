#!/usr/bin/env python3
"""Browser-test server with staged work for fixture folders named Live/SlowPreview.

Run through scripts/browser-smoke.mjs; it wraps the real CLI so the page is
served by exactly the code path a user gets.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from diskclean import cli
from diskclean import scanner
from diskclean import server

original_walk = scanner._walk_dir


def staged_walk(path, *args, **kwargs):
    """Hold named fixture folders open so the UI can be observed mid-scan."""
    progress = kwargs.get("progress")
    staged = progress is not None and Path(progress.path).name in ("Live", "SlowPreview")
    if staged and Path(path).name == "later":
        progress.cancel.wait(max(0, progress.started + 14 - time.monotonic()))
        progress.check()
    node = original_walk(path, *args, **kwargs)
    if staged:
        progress.cancel.wait(max(0, progress.started + 26 - time.monotonic()))
        progress.check()
    return node


original_preview = server.ScanJobs.preview


def delayed_preview(self, job_id, path=None):
    # Prove a delayed chart request cannot freeze scan status or completion.
    if self.job is not None and Path(self.job["path"]).name == "SlowPreview":
        time.sleep(20)
    return original_preview(self, job_id, path)


def fixture_reveal(path):
    # Exercise the HTTP/UI flow without opening real Finder/Explorer windows.
    time.sleep(0.15)
    return (False, "Fixture file-manager error") if "<img" in path else (True, "ok")


if __name__ == "__main__":
    scanner._walk_dir = staged_walk
    server.ScanJobs.preview = delayed_preview
    scanner.reveal = fixture_reveal
    sys.exit(cli.main(sys.argv[1:], prog="browser-fixture-server.py"))
