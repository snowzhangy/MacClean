#!/usr/bin/env python3
"""Browser-test server with staged work for a fixture folder named Live only."""
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import macclean

original_walk = macclean._walk_dir


def staged_walk(path, *args, **kwargs):
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


original_preview = macclean.ScanJobs.preview


def delayed_preview(self, job_id, path=None):
    # Prove that a delayed chart request cannot freeze scan status/completion.
    if self.job is not None and Path(self.job["path"]).name == "SlowPreview":
        time.sleep(20)
    return original_preview(self, job_id, path)


def fixture_reveal(path):
    # Exercise real HTTP/UI behavior without opening the user's Finder windows.
    time.sleep(.15)
    return (False, "Fixture Finder error") if "<img" in path else (True, "ok")


if __name__ == "__main__":
    macclean._walk_dir = staged_walk
    macclean.ScanJobs.preview = delayed_preview
    macclean.reveal_in_finder = fixture_reveal
    sys.exit(macclean.main())
