#!/usr/bin/env python3
"""Compare preview summaries against counters only, then time bounded snapshots."""
import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import macclean


class CountersOnly(macclean.ScanProgress):
    def begin_branch(self, path):
        pass

    def finish_branch(self, path, node=None):
        pass

    def add_file(self, node):
        with self.lock:
            self.bytes += node["size"]

    def add_allocated(self, size, branch=None):
        with self.lock:
            self.bytes += size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args()
    if args.rounds < 2:
        parser.error("--rounds must be at least 2")
    result = {}
    with tempfile.TemporaryDirectory(prefix="macclean-preview-benchmark-") as root:
        for label, folders, files in (("subtrees", 64, 200), ("flat", 1, 12800)):
            dataset = Path(root) / label
            dataset.mkdir()
            for d in range(folders):
                folder = dataset if label == "flat" else dataset / str(d)
                folder.mkdir(exist_ok=True)
                for f in range(files):
                    (folder / str(f)).write_bytes(b"x" * 64)
            times = {"counters_only": [], "live_summaries": []}
            # Alternate execution order to reduce cache/order bias.
            modes = [("counters_only", CountersOnly), ("live_summaries", macclean.ScanProgress)]
            for round_id in range(args.rounds):
                for name, cls in modes[::1 if round_id % 2 == 0 else -1]:
                    progress = cls()
                    start = time.perf_counter()
                    macclean.scan(str(dataset), progress=progress)
                    times[name].append(time.perf_counter() - start)
                    if name == "live_summaries":
                        live = progress
            snapshots = []
            for _ in range(1000):
                live._preview_time = float("-inf")
                start = time.perf_counter()
                encoded = json.dumps(live.preview()).encode()
                snapshots.append(time.perf_counter() - start)
            result[label] = {"files": folders * files,
                "median_scan_seconds": {k: round(statistics.median(v), 5) for k, v in times.items()},
                "median_snapshot_and_json_ms": round(statistics.median(snapshots) * 1000, 4),
                "snapshot_bytes": len(encoded)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
