#!/usr/bin/env python3
"""Reproducible temporary-data benchmark; optionally compare a prior script."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import macclean


def measure(module, root, rounds):
    times = []
    for _ in range(rounds):
        module.INDEX.clear()
        start = time.perf_counter()
        node = module.scan(root)
        times.append(time.perf_counter() - start)
    return {"workers": module.WORKERS, "median_seconds": round(statistics.median(times), 4),
            "allocated_bytes": node["size"], "rounds_seconds": [round(t, 4) for t in times]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, help="prior macclean.py to compare")
    parser.add_argument("--folders", type=int, default=64)
    parser.add_argument("--files", type=int, default=200, help="files per folder")
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if min(args.folders, args.files, args.rounds) < 1:
        parser.error("counts must be positive")
    modules = [("current", macclean)]
    if args.baseline:
        spec = importlib.util.spec_from_file_location("macclean_baseline", args.baseline)
        baseline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(baseline)
        modules.insert(0, ("baseline", baseline))
    with tempfile.TemporaryDirectory(prefix="macclean-benchmark-") as root:
        for d in range(args.folders):
            folder = Path(root) / f"directory-{d}"
            folder.mkdir()
            for f in range(args.files):
                (folder / f"file-{f}").write_bytes(b"x" * 64)
        result = {"files": args.folders * args.files, "results": {}}
        for label, module in modules:
            result["results"][label] = measure(module, root, args.rounds)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
