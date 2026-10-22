# MacClean

An offline disk usage analyzer for macOS. Explore a sunburst chart, find large
folders, and move selected items to Finder’s Trash. Python standard library
only: no packages, build step, account, or internet connection.

## Start

Requires **Python 3.10+**. Keep `macclean.py` and `macclean.html` together.

```sh
python3 macclean.py ~/Downloads
```

The browser opens automatically. The server listens only on `127.0.0.1:8765`.
Stop it with **Ctrl+C** in the terminal. Run as your normal user, without sudo.

```sh
python3 macclean.py                       # start with your home folder
python3 macclean.py ~/Downloads --read-only  # inspect with Trash disabled
python3 macclean.py . --port 0             # choose an available port
python3 macclean.py . --no-open            # print the URL without opening it
python3 macclean.py ~ --exclude ~/Library/CloudStorage/YourDrive/.Trash
python3 macclean.py --help
```

The scanner and read-only UI also work on Linux. Finder and Trash require macOS.

## Use

- **Scan** a folder by entering its path or using a shortcut. Progress shows
  items visited, allocated bytes, and elapsed time. **Cancel scan** keeps the
  previous successful results. Only one scan or Trash action runs at a time.
- **Live chart:** after 10 seconds, a read-only chart shows the largest
  top-level items observed so far. It updates every 10 seconds without
  re-scanning folders. Click folders to explore the data already collected;
  later updates and scan completion keep your current folder in view. Partial
  sizes can grow, and Trash stays disabled until the scan completes. Faster
  scans show their final chart immediately. Cancelling restores the previous
  completed view.
- **Click a folder** in the chart or contents list to open its chart. Use
  breadcrumbs or click the center to go up. Click a file to select it.
- **Shift-click a folder**, or focus it and press **Space**, to select it for
  actions without entering it. Hovering previews its size without changing
  the selected action target. **Enter** opens a focused folder.
- **Search contents** by name and use **Previous / Next** for larger folders.
  This list includes empty files and items too small to appear on the chart.
  Search applies to the current folder’s immediate children.
- **Refresh** re-scans the current folder and corrects ancestor sizes,
  modification times, and incomplete-scan counts. Entering a folder also
  updates the path field, so the next **Scan** targets that folder. Typing a
  different path explicitly changes the next scan target.
- **Reveal in Finder** selects the item without launching its contents.
  It remains available during a background scan and shows its own short
  progress indicator while the native request runs.
- **Move to Trash** asks for confirmation. Restore an item from Finder’s Trash
  if needed. MacClean never permanently deletes files or empties Trash.

The contents list and controls support keyboard navigation. The layout adapts
to narrow windows. Folder colors show grouping; Age colors show modification
times, with old items green and recent items red. Age is not deletion advice.

A successful new scan replaces the current session tree and its Trash
allowlist. Browser tabs share that one tree; use one tab per running instance.
Reloading the page reconnects to the current scan or restores completed results;
it does not automatically launch another full scan. The last viewed folder is
remembered for that browser tab.

The status bar explicitly shows **Done** on completion and restores Scan,
Refresh, and selection controls. If item counts stop changing for 10 seconds,
it shows **Waiting for filesystem** with the directory being read when known;
the elapsed clock keeps advancing. A delayed chart preview cannot block status
polling. Only the button doing work displays a spinning indicator; disabled
buttons use an unavailable cursor.

## Accuracy and permissions

Sizes are **allocated estimates**: `st_blocks × 512`, falling back to apparent
size where block counts are unavailable. Sparse and compressed files usually
report much less than their apparent size. Directory metadata is excluded.
Hard links are counted per path; APFS clones and shared extents are not
deduplicated. The bytes actually freed can therefore be smaller.

Scans are live observations, not filesystem snapshots. Items can change while
being scanned. Unreadable or disappearing items are counted in the status bar,
with sample paths in its tooltip. An unreadable root produces an explicit error.
If macOS privacy settings prevent access, grant your terminal access to the
specific folders you need, then refresh. MacClean does not bypass permissions.

Cloud-provider directories can stall inside a macOS directory read, even when
their contents look local in Finder. Use repeatable `--exclude FOLDER` options
to skip a known stalled folder and its descendants. Exclusions are disclosed
in the omitted-item count and tooltip, and their sizes are excluded from totals.
Cancellation is cooperative and cannot interrupt an already blocked kernel
read; stop the old process before restarting with an exclusion.

## Performance and resource limits

**Refresh** rescans the folder currently shown in the chart and all its
subfolders. It keeps that folder in view, preserves cached sibling folders,
and updates the cached parent totals. The status shows the refreshed path.

Traversal uses `scandir`, descriptor-relative directory opens, and an iterative
walk. Directory symlinks are never followed. Only directory subtrees are sent
to the thread pool; files avoid the overhead of individual worker jobs. The
pending queue is capped at twice the worker count. Results commit together,
so overlapping operations cannot damage cached totals.

The default is **2 workers**, chosen from local APFS measurements; more threads
can increase overhead on cached local disks. Tune with `--workers 1` through
`--workers 32` for your storage. Network filesystems can behave differently.

There is **no fixed entry cap by default**. Instead, a memory budget scales
with your Mac: 25% of physical RAM, with a minimum of 512 MiB and maximum of
4 GiB. The scanner samples its current resident memory at most twice a second,
checking every 4,096 entries. If OS accounting is unavailable, it uses an
estimated entry-memory guard. This is a sampled safeguard, not a hard RAM
ceiling, and the old and new trees coexist during a refresh.

If a budget is reached, previous completed results remain available and the
browser offers **Retry** with a higher budget. You can also configure startup:

```sh
python3 macclean.py ~ --max-memory-mb 8192   # 8 GiB process memory budget
python3 macclean.py ~ --max-entries 2000000  # optional explicit entry cap
```

`--max-entries 0` disables the entry cap while retaining the memory safeguard.
Live previews retain at most 80 completed summaries plus the few active worker
branches, sending at most 81 chart items per update. They never traverse the
full index or filesystem. Opening a folder projects only its immediate
children already in memory and caches that bounded result for 10 seconds;
up to four focused-folder snapshots are retained. No per-file scan tracking
is added for navigation. The final chart is capped at 2,500 nodes; contents
pages have at most 200 entries. Cancellation is cooperative: a blocked
filesystem call must return before its worker can stop.

Reproduce a temporary-data benchmark (no user files are scanned or changed):

```sh
python3 scripts/benchmark.py
# Optionally compare an older standalone version:
python3 scripts/benchmark.py --baseline /path/to/old/macclean.py
python3 scripts/benchmark-preview.py  # isolate preview bookkeeping/encoding cost
```

## Security model

- Loopback binding, strict Host and same-origin checks, and a random session
  token on every API call. The page also rejects unknown Hosts and cross-site
  browser requests. Scans and actions use POST; reading a subtree never starts
  an implicit scan.
- No-store responses, CSP nonces, framing protection, JSON size/type checks,
  socket timeouts, and a cap on concurrent HTTP handlers.
- Trash is limited to indexed items inside the current scanned root. Scan
  roots, protected home/system folders, and mounted volume roots are refused.
- A selection carries its scanned identity. The server checks device, inode,
  type, modification time, and change time immediately before native Trash.
  Changed or replaced items require a refresh and a new selection.
- Prefixes are opened without following symlinks; the final symlink is treated
  as the selected link. Trash uses macOS `NSFileManager`, without a permanent
  deletion fallback. A timeout reports an unknown outcome and asks you to check
  Finder before retrying.

This protects normal local use, not a machine with malicious processes running
as your user. The final identity check and Foundation’s path-based Trash call
are separate operations, so they cannot eliminate every concurrent filesystem
race. `--read-only` disables Trash server-side when only inspection is needed.
Do not expose this local server through a proxy or tunnel.

## Verify

```sh
python3 -m unittest -v test_macclean
```

Tests cover allocation, sparse files, deep trees, permissions, symlink swaps,
cancellation, memory limits, refresh consistency, stale selections, Trash
failure handling, injection escaping, and the HTTP authentication surface.
Native Trash calls are simulated in unit tests; no user files are trashed.
CI runs the Python suite on macOS and Linux with Python 3.10 and 3.14.

The opt-in native macOS check moves generated fixtures to Trash and immediately
restores them, verifying that a final symlink’s target stays untouched:

```sh
python3 scripts/native-trash-smoke.py
```

An optional real Chromium smoke test needs Node 22+ and a browser binary,
but no npm dependencies. It creates and removes its own temporary fixture,
checks the browser workflow, and saves desktop/mobile screenshots in `/tmp`.
It does not execute Trash or Finder actions.
Finder requests use a simulated native result in the browser fixture server;
unit tests verify the real `/usr/bin/open -R` command and timeout handling.

```sh
CHROME_BIN=/path/to/chrome node scripts/browser-smoke.mjs
CHROME_BIN=/path/to/chrome node scripts/browser-smoke.mjs --live
```

`--live` uses a staged temporary fixture to verify actual 10-second updates,
folder navigation, focused updates and completion, the next scan's target,
and cancellation restoration. It also checks waiting-state clock updates,
completion while a preview request is delayed, control recovery, and reloading
both running and completed scans without restarting them. It
also tests the one-click retry control. The staging delay is test-only.

See [the engineering review](engineering-review.md) for changes,
measurements, and remaining validation limits.
