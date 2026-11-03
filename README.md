# DiskClean

A fast, interactive folder size analyzer for **macOS, Windows and Linux**. Scan
a folder, explore it as an interactive **sunburst** in your browser, and move
space-hogs to the **Trash / Recycle Bin** (recoverable) in a click.

No dependencies, no build step, no internet: pure Python standard library plus
a self-contained HTML/SVG UI.

## Entry points

| File | Platform | Notes |
| --- | --- | --- |
| `cleaner.py` | macOS, Windows, Linux | The main program. |
| `winclean.py` | Windows | Same program under a Windows name. |

Both are thin wrappers over the `diskclean` package, so every platform runs
exactly the same scanner, safety checks and UI.

```sh
python3 cleaner.py                       # scan your home folder
python3 cleaner.py ~/Downloads           # scan a specific folder
python3 cleaner.py ~/Downloads --read-only
python3 cleaner.py . --port 0 --no-open

python winclean.py                       # Windows, same flags
python winclean.py %USERPROFILE%\\Downloads
```

It prints a URL (default http://127.0.0.1:8765) and opens it automatically.

## What you get

- **Background scans** that can be cancelled; cancelling keeps the previous
  results. Only one scan or delete runs at a time.
- **Live chart:** after 10 seconds a read-only chart shows the largest items
  found so far and updates every 10 seconds. Trash stays disabled until the
  scan completes.
- **Single-click navigation:** click a folder to open its chart, use the
  breadcrumbs or the center to go up, Shift-click or Space to select a folder
  for actions without entering it.
- **Searchable contents list** with paging, including empty and tiny files that
  are too small for the chart.
- **Reveal in Finder / Explorer**, and **Move to Trash / Recycle Bin** with a
  confirmation and a stale-selection guard.

## Cross-platform behaviour

The same code paths run everywhere; only the native calls differ:

| | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Recoverable delete | Trash (`NSFileManager`) | Recycle Bin (`SendToRecycleBin`) | `gio trash` |
| Reveal | Finder (`open -R`) | Explorer (`explorer /select,`) | `xdg-open` |
| Allocated size | `st_blocks` | `GetCompressedFileSizeW` | `st_blocks` |
| Caches shortcut | `~/Library/Caches` | `%LOCALAPPDATA%` | `~/.cache` |
| Protected OS roots | `/System`, `/Library`, … | `C:\\Windows`, drive roots, … | `/usr`, `/etc`, … |

UI labels ("Reveal in Finder" / "Reveal in Explorer", "Move to Trash" /
"Move to Recycle Bin") follow the platform automatically.

## Project layout

```
cleaner.py            entry point (macOS / Windows / Linux)
winclean.py           entry point (Windows name, same program)
diskclean/
  platform.py         OS identity, path normalization and comparison
  paths.py            protected folders, scanned-root allowlist, revisions
  scanner.py          iterative walker, live progress, in-memory index
  native.py           Trash, reveal, memory accounting per OS
  server.py           loopback HTTP server, request validation, JSON API
  cli.py              shared argparse front end
  ui.html             the page (self-contained, no CDN)
tests/test_diskclean.py
```

### Why the split

Each module has one job and can be tested on its own:

- `platform` answers "where am I and how do paths compare here?" — including
  Windows 8.3 short names and case-insensitive matching.
- `paths` answers "may this be deleted, and is the selection still current?"
- `scanner` answers "what is in this folder, how big, and how far along are we?"
- `native` is the only place that shells out to the OS.
- `server` answers "is this request allowed, and which action does it want?"

## Sizes are an allocated-size estimate

Reported sizes are the **allocated size**, not the apparent size, which is much
closer to real disk usage. On macOS and Linux that is `st_blocks × 512`; on
Windows it is `GetCompressedFileSizeW`, so sparse and compressed files read as
smaller than they look. Treat it as an *estimate of disk usage*, not a promise
of uniquely reclaimable bytes: hard links are counted once per link, and clones
/ shared extents are counted in full for every path, so deleting one copy can
free less than the number shown.

## Incomplete-scan disclosure

Folders that cannot be read are **counted and surfaced** ("3 folders couldn't
be read … totals may be low") with the paths in the tooltip. A locked folder is
never silently shown as empty. Use `--exclude FOLDER` to skip a folder that
stalls the scan, such as a cloud-provider trash directory.

## Safety and security model

This is a local server that can delete files, so it is locked down:

- **Loopback only.** It binds to `127.0.0.1`, so it is not reachable from the
  network.
- **Per-process token.** Every API request must carry a random token embedded
  in the page, so another website cannot drive it (CSRF). Cross-origin calls
  and unexpected `Host` headers are rejected on top of that.
- **Hardened responses.** `no-store`, no framing, a restrictive Content
  Security Policy, and request bodies that are size-limited before parsing.
- **Scanned-root allowlist.** Only items *strictly inside* a folder you scanned
  this session may be deleted.
- **Protected folders.** Home and its main subfolders, OS folders, drive and
  volume roots, and the scan root itself can never be deleted, enforced
  server-side regardless of the UI.
- **Stale-selection guard.** Each item carries a revision derived from its
  identity and timestamps; a delete is refused if the item changed since the
  scan.
- **Links are never followed.** Selecting a symlink trashes the link, not its
  target.
- **Recoverable, never permanent.** Items go to the Trash or Recycle Bin;
  nothing is permanently deleted and no Trash is ever emptied.

## Tests

```sh
python -m unittest discover -s tests -t . -v
```

The suite is identical on all three platforms and covers scanner accuracy
(including sparse files and deep trees), cancellation and limits, progress
accounting, index consistency, deletion validation (outside-root, protected
folders, symlink escapes, stale revisions, read-only mode), and the HTTP surface
(authentication, origin and `Host` checks, error shapes, scan lifecycle,
pagination, delete round trip). One test performs a real Trash/Recycle Bin move
on a file it creates, and skips itself when no Trash integration is available.

## More

- [Usage guide](docs/guide.md) — controls, validation options, troubleshooting
- [Engineering notes](docs/engineering-review.md) — findings and measurements
