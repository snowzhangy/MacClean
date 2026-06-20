# MacClean

A fast, DaisyDisk-style folder size analyzer for macOS. Scans a folder,
shows an interactive **sunburst** in your browser, and lets you move
space-hogs to the **Trash** (recoverable) in one click.

No dependencies, no build step, no internet — pure Python standard library
plus a self-contained HTML/SVG UI.

## Run

```sh
python3 macclean.py                 # scans your home folder
python3 macclean.py ~/Downloads     # scan a specific folder
python3 macclean.py ~/ --port 9000  # custom port
python3 macclean.py ~/ --no-open    # don't auto-open the browser
```

It prints a URL (default http://127.0.0.1:8765) and opens it automatically.

## Using it

- **Hover** a ring segment to see its size and share of the parent.
- **Single-click** to select it (details + actions appear on the right).
- **Double-click** a folder segment — or the center — to dive in / pop out.
- **Right-click** a segment or a list row to **reveal it in Finder**
  (folders open; files are selected in their enclosing folder). There's also
  a **Reveal in Finder** button in the details panel.
- **Breadcrumbs** (top-left) jump back to any ancestor.
- **↻ Refresh** re-scans *only the current folder* from disk and corrects the
  totals up the chain — use it after you delete things (here or in Finder) to
  see the updated usage without re-scanning everything.
- **Move to Trash** sends the selected item to the macOS Trash after a
  confirmation. It is always recoverable — nothing is permanently deleted.
  Sizes update instantly after a delete.

## How it's fast

- Traversal uses `os.scandir` and parallelizes across top-level entries
  with a thread pool (filesystem I/O releases the GIL). Each worker walks its
  subtree into a private index and they're merged once at the end, so threads
  never contend on a lock during the scan.
- Entry types come from the directory's `dirent` (no syscall on macOS) and
  only *files* are `stat`'d for their size — directories are never `stat`'d,
  their size is summed from their children. That roughly halves the syscalls
  versus the naive `isdir`/`islink`/`lstat`-per-entry approach.
- The server keeps the full tree in memory and sends only a pruned slice
  (depth-capped, tiny items aggregated into "(N small items)") so the UI
  stays snappy even on huge folders. Drilling in is an O(1) lookup.

## Sizes are an allocated-size estimate

Reported sizes are the **allocated size** (`st_blocks × 512`) — much closer to
real disk usage than apparent size (`st_size`), which is wildly off for APFS
compression and sparse files. Treat it as an *estimate of disk usage*, not a
promise of uniquely reclaimable bytes: hard links are counted once per link,
and APFS clones / shared extents are counted in full for every path, so
deleting one copy can free less than the number shown. The UI labels this
"allocated est." and explains it in the status-bar tooltip.

## Incomplete-scan disclosure

Folders that can't be read (permission denied) are **counted and surfaced** in
the status bar — e.g. "⚠ 3 folders couldn't be read … totals may be low" —
with the paths in the tooltip. The scan never silently pretends a locked
folder is empty.

## Safety & security model

This is a local server that can delete files, so it's locked down:

- **Loopback only.** It binds to `127.0.0.1` — not reachable from the network.
- **Per-process token.** *Every* API request (scan/refresh as well as
  delete/reveal) must carry a random session token embedded in the page, so
  another website in your browser can't drive it or trigger disk-heavy scans
  (CSRF). Cross-origin requests are rejected on top of that.
- **Hardened local responses.** Pages and API responses are `no-store`, cannot
  be framed, include a restrictive Content Security Policy, and reject oversized
  JSON request bodies before parsing.
- **Scanned-root allowlist.** The server will only Trash items that live
  *strictly inside* a folder you actually scanned this session. Anything
  outside is refused.
- **Protected folders.** Home, `/`, `/System`, `/Applications`, `~/Library`,
  `~/Desktop`/`~/Documents`/`~/Downloads`, volume roots, and the active scan
  root itself can never be trashed — enforced server-side, regardless of the
  UI. Symlinks in the path *prefix* are resolved before the allowlist check,
  so a link can't smuggle a location outside the scanned tree.
- **Trash the item itself, never its target.** Selecting a symlink trashes the
  link, not the file it points at (we use `NSFileManager.trashItemAtURL`,
  which doesn't follow the final symlink).
- **Trash, never delete.** Removal moves items to the normal macOS Trash with
  Put-Back support; nothing is permanently deleted.

## Tests

```sh
python3 -m unittest -v test_macclean
```

Covers scanner accuracy (incl. sparse files), permission-skip reporting,
deletion path validation (outside-root, protected dirs, symlink escapes),
stale-index cleanup after deletes, JS-injection escaping, and the HTTP auth
surface (missing token, cross-origin, refused paths, security headers, request
body limits).
