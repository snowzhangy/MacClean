# Engineering review

## Findings addressed

| Finding | Result |
| --- | --- |
| Hover changed the action panel’s target | Hover preview and explicit selection are separate; browser smoke checks selection stability. |
| Concurrent scans and Trash could interleave index updates | One operation lock; scans build private trees and publish after success. Cancelled/failed scans preserve the prior tree. |
| Recursive traversal raised the interpreter recursion limit to 100,000 | Iterative traversal; no process-wide recursion override. |
| Scanner could follow a directory replaced by a symlink | Descriptor-relative opens with `O_NOFOLLOW`; macOS root opens use `O_NOFOLLOW_ANY`. A regression test swaps the directory during traversal. |
| Every top-level file created a worker job; all entries were queued | Files run in the producer; only subtrees enter a bounded pool. Default concurrency reduced after measurement. |
| Cached ancestors kept stale age/permission information | Refresh/removal recompute sizes, newest descendant times, and skip disclosure. Sorted contents caches are invalidated. |
| Chart aggregation hid small and empty items | Independent searchable contents API with bounded pagination; explicit aggregate nodes even for zero allocated bytes. |
| Chart bounds were only per folder and depth | A global 2,500-node budget also bounds transport and DOM work. |
| Malformed JSON could crash handlers; the root page lacked Host validation | Strict request shapes/types, origin/Host enforcement, body/time/handler limits, and regression coverage. |
| Actions accepted an unversioned path | Indexed item revisions and immediate native preflight identity checks; native command paths are absolute. |
| Filename/age heuristics claimed items were safe to clean | Removed that advice; only folder grouping and age visualization remain. |
| CLI startup failed noisily on occupied ports | Validated options, `--port 0`, actionable errors, read-only mode, and orderly server closure. |
| Backend and UI shared one large string | UI moved to `macclean.html`; one-pass placeholder substitution prevents recursive token expansion. |
| A fixed 500,000-entry default stopped large home scans | Default entry cap removed; current process memory is sampled against a RAM-based budget. Explicit caps remain optional, with per-job browser retries. Failure state retains scalar data so tracebacks cannot keep a failed tree alive. |
| Long scans showed no chart until completion | Separate bounded summaries provide read-only previews every 10 seconds. Opening a folder projects only its immediate children already in memory, caches its preview, and retains that focus for later updates and completion. No extra disk traversal or per-file navigation tracking is added. |
| Clicking folders selected them without entering their chart | A click opens the folder; Shift-click or Space selects it for actions. Entering a folder synchronizes the path field, making the next Scan target that folder. |
| Stalled filesystem reads looked like a frozen/finished scan | Status exposes idle time and the current directory, showing Waiting for filesystem instead of claiming completion. Status polling is independent of preview requests; completion displays Done and releases controls. |
| Every disabled button showed a waiting cursor | Disabled controls use an unavailable cursor. Spinners identify the actual request; Finder stays available during background scanning and clears its own pending state on success or failure. |
| Reloading the page started another full scan | A token-protected current-job status endpoint lets the page reconnect or restore committed results; the tab's focused folder is retained. |
| A cloud-provider Trash folder blocked a directory read | Repeatable --exclude folder options omit known stalled subtrees without opening them and disclose the missing totals. A stack sample of the affected process confirmed a worker waiting in getdirentries64. |

## Local measurements

Measured on the development Mac with Python 3.14.6. The benchmark creates
64 directories with 200 files each, each file containing 64 bytes. Both versions
reported 52,428,800 allocated bytes. Five scans per version, no cold-cache reset:

| Version | Worker threads | Median scan |
| --- | ---: | ---: |
| Initial commit (`bdd9e32`) | 22 | 0.1238 s |
| Revised default | 2 | 0.0759 s |

That is about **39% less elapsed time** on this fixture. It is not a guarantee
for other volumes or workloads. Filesystem caches, network latency, file count,
and directory distribution affect performance. `scripts/benchmark.py` allows
repeating the measurement and comparing a saved prior script.

### Live-preview overhead

`scripts/benchmark-preview.py` alternates ten rounds of scans with lightweight
counters only and scans with live summaries. Each fixture has 12,800 files.
Both configurations retain the same memory safeguard.

| Fixture | Counters only | Live summaries | Snapshot + JSON encoding |
| --- | ---: | ---: | ---: |
| 64 subdirectories | 0.07628 s | 0.07719 s | 0.0528 ms |
| One flat directory | 0.05985 s | 0.06064 s | 0.0683 ms |

Summary maintenance added about 1.2–1.3% in this local measurement. Snapshot
payloads were about 15–19 KiB, generated at most once per ten seconds and shared
across tabs through a cache. This is not a claim of zero overhead; filesystem
and scheduling variation can exceed these differences. The snapshot timing
includes server projection and JSON encoding, not HTTP or browser painting.

## Validation and limits

The Python suite runs against temporary files and an actual loopback HTTP
server. Browser smoke uses local headless Chromium and a temporary fixture,
covering scan, pagination, filtering, escaped filenames, stable selection,
folder navigation, refresh, failed-scan recovery, and a narrow layout. The
staged `--live` browser check passed with two real 10-second updates, growing
partial totals, single-click folder navigation, focused updates and completion,
the next scan's folder target, disabled Trash, and restoration after cancelling.
Additional browser checks exercise Finder success/failure, completion and
button recovery, reconnecting to running/completed jobs, and a preview delayed
beyond scan completion while status continues updating.
No live
user data is changed. Native Trash invocation and outcomes are mocked in unit
tests. An additional opt-in native smoke test passed on this Mac: a generated
regular file and a final symlink were moved to Trash and restored, preserving
their inodes and leaving the symlink target unchanged. Finder’s Put Back UI,
external-volume Trash behavior, and APFS clone reclamation still need manual
verification before distributing a release.

The implementation uses descriptor-relative APIs described by the
[Python OS documentation](https://docs.python.org/3/library/os.html) and native
[Foundation Trash](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:)).
The final native call accepts a path. Its preflight identity check is not atomic
with Trash, so this is not an adversarial filesystem isolation boundary.

Memory sampling uses the resident-size field of Apple's
[proc_taskinfo](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h)
on macOS and `/proc/self/statm` on Linux. Peak RSS is avoided so a failed large
scan does not permanently prevent smaller retries. The fallback estimate used
when OS accounting is unavailable cannot account for all allocator overhead or
previously committed trees.

Additional limits: the index retains one node per observed entry. The sampled
memory budget can be exceeded between samples and does not account for all
swapped or compressed allocations. Deep scans can
exhaust available file descriptors; failures are disclosed as skipped paths.
Cancellation cannot interrupt a blocked kernel filesystem operation. Scan
results are live estimates, not a consistent APFS snapshot or a measurement of
unique reclaimable extents.
