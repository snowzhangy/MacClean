"""Loopback HTTP server and the JSON API.

Threat model: any web page the user has open can send requests to
127.0.0.1. Because this server can delete files, every request must:

* carry a Host header we bound to (defeats DNS rebinding),
* come from our own origin (defeats cross-site form/fetch posts), and
* for API calls, carry a per-process random token the page receives only in
  its own HTML -- a foreign page can neither read it nor set the custom header
  without a CORS preflight, which we never grant.

The server also refuses to act on any path that the delete layer
(`paths.validate_trash_target`) does not approve.
"""

import json
import os
import re
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import native
from . import paths
from . import platform as osplat
from . import scanner

TOKEN_HEADER = "X-DiskClean-Token"

SESSION_TOKEN = secrets.token_urlsafe(32)
ALLOWED_HOSTS = set()
MAX_CONNECTIONS = 24
CONNECTION_TIMEOUT = 10

PAGE = Path(__file__).with_name("ui.html").read_text(encoding="utf-8")


# ---- Background jobs -------------------------------------------------------
class ScanJobs:
    """One background scan at a time, with bounded history and a commit point.

    The scan builds a private tree and only publishes it to INDEX on success,
    so cancelling or failing leaves the previous results intact.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.job = None
        self.thread = None

    def start(self, path, refresh=False, max_entries=None, max_memory_mb=None):
        path = osplat.normalize(path)
        progress = scanner.ScanProgress(max_entries, max_memory_mb)
        if refresh:
            with scanner.INDEX_LOCK:
                if osplat.key(path) not in scanner.INDEX:
                    raise ValueError("Folder is not in the current scan.")
        if not scanner.OPERATION_LOCK.acquire(blocking=False):
            raise paths.BusyError("A scan or Trash operation is already running.")
        job = {"id": secrets.token_urlsafe(12), "path": path, "state": "running",
               "progress": progress, "refresh": refresh}
        with self.lock:
            self.job = job

        def run():
            try:
                root = scanner._perform_scan(path, not refresh, progress)
                if not refresh:
                    with scanner.INDEX_LOCK:
                        for existing in [k for k in scanner.INDEX
                                         if not osplat.inside(k, root["path"])]:
                            del scanner.INDEX[existing]
                with self.lock:
                    job.update(state="done", origin=root["path"])
            except paths.ScanLimitError as exc:
                retry_entries = (min(1_000_000_000, max(progress.max_entries + 1,
                                                       progress.max_entries * 2))
                                 if exc.kind == "entry_limit" else progress.max_entries)
                retry_memory = (min(1_048_576, progress.max_memory_mb * 2)
                                if exc.kind == "memory_limit" else progress.max_memory_mb)
                with self.lock:
                    job.update(state="error", error=str(exc), limit_kind=exc.kind,
                               retry={"max_entries": retry_entries,
                                      "max_memory_mb": retry_memory})
            except paths.ScanCancelled as exc:
                with self.lock:
                    job.update(state="cancelled", error=str(exc))
            except (OSError, ValueError) as exc:
                with self.lock:
                    job.update(state="error", error=str(exc))
            except Exception:  # noqa: BLE001 - never leak a traceback to the page
                with self.lock:
                    job.update(state="error",
                               error="Scan failed unexpectedly. Please try a smaller folder.")
            finally:
                progress.finish()
                progress.release_indexes()
                scanner.OPERATION_LOCK.release()

        self.thread = threading.Thread(target=run, name="diskclean-job", daemon=True)
        try:
            self.thread.start()
        except BaseException:
            scanner.OPERATION_LOCK.release()
            raise
        return self.status(job["id"])

    def status(self, job_id=None):
        with self.lock:
            if self.job is None and job_id is None:
                return {"state": "idle", "cached_origin": None}
            if self.job is None or (job_id is not None and self.job["id"] != job_id):
                raise ValueError("Unknown scan. It may have been replaced by another browser tab.")
            result = {k: v for k, v in self.job.items() if k != "progress"}
            result.update(self.job["progress"].snapshot())
            result["cached_origin"] = paths.cached_origin()
            return result

    def cancel(self, job_id):
        with self.lock:
            if self.job is None or self.job["id"] != job_id:
                raise ValueError("Unknown scan.")
            if self.job["state"] == "running":
                self.job["progress"].cancel.set()
        return self.status(job_id)

    def preview(self, job_id, path=None):
        with self.lock:
            if self.job is None or self.job["id"] != job_id:
                raise ValueError("Unknown scan.")
            job = self.job
            if job["state"] != "running":
                return {"root": None, "state": job["state"]}
        # Drop the lock before inspecting a folder so cancellation and status
        # polling stay responsive.
        root = job["progress"].preview(path)
        with self.lock:
            if self.job is not job:
                raise ValueError("Unknown scan.")
            return {"root": root, "state": job["state"]}

    def close(self):
        with self.lock:
            if self.job:
                self.job["progress"].cancel.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=30)


JOBS = ScanJobs()


# ---- Page rendering --------------------------------------------------------
def _js_literal(value):
    return (json.dumps(value).replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("&", "\\u0026"))


def _html_attr(value):
    return (value.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


def render_page(csp_nonce=""):
    # Single substitution pass, so path text can never introduce a new token.
    values = {
        "START_PATH": _js_literal(scanner.START_PATH),
        "TOKEN": _js_literal(SESSION_TOKEN),
        "READ_ONLY": _js_literal(bool(scanner.READ_ONLY)),
        "CSP_NONCE": csp_nonce,
        "PLATFORM": _js_literal(osplat.PLATFORM),
        "FILE_MANAGER": _js_literal(osplat.FILE_MANAGER),
        "SEP": _js_literal(os.sep),
        "HOME": _html_attr(osplat.HOME),
        "CACHE_PATH": _html_attr(native.cache_shortcut()),
        "TRASH_NAME": _js_literal(scanner.trash_name()),
        # Text placements (attributes / button labels) are HTML-escaped.
        "FILE_MANAGER_TEXT": _html_attr(osplat.FILE_MANAGER),
        "TRASH_TEXT": _html_attr(scanner.trash_name()),
    }
    return re.sub(r"__(START_PATH|TOKEN|READ_ONLY|PLATFORM|FILE_MANAGER|FILE_MANAGER_TEXT|SEP|HOME"
                  r"|CACHE_PATH|TRASH_NAME|TRASH_TEXT|CSP_NONCE)__",
                  lambda m: values[m.group(1)], PAGE)


# ---- Server ----------------------------------------------------------------
class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "DiskClean"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(CONNECTION_TIMEOUT)

    def log_message(self, *args):  # quiet
        pass

    def end_headers(self):
        nonce = getattr(self, "_csp_nonce", "") or secrets.token_urlsafe(16)
        self._csp_nonce = nonce
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; "
                         f"script-src 'self' 'nonce-{nonce}'; "
                         "style-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; "
                         "object-src 'none'; base-uri 'none'; "
                         "frame-ancestors 'none'; form-action 'none'")
        super().end_headers()

    # -- low-level responses --
    def _send(self, body, content_type, code=200):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, ensure_ascii=True).encode("utf-8"),
                   "application/json; charset=utf-8", code)

    def _error(self, message, code=400):
        # One error shape for every failure: the page reads `error`, older
        # callers read `message`.
        self._json({"ok": False, "error": message, "message": message}, code)

    # -- authorization --
    def _same_origin(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + self.headers.get("Host", ""):
            return False
        return self.headers.get("Sec-Fetch-Site") != "cross-site"

    def _has_token(self):
        token = self.headers.get(TOKEN_HEADER, "")
        return (token.isascii() and secrets.compare_digest(token, SESSION_TOKEN)
                and self.headers.get("Host", "") in ALLOWED_HOSTS
                and self._same_origin())

    def _authorized_mutation(self):
        return self._has_token() and self._same_origin()

    # -- routing --
    def do_GET(self):
        if self.headers.get("Host", "") not in ALLOWED_HOSTS or not self._same_origin():
            self._error("Unauthorized host or origin.", 403)
            return
        url = urlparse(self.path)
        if url.path == "/":
            self._csp_nonce = secrets.token_urlsafe(16)
            self._send(render_page(self._csp_nonce).encode("utf-8"),
                       "text/html; charset=utf-8")
            return
        if not self._has_token():
            self._error("Unauthorized.", 403)
            return
        query = parse_qs(url.query)
        try:
            if url.path == "/api/status":
                self._json(JOBS.status(query.get("id", [None])[0]))
            elif url.path == "/api/preview":
                self._json(JOBS.preview(query.get("id", [""])[0], query.get("path", [None])[0]))
            elif url.path == "/api/subtree":
                self._json({"root": scanner.get_subtree(query.get("path", [""])[0])})
            elif url.path == "/api/children":
                self._json(scanner.list_children(
                    query.get("path", [""])[0], query.get("q", [""])[0],
                    _int(query.get("offset", ["0"])[0]),
                    _int(query.get("limit", ["100"])[0])))
            elif url.path == "/api/scan":
                self._error("Use POST /api/scan to start a scan.", 405)
            elif url.path == "/api/progress":
                with JOBS.lock:
                    progress = JOBS.job["progress"] if JOBS.job else None
                self._json(progress.snapshot() if progress else {"state": "idle"})
            else:
                self._error("Not found.", 404)
        except (OSError, ValueError) as exc:
            self._error(str(exc))

    def _read_json_body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported.")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json.")
        if len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("A single Content-Length is required.")
        try:
            length = int(self.headers["Content-Length"])
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if length < 0:
            raise ValueError("Invalid Content-Length.")
        if length > scanner.MAX_JSON_BODY:
            raise ValueError("Request body too large.")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete request body.")
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ValueError("Invalid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object.")
        # Reject lone surrogates before the values reach any OS API.
        for field in ("path", "id", "revision"):
            if field in data and not isinstance(data[field], str):
                raise ValueError(f"{field} must be a string.")
            if isinstance(data.get(field), str):
                try:
                    os.fsencode(data[field])
                except UnicodeEncodeError as exc:
                    raise ValueError(f"Invalid characters in {field}.") from exc
        return data

    def do_POST(self):
        if not self._authorized_mutation():
            self._error("Unauthorized.", 403)
            return
        url = urlparse(self.path)
        if url.path not in ("/api/scan", "/api/cancel", "/api/trash", "/api/reveal"):
            self._error("Not found.", 404)
            return
        try:
            data = self._read_json_body()
            if url.path == "/api/cancel":
                self._json(JOBS.cancel(data.get("id")))
                return
            path = data.get("path")
            if not isinstance(path, str) or not path or "\0" in path:
                raise ValueError("A valid path string is required.")
            if url.path == "/api/scan":
                refresh = data.get("refresh", False)
                if not isinstance(refresh, bool):
                    raise ValueError("refresh must be a boolean.")
                limits = {key: data[key] for key in ("max_entries", "max_memory_mb")
                          if key in data}
                if any(value is None for value in limits.values()):
                    raise ValueError("Scan limits must be integers.")
                self._json(JOBS.start(path, refresh, **limits), 202)
            elif url.path == "/api/trash":
                ok, message = scanner.move_to_trash(path, data.get("revision"))
                self._json({"ok": ok, "message": message}, 200 if ok else 400)
            else:
                ok, message = scanner.reveal(path)
                self._json({"ok": ok, "message": message}, 200 if ok else 400)
        except paths.BusyError as exc:
            self._error(str(exc), 409)
        except (OSError, ValueError) as exc:
            self._error(str(exc), 413 if "too large" in str(exc) else 400)


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Expected an integer.") from exc
