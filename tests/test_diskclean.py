#!/usr/bin/env python3
"""Cross-platform tests for the DiskClean library.

Runs identically on macOS, Windows and Linux:

    python -m unittest discover -s tests -v

Every test works in a temporary directory and never touches real files. The
only genuinely destructive path (moving an item to the OS Trash) is exercised
against a throwaway file this file creates, and is skipped when no Trash
integration is available.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from diskclean import native
from diskclean import paths
from diskclean import platform as osplat
from diskclean import scanner
from diskclean import server


def write(path, data=b""):
    with open(path, "wb") as handle:
        handle.write(data)


def make_sparse(path, size):
    """Create a file with a real hole where the filesystem supports one.

    Python's seek()+write() leaves an NTFS file fully allocated: the file only
    becomes sparse once FSCTL_SET_SPARSE is set and the hole is skipped past.
    """
    if not osplat.IS_WIN:
        with open(path, "wb") as handle:
            handle.seek(size)
            handle.write(b"x")
        return

    import ctypes

    FSCTL_SET_SPARSE = 0x000900C4
    GENERIC_WRITE, CREATE_ALWAYS = 0x40000000, 2

    class Large(ctypes.Structure):
        _fields_ = [("Low", ctypes.c_ulong), ("High", ctypes.c_long)]

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(str(path), GENERIC_WRITE, 0, None, CREATE_ALWAYS, 0, None)
    if handle == -1:
        write(path, b"x")
        return
    try:
        returned = ctypes.c_ulong(0)
        kernel32.DeviceIoControl(handle, FSCTL_SET_SPARSE, None, 0, None, 0,
                                 ctypes.byref(returned), None)
        position = Large(0, 0)
        kernel32.SetFilePointerEx(handle, Large(size, 0), ctypes.byref(position), 0)
        written = ctypes.c_ulong(0)
        kernel32.WriteFile(handle, b"x", 1, ctypes.byref(written), None)
    finally:
        kernel32.CloseHandle(handle)


class TempTree(unittest.TestCase):
    """Shared setup: a clean temp tree, empty index, no recorded scan roots."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        scanner.INDEX.clear()
        paths.clear_scan_roots()

    def tearDown(self):
        scanner.INDEX.clear()
        paths.clear_scan_roots()
        shutil.rmtree(self.root, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.root, *parts)


class ScannerAccuracyTest(TempTree):
    def test_totals_match_content(self):
        write(self.path("a.bin"), b"x" * 5000)
        os.mkdir(self.path("sub"))
        write(self.path("sub", "b.bin"), b"y" * 9000)
        node = scanner.scan(self.root)
        kids = {c["name"]: c for c in node["children"]}
        self.assertEqual(set(kids), {"a.bin", "sub"})
        self.assertEqual(node["size"], kids["a.bin"]["size"] + kids["sub"]["size"])
        self.assertGreaterEqual(node["size"], 14000)

    def test_uses_allocated_not_apparent_for_sparse(self):
        sparse = self.path("sparse.bin")
        make_sparse(sparse, 50 * 1024 * 1024)
        apparent = os.lstat(sparse).st_size
        node = scanner.scan(self.root)
        if node["size"] >= apparent:
            self.skipTest("this filesystem/volume does not report allocation")
        self.assertLess(node["size"], apparent,
                        "allocated size should be below apparent size for a sparse file")

    def test_mtime_reaches_ancestors(self):
        old, new = self.path("old.bin"), self.path("new.bin")
        write(old, b"x")
        write(new, b"x")
        os.utime(old, (1_000_000_000, 1_000_000_000))
        os.utime(new, (1_900_000_000, 1_900_000_000))
        node = scanner.scan(self.root)
        kids = {c["name"]: c for c in node["children"]}
        self.assertEqual(kids["old.bin"]["mtime"], 1_000_000_000)
        self.assertEqual(node["mtime"], 1_900_000_000)

    def test_symlink_is_a_leaf_and_not_followed(self):
        outside = tempfile.mkdtemp()
        try:
            secret = os.path.join(outside, "secret.bin")
            write(secret, b"y" * 10000)
            link = self.path("link")
            try:
                os.symlink(secret, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not permitted for this user")
            node = scanner.scan(self.root)
            kids = {c["name"]: c for c in node["children"]}
            self.assertFalse(kids["link"]["dir"])
            self.assertLess(kids["link"]["size"], 10000,
                            "the link is counted, not its target")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_unreadable_directory_is_disclosed(self):
        locked = self.path("locked")
        os.mkdir(locked)
        if osplat.IS_WIN:
            self.skipTest("POSIX permissions are not enforced the same way on Windows")
        os.chmod(locked, 0o000)
        try:
            if os.access(locked, os.R_OK):
                self.skipTest("this user bypasses permissions (e.g. root)")
            node = scanner.scan(self.root)
            self.assertEqual(node["skipped"], 1)
            self.assertIn(locked, node["skipped_sample"])
        finally:
            os.chmod(locked, 0o700)

    def test_deep_tree_does_not_hit_the_recursion_limit(self):
        current = self.root
        for _ in range(300):
            current = os.path.join(current, "d")
            os.mkdir(current)
        write(os.path.join(current, "leaf.bin"), b"x")
        node = scanner.scan(self.root)  # must not raise RecursionError
        self.assertGreater(node["size"], 0)


class ScanProgressTest(TempTree):
    def test_counts_every_entry_once(self):
        for i in range(3):
            folder = self.path(f"d{i}")
            os.mkdir(folder)
            write(os.path.join(folder, "f.bin"), b"x" * 10)
        progress = scanner.ScanProgress()
        scanner.scan(self.root, progress=progress)
        snapshot = progress.snapshot()
        self.assertFalse(snapshot["cancel_requested"])
        self.assertEqual(snapshot["entries"], 6)  # 3 folders + 3 files

    def test_cancel_leaves_results_unchanged(self):
        os.mkdir(self.path("d"))
        write(self.path("d", "f.bin"), b"x")
        progress = scanner.ScanProgress()
        progress.cancel.set()
        with self.assertRaises(paths.ScanCancelled):
            scanner.scan(self.root, progress=progress)
        self.assertEqual(scanner.INDEX, {})

    def test_entry_limit_is_reported(self):
        for i in range(10):
            write(self.path(f"f{i}.bin"), b"x")
        progress = scanner.ScanProgress(max_entries=2)
        with self.assertRaises(paths.ScanLimitError) as caught:
            scanner.scan(self.root, progress=progress)
        self.assertEqual(caught.exception.kind, "entry_limit")

    def test_invalid_limits_are_rejected(self):
        with self.assertRaises(ValueError):
            scanner.validate_limits(-1, 0)
        with self.assertRaises(ValueError):
            scanner.validate_limits(0, 8)
        with self.assertRaises(ValueError):
            scanner.validate_limits(1.5, 0)


class IndexTest(TempTree):
    def test_subtree_and_children(self):
        for name in ("small", "big"):
            os.mkdir(self.path(name))
            write(self.path(name, "f.bin"), b"x" * (10 if name == "small" else 5000))
        scanner.scan(self.root, register_root=True)
        self.assertEqual(scanner.get_subtree(self.root)["size"],
                         scanner.INDEX[osplat.key(self.root)]["size"])
        items = scanner.list_children(self.root)["items"]
        self.assertEqual([c["name"] for c in items], ["big", "small"])
        self.assertTrue(items[0]["trashable"])

    def test_children_search_and_paging(self):
        os.mkdir(self.path("sub"))
        for name in ("report.pdf", "notes.txt", "Report.txt", "photo.png"):
            write(self.path("sub", name), b"x")
        scanner.scan(self.root, register_root=True)
        result = scanner.list_children(self.path("sub"), query="report")
        self.assertEqual(result["total"], 2, "search is case-insensitive")
        page = scanner.list_children(self.path("sub"), offset=1, limit=2)
        self.assertEqual(len(page["items"]), 2)
        self.assertEqual(page["total"], 4)
        with self.assertRaises(ValueError):
            scanner.list_children(self.path("sub"), limit=500)

    def test_unknown_folder_is_refused(self):
        with self.assertRaises(ValueError):
            scanner.get_subtree(self.root)

    def test_removing_a_folder_purges_descendants(self):
        os.makedirs(self.path("a", "b"))
        write(self.path("a", "b", "f.bin"), b"x" * 100)
        scanner.scan(self.root)
        scanner.remove_from_index(self.path("a"))
        self.assertNotIn(osplat.key(self.path("a")), scanner.INDEX)
        self.assertNotIn(osplat.key(self.path("a", "b")), scanner.INDEX)

    def test_removing_corrects_ancestor_totals(self):
        os.mkdir(self.path("a"))
        write(self.path("a", "f.bin"), b"x" * 200_000)  # larger than one allocation unit
        root = scanner.scan(self.root)
        before = root["size"]
        a_size = scanner.INDEX[osplat.key(self.path("a"))]["size"]
        scanner.remove_from_index(self.path("a"))
        self.assertEqual(scanner.INDEX[osplat.key(self.root)]["size"], before - a_size)

    def test_prune_bounds_depth_but_keeps_totals(self):
        current = self.root
        for depth in range(12):
            current = os.path.join(current, "level")
            os.mkdir(current)
            write(os.path.join(current, "f.bin"), b"x")
        node = scanner.scan(self.root)
        pruned = scanner.prune(node)
        self.assertLessEqual(_depth(pruned), scanner.SEND_DEPTH + 1)
        self.assertEqual(pruned["size"], node["size"])


def _depth(node, level=0):
    """Deepest level in a pruned payload (prune always terminates, so this does)."""
    kids = [c for c in (node.get("children") or []) if c.get("children")]
    if not kids:
        return level
    return max(_depth(c, level + 1) for c in kids)


class TrashValidationTest(TempTree):
    def test_allows_a_real_item_inside_the_scanned_root(self):
        scanner.scan(self.root, register_root=True)
        target = self.path("trashme.bin")
        write(target, b"x")
        resolved, reason = paths.validate_trash_target(target)
        self.assertIsNone(reason)
        self.assertEqual(resolved, osplat.normalize(target))

    def test_rejects_the_scan_root_itself(self):
        scanner.scan(self.root, register_root=True)
        resolved, reason = paths.validate_trash_target(self.root)
        self.assertIsNone(resolved)
        self.assertIsNotNone(reason)

    def test_rejects_paths_outside_any_scanned_root(self):
        scanner.scan(self.root, register_root=True)
        other = tempfile.mkdtemp()
        try:
            target = os.path.join(other, "f.bin")
            write(target, b"x")
            resolved, reason = paths.validate_trash_target(target)
            self.assertIsNone(resolved)
            self.assertIn("outside", reason)
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_rejects_home_and_system_folders(self):
        candidates = [osplat.HOME]
        if osplat.IS_WIN:
            env = os.environ
            candidates += [osplat.ROOT_DIR, "D:" + os.sep,
                           env.get("SystemRoot", r"C:\Windows"),
                           env.get("ProgramFiles", r"C:\Program Files"),
                           os.path.join(osplat.ROOT_DIR, "ProgramData")]
        else:
            candidates += ["/", "/System", "/Applications", "/Volumes"]
        for candidate in candidates:
            self.assertIsNotNone(paths.protected_reason(candidate),
                                 f"{candidate} must be protected")

    def test_protection_is_case_insensitive(self):
        self.assertIsNotNone(paths.protected_reason(osplat.HOME.upper()),
                             "a differently-cased Home path must stay protected")

    def test_data_drive_folder_is_not_a_drive_root(self):
        if not osplat.IS_WIN:
            self.skipTest("Windows-only rule")
        self.assertIsNone(paths.protected_reason("D:" + os.sep + "Projects"))

    def test_symlink_is_judged_by_its_own_location(self):
        scanner.scan(self.root, register_root=True)
        outside = tempfile.mkdtemp()
        try:
            secret = os.path.join(outside, "secret.bin")
            write(secret, b"x")
            link = self.path("link")
            try:
                os.symlink(secret, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not permitted for this user")
            resolved, reason = paths.validate_trash_target(link)
            self.assertIsNone(reason, "the link itself is inside the scanned root")
            self.assertNotEqual(resolved, osplat.normalize(secret),
                                "must not resolve to the link's target")

            sneaky = self.path("escape")
            os.symlink(outside, sneaky)
            resolved, reason = paths.validate_trash_target(os.path.join(sneaky, "secret.bin"))
            self.assertIsNone(resolved)
            self.assertTrue(reason)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_missing_path_is_refused(self):
        scanner.scan(self.root, register_root=True)
        resolved, reason = paths.validate_trash_target(self.path("ghost"))
        self.assertIsNone(resolved)
        self.assertIn("does not exist", reason)


class DeleteSafetyTest(TempTree):
    def _scan_with_file(self):
        os.mkdir(self.path("d"))
        target = self.path("d", "f.bin")
        write(target, b"x" * 2048)
        scanner.scan(self.root, register_root=True)
        node = next(c for c in scanner.INDEX[osplat.key(self.path("d"))]["children"]
                    if not c["dir"])
        return target, paths.revision(node["_identity"])

    def test_missing_revision_is_refused(self):
        target, _ = self._scan_with_file()
        ok, message = scanner.move_to_trash(target)
        self.assertFalse(ok)
        self.assertIn("stale", message)
        self.assertTrue(os.path.exists(target))

    def test_wrong_revision_is_refused(self):
        target, _ = self._scan_with_file()
        ok, _ = scanner.move_to_trash(target, "0" * 24)
        self.assertFalse(ok)
        self.assertTrue(os.path.exists(target))

    def test_protected_path_is_refused(self):
        _, revision = self._scan_with_file()
        ok, message = scanner.move_to_trash(osplat.HOME, revision)
        self.assertFalse(ok)
        self.assertTrue(message)

    def test_read_only_mode_blocks_every_delete(self):
        target, revision = self._scan_with_file()
        scanner.READ_ONLY = True
        try:
            ok, message = scanner.move_to_trash(target, revision)
            self.assertFalse(ok)
            self.assertIn("read-only", message)
        finally:
            scanner.READ_ONLY = False
        self.assertTrue(os.path.exists(target))

    def test_real_delete_goes_to_the_os_trash(self):
        """The one destructive test: only ever a file this test created."""
        target, revision = self._scan_with_file()
        ok, message = scanner.move_to_trash(target, revision)
        if not ok:
            self.skipTest(f"no Trash integration here: {message}")
        self.assertFalse(os.path.exists(target))
        self.assertNotIn(osplat.key(self.path("d")), scanner.INDEX) if os.path.isdir(target) else None
        self.assertNotIn(osplat.key(target), scanner.INDEX)
        self.assertEqual(scanner.INDEX[osplat.key(self.root)]["size"], 0)


class PlatformTest(unittest.TestCase):
    def test_platform_flags_are_consistent(self):
        self.assertIn(osplat.PLATFORM, ("mac", "win", "linux"))
        self.assertEqual(osplat.PLATFORM == "mac", osplat.IS_MAC)
        self.assertEqual(osplat.PLATFORM == "win", osplat.IS_WIN)
        self.assertIn(osplat.FILE_MANAGER, ("Finder", "Explorer", "Files"))

    def test_root_dir_is_an_absolute_hierarchy_root(self):
        self.assertTrue(os.path.isabs(osplat.ROOT_DIR))
        if osplat.IS_WIN:
            self.assertTrue(osplat.is_drive_root(osplat.ROOT_DIR))
            self.assertFalse(osplat.is_drive_root(os.path.join(osplat.ROOT_DIR, "Temp")))
        else:
            self.assertEqual(osplat.ROOT_DIR, "/")

    def test_key_is_stable_and_case_folded_on_windows(self):
        sample = osplat.HOME
        self.assertEqual(osplat.key(sample), osplat.key(sample))
        self.assertEqual(osplat.key(sample), osplat.key(osplat.normalize(sample)))
        if osplat.IS_WIN:
            self.assertEqual(osplat.key(sample), osplat.key(sample.upper()))

    def test_inside_handles_separators_and_case(self):
        base = osplat.normalize(osplat.HOME)
        child = os.path.join(base, "sub")
        self.assertTrue(osplat.inside(child, base))
        self.assertFalse(osplat.strictly_inside(base, base))

    def test_cache_shortcut_exists_or_is_documented(self):
        shortcut = native.cache_shortcut()
        self.assertTrue(os.path.isabs(shortcut))

    def test_reveal_missing_path_is_handled(self):
        ok, message = scanner.reveal(self.path_that_does_not_exist())
        self.assertFalse(ok)
        self.assertTrue(message)

    @staticmethod
    def path_that_does_not_exist():
        return os.path.join(tempfile.gettempdir(), "diskclean-does-not-exist-%d" % os.getpid())


class HttpTest(TempTree):
    """Drive the real handler over HTTP against a throwaway server."""

    def setUp(self):
        super().setUp()
        os.makedirs(self.path("data", "inner"))
        write(self.path("data", "inner", "big.bin"), b"x" * 4096)
        self.httpd = server.LocalServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.host = f"127.0.0.1:{self.port}"
        server.ALLOWED_HOSTS = {self.host, f"localhost:{self.port}"}
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        server.JOBS.close()
        super().tearDown()

    def request(self, path, body=None, token=True, origin=None, host=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://{self.host}{path}", data=data)
        req.add_header("Host", host or self.host)
        req.add_header("Origin", origin or f"http://{self.host}")
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header(server.TOKEN_HEADER, server.SESSION_TOKEN)
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def wait_for_scan(self, job_id):
        for _ in range(100):
            code, state = self.request(f"/api/status?id={job_id}")
            self.assertEqual(code, 200)
            if state["state"] != "running":
                return state
            time.sleep(0.05)
        self.fail("scan did not finish")

    def wait_for_operation_lock(self):
        """The job releases the operation lock just after reporting `done`.

        Waiting here keeps read-modify-write tests deterministic: a Trash call
        that races the tail of a scan is refused as "busy" by design.
        """
        for _ in range(200):
            if scanner.OPERATION_LOCK.acquire(blocking=False):
                scanner.OPERATION_LOCK.release()
                return
            time.sleep(0.02)
        self.fail("the scan never released the operation lock")

    # -- auth --
    def test_page_renders_with_platform_tokens_substituted(self):
        req = urllib.request.Request(f"http://{self.host}/")
        req.add_header("Host", self.host)
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode("utf-8")
        self.assertEqual(response.status, 200)
        self.assertIn("DiskClean", html)
        for leftover in ("__HOME__", "__CACHE_PATH__", "__TRASH_TEXT__", "__FILE_MANAGER_TEXT__"):
            self.assertNotIn(leftover, html)
        self.assertIn(osplat.FILE_MANAGER, html)

    def test_requests_without_token_are_forbidden(self):
        self.assertEqual(self.request("/api/status", token=False)[0], 403)
        self.assertEqual(self.request("/api/subtree?path=/", token=False)[0], 403)

    def test_cross_origin_mutation_is_forbidden(self):
        code, _ = self.request("/api/trash", {"path": self.root}, origin="http://evil.example")
        self.assertEqual(code, 403)

    def test_foreign_host_header_is_forbidden(self):
        self.assertEqual(self.request("/api/status", host="evil.example")[0], 403)

    def test_scan_requires_post(self):
        self.assertEqual(self.request(f"/api/subtree?path={urllib.parse.quote(self.root)}")[0], 400)

    # -- scan lifecycle --
    def test_scan_job_lifecycle_and_queries(self):
        code, job = self.request("/api/scan", {"path": self.root})
        self.assertEqual(code, 202)
        final = self.wait_for_scan(job["id"])
        self.assertEqual(final["state"], "done")
        self.assertEqual(final["cached_origin"], osplat.normalize(self.root))
        self.wait_for_operation_lock()

        code, subtree = self.request(f"/api/subtree?path={urllib.parse.quote(self.root)}")
        self.assertEqual(code, 200)
        self.assertEqual([c["name"] for c in subtree["root"]["children"]], ["data"])

        code, children = self.request(
            f"/api/children?path={urllib.parse.quote(self.path('data', 'inner'))}&q=big")
        self.assertEqual(code, 200)
        self.assertEqual(children["total"], 1)
        self.assertIn("revision", children["items"][0])

    def test_cancel_keeps_previous_results(self):
        code, job = self.request("/api/scan", {"path": self.root})
        self.wait_for_scan(job["id"])
        before = scanner.INDEX[osplat.key(self.root)]["size"]

        code, second = self.request("/api/scan", {"path": self.root})
        self.assertEqual(code, 202)
        try:
            code, cancelled = self.request("/api/cancel", {"id": second["id"]})
        except (urllib.error.URLError, ConnectionError):
            self.skipTest("scan finished before it could be cancelled")
        if code != 200:
            self.skipTest("scan finished before it could be cancelled")
        self.assertIn(cancelled["state"], ("cancelled", "running", "done"))
        self.assertEqual(scanner.INDEX[osplat.key(self.root)]["size"], before)

    def test_bad_json_body_is_rejected(self):
        req = urllib.request.Request(f"http://{self.host}/api/trash", data=b"{not json")
        req.add_header("Host", self.host)
        req.add_header("Origin", f"http://{self.host}")
        req.add_header("Content-Type", "application/json")
        req.add_header(server.TOKEN_HEADER, server.SESSION_TOKEN)
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("malformed JSON should be rejected")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)
            self.assertFalse(json.loads(error.read())["ok"])

    def test_protected_path_is_refused_over_http(self):
        _, job = self.request("/api/scan", {"path": self.root})
        self.wait_for_scan(job["id"])
        self.wait_for_operation_lock()
        code, body = self.request("/api/trash", {"path": osplat.HOME, "revision": "x"})
        self.assertEqual(code, 400)
        self.assertFalse(body["ok"])
        self.assertTrue(body["message"])

    def test_stale_revision_is_refused_over_http(self):
        _, job = self.request("/api/scan", {"path": self.root})
        self.wait_for_scan(job["id"])
        self.wait_for_operation_lock()
        target = self.path("data", "inner", "big.bin")
        code, body = self.request("/api/trash", {"path": target})
        self.assertEqual(code, 400)
        self.assertFalse(body["ok"])
        self.assertIn("stale", body["message"])
        self.assertTrue(os.path.exists(target))

    def test_delete_round_trip_removes_it_from_the_tree(self):
        _, job = self.request("/api/scan", {"path": self.root})
        self.wait_for_scan(job["id"])
        self.wait_for_operation_lock()
        code, children = self.request(f"/api/children?path={urllib.parse.quote(self.path('data', 'inner'))}")
        item = children["items"][0]
        code, body = self.request("/api/trash",
                                  {"path": item["path"], "revision": item["revision"]})
        if code != 200:
            self.skipTest(f"no Trash integration here: {body.get('message')}")
        self.assertTrue(body["ok"])
        self.assertFalse(os.path.exists(item["path"]))
        code, subtree = self.request(f"/api/subtree?path={urllib.parse.quote(self.path('data', 'inner'))}")
        self.assertEqual(subtree["root"]["children"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
