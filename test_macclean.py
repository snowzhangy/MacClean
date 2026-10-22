#!/usr/bin/env python3
"""Tests for MacClean: scanner accuracy, deletion safety, path validation,
stale-index cleanup, permission handling, and the HTTP auth surface.

Run:  python3 -m unittest -v test_macclean
(No third-party deps; uses temp dirs and never touches your real files.)
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.request
from unittest import mock
import time
import stat
import subprocess
import http.client

import macclean


def write(path, data=b""):
    with open(path, "wb") as f:
        f.write(data)


class ScannerAccuracyTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        macclean.INDEX.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_totals_match_manual_allocation(self):
        # Build a tree with known content.
        write(os.path.join(self.root, "a.bin"), b"x" * 5000)
        os.mkdir(os.path.join(self.root, "sub"))
        write(os.path.join(self.root, "sub", "b.bin"), b"y" * 9000)
        write(os.path.join(self.root, "sub", "c.bin"), b"z" * 10)

        node = macclean.scan(self.root)

        # Independently sum allocated bytes (st_blocks*512) for every file.
        expected = 0
        for dirpath, _dirs, files in os.walk(self.root):
            for fn in files:
                st = os.lstat(os.path.join(dirpath, fn))
                expected += macclean._alloc(st)

        self.assertEqual(node["size"], expected)
        self.assertGreater(node["size"], 0)

    def test_mtime_is_reported_for_age_heatmap(self):
        # Files carry their own mtime; a directory reports its newest descendant.
        old = os.path.join(self.root, "old.bin")
        new = os.path.join(self.root, "sub", "new.bin")
        os.mkdir(os.path.join(self.root, "sub"))
        write(old, b"x")
        write(new, b"y")
        os.utime(old, (1_000_000_000, 1_000_000_000))   # 2001
        os.utime(new, (1_900_000_000, 1_900_000_000))   # 2030

        out = macclean.prune(macclean.scan(self.root))
        kids = {c["name"]: c for c in out["children"]}
        self.assertEqual(kids["old.bin"]["mtime"], 1_000_000_000)
        # The folder's mtime is the newest file inside it.
        self.assertEqual(kids["sub"]["mtime"], 1_900_000_000)
        # Root reflects the newest of everything.
        self.assertEqual(out["mtime"], 1_900_000_000)

    def test_uses_allocated_not_apparent_for_sparse(self):
        # A sparse file has large apparent size but tiny allocation.
        p = os.path.join(self.root, "sparse.bin")
        with open(p, "wb") as f:
            f.seek(50 * 1024 * 1024)  # 50 MB hole
            f.write(b"x")
        node = macclean.scan(self.root)
        apparent = os.lstat(p).st_size
        self.assertLess(node["size"], apparent,
                        "allocated size should be far below apparent size for a sparse file")


class PermissionHandlingTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        macclean.INDEX.clear()

    def tearDown(self):
        # Restore perms so cleanup can remove everything.
        try:
            os.chmod(self.root, 0o755)
        except OSError:
            pass
        for dp, dirs, _f in os.walk(self.root):
            for d in dirs:
                try:
                    os.chmod(os.path.join(dp, d), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def test_unreadable_dir_is_counted_as_skipped(self):
        locked = os.path.join(self.root, "locked")
        os.mkdir(locked)
        write(os.path.join(locked, "secret.bin"), b"x" * 1000)
        write(os.path.join(self.root, "open.bin"), b"y" * 1000)
        os.chmod(locked, 0o000)

        if os.access(locked, os.R_OK):
            self.skipTest("running as a user that bypasses permissions (e.g. root)")

        node = macclean.scan(self.root)
        self.assertGreaterEqual(node["skipped"], 1)
        self.assertTrue(any("locked" in p for p in node["skipped_sample"]))
        # Scan still succeeds and reports the readable file.
        self.assertTrue(any(c["name"] == "open.bin" for c in node["children"]))

    def test_unreadable_root_is_an_explicit_error(self):
        os.chmod(self.root, 0o000)
        if os.access(self.root, os.R_OK):
            self.skipTest("running as a user that bypasses permissions (e.g. root)")

        with self.assertRaises(PermissionError):
            macclean.scan(self.root)


class TrashValidationTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        macclean.INDEX.clear()
        with macclean.SCAN_ROOTS_LOCK:
            macclean.SCAN_ROOTS.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        with macclean.SCAN_ROOTS_LOCK:
            macclean.SCAN_ROOTS.clear()

    def test_rejects_path_outside_any_scanned_root(self):
        macclean.scan(self.root, register_root=True)
        other = tempfile.mkdtemp()
        try:
            target = os.path.join(other, "f.bin")
            write(target, b"x")
            rp, reason = macclean.validate_trash_target(target)
            self.assertIsNone(rp)
            self.assertIn("outside", reason)
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_rejects_the_scan_root_itself(self):
        macclean.scan(self.root, register_root=True)
        rp, reason = macclean.validate_trash_target(self.root)
        self.assertIsNone(rp)

    def test_rejects_home_and_system_dirs(self):
        for prot in (os.path.expanduser("~"), "/", "/System", "/Applications"):
            reason = macclean.protected_reason(os.path.realpath(prot))
            self.assertIsNotNone(reason, f"{prot} should be protected")

    def test_allows_real_item_inside_scanned_root(self):
        macclean.scan(self.root, register_root=True)
        target = os.path.join(self.root, "trashme.bin")
        write(target, b"x" * 10)
        rp, reason = macclean.validate_trash_target(target)
        self.assertIsNone(reason)
        self.assertEqual(rp, os.path.realpath(target))

    def test_symlink_target_is_not_followed(self):
        # Selecting a symlink that lives inside the scanned root is allowed,
        # and it validates to the LINK itself — never the file it points at.
        macclean.scan(self.root, register_root=True)
        outside = tempfile.mkdtemp()
        try:
            secret = os.path.join(outside, "secret.bin")
            write(secret, b"x")
            link = os.path.join(self.root, "link")
            os.symlink(secret, link)
            target, reason = macclean.validate_trash_target(link)
            self.assertIsNone(reason, "trashing the link itself should be allowed")
            self.assertEqual(target, os.path.join(os.path.realpath(self.root), "link"))
            self.assertNotEqual(target, os.path.realpath(secret),
                                "must not resolve to the symlink's target")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_prefix_symlink_cannot_escape_allowlist(self):
        # A symlinked *directory* in the path prefix must not let a selection
        # escape the scanned root.
        macclean.scan(self.root, register_root=True)
        outside = tempfile.mkdtemp()
        try:
            write(os.path.join(outside, "passwd"), b"secret")
            os.symlink(outside, os.path.join(self.root, "escape"))
            sneaky = os.path.join(self.root, "escape", "passwd")
            target, reason = macclean.validate_trash_target(sneaky)
            self.assertIsNone(target)
            self.assertIn("outside", reason)
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class StaleIndexTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        macclean.INDEX.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_removing_dir_purges_descendants(self):
        a = os.path.join(self.root, "a")
        b = os.path.join(a, "b")
        os.makedirs(b)
        write(os.path.join(b, "f.bin"), b"x" * 100)
        macclean.scan(self.root)
        self.assertIn(a, macclean.INDEX)
        self.assertIn(b, macclean.INDEX)

        macclean.remove_from_index(a)
        self.assertNotIn(a, macclean.INDEX)
        self.assertNotIn(b, macclean.INDEX,
                         "descendant nodes must not linger in INDEX after delete")

    def test_remove_corrects_ancestor_size(self):
        a = os.path.join(self.root, "a")
        os.mkdir(a)
        write(os.path.join(a, "f.bin"), b"x" * 4096)
        root = macclean.scan(self.root)
        before = root["size"]
        a_size = macclean.INDEX[a]["size"]
        macclean.remove_from_index(a)
        self.assertEqual(macclean.INDEX[self.root]["size"], before - a_size)


class JsInjectionTest(unittest.TestCase):
    def test_script_breakout_is_neutralized(self):
        saved = macclean.START_PATH
        try:
            macclean.START_PATH = "</script><b>x</b>"
            page = macclean.render_page()
            self.assertNotIn("</script><b>", page)
            self.assertIn("\\u003c", macclean._js_literal("<"))
        finally:
            macclean.START_PATH = saved

    def test_spaces_and_unicode_preserved(self):
        lit = macclean._js_literal("/Users/me/Mön Dossier/a b")
        decoded = json.loads(lit.replace("\\u003c", "<")
                                .replace("\\u003e", ">").replace("\\u0026", "&"))
        self.assertEqual(decoded, "/Users/me/Mön Dossier/a b")


class HttpAuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = macclean.LocalServer(("127.0.0.1", 0), macclean.Handler)
        cls.port = cls.srv.server_address[1]
        macclean.ALLOWED_HOSTS = {f"127.0.0.1:{cls.port}", f"localhost:{cls.port}"}
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.t.join(timeout=5)

    def _post(self, path, body, headers):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def _get(self, path, headers):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def _get_text(self, path, headers):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", headers=headers)
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode(), r.headers

    def _post_raw(self, path, data, headers):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read()), r.headers
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read()), e.headers

    def test_root_page_has_no_store_and_frame_protection(self):
        code, body, headers = self._get_text(
            "/", {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy"))
        self.assertIn('nonce="', body)

    def test_scan_get_without_token_is_forbidden(self):
        code, body = self._get("/api/scan?path=/tmp",
                               {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(code, 403)

    def test_token_bearing_get_cannot_start_a_scan(self):
        code, body = self._get("/api/scan?path=/tmp", self.auth())
        self.assertEqual(code, 405)

    def auth(self):
        return {"Host": f"127.0.0.1:{self.port}",
                "X-MacClean-Token": macclean.SESSION_TOKEN,
                "Origin": f"http://127.0.0.1:{self.port}"}

    def test_trash_without_token_is_forbidden(self):
        code, body = self._post("/api/trash", {"path": "/tmp/whatever"},
                                {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(code, 403)
        self.assertFalse(body["ok"])

    def test_oversized_post_body_is_rejected(self):
        code, body, _headers = self._post_raw(
            "/api/trash", b"x" * (macclean.MAX_JSON_BODY + 1),
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacClean-Token": macclean.SESSION_TOKEN,
             "Origin": f"http://127.0.0.1:{self.port}",
             "Content-Type": "application/json"})
        self.assertEqual(code, 413)
        self.assertFalse(body["ok"])

    def test_trash_with_cross_origin_is_forbidden(self):
        code, body = self._post(
            "/api/trash", {"path": "/tmp/whatever"},
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacClean-Token": macclean.SESSION_TOKEN,
             "Origin": "http://evil.example"})
        self.assertEqual(code, 403)

    def test_trash_with_token_but_bad_path_is_refused_not_crash(self):
        code, body = self._post(
            "/api/trash", {"path": "/etc/hosts"},
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacClean-Token": macclean.SESSION_TOKEN,
             "Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(code, 400)
        self.assertFalse(body["ok"])
        self.assertIn("Refusing", body["message"])



class ProductionRegressionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.temp.name)
        macclean.INDEX.clear()
        macclean.SCAN_ROOTS.clear()

    def tearDown(self):
        self.temp.cleanup()
        macclean.INDEX.clear()
        macclean.SCAN_ROOTS.clear()

    def file(self, name, data=b"content"):
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write(path, data)
        return path

    def test_symlinks_are_leaves_and_never_traversed(self):
        self.file("folder/data")
        os.symlink(self.root, self.root + "/cycle")
        os.symlink("missing", self.root + "/dangling")
        node = macclean.scan(self.root)
        kids = {c["name"]: c for c in node["children"]}
        self.assertFalse(kids["cycle"]["dir"])
        self.assertFalse(kids["dangling"]["dir"])
        self.assertNotIn(self.root + "/cycle", macclean.INDEX)

    def test_deep_tree_uses_no_python_recursion(self):
        parts = ["d"] * 180
        leaf = self.file("/".join(parts) + "/data")
        node = macclean.scan(self.root)
        self.assertEqual(node["size"], macclean._alloc(os.lstat(leaf)))
        self.assertEqual(node["skipped"], 0)
        self.assertEqual(len(macclean.INDEX), 181)

    def test_cancel_preserves_committed_tree_and_allowlist(self):
        self.file("old")
        old = macclean.scan(self.root, register_root=True)
        snapshot = dict(macclean.INDEX)
        progress = macclean.ScanProgress()
        progress.cancel.set()
        with self.assertRaises(macclean.ScanCancelled):
            macclean.scan(self.root, register_root=True, progress=progress)
        self.assertEqual(macclean.INDEX, snapshot)
        self.assertIs(macclean.INDEX[self.root], old)
        self.assertEqual(macclean.SCAN_ROOTS, {self.root})

    def test_entry_limit_is_error_and_preserves_previous_results(self):
        self.file("old")
        old = macclean.scan(self.root)
        for i in range(20):
            self.file(f"folder/{i}")
        with self.assertRaises(macclean.ScanLimitError):
            macclean.scan(self.root, progress=macclean.ScanProgress(max_entries=3))
        self.assertIs(macclean.INDEX[self.root], old)
        self.assertFalse(macclean.OPERATION_LOCK.locked())

    def test_new_root_evicts_previous_tree_and_allowlist(self):
        self.file("a/data")
        self.file("b/data")
        macclean.scan(self.root + "/a", register_root=True)
        macclean.scan(self.root + "/b", register_root=True)
        self.assertEqual(macclean.SCAN_ROOTS, {self.root + "/b"})
        self.assertNotIn(self.root + "/a", macclean.INDEX)

    def test_memory_failure_preserves_old_results_and_releases_failed_tree(self):
        import gc
        import weakref
        class PrivateTree:
            pass
        observed = []
        def failed_tree(path, progress):
            payload = PrivateTree()
            observed.append(weakref.ref(payload))
            progress._check_memory()
            raise AssertionError("Memory guard did not stop the scan")
        self.file("old")
        old = macclean.scan(self.root)
        progress = macclean.ScanProgress(max_memory_mb=64)
        with mock.patch.object(macclean, "_scan_tree", side_effect=failed_tree), mock.patch.object(macclean, "_resident_bytes", return_value=65 * 1024 * 1024):
            with self.assertRaises(macclean.ScanLimitError):
                macclean.scan(self.root, progress=progress)
        gc.collect()
        self.assertIs(macclean.INDEX[self.root], old)
        self.assertIsNone(observed[0](), "scan failure retained its private tree through a traceback")

    def test_excluded_folder_is_never_opened_and_omission_is_disclosed(self):
        self.file("nested/cloud/secret")
        self.file("nested/visible")
        excluded = self.root + "/nested/cloud"
        real_open = os.open
        def guarded_open(path, *args, **kwargs):
            self.assertNotIn(path, ("cloud", excluded), "excluded directory was opened")
            return real_open(path, *args, **kwargs)
        with mock.patch.object(macclean, "EXCLUDE_PATHS", (excluded,)), mock.patch.object(macclean.os, "open", side_effect=guarded_open):
            result = macclean.scan(self.root)
        self.assertEqual(result["skipped"], 1)
        self.assertIn("Excluded by --exclude: " + excluded, result["skipped_sample"])
        self.assertNotIn(excluded, macclean.INDEX)

    def test_excluded_top_level_folder_and_root_are_refused(self):
        self.file("cloud/secret")
        excluded = self.root + "/cloud"
        with mock.patch.object(macclean, "EXCLUDE_PATHS", (excluded,)):
            result = macclean.scan(self.root)
            self.assertEqual(result["size"], 0)
            self.assertEqual(result["skipped"], 1)
            with self.assertRaisesRegex(ValueError, "excluded"):
                macclean.scan(excluded)

    def test_reveal_invokes_finder_selection_without_launching_contents(self):
        path = self.file("program.sh")
        with mock.patch.object(macclean.sys, "platform", "darwin"), mock.patch.object(macclean.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            ok, message = macclean.reveal_in_finder(path)
        self.assertTrue(ok, message)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/open", "-R", path])

    def test_reveal_timeout_is_reported(self):
        path = self.file("file")
        with mock.patch.object(macclean.sys, "platform", "darwin"), mock.patch.object(macclean.subprocess, "run", side_effect=subprocess.TimeoutExpired("open", 15)):
            ok, message = macclean.reveal_in_finder(path)
        self.assertFalse(ok)
        self.assertIn("timed out", message)

    def test_refresh_relinks_and_recomputes_ancestor_mtime(self):
        path = self.file("folder/data")
        os.utime(path, (100, 100))
        macclean.scan(self.root)
        macclean.list_children(self.root)  # prime sorted cache
        os.utime(path, (200, 200))
        self.file("folder/new", b"z" * 50000)
        fresh = macclean.rescan(self.root + "/folder")
        root = macclean.INDEX[self.root]
        self.assertIs(root["children"][0], fresh)
        self.assertEqual(root["size"], fresh["size"])
        self.assertEqual(root["mtime"], fresh["mtime"])
        self.assertEqual(macclean.list_children(self.root)["items"][0]["size"], fresh["size"])

    def test_refresh_traverses_all_descendants_and_preserves_sibling_cache(self):
        removed = self.file("folder/nested/deep/old")
        self.file("sibling/existing")
        macclean.scan(self.root, register_root=True)
        sibling = macclean.INDEX[self.root + "/sibling"]
        os.unlink(removed)
        added = self.file("folder/nested/deep/new", b"x" * 50000)
        unscanned = self.file("sibling/new")

        folder = self.root + "/folder"
        real_scandir = os.scandir
        forbidden = {os.stat(self.root).st_ino, os.stat(self.root + "/sibling").st_ino}
        def scoped_scandir(fd):
            self.assertNotIn(os.fstat(fd).st_ino, forbidden,
                             "refresh must not read the parent or sibling directories")
            return real_scandir(fd)
        with mock.patch.object(macclean.os, "scandir", side_effect=scoped_scandir):
            fresh = macclean.rescan(folder)

        descendants = [child["path"] for child in macclean.INDEX[folder + "/nested/deep"]["children"]]
        self.assertIn(added, descendants)
        self.assertNotIn(removed, descendants)
        self.assertNotIn(unscanned, [child["path"] for child in sibling["children"]])
        self.assertIs(macclean.INDEX[self.root + "/sibling"], sibling)
        self.assertEqual(fresh["size"], macclean._alloc(os.stat(added)))
        self.assertEqual(macclean.INDEX[self.root]["size"], fresh["size"] + sibling["size"])
        self.assertEqual(macclean.SCAN_ROOTS, {self.root})

    def test_removal_recomputes_mtime(self):
        old = self.file("old")
        new = self.file("new")
        os.utime(old, (100, 100))
        os.utime(new, (200, 200))
        macclean.scan(self.root)
        macclean.remove_from_index(new)
        self.assertEqual(macclean.INDEX[self.root]["mtime"], 100)
        self.assertEqual([i["name"] for i in macclean.list_children(self.root)["items"]], ["old"])

    def test_page_and_search_include_items_hidden_by_chart(self):
        for i in range(125):
            self.file(f"empty-{i:03}", b"")
        macclean.scan(self.root)
        data = macclean.list_children(self.root, offset=100)
        self.assertEqual(data["total"], 125)
        self.assertEqual(len(data["items"]), 25)
        self.assertEqual(macclean.list_children(self.root, query="EMPTY-124")["items"][0]["name"], "empty-124")
        chart = macclean.get_subtree(self.root)
        self.assertTrue(any(c.get("other") and c["size"] == 0 for c in chart["children"]))

    def test_transport_has_global_node_budget_and_exact_totals(self):
        # A balanced tree defeats depth-only and per-folder-only caps.
        def tree(path, depth):
            node = {"name": path, "path": path, "size": 1, "mtime": 0, "dir": depth > 0}
            if depth:
                node["children"] = [tree(path + "/" + str(i), depth - 1) for i in range(8)]
                node["size"] = sum(c["size"] for c in node["children"])
            return node
        result = macclean.prune(tree("/test", 4))
        def count(node):
            kids = node.get("children", [])
            if kids:
                self.assertEqual(sum(c["size"] for c in kids), node["size"])
            return 1 + sum(count(c) for c in kids)
        self.assertLessEqual(count(result), macclean.MAX_SEND_NODES)

    def test_concurrent_scan_rejected_without_corrupting_state(self):
        with macclean.OPERATION_LOCK:
            with self.assertRaises(macclean.BusyError):
                macclean.scan(self.root)
            self.assertFalse(macclean.INDEX)

    def test_unindexed_subtree_does_not_trigger_disk_scan(self):
        with mock.patch.object(macclean, "scan") as scan:
            with self.assertRaises(ValueError):
                macclean.get_subtree(self.root)
            scan.assert_not_called()

    def test_scan_root_symlink_is_canonicalized(self):
        self.file("folder/data")
        os.symlink(self.root + "/folder", self.root + "/alias")
        result = macclean.scan(self.root + "/alias", register_root=True)
        self.assertEqual(result["path"], self.root + "/folder")
        self.assertEqual(macclean.SCAN_ROOTS, {self.root + "/folder"})

    def test_directory_swapped_for_symlink_is_not_followed(self):
        self.file("folder/data")
        real_open = os.open
        changed = False
        def racing_open(path, flags, *args, **kwargs):
            nonlocal changed
            if path == "folder" and kwargs.get("dir_fd") is not None and not changed:
                changed = True
                os.rename(self.root + "/folder", self.root + "/moved")
                os.symlink("/", self.root + "/folder")
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(macclean.os, "open", side_effect=racing_open):
            result = macclean.scan(self.root)
        self.assertTrue(changed)
        self.assertGreaterEqual(result["skipped"], 1)
        self.assertNotIn(self.root + "/folder", macclean.INDEX)

    def test_prefix_open_refuses_symlink_even_without_macos_flag(self):
        os.mkdir(self.root + "/folder")
        os.symlink("folder", self.root + "/link")
        with mock.patch.object(macclean.os, "O_NOFOLLOW_ANY", create=True):
            # Exercise portable component-wise path opening by removing the flag.
            flag = macclean.os.O_NOFOLLOW_ANY
            del macclean.os.O_NOFOLLOW_ANY
            try:
                with self.assertRaises(OSError):
                    macclean._open_directory(self.root + "/link")
            finally:
                macclean.os.O_NOFOLLOW_ANY = flag

    def test_read_only_never_calls_native_trash(self):
        path = self.file("data")
        macclean.scan(self.root, register_root=True)
        with mock.patch.object(macclean, "READ_ONLY", True), mock.patch.object(macclean.subprocess, "run") as run:
            ok, message = macclean.move_to_trash(path)
        self.assertFalse(ok)
        self.assertIn("read-only", message)
        run.assert_not_called()

    def test_trash_requires_current_revision_and_identity(self):
        path = self.file("data")
        macclean.scan(self.root, register_root=True)
        revision = macclean.list_children(self.root)["items"][0]["revision"]
        write(path, b"changed")
        with mock.patch.object(macclean.sys, "platform", "darwin"), mock.patch.object(macclean.subprocess, "run") as run:
            self.assertFalse(macclean.move_to_trash(path)[0])
            ok, message = macclean.move_to_trash(path, revision)
        self.assertFalse(ok)
        self.assertIn("changed", message)
        run.assert_not_called()

    def test_native_success_updates_index_without_permanent_deletion(self):
        path = self.file("data")
        macclean.scan(self.root, register_root=True)
        revision = macclean.list_children(self.root)["items"][0]["revision"]
        def native(args, **kwargs):
            self.assertEqual(args[0], "/usr/bin/osascript")
            self.assertEqual(args[-1], path)
            os.rename(path, self.root + "/simulated-trash")
            return subprocess.CompletedProcess(args, 0, "ok", "")
        with mock.patch.object(macclean.sys, "platform", "darwin"), mock.patch.object(macclean.subprocess, "run", side_effect=native):
            ok, message = macclean.move_to_trash(path, revision)
        self.assertTrue(ok, message)
        self.assertEqual(macclean.INDEX[self.root]["size"], 0)
        self.assertTrue(os.path.exists(self.root + "/simulated-trash"))

    def test_trash_timeout_reports_unknown_outcome(self):
        path = self.file("data")
        macclean.scan(self.root, register_root=True)
        revision = macclean.list_children(self.root)["items"][0]["revision"]
        with mock.patch.object(macclean.sys, "platform", "darwin"), mock.patch.object(macclean.subprocess, "run", side_effect=subprocess.TimeoutExpired("osascript", 30)):
            ok, message = macclean.move_to_trash(path, revision)
        self.assertFalse(ok)
        self.assertIn("outcome is unknown", message)
        self.assertGreater(macclean.INDEX[self.root]["size"], 0)

    def test_multiple_scan_roots_are_all_protected(self):
        os.mkdir(self.root + "/nested")
        macclean.SCAN_ROOTS.update({self.root, self.root + "/nested"})
        self.assertIsNone(macclean.validate_trash_target(self.root + "/nested")[0])

    def test_template_tokens_in_path_are_not_replaced(self):
        with mock.patch.object(macclean, "START_PATH", "__TOKEN__/__READ_ONLY__"):
            page = macclean.render_page()
        self.assertIn('const START="__TOKEN__/__READ_ONLY__";', page)


class HardenedHttpTest(HttpAuthTest):
    # Inherit the original auth checks as well as exercising real HTTP below.
    def test_root_rejects_dns_rebinding_host(self):
        code, body = self._get("/", {"Host": "attacker.example"})
        self.assertEqual(code, 403)
        self.assertNotIn(macclean.SESSION_TOKEN, json.dumps(body))

    def test_current_status_can_reconnect_without_starting_a_scan(self):
        with mock.patch.object(macclean.JOBS, "start") as start:
            code, status = self._get("/api/status", self.auth())
        self.assertEqual(code, 200)
        self.assertIn(status["state"], ("idle", "running", "done", "error", "cancelled"))
        start.assert_not_called()

    def test_root_rejects_cross_site_fetch(self):
        code, body = self._get("/", {**self.auth(), "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(code, 403)

    def test_origin_requires_exact_scheme_and_host(self):
        for origin in (f"https://127.0.0.1:{self.port}", "null", f"http://localhost:{self.port}"):
            with self.subTest(origin=origin):
                code, _ = self._post("/api/trash", {"path": "/tmp/f"}, {**self.auth(), "Origin": origin})
                self.assertEqual(code, 403)

    def test_non_ascii_token_rejected_without_exception(self):
        code, _ = self._get("/api/status", {**self.auth(), "X-MacClean-Token": "é"})
        self.assertEqual(code, 403)

    def test_bad_json_shapes_and_paths_return_json_error(self):
        bodies = [None, [], 1, "text", {"path": 1}, {"path": []}, {"path": "bad\0path"}, {"path": "\ud800"}]
        for body in bodies:
            with self.subTest(body=repr(body)):
                code, data = self._post("/api/scan", body, self.auth())
                self.assertEqual(code, 400)
                self.assertFalse(data["ok"])

    def test_bad_utf8_and_content_type(self):
        for raw, content_type in ((b"\xff", "application/json"), (b"{}", "text/plain")):
            code, data, _ = self._post_raw("/api/scan", raw, {**self.auth(), "Content-Type": content_type})
            self.assertEqual(code, 400)
            self.assertFalse(data["ok"])

    def test_async_scan_status_children_and_refresh(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "hello"), b"content")
            code, job = self._post("/api/scan", {"path": root}, self.auth())
            self.assertEqual(code, 202)
            deadline = time.monotonic() + 5
            while job["state"] == "running" and time.monotonic() < deadline:
                _, job = self._get("/api/status?id=" + job["id"], self.auth())
                time.sleep(.01)
            self.assertEqual(job["state"], "done", job)
            code, data = self._get("/api/children?path=" + urllib.parse.quote(root), self.auth())
            self.assertEqual(code, 200)
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["items"][0]["name"], "hello")
            self.assertIn("revision", data["items"][0])

    def test_busy_scan_returns_conflict(self):
        with macclean.OPERATION_LOCK:
            code, data = self._post("/api/scan", {"path": tempfile.gettempdir()}, self.auth())
        self.assertEqual(code, 409)

    def test_job_cancellation_is_responsive_and_does_not_publish(self):
        started = threading.Event()
        release = threading.Event()
        previous = dict(macclean.INDEX)
        def slow_tree(path, progress):
            started.set()
            if not release.wait(5):
                raise RuntimeError("Test scan was not released")
            progress.check()
            raise AssertionError("Cancelled scan continued")
        with mock.patch.object(macclean, "_scan_tree", side_effect=slow_tree):
            try:
                code, job = self._post("/api/scan", {"path": tempfile.gettempdir()}, self.auth())
                self.assertTrue(started.wait(2))
                self.assertEqual(code, 202)
                code, cancel = self._post("/api/cancel", {"id": job["id"]}, self.auth())
                self.assertEqual(code, 200)
            finally:
                release.set()
                macclean.JOBS.thread.join(5)
        _, status = self._get("/api/status?id=" + job["id"], self.auth())
        self.assertEqual(status["state"], "cancelled")
        self.assertEqual(previous, macclean.INDEX)

    def test_unknown_job_and_invalid_page_return_errors(self):
        for route in ("/api/status?id=missing", "/api/preview?id=missing", "/api/children?path=/tmp&limit=999", "/api/children?path=/tmp&offset=-1"):
            code, data = self._get(route, self.auth())
            self.assertEqual(code, 400)
            self.assertFalse(data["ok"])

    def test_invalid_scan_limit_overrides_are_rejected(self):
        for key, value in (("max_entries", -1), ("max_entries", True), ("max_entries", None),
                           ("max_entries", "1000"), ("max_memory_mb", 1), ("max_memory_mb", False)):
            with self.subTest(key=key, value=value):
                code, data = self._post("/api/scan", {"path": tempfile.gettempdir(), key: value}, self.auth())
                self.assertEqual(code, 400)

    def test_limit_error_offers_retry_with_a_higher_per_job_budget(self):
        with tempfile.TemporaryDirectory() as root:
            for i in range(3):
                write(os.path.join(root, str(i)), b"x")
            code, job = self._post("/api/scan", {"path": root, "max_entries": 2}, self.auth())
            self.assertEqual(code, 202)
            macclean.JOBS.thread.join(5)
            _, failed = self._get("/api/status?id=" + job["id"], self.auth())
            self.assertEqual(failed["limit_kind"], "entry_limit")
            self.assertEqual(failed["retry"]["max_entries"], 4)
            code, retry = self._post("/api/scan", {"path": root, **failed["retry"]}, self.auth())
            self.assertEqual(code, 202)
            macclean.JOBS.thread.join(5)
            _, done = self._get("/api/status?id=" + retry["id"], self.auth())
            self.assertEqual(done["state"], "done")
            self.assertEqual(done["max_entries"], 4)

    def test_running_preview_does_not_commit_or_allow_actions(self):
        started, release = threading.Event(), threading.Event()
        previous = dict(macclean.INDEX)
        def slow_tree(path, progress):
            progress.path = path
            progress.add_file({"name": "partial", "path": path + "/partial", "size": 4096, "dir": False, "mtime": 0})
            started.set()
            release.wait(5)
            progress.check()
            raise AssertionError("Test should cancel before committing")
        with mock.patch.object(macclean, "_scan_tree", side_effect=slow_tree):
            try:
                _, job = self._post("/api/scan", {"path": tempfile.gettempdir()}, self.auth())
                self.assertTrue(started.wait(2))
                code, preview = self._get("/api/preview?id=" + job["id"], self.auth())
                self.assertEqual(code, 200)
                self.assertTrue(preview["root"]["preview"])
                self.assertFalse(preview["root"]["children"][0]["trashable"])
                self.assertEqual(previous, macclean.INDEX)
                code, _ = self._get("/api/preview?id=" + job["id"], {})
                self.assertEqual(code, 403)
                self._post("/api/cancel", {"id": job["id"]}, self.auth())
            finally:
                release.set()
                macclean.JOBS.thread.join(5)
        self.assertEqual(previous, macclean.INDEX)


class LivePreviewTest(unittest.TestCase):
    def item(self, name, size, is_dir=False):
        return {"name": name, "path": "/preview/" + name, "size": size, "dir": is_dir, "mtime": 100}

    def test_preview_is_bounded_and_totals_include_omitted_items(self):
        progress = macclean.ScanProgress()
        progress.path = "/preview"
        for i in range(10000):
            progress.add_file(self.item(str(i), i))
        result = progress.preview()
        self.assertLessEqual(len(progress.largest), macclean.MAX_CHILDREN)
        self.assertLessEqual(len(result["children"]), macclean.MAX_CHILDREN + 1)
        self.assertEqual(result["size"], sum(range(10000)))
        self.assertEqual(sum(c["size"] for c in result["children"]), result["size"])
        self.assertTrue(result["preview"])
        self.assertTrue(all(not c["trashable"] for c in result["children"]))

    def test_preview_cache_updates_only_after_ten_seconds(self):
        clock = [0]
        with mock.patch.object(macclean.time, "monotonic", side_effect=lambda: clock[0]):
            progress = macclean.ScanProgress()
            progress.path = "/preview"
            progress.add_file(self.item("first", 100))
            first = progress.preview()
            progress.add_file(self.item("second", 200))
            clock[0] = 9.99
            self.assertIs(progress.preview(), first)
            self.assertEqual(first["size"], 100, "previous snapshot must be immutable")
            clock[0] = 10
            second = progress.preview()
            self.assertIsNot(second, first)
            self.assertEqual(second["size"], 300)

    def test_preview_never_traverses_the_filesystem_or_index(self):
        progress = macclean.ScanProgress()
        progress.path = "/preview"
        progress.add_file(self.item("file", 100))
        with mock.patch.object(macclean.os, "scandir") as scandir, mock.patch.object(macclean.os, "stat") as stat_call, mock.patch.object(macclean, "prune") as prune:
            progress.preview()
        scandir.assert_not_called()
        stat_call.assert_not_called()
        prune.assert_not_called()

    def test_running_branch_grows_without_double_counting_when_complete(self):
        progress = macclean.ScanProgress()
        progress.path = "/preview"
        folder = self.item("folder", 123, True)
        progress.begin_branch(folder["path"])
        progress.add_allocated(123, folder["path"])
        first = progress.preview()
        self.assertEqual(first["children"][0]["size"], 123)
        self.assertTrue(first["children"][0]["scanning"])
        progress.finish_branch(folder["path"], folder)
        progress._preview_time = float("-inf")
        second = progress.preview()
        self.assertEqual(second["size"], 123)
        self.assertFalse(second["children"][0]["scanning"])
        self.assertTrue(first["children"][0]["scanning"])

    def test_default_scan_can_pass_the_old_500000_entry_limit(self):
        with mock.patch.object(macclean, "MAX_ENTRIES", 0):
            progress = macclean.ScanProgress()
        progress.entries = 500000
        progress.record()
        self.assertEqual(progress.entries, 500001)
        self.assertFalse(progress.cancel.is_set())

    def test_memory_limit_cancels_and_takes_precedence_over_cancellation(self):
        progress = macclean.ScanProgress(max_memory_mb=64)
        with mock.patch.object(macclean, "_resident_bytes", return_value=65 * 1024 * 1024):
            with self.assertRaises(macclean.ScanLimitError) as error:
                progress._check_memory()
        self.assertEqual(error.exception.kind, "memory_limit")
        self.assertTrue(progress.cancel.is_set())
        with self.assertRaises(macclean.ScanLimitError):
            progress.check()

    def test_memory_checks_are_throttled(self):
        clock = [0]
        with mock.patch.object(macclean.time, "monotonic", side_effect=lambda: clock[0]), mock.patch.object(macclean, "_resident_bytes", return_value=1024) as read:
            progress = macclean.ScanProgress()
            for _ in range(5):
                progress._check_memory()
            self.assertEqual(read.call_count, 1)
            clock[0] = .5
            progress._check_memory()
            self.assertEqual(read.call_count, 2)

    def test_memory_budget_scales_with_ram(self):
        with mock.patch.object(macclean.os, "sysconf", side_effect=lambda name: {"SC_PHYS_PAGES": 2**21, "SC_PAGE_SIZE": 4096}[name]):
            self.assertEqual(macclean._automatic_memory_mb(), 2048)
        with mock.patch.object(macclean.os, "sysconf", side_effect=ValueError):
            self.assertEqual(macclean._automatic_memory_mb(), 1024)

    def test_unavailable_resident_accounting_has_a_conservative_fallback(self):
        progress = macclean.ScanProgress(max_memory_mb=64)
        progress.entries = 100000
        with mock.patch.object(macclean, "_resident_bytes", return_value=None):
            with self.assertRaises(macclean.ScanLimitError):
                progress._check_memory()

    def test_real_resident_memory_probe_is_supported(self):
        self.assertGreater(macclean._resident_bytes(), 0)

    def test_waiting_status_tracks_idle_time_without_per_file_timestamps(self):
        clock = [0]
        with mock.patch.object(macclean.time, "monotonic", side_effect=lambda: clock[0]):
            progress = macclean.ScanProgress()
            progress.reading_directory("worker", "/preview/slow-cloud")
            progress.record()
            progress.snapshot()
            clock[0] = 10
            waiting = progress.snapshot()
            self.assertEqual(waiting["idle_seconds"], 10)
            self.assertEqual(waiting["waiting_paths"], ["/preview/slow-cloud"])
            self.assertEqual(waiting["elapsed"], 10)
            clock[0] = 11
            self.assertEqual(progress.snapshot()["elapsed"], 11)
            progress.record()
            self.assertEqual(progress.snapshot()["idle_seconds"], 0)

    def test_finished_elapsed_time_stays_fixed(self):
        clock = [0]
        with mock.patch.object(macclean.time, "monotonic", side_effect=lambda: clock[0]):
            progress = macclean.ScanProgress()
            clock[0] = 12
            progress.finish()
            clock[0] = 100
            status = progress.snapshot()
        self.assertEqual(status["elapsed"], 12)
        self.assertEqual(status["idle_seconds"], 0)
        self.assertEqual(status["waiting_paths"], [])

    def test_focused_preview_reads_only_the_selected_folder_in_memory(self):
        progress = macclean.ScanProgress()
        progress.path = "/preview"
        child = self.item("folder/child", 123)
        folder = {**self.item("folder", 123, True), "children": [child]}
        progress.attach_index(folder["path"], {folder["path"]: folder})
        with mock.patch.object(macclean.os, "scandir") as scandir, mock.patch.object(macclean.os.path, "realpath") as realpath:
            result = progress.preview(folder["path"])
        self.assertEqual(result["path"], folder["path"])
        self.assertEqual(result["size"], 123)
        self.assertEqual(result["children"][0]["path"], child["path"])
        self.assertFalse(result["children"][0]["trashable"])
        self.assertNotIn("preview", child, "preview must not modify private scan nodes")
        scandir.assert_not_called()
        realpath.assert_not_called()

    def test_focused_preview_is_cached_for_ten_seconds_and_bounded(self):
        clock = [0]
        with mock.patch.object(macclean.time, "monotonic", side_effect=lambda: clock[0]):
            progress = macclean.ScanProgress()
            progress.path = "/preview"
            folder = {**self.item("folder", 0, True), "children": [self.item(f"folder/{i}", i) for i in range(1000)]}
            progress.attach_index(folder["path"], {folder["path"]: folder})
            first = progress.preview(folder["path"])
            self.assertLessEqual(len(first["children"]), macclean.MAX_CHILDREN + 1)
            self.assertEqual(sum(c["size"] for c in first["children"]), first["size"])
            folder["children"].append(self.item("folder/new", 100000))
            clock[0] = 9
            self.assertIs(progress.preview(folder["path"]), first)
            clock[0] = 10
            second = progress.preview(folder["path"])
            self.assertEqual(second["size"], first["size"] + 100000)

    def test_focused_preview_allows_pending_branches_but_rejects_unseen_paths(self):
        progress = macclean.ScanProgress()
        progress.path = "/preview"
        progress.begin_branch("/preview/pending")
        result = progress.preview("/preview/pending")
        self.assertEqual(result["children"], [])
        self.assertTrue(result["scanning"])
        for path in ("/outside", "/preview/unknown", "/preview/../outside"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                progress.preview(path)

    def test_completed_subtrees_stay_browsable_after_worker_collection(self):
        progress = macclean.ScanProgress()
        progress.path = "/preview"
        child = self.item("folder/file", 123)
        folder = {**self.item("folder", 123, True), "children": [child], "_complete": True}
        progress.begin_branch(folder["path"])
        progress.attach_index(folder["path"], {folder["path"]: folder})
        progress._root_index = {folder["path"]: folder}
        progress.finish_branch(folder["path"], folder)
        result = progress.preview(folder["path"])
        self.assertEqual(result["size"], 123)
        self.assertFalse(result["scanning"])
        progress.release_indexes()
        self.assertIsNone(progress._root_index)
        self.assertEqual(progress._worker_indexes, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
