#!/usr/bin/env python3
"""Tests for MacWinClean: scanner accuracy, deletion safety, path validation,
stale-index cleanup, permission handling, and the HTTP auth surface.

Run:  python3 -m unittest -v test_macwinclean
(No third-party deps; uses temp dirs and never touches your real files.)
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

import macwinclean


def write(path, data=b""):
    with open(path, "wb") as f:
        f.write(data)


class ScannerAccuracyTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        macwinclean.INDEX.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_totals_match_manual_allocation(self):
        # Build a tree with known content.
        write(os.path.join(self.root, "a.bin"), b"x" * 5000)
        os.mkdir(os.path.join(self.root, "sub"))
        write(os.path.join(self.root, "sub", "b.bin"), b"y" * 9000)
        write(os.path.join(self.root, "sub", "c.bin"), b"z" * 10)

        node = macwinclean.scan(self.root)

        # Independently sum allocated bytes (st_blocks*512) for every file.
        expected = 0
        for dirpath, _dirs, files in os.walk(self.root):
            for fn in files:
                st = os.lstat(os.path.join(dirpath, fn))
                expected += macwinclean._alloc(st)

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

        out = macwinclean.prune(macwinclean.scan(self.root))
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
        node = macwinclean.scan(self.root)
        apparent = os.lstat(p).st_size
        self.assertLess(node["size"], apparent,
                        "allocated size should be far below apparent size for a sparse file")


class ScanProgressTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        macwinclean.INDEX.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_progress_counts_every_node_once(self):
        # 1 top file + 1 top dir + 3 files inside = 5 entries.
        write(os.path.join(self.root, "top.bin"), b"x" * 100)
        os.mkdir(os.path.join(self.root, "sub"))
        for i in range(3):
            write(os.path.join(self.root, "sub", f"f{i}.bin"), b"y" * 10)

        prog = macwinclean.ScanProgress()
        macwinclean.scan(self.root, progress=prog)
        snap = prog.snapshot()

        self.assertEqual(snap["items"], 5)
        self.assertEqual(snap["totalTop"], 2)   # top.bin + sub/
        self.assertEqual(snap["doneTop"], 2)
        self.assertGreater(snap["bytes"], 0)

    def test_snapshot_default_when_no_scan(self):
        snap = macwinclean.progress_snapshot()
        self.assertIn("items", snap)
        self.assertTrue(snap["finished"])


class PlatformTest(unittest.TestCase):
    def test_reveal_missing_path_is_handled(self):
        ok, msg = macwinclean.reveal_path("/nope/does/not/exist")
        self.assertFalse(ok)

    def test_protected_reason_covers_home(self):
        self.assertIsNotNone(macwinclean.protected_reason(os.path.realpath(os.path.expanduser("~"))))

    def test_platform_flags_consistent(self):
        # Exactly one of the platform branches should be active.
        self.assertEqual(macwinclean.IS_WIN, not macwinclean.IS_POSIX)
        self.assertIn(macwinclean.PLATFORM, ("mac", "win", "other"))


class PermissionHandlingTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        macwinclean.INDEX.clear()

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

        node = macwinclean.scan(self.root)
        self.assertGreaterEqual(node["skipped"], 1)
        self.assertTrue(any("locked" in p for p in node["skipped_sample"]))
        # Scan still succeeds and reports the readable file.
        self.assertTrue(any(c["name"] == "open.bin" for c in node["children"]))

    def test_unreadable_root_is_counted_as_skipped(self):
        os.chmod(self.root, 0o000)
        if os.access(self.root, os.R_OK):
            self.skipTest("running as a user that bypasses permissions (e.g. root)")

        node = macwinclean.scan(self.root)
        self.assertEqual(node["skipped"], 1)
        self.assertIn(self.root, node["skipped_sample"])


class TrashValidationTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        macwinclean.INDEX.clear()
        with macwinclean.SCAN_ROOTS_LOCK:
            macwinclean.SCAN_ROOTS.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        with macwinclean.SCAN_ROOTS_LOCK:
            macwinclean.SCAN_ROOTS.clear()

    def test_rejects_path_outside_any_scanned_root(self):
        macwinclean.scan(self.root, register_root=True)
        other = tempfile.mkdtemp()
        try:
            target = os.path.join(other, "f.bin")
            write(target, b"x")
            rp, reason = macwinclean.validate_trash_target(target)
            self.assertIsNone(rp)
            self.assertIn("outside", reason)
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_rejects_the_scan_root_itself(self):
        macwinclean.scan(self.root, register_root=True)
        rp, reason = macwinclean.validate_trash_target(self.root)
        self.assertIsNone(rp)

    def test_rejects_home_and_system_dirs(self):
        for prot in (os.path.expanduser("~"), "/", "/System", "/Applications"):
            reason = macwinclean.protected_reason(os.path.realpath(prot))
            self.assertIsNotNone(reason, f"{prot} should be protected")

    def test_allows_real_item_inside_scanned_root(self):
        macwinclean.scan(self.root, register_root=True)
        target = os.path.join(self.root, "trashme.bin")
        write(target, b"x" * 10)
        rp, reason = macwinclean.validate_trash_target(target)
        self.assertIsNone(reason)
        self.assertEqual(rp, os.path.realpath(target))

    def test_symlink_target_is_not_followed(self):
        # Selecting a symlink that lives inside the scanned root is allowed,
        # and it validates to the LINK itself — never the file it points at.
        macwinclean.scan(self.root, register_root=True)
        outside = tempfile.mkdtemp()
        try:
            secret = os.path.join(outside, "secret.bin")
            write(secret, b"x")
            link = os.path.join(self.root, "link")
            os.symlink(secret, link)
            target, reason = macwinclean.validate_trash_target(link)
            self.assertIsNone(reason, "trashing the link itself should be allowed")
            self.assertEqual(target, os.path.join(os.path.realpath(self.root), "link"))
            self.assertNotEqual(target, os.path.realpath(secret),
                                "must not resolve to the symlink's target")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_prefix_symlink_cannot_escape_allowlist(self):
        # A symlinked *directory* in the path prefix must not let a selection
        # escape the scanned root.
        macwinclean.scan(self.root, register_root=True)
        outside = tempfile.mkdtemp()
        try:
            write(os.path.join(outside, "passwd"), b"secret")
            os.symlink(outside, os.path.join(self.root, "escape"))
            sneaky = os.path.join(self.root, "escape", "passwd")
            target, reason = macwinclean.validate_trash_target(sneaky)
            self.assertIsNone(target)
            self.assertIn("outside", reason)
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class StaleIndexTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        macwinclean.INDEX.clear()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_removing_dir_purges_descendants(self):
        a = os.path.join(self.root, "a")
        b = os.path.join(a, "b")
        os.makedirs(b)
        write(os.path.join(b, "f.bin"), b"x" * 100)
        macwinclean.scan(self.root)
        self.assertIn(a, macwinclean.INDEX)
        self.assertIn(b, macwinclean.INDEX)

        macwinclean.remove_from_index(a)
        self.assertNotIn(a, macwinclean.INDEX)
        self.assertNotIn(b, macwinclean.INDEX,
                         "descendant nodes must not linger in INDEX after delete")

    def test_remove_corrects_ancestor_size(self):
        a = os.path.join(self.root, "a")
        os.mkdir(a)
        write(os.path.join(a, "f.bin"), b"x" * 4096)
        root = macwinclean.scan(self.root)
        before = root["size"]
        a_size = macwinclean.INDEX[a]["size"]
        macwinclean.remove_from_index(a)
        self.assertEqual(macwinclean.INDEX[self.root]["size"], before - a_size)


class JsInjectionTest(unittest.TestCase):
    def test_script_breakout_is_neutralized(self):
        saved = macwinclean.START_PATH
        try:
            macwinclean.START_PATH = "</script><b>x</b>"
            page = macwinclean.render_page()
            self.assertNotIn("</script><b>", page)
            self.assertIn("\\u003c", macwinclean._js_literal("<"))
        finally:
            macwinclean.START_PATH = saved

    def test_spaces_and_unicode_preserved(self):
        lit = macwinclean._js_literal("/Users/me/Mön Dossier/a b")
        decoded = json.loads(lit.replace("\\u003c", "<")
                                .replace("\\u003e", ">").replace("\\u0026", "&"))
        self.assertEqual(decoded, "/Users/me/Mön Dossier/a b")


class HttpAuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), macwinclean.Handler)
        cls.port = cls.srv.server_address[1]
        macwinclean.ALLOWED_HOSTS = {f"127.0.0.1:{cls.port}", f"localhost:{cls.port}"}
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

    def test_subtree_get_with_token_is_allowed(self):
        # A token-bearing GET is accepted (404-free, returns JSON).
        code, body = self._get(
            "/api/scan?path=" + tempfile.gettempdir(),
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacWinClean-Token": macwinclean.SESSION_TOKEN})
        self.assertEqual(code, 200)
        self.assertIn("root", body)

    def test_trash_without_token_is_forbidden(self):
        code, body = self._post("/api/trash", {"path": "/tmp/whatever"},
                                {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(code, 403)
        self.assertFalse(body["ok"])

    def test_oversized_post_body_is_rejected(self):
        code, body, _headers = self._post_raw(
            "/api/trash", b"x" * (macwinclean.MAX_JSON_BODY + 1),
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacWinClean-Token": macwinclean.SESSION_TOKEN,
             "Origin": f"http://127.0.0.1:{self.port}",
             "Content-Type": "application/json"})
        self.assertEqual(code, 413)
        self.assertFalse(body["ok"])

    def test_trash_with_cross_origin_is_forbidden(self):
        code, body = self._post(
            "/api/trash", {"path": "/tmp/whatever"},
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacWinClean-Token": macwinclean.SESSION_TOKEN,
             "Origin": "http://evil.example"})
        self.assertEqual(code, 403)

    def test_trash_with_token_but_bad_path_is_refused_not_crash(self):
        code, body = self._post(
            "/api/trash", {"path": "/etc/hosts"},
            {"Host": f"127.0.0.1:{self.port}",
             "X-MacWinClean-Token": macwinclean.SESSION_TOKEN,
             "Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(code, 400)
        self.assertFalse(body["ok"])
        self.assertIn("Refusing", body["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
