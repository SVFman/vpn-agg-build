"""Юнит-тесты mirror_sources.py (без сети: fetch_once и сон замокаются).

Запуск:  python3 -m unittest discover -s tests -v
"""
import base64
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import mirror_sources as mir  # noqa: E402


class TmpCwdTestCase(unittest.TestCase):
    """Переносит тест в пустой временный cwd (TARGETS пишут относительные пути)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.tmp)


class TestConfigLineCount(TmpCwdTestCase):
    def test_plain(self):
        self.assertEqual(mir.config_line_count("vless://a\nss://b\n"), 2)

    def test_base64(self):
        enc = base64.b64encode(b"vless://a\nss://b\n").decode()
        self.assertEqual(mir.config_line_count(enc), 2)

    def test_html_is_zero(self):
        self.assertEqual(mir.config_line_count("<html>429 Too Many Requests</html>"), 0)

    def test_empty_is_zero(self):
        self.assertEqual(mir.config_line_count(""), 0)


class TestSaveMirror(TmpCwdTestCase):
    def test_atomic_write_and_newline(self):
        mir.save_mirror("mirrors/x.txt", "a\nb")
        self.assertFalse(os.path.exists("mirrors/x.txt.tmp"))
        with open("mirrors/x.txt", encoding="utf-8") as f:
            self.assertEqual(f.read(), "a\nb\n")

    def test_overwrite(self):
        mir.save_mirror("mirrors/x.txt", "old\n")
        mir.save_mirror("mirrors/x.txt", "new\n")
        with open("mirrors/x.txt", encoding="utf-8") as f:
            self.assertEqual(f.read(), "new\n")


class TestFetchPatient(TmpCwdTestCase):
    @staticmethod
    def _http_error(code, retry_after=None):
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        return urllib.error.HTTPError("u", code, "e", headers, None)

    @staticmethod
    def _far_deadline():
        return time.monotonic() + 3600

    def test_success_first_try(self):
        with mock.patch.object(mir, "fetch_once", return_value="vless://a\n"), \
             mock.patch("time.sleep") as ms:
            self.assertEqual(mir.fetch_patient("https://x/1", "L", self._far_deadline()), "vless://a\n")
        ms.assert_not_called()

    def test_persistent_429_exhausts_attempts(self):
        sleeps = []
        with mock.patch.object(mir, "fetch_once",
                               side_effect=self._http_error(429, retry_after=5)), \
             mock.patch("time.sleep", side_effect=sleeps.append):
            self.assertIsNone(mir.fetch_patient("https://x/1", "L", self._far_deadline()))
        self.assertEqual(len(sleeps), mir.ATTEMPTS - 1)
        for w in sleeps:  # min(max(RA=5, 90), 600) + uniform(0, 15), дедлайн далеко
            self.assertGreaterEqual(w, 90)
            self.assertLessEqual(w, 105)

    def test_url_error_pauses(self):
        sleeps = []
        with mock.patch.object(mir, "fetch_once",
                               side_effect=urllib.error.URLError("conn refused")), \
             mock.patch("time.sleep", side_effect=sleeps.append):
            self.assertIsNone(mir.fetch_patient("https://x/1", "L", self._far_deadline()))
        self.assertEqual(len(sleeps), mir.ATTEMPTS - 1)
        self.assertGreaterEqual(sleeps[0], mir.ATTEMPT_PAUSE)

    def test_recovers_after_errors(self):
        err = self._http_error(503, retry_after=1)
        with mock.patch.object(mir, "fetch_once",
                               side_effect=[err, err, "vless://ok\n"]), \
             mock.patch("time.sleep"):
            self.assertEqual(mir.fetch_patient("https://x/1", "L", self._far_deadline()), "vless://ok\n")

    def test_exhausted_deadline_refuses_to_start(self):
        with mock.patch.object(mir, "fetch_once") as once, \
             mock.patch("time.sleep"):
            self.assertIsNone(mir.fetch_patient("https://x/1", "L", time.monotonic()))
        once.assert_not_called()

    def test_sleep_capped_by_deadline(self):
        # RA=600 не должен уводить сон за остаток дедлайна (200 с - FETCH_TIMEOUT = 170 с);
        # при замоканном сне монотонное время стоит, поэтому каждая из паур ограничена
        sleeps = []
        with mock.patch.object(mir, "fetch_once",
                               side_effect=self._http_error(429, retry_after=600)), \
             mock.patch("time.sleep", side_effect=sleeps.append):
            self.assertIsNone(mir.fetch_patient("https://x/1", "L", time.monotonic() + 200))
        self.assertEqual(len(sleeps), mir.ATTEMPTS - 1)
        for w in sleeps:
            self.assertLessEqual(w, 170)
            self.assertGreaterEqual(w, 160)


class TestMain(TmpCwdTestCase):
    def _run(self, patient=None):
        with mock.patch.object(mir, "fetch_patient",
                               return_value=None, side_effect=patient) as fp, \
             mock.patch("time.sleep"):
            mir.main()
        return fp

    def test_no_refresh_but_mirrors_exist_is_ok(self):
        os.makedirs("mirrors")
        for _, path in mir.TARGETS:
            open(path, "w").close()
        self._run()  # exit 0

    def test_no_refresh_and_no_mirrors_is_failure(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run()
        self.assertEqual(ctx.exception.code, 1)

    def test_refresh_ok(self):
        texts = ["vless://a\n", "vmess://" + base64.b64encode(b'{"add":"1.2.3.4"}').decode()]
        self._run(patient=texts)
        for _, path in mir.TARGETS:
            self.assertTrue(os.path.exists(path), path)

    def test_deadline_passed_to_fetch_patient(self):
        os.makedirs("mirrors")
        for _, path in mir.TARGETS:
            open(path, "w").close()
        before = time.monotonic()
        fp = self._run()
        self.assertEqual(fp.call_count, len(mir.TARGETS))
        for call in fp.call_args_list:
            url, label, deadline = call.args
            self.assertGreater(deadline, before)
            self.assertLessEqual(deadline, before + mir.MIRROR_DEADLINE_SECS + 1)


if __name__ == "__main__":
    unittest.main()
