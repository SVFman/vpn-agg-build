"""Юнит-тесты aggregate_subscription.py (без сети: urllib и сон замокаются).

Запуск:  python3 -m unittest discover -s tests -v
Стабильная семантика, которую не должны ломать доработки:
декодирование, парсеры, дедуп-ключ, загрузка источников, формат сохранения.
"""
import base64
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import aggregate_subscription as agg  # noqa: E402


UUID = "11111111-2222-3333-4444-555555555555"


def vless(extra="", host="93.184.216.34", port="443", uuid=UUID, remark="N"):
    return f"vless://{uuid}@{host}:{port}?{extra}#{remark}"


class TestDecode(unittest.TestCase):
    def test_base64_roundtrip(self):
        text = "vless://x\nss://y\n"
        enc = base64.b64encode(text.encode()).decode()
        self.assertEqual(agg.try_base64_decode(enc), text)

    def test_urlsafe_variant(self):
        text = "vmess://test-line_*_\n"
        enc = base64.urlsafe_b64encode(text.encode()).decode()
        self.assertEqual(agg.try_base64_decode(enc), text)

    def test_garbage_is_none(self):
        self.assertIsNone(agg.try_base64_decode("это не base64 !!!"))
        self.assertIsNone(agg.try_base64_decode(""))

    def test_scan_lines(self):
        text = "vless://a\n# comment\nss://b\ntrash\n"
        self.assertEqual(agg.scan_lines(text), ["vless://a", "ss://b"])

    def test_extract_configs_direct_and_b64(self):
        direct = agg.extract_configs("vless://a\n")
        self.assertEqual(direct, ["vless://a"])
        enc = base64.b64encode(b"ss://b\n").decode()
        self.assertEqual(agg.extract_configs(enc), ["ss://b"])
        self.assertEqual(agg.extract_configs("<html>error</html>"), [])


class TestSafeAddress(unittest.TestCase):
    def test_public_ip_ok(self):
        self.assertTrue(agg.is_safe_address("93.184.216.34"))
        self.assertTrue(agg.is_safe_address("2606:2800:220:1:248:1893:25c8:1946"))

    def test_gray_and_local_ip_rejected(self):
        for bad in ("10.0.0.1", "192.168.1.1", "172.16.0.9", "127.0.0.1", "::1",
                    "169.254.1.1", "224.0.0.1", "0.0.0.0"):
            self.assertFalse(agg.is_safe_address(bad), bad)

    def test_hostname_ok(self):
        self.assertTrue(agg.is_safe_address("example.com"))

    def test_local_hostnames_rejected(self):
        for bad in ("localhost", "LOCALHOST", "mypc.local", "foo.localhost", "localhost."):
            self.assertFalse(agg.is_safe_address(bad), bad)

    def test_trailing_dot_hostname_ok(self):
        self.assertTrue(agg.is_safe_address("example.com."))


class TestParseVless(unittest.TestCase):
    def test_full_reality(self):
        line = vless("security=reality&sni=a.com&pbk=KEY1&sid=01ab&flow=xtls-rprx-vision&type=tcp")
        p = agg.parse_vless(line)
        self.assertIsNotNone(p)
        self.assertEqual(p["protocol"], "vless")
        self.assertEqual(p["address"], "93.184.216.34")
        self.assertEqual(p["port"], 443)
        self.assertEqual(p["security"], "reality")
        self.assertEqual(p["pbk"], "KEY1")
        self.assertEqual(p["sid"], "01ab")
        self.assertEqual(p["sni"], "a.com")
        self.assertEqual(p["net"], "tcp")

    def test_sni_fallback_to_peer_then_host(self):
        p = agg.parse_vless(vless("security=tls&peer=peer.com"))
        self.assertEqual(p["sni"], "peer.com")
        # fallback на host работает для строк без tls-дефекта (security не tls)
        p = agg.parse_vless(vless("type=ws"))
        self.assertEqual(p["sni"], "93.184.216.34")

    def test_unsafe_ip_rejected(self):
        self.assertIsNone(agg.parse_vless(vless("security=tls", host="10.0.0.5")))

    def test_missing_fields_rejected(self):
        self.assertIsNone(agg.parse_vless("vless://@host:443?#x"))
        self.assertIsNone(agg.parse_vless("vless://zzz"))


class TestVlessDefect(unittest.TestCase):
    """№5: битые vless отбрасываются по СЫРЫМ query-параметрам."""

    def test_invalid_uuid(self):
        line = vless("security=tls&sni=a.com", uuid="not-a-uuid")
        self.assertEqual(agg.vless_defect(line), "vless: невалидный UUID")
        self.assertIsNone(agg.parse_vless(line))

    def test_valid_uuid_ok(self):
        self.assertIsNone(agg.vless_defect(vless("security=tls&sni=a.com")))

    def test_uppercase_uuid_ok(self):
        self.assertIsNone(agg.vless_defect(vless("security=tls&sni=a.com", uuid=UUID.upper())))

    def test_reality_without_pbk(self):
        line = vless("security=reality&sni=a.com")
        self.assertEqual(agg.vless_defect(line), "vless: reality без pbk")
        self.assertIsNone(agg.parse_vless(line))

    def test_reality_without_sni(self):
        line = vless("security=reality&pbk=K")
        self.assertEqual(agg.vless_defect(line), "vless: reality без sni")
        self.assertIsNone(agg.parse_vless(line))

    def test_reality_full_ok(self):
        self.assertIsNone(agg.vless_defect(vless("security=reality&sni=a.com&pbk=K")))

    def test_tls_without_any_sni_source(self):
        # суть сужённой редакции: parse_vless подставляет sni из host, поэтому
        # проверять надо сырые query — строка без sni/peer/host должна отбрасываться
        line = vless("security=tls")
        self.assertEqual(agg.vless_defect(line), "vless: tls без sni/peer/host")
        self.assertIsNone(agg.parse_vless(line))

    def test_tls_with_peer_only_ok(self):
        self.assertIsNone(agg.vless_defect(vless("security=tls&peer=p.com")))

    def test_tls_with_host_param_only_ok(self):
        self.assertIsNone(agg.vless_defect(vless("security=tls&host=h.com")))

    def test_security_none_not_checked(self):
        self.assertIsNone(agg.vless_defect(vless("type=ws")))


class TestOtherSchemeSafety(unittest.TestCase):
    """№4: единая проверка адреса для остальных протоколов."""

    SS_SIP002 = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@{host}:8388#P"  # aes-256-gcm:password

    def test_trojan_local_rejected(self):
        parsed, reason = agg.process_line("trojan://pass@localhost:443?sni=a.com#T")
        self.assertIsNone(parsed)
        self.assertEqual(reason, "trojan: серый/локальный IP")

    def test_trojan_gray_ip_rejected(self):
        parsed, reason = agg.process_line("trojan://pass@192.168.1.3:443#T")
        self.assertEqual(reason, "trojan: серый/локальный IP")

    def test_trojan_ok(self):
        parsed, reason = agg.process_line("trojan://pass@example.com:443?sni=a.com#T")
        self.assertIsNone(parsed)
        self.assertIsNone(reason)

    def test_ss_sip002_rejected_and_kept(self):
        parsed, reason = agg.process_line(self.SS_SIP002.format(host="10.0.0.9"))
        self.assertEqual(reason, "ss: серый/локальный IP")
        parsed, reason = agg.process_line(self.SS_SIP002.format(host="93.184.216.34"))
        self.assertIsNone(reason)

    def test_ss_legacy_base64_rejected_and_kept(self):
        for host, expected_reason in (("127.0.0.1", "ss: серый/локальный IP"), ("93.184.216.34", None)):
            line = "ss://" + base64.b64encode(f"aes-256-gcm:pass@{host}:8388".encode()).decode()
            parsed, reason = agg.process_line(line)
            self.assertEqual(reason, expected_reason, line)

    def test_ss_unparseable_kept(self):
        parsed, reason = agg.process_line("ss://!!!not-base64!!!")
        self.assertIsNone(reason)

    def test_hysteria2_tuic_wireguard_rejected(self):
        for scheme in ("hy2", "hysteria2", "tuic", "wireguard"):
            parsed, reason = agg.process_line(f"{scheme}://pass@10.1.2.3:443#X")
            self.assertEqual(reason, f"{scheme}: серый/локальный IP", scheme)

    def test_hysteria2_ok(self):
        parsed, reason = agg.process_line("hysteria2://pass@hy2.example.com:443#X")
        self.assertIsNone(reason)

    def test_vless_rejected_reason_counted(self):
        parsed, reason = agg.process_line("vless://bad@93.184.216.34:443?security=tls&sni=a.com#X")
        self.assertIsNone(parsed)
        self.assertEqual(reason, "vless: невалидный UUID")


class TestParseVmess(unittest.TestCase):
    def vmess(self, **over):
        data = {"add": "93.184.216.34", "port": 443, "id": UUID,
                "net": "ws", "tls": "tls", "sni": "a.com", "path": "/p"}
        data.update(over)
        raw = base64.b64encode(json.dumps(data).encode()).decode()
        return "vmess://" + raw

    def test_good(self):
        p = agg.parse_vmess(self.vmess())
        self.assertIsNotNone(p)
        self.assertEqual(p["protocol"], "vmess")
        self.assertEqual(p["net"], "ws")
        self.assertEqual(p["security"], "tls")
        self.assertEqual(p["sni"], "a.com")

    def test_unsafe_rejected(self):
        self.assertIsNone(agg.parse_vmess(self.vmess(add="192.168.0.1")))

    def test_broken_rejected(self):
        self.assertIsNone(agg.parse_vmess("vmess://not_base64!!!"))
        self.assertIsNone(agg.parse_vmess("vmess://" + base64.b64encode(b"[1,2,3]").decode()))

    def test_tls_flag_variants(self):
        self.assertEqual(agg.parse_vmess(self.vmess(tls=""))["security"], "none")
        self.assertEqual(agg.parse_vmess(self.vmess(tls="1"))["security"], "tls")


class TestDedupKey(unittest.TestCase):
    def test_same_node_differs_only_by_remark(self):
        a = agg.make_dedup_key(vless("security=reality&sni=a.com&pbk=K&sid=1", remark="A"))
        b = agg.make_dedup_key(vless("security=reality&sni=a.com&pbk=K&sid=1", remark="B"))
        self.assertEqual(a, b)

    def test_differs_by_reality_params(self):
        a = agg.make_dedup_key(vless("security=reality&sni=a.com&pbk=K1&sid=1"))
        b = agg.make_dedup_key(vless("security=reality&sni=a.com&pbk=K2&sid=1"))
        self.assertNotEqual(a, b)

    def test_differs_by_transport(self):
        a = agg.make_dedup_key(vless("security=tls&sni=a.com&type=ws"))
        b = agg.make_dedup_key(vless("security=tls&sni=a.com&type=grpc"))
        self.assertNotEqual(a, b)

    def test_raw_key_for_other_schemes(self):
        line = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@93.184.216.34:8388#SS1"
        key = agg.make_dedup_key(line)
        self.assertEqual(key, ("raw", line.split("#", 1)[0]))
        self.assertEqual(key, agg.make_dedup_key(line + "-remark"))


class TestSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "sources.txt")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_markers_and_comments(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(
                "# комментарий\n"
                "!https://a/1.txt\n"
                "@https://b/2.txt\n"
                "https://c/3.txt\n"
                "\n"
                "!file:mirrors/KvRuVPN.txt\n"
            )
        old_cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            trusted, cepreu54, checked = agg.load_sources("sources.txt")
        finally:
            os.chdir(old_cwd)
        self.assertEqual(trusted, ["https://a/1.txt", "file://" + os.path.join(self.tmp, "mirrors/KvRuVPN.txt")])
        self.assertEqual(cepreu54, ["https://b/2.txt"])
        self.assertEqual(checked, ["https://c/3.txt"])


class TestSave(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_out = agg.OUT_DIR
        agg.OUT_DIR = os.path.join(self.tmp, "subscription")

    def tearDown(self):
        agg.OUT_DIR = self.old_out
        shutil.rmtree(self.tmp)

    def read(self, name):
        with open(os.path.join(agg.OUT_DIR, name), encoding="utf-8") as f:
            return f.read()

    def test_pair_written(self):
        agg.save_subscription(["a", "b"], "grp")
        self.assertEqual(self.read("grp.txt"), "a\nb\n")
        raw = self.read("grp_base64.txt")
        self.assertEqual(base64.b64decode(raw).decode(), "a\r\nb")

    def test_empty_raises_and_writes_nothing(self):
        with self.assertRaises(agg.AggregationError):
            agg.save_subscription([], "grp")
        self.assertFalse(os.path.exists(os.path.join(agg.OUT_DIR, "grp.txt")))

    def test_no_tmp_leftover_after_save(self):
        agg.save_subscription(["a"], "grp")
        files = os.listdir(agg.OUT_DIR)
        self.assertEqual(sorted(files), ["grp.txt", "grp_base64.txt"])

    def _plant_old(self, prefix, count):
        os.makedirs(agg.OUT_DIR, exist_ok=True)
        old = [f"ss://old-{i}" for i in range(count)]
        with open(os.path.join(agg.OUT_DIR, f"{prefix}.txt"), "w") as f:
            f.write("\n".join(old) + "\n")
        return "\n".join(old) + "\n"

    def test_shrink_rejected_files_untouched(self):
        old = self._plant_old("grp", 100)
        with self.assertRaises(agg.ShrinkRejected):
            agg.save_subscription([f"ss://new-{i}" for i in range(30)], "grp")
        self.assertEqual(self.read("grp.txt"), old)  # прежний файл не тронут
        self.assertEqual(sorted(os.listdir(agg.OUT_DIR)), ["grp.txt"])  # .tmp не осталось, base64 не появился

    def test_shrink_boundary_50_percent_allowed(self):
        self._plant_old("grp", 100)
        agg.save_subscription([f"ss://n{i}" for i in range(50)], "grp")  # ровно 50% — это не деградация
        self.assertEqual(len(self.read("grp.txt").splitlines()), 50)

    def test_small_baseline_not_protected(self):
        self._plant_old("grp", agg.SHRINK_BASELINE_MIN - 1)
        agg.save_subscription(["ss://a"], "grp")  # 19 -> 1 строка: защита не включается
        self.assertEqual(self.read("grp.txt"), "ss://a\n")

    def test_allow_shrink_forces_write(self):
        self._plant_old("grp", 100)
        agg.save_subscription([f"ss://n{i}" for i in range(30)], "grp", allow_shrink=True)
        self.assertEqual(len(self.read("grp.txt").splitlines()), 30)
        self.assertTrue(os.path.exists(os.path.join(agg.OUT_DIR, "grp_base64.txt")))

    def test_max_lines_trim(self):
        agg.save_subscription([f"ss://{i}" for i in range(agg.MAX_LINES + 5)], "grp")
        self.assertEqual(len(self.read("grp.txt").splitlines()), agg.MAX_LINES)


class TestFetchSource(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # общий дедлайн (№1) — глобальное состояние модуля: сбрасываем, чтобы
        # тесты не зависели от порядка выполнения
        agg._global_deadline = None
        # глушим троттлинг домена: он использует тот же time.sleep и
        # хранит состояние в глобальном реестре, что мешает точным проверкам
        patcher = mock.patch.object(agg, "_wait_slot")
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        agg._domain_last_req.clear()
        shutil.rmtree(self.tmp)

    def test_success(self):
        resp = mock.MagicMock()
        resp.read.return_value = b"vless://a\n"
        resp.__enter__.return_value = resp
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertEqual(agg.fetch_source("https://x/1.txt"), "vless://a\n")

    def test_file_url(self):
        path = os.path.join(self.tmp, "src.txt")
        with open(path, "w") as f:
            f.write("ss://b\n")
        self.assertEqual(agg.fetch_source("file://" + path), "ss://b\n")

    @staticmethod
    def _http_error(code, retry_after=None):
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        return urllib.error.HTTPError("u", code, "e", headers, None)

    def test_retry_then_success(self):
        err = self._http_error(429, retry_after=1)
        ok = mock.MagicMock()
        ok.read.return_value = b"data"
        ok.__enter__.return_value = ok
        sleeps = []
        with mock.patch("urllib.request.urlopen", side_effect=[err, ok]), \
             mock.patch("time.sleep", side_effect=sleeps.append):
            self.assertEqual(agg.fetch_source("https://x/1.txt"), "data")
        self.assertEqual(len(sleeps), 1)  # одна пауза ретрая, без бэкоффов и троттлинга
        self.assertGreaterEqual(sleeps[0], 1.0)   # Retry-After = 1
        self.assertLessEqual(sleeps[0], 4.0)      # + jitter

    def test_no_retry_on_404(self):
        with mock.patch("urllib.request.urlopen", side_effect=self._http_error(404)), \
             mock.patch("time.sleep") as ms:
            with self.assertRaises(urllib.error.HTTPError):
                agg.fetch_source("https://x/1.txt")
            ms.assert_not_called()

    def test_exhausted_retries_raise(self):
        with mock.patch("urllib.request.urlopen", side_effect=self._http_error(429, 1)), \
             mock.patch("time.sleep"):
            with self.assertRaises(urllib.error.HTTPError):
                agg.fetch_source("https://x/1.txt")

    def test_retry_after_capped_at_60(self):
        sleeps = []
        ok = mock.MagicMock()
        ok.read.return_value = b"data"
        ok.__enter__.return_value = ok
        with mock.patch("urllib.request.urlopen",
                        side_effect=[self._http_error(429, retry_after=600), ok]), \
             mock.patch("time.sleep", side_effect=sleeps.append):
            self.assertEqual(agg.fetch_source("https://x/1.txt"), "data")
        self.assertEqual(len(sleeps), 1)
        self.assertLessEqual(sleeps[0], agg.RETRY_AFTER_CAP)
        self.assertGreaterEqual(sleeps[0], agg.RETRY_AFTER_CAP - 1)

    def test_zero_deadline_refuses_to_start(self):
        with mock.patch.object(agg, "FETCH_DEADLINE_SECS", 0), \
             mock.patch("urllib.request.urlopen") as urlopen, \
             mock.patch("time.sleep"):
            with self.assertRaises(TimeoutError):
                agg.fetch_source("https://x/1.txt")
            urlopen.assert_not_called()

    def test_deadline_blocks_useless_retry_sleep(self):
        # Дедлайн почти исчерпан: злой Retry-After не должен приводить к бесполезному сну
        with mock.patch.object(agg, "FETCH_DEADLINE_SECS", 10), \
             mock.patch("urllib.request.urlopen",
                        side_effect=self._http_error(429, retry_after=600)), \
             mock.patch("time.sleep") as ms:
            with self.assertRaises(TimeoutError):
                agg.fetch_source("https://x/1.txt")
            ms.assert_not_called()

    def test_process_deadline_lazy_init(self):
        """№1: общий дедлайн лениво привязывается к моменту первого вызова."""
        agg._global_deadline = None
        self.addCleanup(setattr, agg, "_global_deadline", None)
        before = time.monotonic()
        deadline = agg._process_deadline()
        self.assertAlmostEqual(
            deadline - before, agg.FETCH_DEADLINE_SECS, delta=1.0)

    def test_global_deadline_shared_between_sources(self):
        """№1: бюджет общий — исчерпанный дедлайн останавливает и второй источник.

        Новая «волна» (вторая порция источников при переполнении пула потоков,
        а также cepreu54/checked после igareck) свежие 180 с не получает: при
        массовом сбое сборка падает быстро сама, а не убивается по timeout.
        """
        agg._global_deadline = time.monotonic() - 1  # бюджет исчерпан «первой волной»
        self.addCleanup(setattr, agg, "_global_deadline", None)
        with mock.patch("urllib.request.urlopen") as urlopen, \
             mock.patch("time.sleep"):
            with self.assertRaises(TimeoutError):
                agg.fetch_source("https://x/2.txt")
            urlopen.assert_not_called()


class TestFetchBatch(unittest.TestCase):
    def test_partial_failure_ok(self):
        """№9: fetch_batch возвращает per-source статистику в порядке urls."""
        with mock.patch.object(agg, "fetch_source",
                               side_effect=["vless://a\nss://b\n", RuntimeError("boom")]):
            sources = agg.fetch_batch(["https://ok/1", "https://bad/2"], "T")
        self.assertEqual([s["url"] for s in sources], ["https://ok/1", "https://bad/2"])
        self.assertEqual(sources[0]["raw_count"], 2)
        # vless://a отклоняется парсером (невалидный UUID), ss://b принимается
        self.assertEqual([ln for ln, _ in sources[0]["records"]], ["ss://b"])
        self.assertEqual(sources[0]["rejects"], {"vless: невалидный UUID": 1})
        self.assertIsNone(sources[0]["error"])
        self.assertEqual(sources[1]["error"], "boom")
        self.assertEqual(sources[1]["records"], [])

    def test_rejects_attributed_to_source(self):
        """№9: каждый отброс привязан к своему источнику (разбор на стадии загрузки)."""
        bad_vless = "vless://bad@93.184.216.34:443?security=tls&sni=a.com#X"
        gray_ss = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@10.0.0.9:8388#GRAY"
        good = vless("security=tls&sni=a.com")
        with mock.patch.object(agg, "fetch_source",
                               side_effect=[good + "\n" + bad_vless + "\n", gray_ss + "\n"]):
            sources = agg.fetch_batch(["https://a/1", "https://b/2"], "T")
        self.assertEqual(sources[0]["rejects"], {"vless: невалидный UUID": 1})
        self.assertEqual(sources[0]["raw_count"], 2)
        self.assertEqual(sources[1]["rejects"], {"ss: серый/локальный IP": 1})

    def test_zero_lines_marked(self):
        with mock.patch.object(agg, "fetch_source", return_value="<html>err</html>"):
            sources = agg.fetch_batch(["https://a/1"], "T")
        self.assertEqual(sources[0]["raw_count"], 0)
        self.assertIsNone(sources[0]["error"])

    def test_all_failed_raises(self):
        with mock.patch.object(agg, "fetch_source", side_effect=RuntimeError("down")):
            with self.assertRaises(agg.AggregationError):
                agg.fetch_batch(["https://a/1", "https://b/2"], "T")


class TestRunGroup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_out = agg.OUT_DIR
        agg.OUT_DIR = os.path.join(self.tmp, "subscription")

    def tearDown(self):
        agg.OUT_DIR = self.old_out
        shutil.rmtree(self.tmp)

    def read(self, name):
        with open(os.path.join(agg.OUT_DIR, name), encoding="utf-8") as f:
            return f.read()

    def test_dedup_drops_broken_and_duplicates(self):
        raw = "\n".join([
            vless("security=reality&sni=a.com&pbk=K1&sid=1&type=tcp", remark="A"),
            vless("security=reality&sni=a.com&pbk=K1&sid=1&type=tcp", remark="A-dup"),
            "vless://zzz",  # битая строка vless
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@93.184.216.34:8388#SS1",
        ])
        with mock.patch.object(agg, "fetch_source", return_value=raw):
            agg.run_group(["https://x/1"], "G", "grp", dedup=True)
        content = self.read("grp.txt").splitlines()
        self.assertEqual(len(content), 2)
        self.assertIn(vless("security=reality&sni=a.com&pbk=K1&sid=1&type=tcp", remark="A"), content)
        self.assertIn("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@93.184.216.34:8388#SS1", content)

    def test_no_dedup_keeps_all(self):
        raw = vless("security=tls&sni=a.com") + "\n" + vless("security=tls&sni=a.com")
        with mock.patch.object(agg, "fetch_source", return_value=raw):
            agg.run_group(["https://x/1"], "G", "grp", dedup=False)
        self.assertEqual(len(self.read("grp.txt").splitlines()), 2)

    def test_safety_filter_applies_in_dedup_mode(self):
        raw = "\n".join([
            self.SS_SAFE,
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@10.0.0.9:8388#GRAY",
            vless("security=reality&sni=a.com"),  # reality без pbk
        ])
        with mock.patch.object(agg, "fetch_source", return_value=raw):
            agg.run_group(["https://x/1"], "G", "grp", dedup=True)
        content = self.read("grp.txt").splitlines()
        self.assertEqual(content, [self.SS_SAFE])

    SS_SAFE = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@93.184.216.34:8388#SS1"

    def test_dedup_stats_intra_cross(self):
        """№9: дубли внутри источника и между источниками считаются раздельно."""
        line_x = vless("security=tls&sni=a.com")
        line_y = vless("security=tls&sni=b.com")
        src_a = line_x + "\n" + line_x + "\n" + line_y       # дубль внутри A
        src_b = line_x + "\n" + vless("security=tls&sni=c.com")  # X перекрыт источником A
        with mock.patch.object(agg, "fetch_source", side_effect=[src_a, src_b]):
            stats = agg.run_group(["https://a/1", "https://b/2"], "G", "grp", dedup=True)
        self.assertEqual(stats["kept"], 3)          # X(A), Y(A), C(B)
        self.assertEqual(stats["intra"], [1, 0])
        self.assertEqual(stats["cross"], [0, 1])
        self.assertEqual(stats["contribution"], [2, 1])

    def test_tcp_raw_classes_counted(self):
        """№9: счётчик tcp/raw (reality отдельно), другие транспорты не считаются."""
        r = vless("security=reality&sni=a.com&pbk=K&type=tcp")
        t1 = vless("security=tls&sni=a.com&type=tcp")
        t2 = vless("security=tls&sni=b.com&type=raw")
        w = vless("security=tls&sni=a.com&type=ws")
        with mock.patch.object(agg, "fetch_source", return_value="\n".join([r, t1, t2, w])):
            stats = agg.run_group(["https://a/1"], "G", "grp", dedup=True)
        self.assertEqual(stats["raw_classes"], {"reality": 1, "other": 2})

    def test_all_sources_down_leaves_files(self):
        with mock.patch.object(agg, "fetch_source", side_effect=RuntimeError("down")):
            with self.assertRaises(agg.AggregationError):
                agg.run_group(["https://x/1"], "G", "grp", dedup=True)
        self.assertFalse(os.path.exists(os.path.join(agg.OUT_DIR, "grp.txt")))

    def test_empty_urls_skips(self):
        self.assertFalse(agg.run_group([], "G", "grp", dedup=True))
        self.assertFalse(os.path.exists(os.path.join(agg.OUT_DIR, "grp.txt")))

    def test_shrink_rejection_propagates(self):
        os.makedirs(agg.OUT_DIR, exist_ok=True)
        old = "\n".join(f"ss://old-{i}" for i in range(100)) + "\n"
        with open(os.path.join(agg.OUT_DIR, "grp.txt"), "w") as f:
            f.write(old)
        with mock.patch.object(agg, "fetch_source", return_value="ss://one\n"):
            with self.assertRaises(agg.ShrinkRejected):
                agg.run_group(["https://x/1"], "G", "grp", dedup=True)
        self.assertEqual(self.read("grp.txt"), old)


class TestSummary(unittest.TestCase):
    """№9: markdown-сводка по источникам в $GITHUB_STEP_SUMMARY."""

    @staticmethod
    def _stats():
        line = vless("security=tls&sni=a.com")
        src_ok = {"url": "https://a/1.txt", "raw_count": 3,
                  "records": [(line, agg.parse_config_line(line))],
                  "rejects": {"vless: невалидный UUID": 2}, "error": None}
        src_zero = {"url": "https://z/0.txt", "raw_count": 0, "records": [], "rejects": {}, "error": None}
        src_err = {"url": "https://e/1|pipe.txt", "raw_count": 0, "records": [], "rejects": {},
                   "error": "HTTP Error 429"}
        return {
            "label": "G", "prefix": "grp", "sources": [src_ok, src_zero, src_err],
            "intra": [1, 0, 0], "cross": [0, 0, 0],
            "contribution": [1, 0, 0], "kept": 1,
            "raw_classes": {"reality": 1, "other": 2},
        }

    def test_table_rows(self):
        md = agg.format_summary([self._stats()])
        self.assertIn("| Источник | Строк | Откл. при разборе | Дублей внутри | Перекрыт др. ист. | В файле | Статус |", md)
        self.assertIn("| https://a/1.txt | 3 | 2 (uuid 2) | 1 | 0 | 1 | ok |", md)
        self.assertIn("| https://z/0.txt | 0 | 0 | 0 | 0 | 0 | **0 строк** |", md)
        self.assertIn("ERR: HTTP Error 429", md)
        self.assertIn("| **Итого grp** | 3 | 2 | 1 | 0 | 1 | |", md)
        self.assertIn("| tcp/raw + reality (блокируемый ТСПУ) | 1 |", md)
        self.assertIn("| tcp/raw прочие | 2 |", md)

    def test_pipe_in_url_escaped(self):
        md = agg.format_summary([self._stats()])
        self.assertIn("https://e/1\\|pipe.txt", md)

    def test_write_summary_to_env_file(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "summary.md")
        with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": path}):
            agg.write_summary("## t\n| a | b |\n")
        with open(path, encoding="utf-8") as f:
            self.assertIn("| a | b |", f.read())

    def test_write_summary_without_env_ok(self):
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
        with mock.patch.dict(os.environ, env, clear=True):
            agg.write_summary("x")  # не падает и ничего не пишет


class TestXhttpSubscription(unittest.TestCase):
    """№6: отдельные подписки только из xhttp/grpc (splithttp = синоним xhttp)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_out = agg.OUT_DIR
        agg.OUT_DIR = os.path.join(self.tmp, "subscription")

    def tearDown(self):
        agg.OUT_DIR = self.old_out
        shutil.rmtree(self.tmp)

    def read(self, name):
        with open(os.path.join(agg.OUT_DIR, name), encoding="utf-8") as f:
            return f.read()

    XHTTP = vless("security=reality&sni=a.com&pbk=K&type=xhttp")
    GRPC = vless("security=tls&sni=a.com&type=grpc")
    SPLIT = vless("security=tls&sni=b.com&type=splithttp")
    WS = vless("security=tls&sni=a.com&type=ws")
    SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@93.184.216.34:8388#SS1"

    def test_transport_of(self):
        self.assertEqual(agg.transport_of(self.XHTTP), "xhttp")
        self.assertEqual(agg.transport_of(self.GRPC), "grpc")
        self.assertEqual(agg.transport_of(self.SPLIT), "xhttp")  # синоним
        self.assertEqual(agg.transport_of(self.WS), "ws")
        self.assertEqual(agg.transport_of(self.SS), "")
        vmess = agg.parse_vmess("vmess://" + base64.b64encode(json.dumps(
            {"add": "1.2.3.4", "port": 443, "id": UUID, "net": "xhttp"}).encode()).decode())
        self.assertEqual(agg.transport_of("vmess://x", vmess), "xhttp")

    def test_pair_written_only_xhttp_grpc(self):
        n = agg.save_xhttp_subscription([self.XHTTP, self.WS, self.GRPC, self.SPLIT, self.SS], "grp")
        self.assertEqual(n, 3)
        self.assertEqual(sorted(os.listdir(agg.OUT_DIR)),
                         ["grp_xhttp.txt", "grp_xhttp_base64.txt"])
        self.assertEqual(self.read("grp_xhttp.txt").splitlines(), [self.XHTTP, self.GRPC, self.SPLIT])
        decoded = base64.b64decode(self.read("grp_xhttp_base64.txt")).decode()
        self.assertEqual(decoded, "\r\n".join([self.XHTTP, self.GRPC, self.SPLIT]))

    def test_empty_result_touches_nothing(self):
        n = agg.save_xhttp_subscription([self.WS, self.SS], "grp")
        self.assertEqual(n, 0)
        self.assertFalse(os.path.exists(os.path.join(agg.OUT_DIR)))

    def test_run_group_writes_xhttp_outputs(self):
        raw = "\n".join([self.XHTTP, self.WS, self.XHTTP])  # дубль xhttp убирается дедупом
        with mock.patch.object(agg, "fetch_source", return_value=raw):
            agg.run_group(["https://x/1"], "G", "grp", dedup=True, also_xhttp=True)
        self.assertEqual(sorted(os.listdir(agg.OUT_DIR)),
                         ["grp.txt", "grp_base64.txt", "grp_xhttp.txt", "grp_xhttp_base64.txt"])
        self.assertEqual(self.read("grp_xhttp.txt").splitlines(), [self.XHTTP])


class TestMainArgparse(unittest.TestCase):
    def test_mode_choices(self):
        for m in ("trusted", "cepreu54", "checked", "all"):
            args = agg.build_parser().parse_args(["--mode", m])
            self.assertEqual(args.mode, m)

    def test_bad_mode_rejected(self):
        with self.assertRaises(SystemExit):
            agg.build_parser().parse_args(["--mode", "drop-table"])

    def test_allow_shrink_flag(self):
        self.assertFalse(agg.build_parser().parse_args([]).allow_shrink)
        self.assertTrue(agg.build_parser().parse_args(["--allow-shrink"]).allow_shrink)

    def test_checked_runs_with_dedup(self):
        """№3: режим checked собирается с дедупликацией (143 -> 92 строки на живом замере)."""
        with mock.patch.object(agg, "run_group") as rg, \
             mock.patch.object(agg, "load_sources", return_value=(["t"], ["c"], ["k"])), \
             mock.patch("os.path.exists", return_value=True), \
             mock.patch.object(sys, "argv", ["agg", "--mode", "checked"]):
            agg.main()
        self.assertEqual(rg.call_args.kwargs["dedup"], True)
        self.assertEqual(rg.call_args.args[2], "checked")


if __name__ == "__main__":
    unittest.main()
