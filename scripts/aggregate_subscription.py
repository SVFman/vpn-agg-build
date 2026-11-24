#!/usr/bin/env python3
"""Агрегатор VPN-подписок: сбор, фильтрация и дедупликация конфигов из источников.

Изменения по итогам ревизии:
- ключ дедупликации учитывает транспорт (net/type) и параметры REALITY (pbk/sid/flow),
  регистр UUID нормализован — разные узлы больше не схлопываются;
- пустой результат не затирает рабочую подписку (save_subscription прерывает сборку);
- честные коды выхода: файл источников не найден или все источники недоступны — job краснеет;
- режимы независимы: авария одного не блокирует сборку остальных, итоговый код — 1, если упал хотя бы один;
- режим без заданных источников пропускается, а не затирает файлы пустой подпиской;
- замок домена удерживается только на троттлинг, а не на весь цикл ретраев;
- реестр замков потокобезопасен (устранена гонка defaultdict);
- ретраи включают код 500; поддержан urlsafe-base64 (vmess); усечения MAX_SOURCE_BYTES
  и MAX_LINES логируются;
- удалён мёртвый код и лишние параметры (last_error, parsed, schemes);
- run_dedup_group/run_checked объединены в run_group(..., dedup=...);
- plain-файл завершается переводом строки;
- поддержка локальных зеркал: строка `file:путь/от/корня` в subscription-sources.txt
  читается с диска без ретраев и троттлинга (списки, зеркалируемые workflow
  "Mirror GitVerse Sources", см. scripts/mirror_sources.py).

Изменения по второй ревизии (независимый эксперт, ноябрь 2026):
- №1 потолок Retry-After (RETRY_AFTER_CAP=60 с) + ОБЩИЙ дедлайн сбора 180 с от
  старта процесса (env FETCH_DEADLINE_SECS), один на все источники всех режимов;
  per-source потолок — второй ограничитель; попытка не начинается без запаса на
  таймаут;
- №3 режим checked собирается с дедупликацией;
- №4 единая проверка адреса для всех протоколов (trojan/ss/hysteria2/hy2/tuic/wireguard;
  для ss — SIP002 и legacy-base64), отсечение localhost/*.local/*.localhost;
- №5 битые vless отбрасываются по сырым query-параметрам (vless_defect): невалидный
  UUID, reality без pbk/sni, tls без sni/peer/host; счётчики по категориям;
- №6 подписки <prefix>_xhttp(+_base64): только xhttp/grpc (splithttp = синоним);
  пустой результат файл не трогает;
- №7 защита от деградации (<50% прежнего файла от 20 строк — запись отменена, job
  краснеет), ручной обход --allow-shrink;
- №8 атомарная запись всех пар (оба .tmp, затем два os.replace);
- №9 разбор строк на стадии загрузки (атрибуция отбросов источнику), сводка по
  источникам в $GITHUB_STEP_SUMMARY (format_summary/write_summary), счётчик tcp/raw
  (reality отдельно — ТСПУ класс), детерминированный порядок источников;
- №10-№11 — в workflow (mode через env) и README.
"""
import argparse
import base64
import ipaddress
import json
import os
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES_FILE = "subscription-sources.txt"
OUT_DIR = "subscription"
FETCH_TIMEOUT = 15
FETCH_MAX_RETRIES = 4
FETCH_RETRY_BACKOFF = 3       # секунд; удваивается с каждой повторной попыткой
MAX_SOURCE_BYTES = 5 * 1024 * 1024  # лимит 5 МБ на один источник для защиты от OOM
MAX_LINES = 20000
MIN_SUBSCRIPTION_LINES = 1    # попытка сохранить меньше строк считается аварией сборки
SHRINK_BASELINE_MIN = 20      # защита от деградации включается для файлов от 20 строк

RETRY_AFTER_CAP = 60         # потолок паузы по Retry-After: злой заголовок (600 с) не убьёт job


def _env_int(name, default):
    """Целое из переменной окружения; без/с мусором — значение по умолчанию."""
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return default


# №1: дедлайн сбора — 180 с от СТАРТА ПРОЦЕССА, один на все источники всех
# режимов суммарно (первый ограничитель). Массовый сбой одной группы больше не
# даёт следующим «волнам» источников свежий бюджет: сборка падает быстро сама
# (exit 1, прежние файлы нетронуты), а не убивается по timeout-minutes в
# произвольном месте. Per-source потолок в fetch_source — второй ограничитель.
# Переопределяется переменной окружения FETCH_DEADLINE_SECS.
FETCH_DEADLINE_SECS = _env_int("FETCH_DEADLINE_SECS", 180)

# Момент (time.monotonic) общего дедлайна; ленивая инициализация при первом
# обращении. В main() привязывается к фактическому старту процесса явно.
_global_deadline = None


def _process_deadline():
    """Момент общего дедлайна сбора (№1); ленивая инициализация.

    В тестах состояние сбрасывается присваиванием agg._global_deadline = None.
    """
    global _global_deadline
    if _global_deadline is None:
        _global_deadline = time.monotonic() + FETCH_DEADLINE_SECS
    return _global_deadline

# gitverse.ru отвечает 429 при частых запросах с IP раннера GitHub Actions:
# 4 источника с паузой 1.5 с и ретраями не проходили (прод-запуск №1),
# поэтому пауза увеличена до 4 с (последний из 4 URL при таком разрыве прошёл).
DOMAIN_DELAYS = {
    "gitverse.ru": 4.0,
    "raw.githubusercontent.com": 0.05,
    "gist.githubusercontent.com": 0.05,
}
DEFAULT_DOMAIN_DELAY = 0.5

RETRY_HTTP_CODES = (429, 500, 502, 503, 504)

# №6: отдельные подписки только из этих транспортов (splithttp — синоним xhttp)
XHTTP_TRANSPORTS = ("xhttp", "grpc")

SUPPORTED_SCHEMES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hy2://",
    "hysteria2://",
    "tuic://",
    "wireguard://",
)


class AggregationError(Exception):
    """Авария сборки: полный отказ источников или пустой результат режима."""


class ShrinkRejected(AggregationError):
    """Новый результат меньше половины прежнего файла — запись отменена.

    Защита от деградации: если источник внезапно отдал мусор (капча, обрезанный
    список), прежние рабочие файлы остаются нетронутыми, job краснеет.
    Закономерное сокращение (источник удалён навсегда) обходится ручным запуском
    workflow с allow_shrink = true (CLI: --allow-shrink).
    """


_domain_locks = {}
_domain_locks_guard = threading.Lock()
_domain_last_req = {}


# ---------- 1. Сбор и декодирование источников (троттлинг по доменам + ретраи) ----------

def _get_domain_lock(domain):
    """Потокобезопасно возвращает замок домена (вместо гонки на defaultdict)."""
    lock = _domain_locks.get(domain)
    if lock is None:
        with _domain_locks_guard:
            lock = _domain_locks.setdefault(domain, threading.Lock())
    return lock


def _wait_slot(domain, delay):
    """Троттлинг запросов к домену; замок удерживается только на паузу.

    HTTP-запросы и сны бэкоффа выполняются вне замка, поэтому один
    недоступный источник больше не блокирует остальные потоки домена.
    """
    with _get_domain_lock(domain):
        elapsed = time.monotonic() - _domain_last_req.get(domain, 0.0)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        _domain_last_req[domain] = time.monotonic()


def _decode_source_payload(data, url):
    if len(data) > MAX_SOURCE_BYTES:
        print(f"WARN {url}: источник обрезан до {MAX_SOURCE_BYTES} байт", flush=True)
        data = data[:MAX_SOURCE_BYTES]
    return data.decode("utf-8", errors="ignore")


def fetch_source(url):
    # Локальные зеркала (file:) — мгновенно, без ретраев и троттлинга.
    if url.startswith("file://"):
        with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as resp:
            return _decode_source_payload(resp.read(MAX_SOURCE_BYTES + 1), url)

    # Эффективный дедлайн — более ранний из двух ограничителей: общий дедлайн
    # сбора (от старта процесса, один на все источники) и per-source потолок.
    deadline = min(_process_deadline(), time.monotonic() + FETCH_DEADLINE_SECS)

    def no_time(why):
        raise TimeoutError(
            f"{url}: дедлайн сбора ({FETCH_DEADLINE_SECS} с) исчерпан — {why}")

    domain = urllib.parse.urlparse(url).netloc.lower()
    delay = DOMAIN_DELAYS.get(domain, DEFAULT_DOMAIN_DELAY)

    for attempt in range(FETCH_MAX_RETRIES):
        # Попытку не начинаем, если на неё не остаётся полного таймаута запроса.
        if time.monotonic() >= deadline - FETCH_TIMEOUT:
            no_time(f"осталось меньше FETCH_TIMEOUT={FETCH_TIMEOUT} с")
        _wait_slot(domain, delay)
        if time.monotonic() >= deadline - FETCH_TIMEOUT:
            no_time("очередь троттлинга съела остаток дедлайна")
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/plain,text/html,*/*;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                return _decode_source_payload(resp.read(MAX_SOURCE_BYTES + 1), url)
        except urllib.error.HTTPError as e:
            if e.code in RETRY_HTTP_CODES and attempt < FETCH_MAX_RETRIES - 1:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                try:
                    base_wait = float(retry_after) if retry_after else FETCH_RETRY_BACKOFF * (2 ** attempt)
                except (TypeError, ValueError):
                    base_wait = FETCH_RETRY_BACKOFF * (2 ** attempt)
                # Потолок Retry-After + уважение общего дедлайна: сон не длиннее
                # остатка, при котором ещё возможна одна полная попытка.
                usable = deadline - time.monotonic() - FETCH_TIMEOUT
                wait = min(base_wait + random.uniform(0.5, 2.0), RETRY_AFTER_CAP, max(usable, 0.0))
                if wait <= 0:
                    no_time(f"HTTP {e.code} требует паузы {base_wait:.0f} с")
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < FETCH_MAX_RETRIES - 1:
                usable = deadline - time.monotonic() - FETCH_TIMEOUT
                wait = min(FETCH_RETRY_BACKOFF * (2 ** attempt) + random.uniform(0.5, 1.5), max(usable, 0.0))
                if wait <= 0:
                    no_time("сеть недоступна, дедлайн истекает")
                time.sleep(wait)
                continue
            raise


def try_base64_decode(content):
    cleaned = "".join(content.split())
    if not cleaned:
        return None
    cleaned = cleaned.replace("-", "+").replace("_", "/")  # urlsafe-вариант base64 (vmess)
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return None


def scan_lines(text):
    found = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(SUPPORTED_SCHEMES):
            found.append(line)
    return found


def extract_configs(raw_text):
    direct = scan_lines(raw_text)
    if direct:
        return direct
    decoded = try_base64_decode(raw_text)
    if decoded is None:
        return []
    return scan_lines(decoded)


def is_safe_address(host):
    """Отсекает серые, локальные и мусорные IP-адреса, а также локальные имена хостов."""
    h = str(host).strip().rstrip(".").lower()
    if not h:
        return False
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False
    except ValueError:
        pass
    return True


# ---------- 2. Парсеры для фильтрации небезопасных IP и дедупликации ----------

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def vless_defect(line):
    """Проверяет СЫРЫЕ query-параметры vless (не распарсенный dict, где sni уже
    подставлен через fallback peer/host) и возвращает текст дефекта или None.

    Отбрасываются (согласовано с экспертом, суженная редакция):
    - невалидный UUID;
    - reality без pbk (подключиться нельзя) и reality без sni;
    - tls без sni, peer и host — строка без единого источника SNI.
    """
    try:
        body = line[len("vless://"):].split("#", 1)[0]
        url = urllib.parse.urlparse("vless://" + body)
        if not _UUID_RE.match(url.username or ""):
            return "vless: невалидный UUID"
        qs = urllib.parse.parse_qs(url.query)

        def q(name):
            v = qs.get(name)
            return (v[0] if v else "") or ""

        security = q("security").lower()
        if security == "reality":
            if not q("pbk"):
                return "vless: reality без pbk"
            if not q("sni"):
                return "vless: reality без sni"
        elif security == "tls" and not (q("sni") or q("peer") or q("host")):
            return "vless: tls без sni/peer/host"
    except Exception:
        return "vless: строка не разбирается"
    return None


def parse_vless(line):
    try:
        defect = vless_defect(line)
        if defect:
            return None
        body = line[len("vless://"):].split("#", 1)[0]
        parsed = urllib.parse.urlparse("vless://" + body)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port
        if not uuid or not host or not port:
            return None
        if not is_safe_address(host):
            return None

        qs = urllib.parse.parse_qs(parsed.query)

        def q(name, default=""):
            v = qs.get(name)
            return (v[0] if v else default) or default

        return {
            "protocol": "vless",
            "address": host,
            "port": port,
            "id": uuid,
            "net": q("type", "tcp"),
            "security": q("security", "none"),
            "sni": q("sni") or q("peer") or host,
            "path": q("path", "/"),
            "flow": q("flow"),
            "pbk": q("pbk"),
            "sid": q("sid"),
        }
    except Exception:
        return None


def parse_vmess(line):
    """Разбирает стандартный vmess:// (Base64 JSON)."""
    try:
        raw_b64 = line[len("vmess://"):].split("#", 1)[0].strip()
        decoded = try_base64_decode(raw_b64)
        if not decoded:
            return None
        data = json.loads(decoded)
        if not isinstance(data, dict):
            return None

        host = str(data.get("add") or "").strip()
        port = int(data.get("port") or 0)
        uuid = str(data.get("id") or "").strip()
        if not host or not port or not uuid:
            return None
        if not is_safe_address(host):
            return None

        tls_raw = str(data.get("tls") or "").strip().lower()
        if tls_raw not in ("", "none", "0", "false", "tls", "1", "true"):
            return None

        sec = "tls" if tls_raw in ("tls", "1", "true") else "none"
        sni = str(data.get("sni") or data.get("host") or host).strip()
        path = str(data.get("path") or "/").strip() or "/"

        return {
            "protocol": "vmess",
            "address": host,
            "port": port,
            "id": uuid,
            "net": str(data.get("net") or "tcp"),
            "security": sec,
            "sni": sni,
            "path": path,
            "flow": "",
            "pbk": "",
            "sid": "",
        }
    except Exception:
        return None


def parse_config_line(line):
    if line.startswith("vless://"):
        return parse_vless(line)
    if line.startswith("vmess://"):
        return parse_vmess(line)
    return None


def reject_reason(line):
    """Классифицирует отброшенную строку vless/vmess для счётчиков в логе."""
    if line.startswith("vless://"):
        defect = vless_defect(line)
        if defect:
            return defect
        try:
            body = line[len("vless://"):].split("#", 1)[0]
            host = urllib.parse.urlparse("vless://" + body).hostname
            if host and not is_safe_address(host):
                return "vless: серый/локальный IP"
        except Exception:
            pass
        return "vless: битая строка"
    try:
        raw_b64 = line[len("vmess://"):].split("#", 1)[0].strip()
        decoded = try_base64_decode(raw_b64)
        data = json.loads(decoded) if decoded else None
        host = str((data or {}).get("add") or "").strip() if isinstance(data, dict) else ""
        if host and not is_safe_address(host):
            return "vmess: серый/локальный IP"
    except Exception:
        pass
    return "vmess: битая строка"


def _other_scheme_host(line):
    """(host, port) для trojan/ss/hysteria2/hy2/tuic/wireguard; None — не разобрали.

    ss поддерживает оба формата: SIP002 (base64-userinfo@host:port) и legacy
    (base64(method:pass@host:port) целиком). Не разобранный адрес — не повод
    отбрасывать строку (проверяем только то, что уверенно распознали).
    """
    scheme, sep, body = line.partition("://")
    if not sep:
        return None
    body = body.split("#", 1)[0].strip()
    if not body:
        return None
    if scheme == "ss":
        if "@" in body:
            hostpart = body.rsplit("@", 1)[1]      # SIP002: хост справа от последнего @
        else:
            decoded = try_base64_decode(body)      # legacy: весь payload base64
            if not decoded or "@" not in decoded:
                return None
            hostpart = decoded.rsplit("@", 1)[1]
        return _split_hostport(hostpart)
    try:
        url = urllib.parse.urlparse(f"{scheme}://{body}")
        if url.hostname and url.port:
            return url.hostname, url.port
    except ValueError:
        pass
    return None


def _split_hostport(hostpart):
    """(host, port) из 'host:port'/'[v6]:port'; query/path отсекаются urlparse."""
    try:
        url = urllib.parse.urlparse("//" + hostpart.strip())
        if url.hostname and url.port:
            return url.hostname, url.port
    except ValueError:
        pass
    return None


def process_line(line):
    """Единая проверка строки ДО дедупликации.

    Возвращает (parsed, reason): parsed — dict vless/vmess (для остальных схем
    None); reason — текст отказа или None, если строка принята. Проверка адреса
    распространена на все протоколы (vless/vmess — в парсерах, остальные — здесь).
    """
    if line.startswith(("vless://", "vmess://")):
        parsed = parse_config_line(line)
        if parsed is None:
            return None, reject_reason(line)
        return parsed, None
    host = _other_scheme_host(line)
    if host is not None and not is_safe_address(host[0]):
        scheme = line.split("://", 1)[0]
        return None, f"{scheme}: серый/локальный IP"
    return None, None


def _dedup_key(parsed, line):
    """
    Умная дедупликация:
    - для VLESS и VMess формирует структурный ключ по параметрам узла, включая
      транспорт (net) и параметры REALITY (pbk/sid/flow), чтобы не схлопывать
      разные серверы на одном host:port;
    - для остальных протоколов сравнивает URI без #remark.
    """
    if parsed:
        return (
            parsed["protocol"],
            parsed["id"].lower(),
            parsed["address"].lower(),
            parsed["port"],
            parsed["net"].lower(),
            parsed["security"].lower(),
            parsed["sni"].lower(),
            parsed.get("path", "/"),
            parsed.get("pbk", ""),
            parsed.get("sid", ""),
            parsed.get("flow", ""),
        )
    return ("raw", line.split("#", 1)[0].strip())


def make_dedup_key(line):
    """Ключ дедупликации по строке (обёртка _dedup_key для внешних вызовов)."""
    parsed = parse_config_line(line) if line.startswith(("vless://", "vmess://")) else None
    return _dedup_key(parsed, line)


# ---------- 3. Управление источниками и сохранением ----------

def _normalize_url(url):
    """`file:путь` (от корня репо) -> абсолютный file:// URL для urllib."""
    if url.startswith("file://"):
        return url
    if url.startswith("file:"):
        return "file://" + os.path.abspath(url[len("file:"):])
    return url


def load_sources(filepath):
    trusted_urls = []
    cepreu54_urls = []
    check_urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                url = line[1:].strip()
                if url:
                    trusted_urls.append(_normalize_url(url))
            elif line.startswith("@"):
                url = line[1:].strip()
                if url:
                    cepreu54_urls.append(_normalize_url(url))
            else:
                check_urls.append(_normalize_url(line))
    return trusted_urls, cepreu54_urls, check_urls


def fetch_batch(urls, label):
    """Загружает источники и СРАЗУ разбирает строки: каждый отказ и каждый
    отброс привязаны к своему источнику (атрибуция нужна для сводки №9).

    Возвращает список словарей в порядке urls (детерминированная обработка,
    дедуп-победитель не зависит от скорости потоков):
        {"url", "raw_count", "records": [(line, parsed)], "rejects": {причина: n}, "error"}
    Полный отказ всех источников — AggregationError (авария режима).
    """
    if not urls:
        return []
    print(f"[{label}] Загрузка {len(urls)} источников...", flush=True)
    collected = [None] * len(urls)
    failed = 0
    with ThreadPoolExecutor(max_workers=10) as fetcher:
        futures = {fetcher.submit(fetch_source, u): i for i, u in enumerate(urls)}
        for future in as_completed(futures):
            i = futures[future]
            u = urls[i]
            src = {"url": u, "raw_count": 0, "records": [], "rejects": {}, "error": None}
            collected[i] = src
            try:
                text = future.result()
                lines = extract_configs(text)
                src["raw_count"] = len(lines)
                for ln in lines:
                    parsed, reason = process_line(ln)
                    if reason:
                        src["rejects"][reason] = src["rejects"].get(reason, 0) + 1
                    else:
                        src["records"].append((ln, parsed))
                rejected = sum(src["rejects"].values())
                if not lines:
                    print(f"OK  (     0) {u}", flush=True)
                    print(f"WARN {u}: 0 строк конфигов — проверьте доступность источника.", flush=True)
                elif rejected:
                    print(f"OK  ({len(lines):6d}, отклонено {rejected}) {u}", flush=True)
                else:
                    print(f"OK  ({len(lines):6d}) {u}", flush=True)
            except Exception as e:
                src["error"] = str(e)
                failed += 1
                print(f"ERR           {u} -> {e}", flush=True)
    if failed:
        print(f"[{label}] Недоступно источников: {failed} из {len(urls)}", flush=True)
    if failed == len(urls):
        # Полный отказ источников — авария режима; прежние файлы остаются нетронутыми.
        raise AggregationError(f"[{label}] Все {len(urls)} источников недоступны")
    return collected


def _atomic_write_pair(plain_path, plain_text, b64_path, b64_text):
    """Атомарная запись пары (plain, base64): оба .tmp, затем два os.replace.

    Обрыв в середине не оставит ни битого, ни рассинхронизированного файла:
    в худшем случае один файл пары остаётся прежним, но целым.
    """
    os.makedirs(os.path.dirname(plain_path) or ".", exist_ok=True)
    tmp_plain, tmp_b64 = plain_path + ".tmp", b64_path + ".tmp"
    with open(tmp_plain, "w", encoding="utf-8") as f:
        f.write(plain_text)
    with open(tmp_b64, "w", encoding="utf-8") as f:
        f.write(b64_text)
    os.replace(tmp_plain, plain_path)
    os.replace(tmp_b64, b64_path)


def _file_line_count(path):
    """Число непустых строк существующего файла; файла нет — 0."""
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def save_subscription(lines, prefix, allow_shrink=False):
    if len(lines) < MIN_SUBSCRIPTION_LINES:
        print(
            f"[{prefix}] Получено {len(lines)} строк — сохранение прервано, "
            "прежние файлы подписки не изменяются.",
            flush=True,
        )
        raise AggregationError(f"[{prefix}] пустой результат ({len(lines)} строк)")

    final_lines = lines[:MAX_LINES]
    if len(lines) > MAX_LINES:
        print(f"[{prefix}] Обрезано до {MAX_LINES} строк (было {len(lines)}).", flush=True)

    plain_path = f"{OUT_DIR}/{prefix}.txt"
    b64_path = f"{OUT_DIR}/{prefix}_base64.txt"

    # Защита от деградации: сравнение с прежним plain-файлом ДО записи.
    if not allow_shrink:
        old_count = _file_line_count(plain_path)
        if old_count >= SHRINK_BASELINE_MIN and len(final_lines) * 2 < old_count:
            print(
                f"ERROR [{prefix}] деградация результата: в прежнем файле {old_count} строк, "
                f"новый результат {len(final_lines)} (<50%) — запись отменена, прежние файлы "
                "сохранены. Если сокращение закономерно (источник удалён навсегда), "
                "запустите workflow с allow_shrink = true.",
                flush=True,
            )
            raise ShrinkRejected(
                f"[{prefix}] деградация результата: {old_count} -> {len(final_lines)} строк")

    plain_text = "\n".join(final_lines) + "\n"
    b64_text = base64.b64encode("\r\n".join(final_lines).encode("utf-8")).decode("ascii")
    _atomic_write_pair(plain_path, plain_text, b64_path, b64_text)

    print(f"Сохранено в {plain_path} и {b64_path}: {len(final_lines)} серверов.", flush=True)


def transport_of(line, parsed=None):
    """Транспорт (net/type) строки конфига; splithttp считается синонимом xhttp."""
    if parsed is None and line.startswith(("vless://", "vmess://")):
        parsed = parse_config_line(line)
    if parsed:
        net = parsed["net"].lower()
    else:
        try:
            body = line.split("://", 1)[1].split("#", 1)[0]
            qs = urllib.parse.parse_qs(urllib.parse.urlparse("x://" + body).query)
            net = (qs.get("type") or qs.get("net") or [""])[0].lower()
        except Exception:
            net = ""
    return "xhttp" if net == "splithttp" else net


def save_xhttp_subscription(lines, prefix):
    """№6: отдельная подписка только из xhttp/grpc-строк.

    Пустой результат файл не затирает (и не создаёт, если его ещё нет) — WARN в лог.
    """
    xlines = [line for line in lines if transport_of(line) in XHTTP_TRANSPORTS]
    plain_path = f"{OUT_DIR}/{prefix}_xhttp.txt"
    b64_path = f"{OUT_DIR}/{prefix}_xhttp_base64.txt"
    if not xlines:
        print(
            f"WARN [{prefix}] xhttp/grpc строк 0 — {plain_path} не создаётся/не обновляется.",
            flush=True,
        )
        return 0
    plain_text = "\n".join(xlines) + "\n"
    b64_text = base64.b64encode("\r\n".join(xlines).encode("utf-8")).decode("ascii")
    _atomic_write_pair(plain_path, plain_text, b64_path, b64_text)
    print(f"Сохранено в {plain_path} и {b64_path}: {len(xlines)} серверов (только xhttp/grpc).", flush=True)
    return len(xlines)


def run_group(urls, label, prefix, dedup=True, allow_shrink=False, also_xhttp=False):
    """Собирает группу: загрузка с разбором на месте, дедуп, сохранение.

    Дедуп-победитель — первый источник в порядке subscription-sources.txt
    (детерминировано, независимо от скорости потоков). Счётчики дублей:
    внутри одного источника и перекрытые другим, более ранним источником.
    Возвращает статистику для сводки по источникам или False, если режим
    пропущен (нет источников).
    """
    if not urls:
        print(f"[{label}] Источники не заданы — пропуск режима.", flush=True)
        return False
    sources = fetch_batch(urls, label)

    kept = []                       # [(line, idx источника)]
    seen = {}                       # ключ дедупа -> idx источника-победителя
    intra = [0] * len(sources)      # дубли внутри одного источника
    cross = [0] * len(sources)      # дубли, перекрытые более ранним источником
    raw_classes = {"reality": 0, "other": 0}  # счётчик tcp/raw (ТСПУ-классы)

    for idx, src in enumerate(sources):
        for line, parsed in src["records"]:
            if dedup:
                key = _dedup_key(parsed, line)
                first = seen.get(key)
                if first is not None:
                    if first == idx:
                        intra[idx] += 1
                    else:
                        cross[idx] += 1
                    continue
                seen[key] = idx
            kept.append((line, idx))
            if parsed and parsed["net"].lower() in ("tcp", "raw"):
                cls = "reality" if parsed["security"].lower() == "reality" else "other"
                raw_classes[cls] += 1

    lines = [line for line, _ in kept]
    total_raw = sum(s["raw_count"] for s in sources)
    total_rejected = sum(sum(s["rejects"].values()) for s in sources)
    total_dup = sum(intra) + sum(cross)
    print(
        f"[{prefix.upper()}] Собрано строк: {total_raw} | Принято после дедупа: {len(lines)}"
        f" | Отклонено при разборе: {total_rejected} | Дублей: {total_dup}"
        f" (внутри источников {sum(intra)}, между источниками {sum(cross)})",
        flush=True,
    )
    for idx, src in enumerate(sources):
        if src["rejects"]:
            details = ", ".join(f"{k}: {v}" for k, v in sorted(src["rejects"].items()))
            print(f"  [{prefix}] {src['url']}: отклонено {sum(src['rejects'].values())} ({details})", flush=True)

    save_subscription(lines, prefix, allow_shrink=allow_shrink)
    if also_xhttp:
        save_xhttp_subscription(lines, prefix)

    contribution = {}
    for _, idx in kept:
        contribution[idx] = contribution.get(idx, 0) + 1
    return {
        "label": label,
        "prefix": prefix,
        "sources": sources,
        "intra": intra,
        "cross": cross,
        "contribution": [contribution.get(i, 0) for i in range(len(sources))],
        "kept": len(lines),
        "raw_classes": raw_classes,
    }


# ---------- 3b. Сводка по источникам ($GITHUB_STEP_SUMMARY, №9) ----------

_REJECT_SHORT = {
    "vless: невалидный UUID": "uuid",
    "vless: reality без pbk": "reality-pbk",
    "vless: reality без sni": "reality-sni",
    "vless: tls без sni/peer/host": "tls-sni",
    "vless: битая строка": "vless-битая",
    "vless: строка не разбирается": "vless-битая",
    "vless: серый/локальный IP": "vless-серый",
    "vmess: битая строка": "vmess-битая",
    "vmess: серый/локальный IP": "vmess-серый",
}


def _short_reason(reason):
    short = _REJECT_SHORT.get(reason)
    if short:
        return short
    return reason.replace("серый/локальный IP", "серый IP").replace(": ", "=")


def _cell(value):
    """Ячейка markdown-таблицы: | экранируется, чтобы не ломать колонки."""
    return str(value).replace("|", "\\|")


def format_summary(group_stats):
    """Markdown-сводка по источникам: по строке на источник + счётчик tcp/raw."""
    out = ["## Сводка по источникам", ""]
    for gs in group_stats:
        out += [
            f"### {gs['prefix']} ({gs['label']})",
            "",
            "| Источник | Строк | Откл. при разборе | Дублей внутри | Перекрыт др. ист. | В файле | Статус |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
        for idx, src in enumerate(gs["sources"]):
            url = _cell(src["url"])
            if src["error"]:
                out.append(f"| {url} | — | — | — | — | — | ERR: {_cell(src['error'])} |")
                continue
            rejected = sum(src["rejects"].values())
            if rejected:
                details = ", ".join(
                    f"{_short_reason(r)} {n}" for r, n in sorted(src["rejects"].items()))
                rej = f"{rejected} ({details})"
            else:
                rej = "0"
            status = "**0 строк**" if src["raw_count"] == 0 else "ok"
            out.append(
                f"| {url} | {src['raw_count']} | {_cell(rej)} | {gs['intra'][idx]}"
                f" | {gs['cross'][idx]} | {gs['contribution'][idx]} | {status} |")
        out.append(
            f"| **Итого {gs['prefix']}** | {sum(s['raw_count'] for s in gs['sources'])}"
            f" | {sum(sum(s['rejects'].values()) for s in gs['sources'])}"
            f" | {sum(gs['intra'])} | {sum(gs['cross'])} | {gs['kept']} | |")
        out.append("")

    reality = sum(gs["raw_classes"]["reality"] for gs in group_stats)
    other = sum(gs["raw_classes"]["other"] for gs in group_stats)
    out += [
        "## Транспорт tcp/raw (классы ТСПУ)",
        "",
        "| Класс | Строк в файлах |",
        "|---|---:|",
        f"| tcp/raw + reality (блокируемый ТСПУ) | {reality} |",
        f"| tcp/raw прочие | {other} |",
        "",
    ]
    return "\n".join(out).rstrip() + "\n"


def write_summary(md_text):
    """Сводка — в лог и (если задан) в файл $GITHUB_STEP_SUMMARY."""
    print(md_text, flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(md_text if md_text.endswith("\n") else md_text + "\n")
    except OSError as e:
        print(f"WARN не удалось записать $GITHUB_STEP_SUMMARY: {e}", flush=True)


# ---------- 4. Точка входа ----------

def build_parser():
    parser = argparse.ArgumentParser(description="VPN Subscription Aggregator")
    parser.add_argument(
        "--mode",
        choices=["trusted", "cepreu54", "checked", "all"],
        default="all",
        help="Режим сборки: trusted (Igareck), cepreu54 (Cepreu54), checked (прямой сбор), all (все)",
    )
    parser.add_argument(
        "--allow-shrink",
        action="store_true",
        help="Разрешить запись при деградации (<50%% строк прежнего файла); "
             "для закономерных сокращений (источник удалён навсегда)",
    )
    return parser


def main():
    args = build_parser().parse_args()
    # №1: общий дедлайн сбора привязан к старту процесса (один на все источники).
    _process_deadline()

    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден!", flush=True)
        raise SystemExit(1)

    trusted_urls, cepreu54_urls, check_urls = load_sources(SOURCES_FILE)

    # Режимы независимы: авария одного (упавшие источники, пустой результат,
    # деградация) не блокирует сборку остальных. Job краснеет, если упал хотя бы один.
    failures = []
    group_stats = []

    if args.mode in ("trusted", "all"):
        try:
            stats = run_group(trusted_urls, "IGARECK/TRUSTED", "igareck", dedup=True,
                              allow_shrink=args.allow_shrink, also_xhttp=True)
            if stats:
                group_stats.append(stats)
        except AggregationError as e:
            print(f"ERROR {e}", flush=True)
            failures.append("trusted")

    if args.mode in ("cepreu54", "all"):
        try:
            stats = run_group(cepreu54_urls, "CEPREU54", "cepreu54", dedup=True,
                              allow_shrink=args.allow_shrink, also_xhttp=True)
            if stats:
                group_stats.append(stats)
        except AggregationError as e:
            print(f"ERROR {e}", flush=True)
            failures.append("cepreu54")

    if args.mode in ("checked", "all"):
        try:
            stats = run_group(check_urls, "CHECKED", "checked", dedup=True, allow_shrink=args.allow_shrink)
            if stats:
                group_stats.append(stats)
        except AggregationError as e:
            print(f"ERROR {e}", flush=True)
            failures.append("checked")

    if group_stats:
        write_summary(format_summary(group_stats))

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
