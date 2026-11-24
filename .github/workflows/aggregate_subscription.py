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
"""
import argparse
import base64
import ipaddress
import json
import os
import random
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

    domain = urllib.parse.urlparse(url).netloc.lower()
    delay = DOMAIN_DELAYS.get(domain, DEFAULT_DOMAIN_DELAY)

    for attempt in range(FETCH_MAX_RETRIES):
        _wait_slot(domain, delay)
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
                time.sleep(base_wait + random.uniform(0.5, 2.0))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < FETCH_MAX_RETRIES - 1:
                time.sleep(FETCH_RETRY_BACKOFF * (2 ** attempt) + random.uniform(0.5, 1.5))
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
    """Отсекает серые, локальные и мусорные IP-адреса."""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False
    except ValueError:
        pass
    return True


# ---------- 2. Парсеры для фильтрации небезопасных IP и дедупликации ----------

def parse_vless(line):
    try:
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


def make_dedup_key(line):
    """
    Умная дедупликация:
    - для VLESS и VMess формирует структурный ключ по параметрам узла, включая
      транспорт (net) и параметры REALITY (pbk/sid/flow), чтобы не схлопывать
      разные серверы на одном host:port;
    - для остальных протоколов сравнивает URI без #remark.
    """
    parsed = parse_config_line(line)
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
    if not urls:
        return []
    print(f"[{label}] Загрузка {len(urls)} источников...", flush=True)
    collected, failed = [], 0
    with ThreadPoolExecutor(max_workers=10) as fetcher:
        futures = {fetcher.submit(fetch_source, u): u for u in urls}
        for future in as_completed(futures):
            u = futures[future]
            try:
                text = future.result()
                lines = extract_configs(text)
                collected.extend(lines)
                print(f"OK  ({len(lines):6d}) {u}", flush=True)
            except Exception as e:
                failed += 1
                print(f"ERR           {u} -> {e}", flush=True)
    if failed:
        print(f"[{label}] Недоступно источников: {failed} из {len(urls)}", flush=True)
    if failed == len(urls):
        # Полный отказ источников — авария режима; прежние файлы остаются нетронутыми.
        raise AggregationError(f"[{label}] Все {len(urls)} источников недоступны")
    return collected


def save_subscription(lines, prefix):
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

    os.makedirs(OUT_DIR, exist_ok=True)
    plain_path = f"{OUT_DIR}/{prefix}.txt"
    b64_path = f"{OUT_DIR}/{prefix}_base64.txt"

    with open(plain_path, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines) + "\n")

    b64 = base64.b64encode("\r\n".join(final_lines).encode("utf-8")).decode("ascii")
    with open(b64_path, "w", encoding="utf-8") as f:
        f.write(b64)

    print(f"Сохранено в {plain_path} и {b64_path}: {len(final_lines)} серверов.", flush=True)


def run_group(urls, label, prefix, dedup=True):
    if not urls:
        print(f"[{label}] Источники не заданы — пропуск режима.", flush=True)
        return False
    raw_lines = fetch_batch(urls, label)
    if dedup:
        seen, unique_lines, bad_lines = set(), [], 0
        for line in raw_lines:
            parsed = parse_config_line(line)
            if line.startswith(("vless://", "vmess://")) and not parsed:
                bad_lines += 1
                continue
            key = make_dedup_key(line)
            if key not in seen:
                seen.add(key)
                unique_lines.append(line)
        print(
            f"[{prefix.upper()}] Собрано строк: {len(raw_lines)} | Уникальных: {len(unique_lines)}"
            f" | Отброшено vless/vmess (битые/серые IP): {bad_lines}",
            flush=True,
        )
        lines = unique_lines
    else:
        print(f"[{prefix.upper()}] Собрано строк (без дедупликации): {len(raw_lines)}", flush=True)
        lines = raw_lines
    save_subscription(lines, prefix)


# ---------- 4. Точка входа ----------

def main():
    parser = argparse.ArgumentParser(description="VPN Subscription Aggregator")
    parser.add_argument(
        "--mode",
        choices=["trusted", "cepreu54", "checked", "all"],
        default="all",
        help="Режим сборки: trusted (Igareck), cepreu54 (Cepreu54), checked (прямой сбор), all (все)",
    )
    args = parser.parse_args()

    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден!", flush=True)
        raise SystemExit(1)

    trusted_urls, cepreu54_urls, check_urls = load_sources(SOURCES_FILE)

    # Режимы независимы: авария одного (упавшие источники, пустой результат)
    # не блокирует сборку остальных. Job краснеет, если упал хотя бы один.
    failures = []

    if args.mode in ("trusted", "all"):
        try:
            run_group(trusted_urls, "IGARECK/TRUSTED", "igareck", dedup=True)
        except AggregationError as e:
            print(f"ERROR {e}", flush=True)
            failures.append("trusted")

    if args.mode in ("cepreu54", "all"):
        try:
            run_group(cepreu54_urls, "CEPREU54", "cepreu54", dedup=True)
        except AggregationError as e:
            print(f"ERROR {e}", flush=True)
            failures.append("cepreu54")

    if args.mode in ("checked", "all"):
        try:
            run_group(check_urls, "CHECKED", "checked", dedup=False)
        except AggregationError as e:
            print(f"ERROR {e}", flush=True)
            failures.append("checked")

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
