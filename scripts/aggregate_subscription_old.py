#!/usr/bin/env python3
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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES_FILE = "subscription-sources.txt"
OUT_DIR = "subscription"
FETCH_TIMEOUT = 15
FETCH_MAX_RETRIES = 4
FETCH_RETRY_BACKOFF = 3       # секунд; удваивается с каждой повторной попыткой
MAX_SOURCE_BYTES = 5 * 1024 * 1024  # лимит 5 МБ на один источник для защиты от OOM
MAX_LINES = 20000

DOMAIN_DELAYS = {
    "gitverse.ru": 1.5,
    "raw.githubusercontent.com": 0.05,
    "gist.githubusercontent.com": 0.05,
}
DEFAULT_DOMAIN_DELAY = 0.5

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

_domain_locks = defaultdict(threading.Lock)
_domain_last_req = {}


# ---------- 1. Сбор и декодирование источников (с повторными попытками и лимитами по доменам) ----------

def fetch_source(url):
    domain = urllib.parse.urlparse(url).netloc.lower()
    delay = DOMAIN_DELAYS.get(domain, DEFAULT_DOMAIN_DELAY)
    last_error = None

    with _domain_locks[domain]:
        for attempt in range(FETCH_MAX_RETRIES):
            elapsed = time.monotonic() - _domain_last_req.get(domain, 0.0)
            if elapsed < delay:
                time.sleep(delay - elapsed)
            _domain_last_req[domain] = time.monotonic()

            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept": "text/plain,text/html,*/*;q=0.8",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                    return resp.read(MAX_SOURCE_BYTES).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                last_error = e
                if e.code in (429, 502, 503, 504) and attempt < FETCH_MAX_RETRIES - 1:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    try:
                        base_wait = float(retry_after) if retry_after else FETCH_RETRY_BACKOFF * (2 ** attempt)
                    except (TypeError, ValueError):
                        base_wait = FETCH_RETRY_BACKOFF * (2 ** attempt)
                    time.sleep(base_wait + random.uniform(0.5, 2.0))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as e:
                last_error = e
                if attempt < FETCH_MAX_RETRIES - 1:
                    time.sleep(FETCH_RETRY_BACKOFF * (2 ** attempt) + random.uniform(0.5, 1.5))
                    continue
                raise

    raise last_error


def try_base64_decode(content):
    cleaned = "".join(content.split())
    if not cleaned:
        return None
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return None


def scan_lines(text, schemes=SUPPORTED_SCHEMES):
    found = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(schemes):
            found.append(line)
    return found


def extract_configs(raw_text, schemes=SUPPORTED_SCHEMES):
    direct = scan_lines(raw_text, schemes)
    if direct:
        return direct
    decoded = try_base64_decode(raw_text)
    if decoded is None:
        return []
    return scan_lines(decoded, schemes)


def is_safe_address(host):
    """Отсекает серые, локальные и мусорные IP-адреса."""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False
    except ValueError:
        pass
    return True


# ---------- 2. Парсеры для фильтрации небезопасных IP и дедупликации Igareck ----------

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
            return v[0] if v else default

        return {
            "protocol": "vless",
            "address": host,
            "port": int(port),
            "id": uuid,
            "security": q("security", "none") or "none",
            "sni": q("sni") or q("peer") or host,
            "path": q("path", "/") or "/",
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
            "security": sec,
            "sni": sni,
            "path": path,
        }
    except Exception:
        return None


def parse_config_line(line):
    if line.startswith("vless://"):
        return parse_vless(line)
    if line.startswith("vmess://"):
        return parse_vmess(line)
    return None


def make_dedup_key(line, parsed=None):
    """
    Умная дедупликация:
    - для VLESS и VMess формирует структурный ключ по параметрам узла;
    - для остальных протоколов из доверенного списка сравнивает URI без #remark.
    """
    if parsed is None:
        parsed = parse_config_line(line)

    if parsed:
        return (
            parsed["protocol"],
            parsed["id"],
            parsed["address"].lower(),
            parsed["port"],
            parsed["security"].lower(),
            parsed["sni"].lower(),
            parsed.get("path", "/"),
        )
    return ("raw", line.split("#", 1)[0].strip())


# ---------- 3. Управление источниками и сохранением ----------

def load_sources(filepath):
    trusted_urls = []
    check_urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                url = line[1:].strip()
                if url:
                    trusted_urls.append(url)
            else:
                check_urls.append(line)
    return trusted_urls, check_urls


def fetch_batch(urls, label, schemes=SUPPORTED_SCHEMES):
    if not urls:
        return []
    print(f"[{label}] Загрузка {len(urls)} источников...", flush=True)
    collected = []
    with ThreadPoolExecutor(max_workers=10) as fetcher:
        futures = {fetcher.submit(fetch_source, u): u for u in urls}
        for future in as_completed(futures):
            u = futures[future]
            try:
                text = future.result()
                lines = extract_configs(text, schemes=schemes)
                collected.extend(lines)
                print(f"OK  ({len(lines):6d}) {u}", flush=True)
            except Exception as e:
                print(f"ERR           {u} -> {e}", flush=True)
    return collected


def save_subscription(lines, prefix):
    final_lines = lines[:MAX_LINES]
    os.makedirs(OUT_DIR, exist_ok=True)
    plain_path = f"{OUT_DIR}/{prefix}.txt"
    b64_path = f"{OUT_DIR}/{prefix}_base64.txt"

    with open(plain_path, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    b64 = base64.b64encode("\r\n".join(final_lines).encode("utf-8")).decode("ascii")
    with open(b64_path, "w", encoding="utf-8") as f:
        f.write(b64)

    print(f"Сохранено в {plain_path} и {b64_path}: {len(final_lines)} серверов.", flush=True)


def run_trusted(trusted_urls):
    seen = set()
    trusted_raw = fetch_batch(trusted_urls, "IGARECK/TRUSTED")
    trusted_lines = []
    for line in trusted_raw:
        parsed = parse_config_line(line)
        if line.startswith(("vless://", "vmess://")) and not parsed:
            continue
        key = make_dedup_key(line, parsed)
        if key not in seen:
            seen.add(key)
            trusted_lines.append(line)

    print("----", flush=True)
    print(f"[IGARECK] Собрано строк: {len(trusted_raw)} | Уникальных: {len(trusted_lines)}", flush=True)
    save_subscription(trusted_lines, "igareck")


def run_checked(check_urls):
    # Прямой сбор без дедупликации и без проверки TCP/TLS
    check_raw = fetch_batch(check_urls, "CHECKED")
    print("----", flush=True)
    print(f"[CHECKED] Собрано строк (без дедупликации и проверок): {len(check_raw)}", flush=True)
    save_subscription(check_raw, "checked")


# ---------- 4. Точка входа ----------

def main():
    parser = argparse.ArgumentParser(description="VPN Subscription Aggregator")
    parser.add_argument(
        "--mode",
        choices=["trusted", "checked", "all"],
        default="all",
        help="Режим сборки: trusted (Igareck с дедупом), checked (прямой сбор), all (оба)",
    )
    args = parser.parse_args()

    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден!", flush=True)
        return

    trusted_urls, check_urls = load_sources(SOURCES_FILE)

    if args.mode in ("trusted", "all"):
        run_trusted(trusted_urls)

    if args.mode in ("checked", "all"):
        run_checked(check_urls)


if __name__ == "__main__":
    main()
