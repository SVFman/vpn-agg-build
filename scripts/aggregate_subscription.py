#!/usr/bin/env python3
import base64
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES_FILE = "subscription-sources.txt"
OUT_DIR = "subscription"
PLAIN_OUT = f"{OUT_DIR}/aggregated.txt"
BASE64_OUT = f"{OUT_DIR}/aggregated_base64.txt"
FETCH_TIMEOUT = 12

MAX_LINES = 20000

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray")
CHECK_CONCURRENCY = int(os.environ.get("CHECK_CONCURRENCY", "40"))
PRE_FILTER_CONCURRENCY = 200
TCP_PRE_TIMEOUT = 1.2

# Эталонная проверка доступности в v2rayNG
TEST_URL = "https://www.gstatic.com/generate_204"
CURL_TIMEOUT = 4


# ---------- 1. Сбор и парсинг источников ----------

def fetch_source(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (GitHubActions) VpnAggregator/1.0"},
    )
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def try_base64_decode(content):
    cleaned = content.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    if not cleaned:
        return None
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
        if line.startswith("vless://"):
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


def parse_vless(line):
    """
    Разбирает VLESS URI с аккуратным извлечением всех параметров.
    """
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
            "flow": q("flow"),
            "network": q("type", "tcp") or "tcp",
            "security": q("security", "none") or "none",
            "sni": q("sni") or q("peer") or host,
            "fp": q("fp") or "chrome",
            "pbk": q("pbk"),
            "sid": q("sid"),
            "spx": q("spx"),
            "path": q("path", "/") or "/",
            "host_header": q("host"),
            "service_name": q("serviceName"),
            "alpn": q("alpn"),
        }
    except Exception:
        return None


# ---------- 2. TCP Pre-check и порты ----------

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=1.5):
    """
    Ожидает поднятия локального SOCKS-порта ядром Xray.
    Устраняет race condition при старте процессов.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except Exception:
            time.sleep(0.04)
    return False


def fast_tcp_check(item):
    _, parsed = item
    try:
        with socket.create_connection((parsed["address"], int(parsed["port"])), timeout=TCP_PRE_TIMEOUT):
            return item, True
    except Exception:
        return item, False


# ---------- 3. Тест через Xray ----------

def build_xray_config(p, socks_port):
    net = (p.get("network") or "tcp").lower()
    sec = (p.get("security") or "none").lower()
    sni = p.get("sni") or p.get("address")

    stream = {
        "network": net,
        "security": sec,
    }

    # Транспорт
    if net == "ws":
        ws_settings = {"path": p.get("path") or "/"}
        host = p.get("host_header") or p.get("sni")
        if host:
            ws_settings["headers"] = {"Host": host}
        stream["wsSettings"] = ws_settings

    elif net == "grpc":
        grpc_settings = {"multiMode": False}
        if p.get("service_name"):
            grpc_settings["serviceName"] = p["service_name"]
        stream["grpcSettings"] = grpc_settings

    elif net in ("h2", "http"):
        http_settings = {"path": p.get("path") or "/"}
        host = p.get("host_header") or p.get("sni")
        if host:
            http_settings["host"] = [host]
        stream["httpSettings"] = http_settings

    # Безопасность
    if sec == "tls":
        tls_settings = {
            "serverName": sni,
            "allowInsecure": True,
            "fingerprint": p.get("fp") or "chrome",
        }
        if p.get("alpn"):
            tls_settings["alpn"] = [a.strip() for a in p["alpn"].split(",") if a.strip()]
        stream["tlsSettings"] = tls_settings

    elif sec == "reality":
        reality_settings = {
            "serverName": sni,
            "fingerprint": p.get("fp") or "chrome",
            "publicKey": p.get("pbk") or "",
        }
        if p.get("sid"):
            reality_settings["shortId"] = p["sid"]
        if p.get("spx"):
            reality_settings["spiderX"] = p["spx"]
        stream["realitySettings"] = reality_settings

    # Пользователь
    user = {
        "id": p["id"],
        "encryption": "none",
    }

    # flow (xtls-rprx-vision) поддерживается ядром только для TCP + TLS/Reality
    raw_flow = (p.get("flow") or "").strip()
    if raw_flow and net == "tcp" and sec in ("tls", "reality"):
        user["flow"] = raw_flow

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": p["address"],
                "port": int(p["port"]),
                "users": [user]
            }]
        },
        "streamSettings": stream,
    }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }


def check_config(parsed):
    socks_port = get_free_port()
    config = build_xray_config(parsed, socks_port)
    config_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            config_path = f.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not wait_for_port(socks_port, timeout=1.5):
            return False

        result = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", str(CURL_TIMEOUT),
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                TEST_URL,
            ],
            capture_output=True, text=True, timeout=CURL_TIMEOUT + 2,
        )
        return result.stdout.strip() in ("204", "200")
    except Exception:
        return False
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass
        if config_path:
            try:
                os.remove(config_path)
            except Exception:
                pass


# ---------- 4. Основной сценарий ----------

def main():
    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден!", flush=True)
        return

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Параллельная загрузка {len(urls)} источников...", flush=True)
    all_lines = []
    errors = 0

    with ThreadPoolExecutor(max_workers=10) as fetcher:
        futures = {fetcher.submit(fetch_source, u): u for u in urls}
        for future in as_completed(futures):
            u = futures[future]
            try:
                text = future.result()
                lines = extract_configs(text)
                all_lines.extend(lines)
                print(f"OK  ({len(lines):6d}) {u}", flush=True)
            except Exception as e:
                errors += 1
                print(f"ERR           {u} -> {e}", flush=True)

    # Умная дедупликация: учитывает UUID, хост, порт, протокол безопасности и SNI,
    # чтобы не заменять рабочие варианты под белые списки нерабочими дубликатами.
    seen = set()
    candidates = []
    for line in all_lines:
        parsed = parse_vless(line)
        if not parsed:
            continue
        key = (
            parsed["id"],
            parsed["address"].lower(),
            parsed["port"],
            parsed["security"].lower(),
            parsed["sni"].lower(),
        )
        if key not in seen:
            seen.add(key)
            candidates.append((line, parsed))

    print("----", flush=True)
    print(f"Собрано сырых VLESS строк: {len(all_lines)}", flush=True)
    print(f"Уникальных кандидатов: {len(candidates)}", flush=True)

    if not candidates:
        print("Подходящих VLESS серверов не найдено.", flush=True)
        return

    # Этап 1: Быстрый TCP pre-check
    print(f"Этап 1: TCP pre-check ({len(candidates)} хостов)...", flush=True)
    live_candidates = []
    tcp_checked = 0
    with ThreadPoolExecutor(max_workers=PRE_FILTER_CONCURRENCY) as pre_exec:
        futures = [pre_exec.submit(fast_tcp_check, c) for c in candidates]
        for f in as_completed(futures):
            item, is_alive = f.result()
            tcp_checked += 1
            if is_alive:
                live_candidates.append(item)
            if tcp_checked % 1000 == 0 or tcp_checked == len(candidates):
                print(f"  TCP чек: {tcp_checked}/{len(candidates)} | Доступно по порту: {len(live_candidates)}", flush=True)

    print(f"Живых хостов для Xray: {len(live_candidates)} из {len(candidates)}", flush=True)

    # Этап 2: Проверка через Xray
    print(f"Этап 2: Проверка через Xray (цель: generate_204, параллельность {CHECK_CONCURRENCY})...", flush=True)
    working_lines = []
    xray_checked = 0
    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as executor:
        future_map = {executor.submit(check_config, parsed): line for line, parsed in live_candidates}
        for future in as_completed(future_map):
            line = future_map[future]
            xray_checked += 1
            try:
                if future.result():
                    working_lines.append(line)
            except Exception:
                pass
            if xray_checked % 50 == 0 or xray_checked == len(live_candidates):
                print(f"  Xray чек: {xray_checked}/{len(live_candidates)} | Рабочих: {len(working_lines)}", flush=True)

    # Запись результатов в файлы
    final_lines = working_lines[:MAX_LINES]
    os.makedirs(OUT_DIR, exist_ok=True)

    with open(PLAIN_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    b64 = base64.b64encode("\n".join(final_lines).encode("utf-8")).decode("ascii")
    with open(BASE64_OUT, "w", encoding="utf-8") as f:
        f.write(b64)

    print(f"Готово! В подписку v2rayNG записано серверов: {len(final_lines)}", flush=True)


if __name__ == "__main__":
    main()
