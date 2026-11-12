#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import json
import os
import queue
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES_FILE = "subscription-sources.txt"
OUT_DIR = "subscription"
FETCH_TIMEOUT = 12

MAX_LINES = 20000

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray")
CHECK_CONCURRENCY = int(os.environ.get("CHECK_CONCURRENCY", "70"))
PRE_FILTER_CONCURRENCY = 250
TCP_PRE_TIMEOUT = 1.0
TLS_PRE_TIMEOUT = 1.2

TEST_URL = "https://www.gstatic.com/generate_204"
CURL_TIMEOUT = 2.5

TRUSTED_SCHEMES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hy2://",
    "hysteria2://",
    "tuic://",
    "wireguard://",
)

CHECKED_SCHEMES = ("vless://", "vmess://")

PORT_POOL = queue.Queue()
for _p in range(30000, 45000):
    PORT_POOL.put(_p)


# ---------- 1. Сбор и декодирование источников ----------

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


def scan_lines(text, schemes):
    found = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(schemes):
            found.append(line)
    return found


def extract_configs(raw_text, schemes):
    direct = scan_lines(raw_text, schemes)
    if direct:
        return direct
    decoded = try_base64_decode(raw_text)
    if decoded is None:
        return []
    return scan_lines(decoded, schemes)


def is_safe_address(host):
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False
    except ValueError:
        pass
    return True


# ---------- 2. Парсеры VLESS и VMess ----------

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


def parse_vmess(line):
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

        net = str(data.get("net") or "tcp").lower()
        tls_raw = str(data.get("tls") or "").lower()
        sec = "tls" if tls_raw in ("tls", "1", "true") else "none"
        sni = str(data.get("sni") or data.get("host") or host).strip()
        host_header = str(data.get("host") or "").strip()
        path = str(data.get("path") or "/").strip() or "/"
        aid = int(data.get("aid") or 0)
        scy = str(data.get("scy") or "auto").strip() or "auto"

        return {
            "protocol": "vmess",
            "address": host,
            "port": port,
            "id": uuid,
            "alterId": aid,
            "security_vmess": scy,
            "network": net,
            "security": sec,
            "sni": sni,
            "fp": str(data.get("fp") or "chrome"),
            "path": path,
            "host_header": host_header,
            "service_name": path if net == "grpc" else "",
            "alpn": str(data.get("alpn") or ""),
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


# ---------- 3. Быстрые сетевые фильтры ----------

def wait_for_port(port, timeout=1.5):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except Exception:
            time.sleep(0.04)
    return False


TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE


def fast_socket_and_tls_check(item):
    _, parsed = item
    host = parsed["address"]
    port = int(parsed["port"])
    sec = (parsed.get("security") or "none").lower()
    sni = parsed.get("sni") or host

    try:
        with socket.create_connection((host, port), timeout=TCP_PRE_TIMEOUT) as raw_sock:
            if sec == "tls":
                raw_sock.settimeout(TLS_PRE_TIMEOUT)
                with TLS_CTX.wrap_socket(raw_sock, server_hostname=sni):
                    return item, True
            return item, True
    except Exception:
        return item, False


# ---------- 4. Сборка JSON и проверка через Xray ----------

def build_xray_config(p, socks_port):
    proto = p["protocol"]
    net = (p.get("network") or "tcp").lower()
    sec = (p.get("security") or "none").lower()
    sni = p.get("sni") or p.get("address")

    stream = {
        "network": net,
        "security": sec,
    }

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

    if proto == "vless":
        user = {
            "id": p["id"],
            "encryption": "none",
        }
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
    else:
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": p["address"],
                    "port": int(p["port"]),
                    "users": [{
                        "id": p["id"],
                        "alterId": p.get("alterId", 0),
                        "security": p.get("security_vmess", "auto"),
                    }]
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
    socks_port = PORT_POOL.get()
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
            capture_output=True, text=True, timeout=CURL_TIMEOUT + 1.5,
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
        PORT_POOL.put(socks_port)


# ---------- 5. Управление источниками и сохранением ----------

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


def fetch_batch(urls, schemes, label):
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
    trusted_raw = fetch_batch(trusted_urls, TRUSTED_SCHEMES, "IGARECK/TRUSTED")
    trusted_lines = []
    for line in trusted_raw:
        parsed = parse_config_line(line)
        if line.startswith(CHECKED_SCHEMES) and not parsed:
            continue
        key = make_dedup_key(line, parsed)
        if key not in seen:
            seen.add(key)
            trusted_lines.append(line)

    print("----", flush=True)
    print(f"[IGARECK] Собрано строк: {len(trusted_raw)} | Уникальных: {len(trusted_lines)}", flush=True)
    save_subscription(trusted_lines, "igareck")


def run_checked(check_urls):
    seen = set()
    check_raw = fetch_batch(check_urls, CHECKED_SCHEMES, "CHECKED")
    candidates = []
    for line in check_raw:
        parsed = parse_config_line(line)
        if not parsed:
            continue
        key = make_dedup_key(line, parsed)
        if key not in seen:
            seen.add(key)
            candidates.append((line, parsed))

    print("----", flush=True)
    print(f"[CHECKED] Собрано строк: {len(check_raw)} | Уникальных кандидатов: {len(candidates)}", flush=True)

    working_lines = []
    if candidates:
        print(f"Этап 1: Быстрый TCP + TLS pre-check ({len(candidates)} хостов)...", flush=True)
        live_candidates = []
        pre_checked = 0
        with ThreadPoolExecutor(max_workers=PRE_FILTER_CONCURRENCY) as pre_exec:
            futures = [pre_exec.submit(fast_socket_and_tls_check, c) for c in candidates]
            for f in as_completed(futures):
                item, is_alive = f.result()
                pre_checked += 1
                if is_alive:
                    live_candidates.append(item)
                if pre_checked % 1000 == 0 or pre_checked == len(candidates):
                    print(f"  Pre-check: {pre_checked}/{len(candidates)} | Прошло дальше: {len(live_candidates)}", flush=True)

        print(f"Живых хостов для Xray: {len(live_candidates)} из {len(candidates)}", flush=True)

        print(f"Этап 2: Проверка через Xray (таймаут {CURL_TIMEOUT}с, потоков {CHECK_CONCURRENCY})...", flush=True)
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

    print("----", flush=True)
    save_subscription(working_lines, "checked")


def main():
    parser = argparse.ArgumentParser(description="VPN Subscription Aggregator")
    parser.add_argument(
        "--mode",
        choices=["trusted", "checked", "all"],
        default="all",
        help="Режим сборки: trusted (только Igareck), checked (проверка Xray), all (оба)",
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
