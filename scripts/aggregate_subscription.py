#!/usr/bin/env python3
import base64
import json
import os
import queue
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
FETCH_TIMEOUT = 15

MAX_LINES = 20000

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray")
CHECK_CONCURRENCY = int(os.environ.get("CHECK_CONCURRENCY", "60"))
BASE_PORT = 20000
TEST_URL = "https://www.gstatic.com/generate_204"
CURL_TIMEOUT = 4
XRAY_STARTUP_WAIT = 0.4


# ---------- Сбор источников ----------

def read_sources(path):
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def fetch(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (GitHubActions) VpnAggregator/1.0"},
    )
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def scan_lines(text):
    found = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("vless://") or line.startswith("vmess://"):
            found.append(line)
    return found


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


def extract_configs(raw_text):
    direct = scan_lines(raw_text)
    if direct:
        return direct
    decoded = try_base64_decode(raw_text)
    if decoded is None:
        return []
    return scan_lines(decoded)


# ---------- Разбор vless/vmess в структуру для xray-конфига ----------

def parse_vless(line):
    try:
        body = line[len("vless://"):].split("#", 1)[0]
        parsed = urllib.parse.urlparse("vless://" + body)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port
        if not uuid or not host or not port:
            return None

        qs = urllib.parse.parse_qs(parsed.query)

        def q(name, default=""):
            v = qs.get(name)
            return v[0] if v else default

        return {
            "protocol": "vless",
            "address": host,
            "port": port,
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
        payload = line[len("vmess://"):].split("#", 1)[0]
        padding = len(payload) % 4
        if padding:
            payload += "=" * (4 - padding)
        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
        data = json.loads(decoded)

        host = data.get("add")
        port = int(data.get("port", 0) or 0)
        vid = data.get("id")
        if not host or not port or not vid:
            return None

        net = data.get("net", "tcp") or "tcp"
        is_tls = str(data.get("tls", "")).lower() == "tls"

        return {
            "protocol": "vmess",
            "address": host,
            "port": port,
            "id": vid,
            "aid": int(data.get("aid", 0) or 0),
            "network": net,
            "security": "tls" if is_tls else "none",
            "sni": data.get("sni") or data.get("host") or host,
            "fp": "chrome",
            "pbk": "",
            "sid": "",
            "spx": "",
            "path": data.get("path", "/") or "/",
            "host_header": data.get("host", "") or "",
            "service_name": data.get("path", "") if net == "grpc" else "",
            "alpn": data.get("alpn", "") or "",
        }
    except Exception:
        return None


def parse_config(line):
    if line.startswith("vless://"):
        return parse_vless(line)
    if line.startswith("vmess://"):
        return parse_vmess(line)
    return None


# ---------- Сборка xray-конфига и живая проверка ----------

def build_xray_config(p, socks_port):
    stream = {
        "network": p["network"] or "tcp",
        "security": p["security"] or "none",
    }

    if p["network"] == "ws":
        stream["wsSettings"] = {
            "path": p.get("path") or "/",
            "headers": {"Host": p.get("host_header") or p.get("sni") or p["address"]},
        }
    elif p["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("service_name") or ""}
    elif p["network"] in ("h2", "http"):
        stream["httpSettings"] = {
            "path": p.get("path") or "/",
            "host": [p.get("host_header") or p.get("sni") or p["address"]],
        }

    if p["security"] == "tls":
        tls = {
            "serverName": p.get("sni") or p["address"],
            "allowInsecure": True,
            "fingerprint": p.get("fp") or "chrome",
        }
        if p.get("alpn"):
            tls["alpn"] = p["alpn"].split(",")
        stream["tlsSettings"] = tls
    elif p["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": p.get("sni") or p["address"],
            "fingerprint": p.get("fp") or "chrome",
            "publicKey": p.get("pbk") or "",
            "shortId": p.get("sid") or "",
            "spiderX": p.get("spx") or "",
        }

    if p["protocol"] == "vless":
        user = {"id": p["id"], "encryption": "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [user]}]},
            "streamSettings": stream,
        }
    else:
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": p["address"],
                    "port": p["port"],
                    "users": [{"id": p["id"], "alterId": p.get("aid", 0), "security": "auto"}],
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


def check_config(parsed, socks_port):
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
        time.sleep(XRAY_STARTUP_WAIT)

        result = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", str(CURL_TIMEOUT),
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                TEST_URL,
            ],
            capture_output=True, text=True, timeout=CURL_TIMEOUT + 3,
        )
        return result.stdout.strip() in ("204", "200")
    except Exception:
        return False
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        if config_path:
            try:
                os.remove(config_path)
            except Exception:
                pass


# ---------- Главный сценарий ----------

def main():
    urls = read_sources(SOURCES_FILE)
    all_lines = []
    errors = {}

    for url in urls:
        try:
            text = fetch(url)
            lines = extract_configs(text)
            all_lines.extend(lines)
            print(f"OK  ({len(lines):6d}) {url}")
        except Exception as e:
            errors[url] = str(e)
            print(f"ERR           {url} -> {e}")

    total_collected = len(all_lines)

    # Парсим + дедуплицируем по host+port+id, но храним ОРИГИНАЛЬНУЮ строку
    # целиком (с её tls/sni/reality/ws-параметрами) — именно её и нужно
    # отдавать на выходе, а не восстановленную вручную урезанную версию.
    seen = set()
    candidates = []  # list of (original_line, parsed_dict)
    dropped_unparsed = 0
    for line in all_lines:
        parsed = parse_config(line)
        if parsed is None:
            dropped_unparsed += 1
            continue
        key = (parsed["protocol"], parsed["id"], parsed["address"].lower(), parsed["port"])
        if key in seen:
            continue
        seen.add(key)
        candidates.append((line, parsed))

    print("----")
    print(f"Источников: {len(urls)}, ошибок загрузки: {len(errors)}")
    print(f"Собрано всего строк: {total_collected}")
    print(f"Отброшено нераспарсенных: {dropped_unparsed}")
    print(f"Уникальных кандидатов после дедупа: {len(candidates)}")
    print(f"Проверка через xray ({len(candidates)} шт., параллельность {CHECK_CONCURRENCY})…")

    port_pool = queue.Queue()
    for p in range(BASE_PORT, BASE_PORT + CHECK_CONCURRENCY * 2):
        port_pool.put(p)

    def worker(item):
        line, parsed = item
        port = port_pool.get()
        try:
            ok = check_config(parsed, port)
        finally:
            port_pool.put(port)
        return line, ok

    working_lines = []
    checked = 0
    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as executor:
        futures = [executor.submit(worker, c) for c in candidates]
        for future in as_completed(futures):
            line, ok = future.result()
            checked += 1
            if ok:
                # Сохраняем оригинальную строку как есть — со всеми
                # параметрами (security, sni, flow, pbk и т.д.), иначе
                # v2rayNG не сможет подключиться по урезанному адресу.
                working_lines.append(line)
            if checked % 500 == 0 or checked == len(candidates):
                print(f"  проверено {checked}/{len(candidates)}, рабочих пока {len(working_lines)}")

    print(f"Рабочих серверов: {len(working_lines)} из {len(candidates)}")

    truncated = len(working_lines) > MAX_LINES
    final_lines = working_lines[:MAX_LINES] if truncated else working_lines

    os.makedirs(OUT_DIR, exist_ok=True)

    with open(PLAIN_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    joined = "\n".join(final_lines).encode("utf-8")
    b64 = base64.b64encode(joined).decode("ascii")
    with open(BASE64_OUT, "w", encoding="utf-8") as f:
        f.write(b64)

    if truncated:
        print(f"Обрезано до лимита: {MAX_LINES}")


if __name__ == "__main__":
    main()
    nes = []
    checked = 0
    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as executor:
        futures = [executor.submit(worker, c) for c in candidates]
        for future in as_completed(futures):
            parsed, ok = future.result()
            checked += 1
            if ok:
                # Восстанавливаем исходную ссылку в простом виде, без remark —
                # этого достаточно, чтобы v2rayNG подключился.
                if parsed["protocol"] == "vless":
                    line = f"vless://{parsed['id']}@{parsed['address']}:{parsed['port']}"
                else:
                    line = f"vmess://{parsed['id']}@{parsed['address']}:{parsed['port']}"
                working_lines.append((parsed, line))
            if checked % 500 == 0 or checked == len(candidates):
                print(f"  проверено {checked}/{len(candidates)}, рабочих пока {len(working_lines)}")

    print(f"Рабочих серверов: {len(working_lines)} из {len(candidates)}")

    truncated = len(working_lines) > MAX_LINES
    final = working_lines[:MAX_LINES] if truncated else working_lines
    final_lines = [line for _, line in final]

    os.makedirs(OUT_DIR, exist_ok=True)

    with open(PLAIN_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    joined = "\n".join(final_lines).encode("utf-8")
    b64 = base64.b64encode(joined).decode("ascii")
    with open(BASE64_OUT, "w", encoding="utf-8") as f:
        f.write(b64)

    if truncated:
        print(f"Обрезано до лимита: {MAX_LINES}")


if __name__ == "__main__":
    main()
