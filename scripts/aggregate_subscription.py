#!/usr/bin/env python3
import base64
import json
import os
import urllib.parse
import urllib.request

SOURCES_FILE = "subscription-sources.txt"
OUT_DIR = "subscription"
PLAIN_OUT = f"{OUT_DIR}/aggregated.txt"
BASE64_OUT = f"{OUT_DIR}/aggregated_base64.txt"
TIMEOUT = 15

MAX_LINES = 20000


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
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
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


def connection_key(line):
    """
    Возвращает "суть" сервера (хост+порт+id), игнорируя имя/remark,
    чтобы ловить дубликаты так же, как это делает v2rayNG — а не только
    строки, совпадающие посимвольно целиком.
    Если распарсить не получилось — используем строку как есть
    (не ломает дедупликацию, просто не улучшает её для этой строки).
    """
    try:
        if line.startswith("vless://"):
            body = line[len("vless://"):]
            # отрезаем remark (#...) перед парсингом
            body = body.split("#", 1)[0]
            parsed = urllib.parse.urlparse("vless://" + body)
            uuid = parsed.username or ""
            host = (parsed.hostname or "").lower()
            port = parsed.port or 0
            return ("vless", uuid, host, port)

        if line.startswith("vmess://"):
            payload = line[len("vmess://"):].split("#", 1)[0]
            padding = len(payload) % 4
            if padding:
                payload += "=" * (4 - padding)
            decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            vid = str(data.get("id", ""))
            host = str(data.get("add", "")).lower()
            port = str(data.get("port", ""))
            return ("vmess", vid, host, port)
    except Exception:
        pass
    return ("raw", line)


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

    seen = set()
    deduped = []
    for line in all_lines:
        key = connection_key(line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(line)

    truncated = len(deduped) > MAX_LINES
    final_lines = deduped[:MAX_LINES] if truncated else deduped

    os.makedirs(OUT_DIR, exist_ok=True)

    with open(PLAIN_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    joined = "\n".join(final_lines).encode("utf-8")
    b64 = base64.b64encode(joined).decode("ascii")
    with open(BASE64_OUT, "w", encoding="utf-8") as f:
        f.write(b64)

    print("----")
    print(f"Источников: {len(urls)}, ошибок: {len(errors)}")
    print(f"Собрано всего: {total_collected}")
    print(f"После дедупа по host+port+id (игнорируя имя): {len(deduped)}")
    if truncated:
        print(f"Обрезано до лимита: {MAX_LINES}")


if __name__ == "__main__":
    main()
