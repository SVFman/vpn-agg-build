#!/usr/bin/env python3
import base64
import os
import urllib.request

SOURCES_FILE = "subscription-sources.txt"
OUT_DIR = "subscription"
PLAIN_OUT = f"{OUT_DIR}/aggregated.txt"
BASE64_OUT = f"{OUT_DIR}/aggregated_base64.txt"
TIMEOUT = 15


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


def main():
    urls = read_sources(SOURCES_FILE)
    all_lines = []
    errors = {}

    for url in urls:
        try:
            text = fetch(url)
            lines = extract_configs(text)
            all_lines.extend(lines)
            print(f"OK  ({len(lines):5d}) {url}")
        except Exception as e:
            errors[url] = str(e)
            print(f"ERR          {url} -> {e}")

    total_collected = len(all_lines)
    deduped = list(dict.fromkeys(all_lines))

    os.makedirs(OUT_DIR, exist_ok=True)

    with open(PLAIN_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(deduped))

    joined = "\n".join(deduped).encode("utf-8")
    b64 = base64.b64encode(joined).decode("ascii")
    with open(BASE64_OUT, "w", encoding="utf-8") as f:
        f.write(b64)

    print("----")
    print(f"Источников: {len(urls)}, ошибок: {len(errors)}")
    print(f"Собрано всего: {total_collected}, после дедупа: {len(deduped)}")


if __name__ == "__main__":
    main()
