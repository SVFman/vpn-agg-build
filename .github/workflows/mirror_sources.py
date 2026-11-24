#!/usr/bin/env python3
"""Зеркалирует gitverse-списки в репозиторий (каталог mirrors/).

Зачем: gitverse.ru жёстко лимитирует запросы с IP раннеров GitHub Actions
(прод-запуски стабильно ловят 429 на части источников), поэтому проблемные
списки скачиваются отдельным терпеливым запуском раз в сутки (workflow
"Mirror GitVerse Sources") и коммитятся в mirrors/. Основной агрегатор
читает их локально через file:mirrors/... и к gitverse не обращается.

Гарантии:
- зеркал-файл перезаписывается только успешной загрузкой валидного контента
  (должна быть хотя бы одна строка конфига; HTML-страница ошибки не пройдёт);
- при неудаче остаётся прежняя (последняя удачная) версия;
- exit 1 только если обновить не удалось ни один список и зеркал ещё нет.
"""
import base64
import os
import random
import time
import urllib.error
import urllib.request

FETCH_TIMEOUT = 30
MAX_SOURCE_BYTES = 5 * 1024 * 1024
ATTEMPTS = 8          # попыток на источник
ATTEMPT_PAUSE = 90    # секунд между попытками (минимум; Retry-After уважается)
URL_PAUSE = 15        # пауза между разными источниками

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

TARGETS = [
    (
        "https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/KvRuVPN/KvRuVPN.txt",
        "mirrors/KvRuVPN.txt",
    ),
    (
        "https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/Zieng2/Zieng2_NowMeow.txt",
        "mirrors/Zieng2_NowMeow.txt",
    ),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/plain,*/*;q=0.8",
}


def config_line_count(text):
    """Сколько строк распознаются как конфиги (учитывает и base64-подписки)."""

    def scan(t):
        return sum(1 for l in t.splitlines() if l.strip().startswith(SUPPORTED_SCHEMES))

    n = scan(text)
    if n:
        return n
    cleaned = "".join(text.split())
    if not cleaned:
        return 0
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return 0
    return scan(decoded)


def fetch_once(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read(MAX_SOURCE_BYTES + 1).decode("utf-8", errors="ignore")


def fetch_patient(url, label):
    """До ATTEMPTS попыток с паузами; Retry-After уважается (но не короче ATTEMPT_PAUSE)."""
    for attempt in range(ATTEMPTS):
        try:
            return fetch_once(url)
        except urllib.error.HTTPError as e:
            retry_after = e.headers.get("Retry-After") if e.headers else None
            try:
                wait = float(retry_after)
            except (TypeError, ValueError):
                wait = ATTEMPT_PAUSE
            wait = min(max(wait, ATTEMPT_PAUSE), 600) + random.uniform(0, 15)
            if attempt < ATTEMPTS - 1:
                print(f"[{label}] Попытка {attempt + 1}/{ATTEMPTS}: HTTP {e.code}, жду {wait:.0f} с...", flush=True)
                time.sleep(wait)
            else:
                print(f"[{label}] HTTP {e.code} после {ATTEMPTS} попыток.", flush=True)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < ATTEMPTS - 1:
                print(f"[{label}] Попытка {attempt + 1}/{ATTEMPTS}: {e}; жду {ATTEMPT_PAUSE} с...", flush=True)
                time.sleep(ATTEMPT_PAUSE + random.uniform(0, 15))
            else:
                print(f"[{label}] Не удалось скачать после {ATTEMPTS} попыток: {e}", flush=True)
    return None


def save_mirror(path, text):
    """Атомарная запись: сначала .tmp, затем replace — обрыв не оставит битый файл."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text if text.endswith("\n") else text + "\n")
    os.replace(tmp, path)


def main():
    refreshed = 0
    for i, (url, path) in enumerate(TARGETS):
        label = os.path.basename(path)
        text = fetch_patient(url, label)
        if text is None or config_line_count(text) == 0:
            if text is not None:
                print(f"[{label}] В контенте нет строк конфигов — не сохраняю.", flush=True)
            if os.path.exists(path):
                print(f"[{label}] Оставляю прежнее зеркало (последняя удачная версия).", flush=True)
            else:
                print(f"[{label}] Зеркала ещё нет — сборщик пропустит этот источник.", flush=True)
        else:
            save_mirror(path, text)
            print(
                f"[{label}] Обновлено: {config_line_count(text)} строк конфигов -> {path}",
                flush=True,
            )
            refreshed += 1
        if i < len(TARGETS) - 1:
            time.sleep(URL_PAUSE)

    missing = [p for _, p in TARGETS if not os.path.exists(p)]
    if refreshed == 0 and missing:
        print(f"ERROR: ни один список не обновлён, зеркала отсутствуют: {missing}", flush=True)
        raise SystemExit(1)
    if refreshed == 0:
        print("Ни один список не обновлён — работаем на прежних зеркалах.", flush=True)


if __name__ == "__main__":
    main()
