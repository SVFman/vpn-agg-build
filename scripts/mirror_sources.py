#!/usr/bin/env python3
"""Зеркалирует gitverse-списки в репозиторий (каталог mirrors/).

Зачем: gitverse.ru жёстко лимитирует запросы с IP раннеров GitHub Actions
(прод-запуски стабильно ловят 429 на части источников), поэтому проблемные
списки скачиваются отдельным терпеливым запуском раз в сутки (workflow
"Mirror GitVerse Sources") и коммитятся в mirrors/. Основной агрегатор
читает их локально через file:mirrors/... и к gitverse не обращается.

Гарантии:
- общий дедлайн прогона 17 минут (env MIRROR_DEADLINE_SECS), укладывается в
  timeout-minutes: 25 workflow; попытка/сон не начинаются, если на них не хватает остатка;
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


def _env_int(name, default):
    """Целое из переменной окружения; без/с мусором — значение по умолчанию."""
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return default


# Общий дедлайн прогона (все источники и паузы суммарно): 17 минут, чтобы
# гарантированно уложиться в timeout-minutes: 25 workflow (запас ~8 минут на
# чекаут и коммит). Худший случай без дедлайна: два источника по 8 попыток
# с паузами 90-615 с — это больше 20 минут даже без злого Retry-After.
# Переопределяется переменной окружения MIRROR_DEADLINE_SECS.
MIRROR_DEADLINE_SECS = _env_int("MIRROR_DEADLINE_SECS", 17 * 60)

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


def fetch_patient(url, label, deadline):
    """До ATTEMPTS попыток с паузами; Retry-After уважается (но не короче ATTEMPT_PAUSE).

    Общий дедлайн прогона сильнее числа попыток: перед каждой попыткой и перед
    каждым сном проверяется остаток. Попытка не начинается и сон не делается,
    если на полноценную попытку (FETCH_TIMEOUT) времени уже не хватает.
    """
    for attempt in range(ATTEMPTS):
        remaining = deadline - time.monotonic()
        if remaining <= FETCH_TIMEOUT:
            print(
                f"[{label}] Дедлайн прогона исчерпан "
                f"({MIRROR_DEADLINE_SECS // 60} мин) — попытки прекращены на {attempt + 1}-й.",
                flush=True,
            )
            return None
        try:
            return fetch_once(url)
        except urllib.error.HTTPError as e:
            retry_after = e.headers.get("Retry-After") if e.headers else None
            try:
                wait = float(retry_after)
            except (TypeError, ValueError):
                wait = ATTEMPT_PAUSE
            wait = min(max(wait, ATTEMPT_PAUSE), 600) + random.uniform(0, 15)
            # сон не съедает шанс ещё одной попытки
            wait = min(wait, max(deadline - time.monotonic() - FETCH_TIMEOUT, 0))
            if attempt < ATTEMPTS - 1 and wait > 0:
                print(f"[{label}] Попытка {attempt + 1}/{ATTEMPTS}: HTTP {e.code}, жду {wait:.0f} с...", flush=True)
                time.sleep(wait)
            else:
                if wait <= 0:
                    print(f"[{label}] HTTP {e.code}: до дедлайна не остаётся времени на ещё одну попытку.", flush=True)
                    return None
                print(f"[{label}] HTTP {e.code} после {ATTEMPTS} попыток.", flush=True)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            pause = min(ATTEMPT_PAUSE + random.uniform(0, 15),
                        max(deadline - time.monotonic() - FETCH_TIMEOUT, 0))
            if attempt < ATTEMPTS - 1 and pause > 0:
                print(f"[{label}] Попытка {attempt + 1}/{ATTEMPTS}: {e}; жду {pause:.0f} с...", flush=True)
                time.sleep(pause)
            else:
                if pause <= 0:
                    print(f"[{label}] {e}: до дедлайна не остаётся времени на ещё одну попытку.", flush=True)
                    return None
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
    deadline = time.monotonic() + MIRROR_DEADLINE_SECS
    refreshed = 0
    for i, (url, path) in enumerate(TARGETS):
        label = os.path.basename(path)
        text = fetch_patient(url, label, deadline)
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
            # пауза между источниками — тоже под контролем дедлайна
            pause = min(URL_PAUSE, max(deadline - time.monotonic() - FETCH_TIMEOUT, 0))
            if pause > 0:
                time.sleep(pause)

    missing = [p for _, p in TARGETS if not os.path.exists(p)]
    if refreshed == 0 and missing:
        print(f"ERROR: ни один список не обновлён, зеркала отсутствуют: {missing}", flush=True)
        raise SystemExit(1)
    if refreshed == 0:
        print("Ни один список не обновлён — работаем на прежних зеркалах.", flush=True)


if __name__ == "__main__":
    main()
