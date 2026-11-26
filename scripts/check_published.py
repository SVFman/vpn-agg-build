#!/usr/bin/env python3
"""Проверка опубликованных подписок без токена (восьмая ревизия).

Репозиторий публичный, поэтому подписки доступны приложениям на устройствах
по ссылкам https://raw.githubusercontent.com/<repo>/<ref>/subscription/<файл>
без всяких токенов. Скрипт запускается workflow ПОСЛЕ коммита и проверяет,
что каждый файл каталога subscription/ реально отдаётся по raw-ссылке и
содержит распознанные конфиги (для *_base64.txt — после декодирования).

Проверка информационная: raw-кэш GitHub может запаздывать на несколько минут,
особенно для новых файлов, поэтому любые проблемы — WARN в сводке, а код
выхода всегда 0. Токен не используется и не нужен.
"""
import base64
import os
import pathlib
import urllib.error
import urllib.parse
import urllib.request

SUB_DIR = "subscription"
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://",
           "hysteria2://", "tuic://", "wireguard://")
TIMEOUT_SECS = 20
MAX_BODY_BYTES = 10 * 1024 * 1024   # достаточно для любой подписки этого репо


def build_raw_url(repo, ref, name):
    """raw-ссылка на файл подписки; ref и имя кодируются (ветки со слэшем, пробелы)."""
    return "https://raw.githubusercontent.com/{}/{}/subscription/{}".format(
        repo, urllib.parse.quote(ref, safe=""), urllib.parse.quote(name))


def _decoded_or_none(body):
    """Тело base64-подписки после декодирования; не декодируется — None."""
    cleaned = "".join(body.split())
    if not cleaned:
        return None
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4)).decode(
            "utf-8", "ignore")
    except Exception:
        return None


def _count_schemes(text):
    """Число строк, начинающихся с поддерживаемой схемы конфига."""
    return sum(1 for line in text.splitlines() if line.strip().startswith(SCHEMES))


def classify(name, status, body):
    """(вердикт, подробность) по коду ответа и телу. body None — ошибка сети/HTTP.

    Вердикт 'ok' — файл доступен и в нём видны конфиги; 'WARN' — остальное
    (в том числе запаздывание raw-кэша: рядом всегда напоминаем об этом).
    """
    if status is None:
        return "WARN", "сеть недоступна (raw-кэш может запаздывать)"
    if status != 200:
        return "WARN", f"HTTP {status} (raw-кэш может запаздывать для новых файлов)"
    if not body:
        return "WARN", "HTTP 200, тело пустое"
    if name.endswith("_base64.txt"):
        decoded = _decoded_or_none(body)
        n = _count_schemes(decoded) if decoded else 0
        if n:
            return "ok", f"base64, строк конфигов: {n}"
        return "WARN", "HTTP 200, конфигов не видно (не base64 или пусто)"
    n = _count_schemes(body)
    if n:
        return "ok", f"строк конфигов: {n}"
    return "WARN", "HTTP 200, строк конфигов не видно (HTML/пусто)"


def _fetch(url):
    """(код, тело) по raw-ссылке; код None — сеть недоступна."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "subscription-selfcheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
            raw = resp.read(MAX_BODY_BYTES + 1)
            return getattr(resp, "status", None), raw.decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def _emit(lines):
    """Сводка — в лог и (если задан) в файл $GITHUB_STEP_SUMMARY."""
    text = "\n".join(lines).rstrip() + "\n"
    print(text, flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
    except OSError as e:
        print(f"WARN не удалось записать $GITHUB_STEP_SUMMARY: {e}", flush=True)


def main(sub_dir=SUB_DIR):
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    ref = os.environ.get("GITHUB_REF_NAME", "")
    if not repo or not ref:
        _emit(["## Проверка опубликованных подписок (raw, без токена)", "",
               "Запуск вне GitHub Actions (нет GITHUB_REPOSITORY/GITHUB_REF_NAME) — "
               "проверка пропущена."])
        return
    files = sorted(p.name for p in pathlib.Path(sub_dir).glob("*.txt"))
    if not files:
        _emit(["## Проверка опубликованных подписок (raw, без токена)", "",
               "В каталоге subscription/ нет файлов — нечего проверять "
               "(сборка могла завершиться ошибкой)."])
        return
    out = ["## Проверка опубликованных подписок (raw, без токена)", "",
           "| Файл | Код | Вердикт |", "|---|---|---|"]
    warned = 0
    for name in files:
        status, body = _fetch(build_raw_url(repo, ref, name))
        verdict, detail = classify(name, status, body)
        warned += verdict == "WARN"
        code = status if status is not None else "—"
        out.append(f"| {name} | {code} | {verdict}: {detail} |")
    if warned:
        out += ["", f"Предупреждений: {warned}. Raw-кэш GitHub может запаздывать "
                    "на несколько минут — если предупреждения повторятся в "
                    "следующем запуске, тогда и разбираться."]
    else:
        out += ["", "Все файлы доступны публично: токен для приложений не нужен, "
                    "ссылки вида https://raw.githubusercontent.com/"
                    f"{repo}/{ref}/subscription/<файл> можно использовать в клиентах VPN."]
    _emit(out)


if __name__ == "__main__":
    main()
