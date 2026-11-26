#!/usr/bin/env python3
"""Недельный отчёт по журналу источников (I9, девятая ревизия).

Читает stats/sources_log.csv и строит из ОДНОГО расчёта три формата:
  1) Markdown в stdout и (если задан) $GITHUB_STEP_SUMMARY — для страницы запуска;
  2) stats/weekly.md — читается в приложении GitHub на телефоне без доработок;
  3) stats/weekly.json — машиночитаемый файл со схемой vpn-agg-weekly/1,
     «API» для будущего приложения; копия кладётся в stats/archive/ГГГГ-Wнн.json.

Принципы (по согласованию трёхраундовой сверки 25–26.11.2026):
- отчёт информационный: пустой, укороченный или повреждённый журнал не роняет
  скрипт; код выхода всегда 0, ошибки журнала — примечания в самом отчёте;
- данных меньше окна — печатается «данных за N суток», отчёт всё равно строится;
- концентрация по владельцам — ОЦЕНКА-ВИЛКА: сумма uniq по источникам владельца
  <= потеря <= сумма in_file. Нижняя граница занижена внутривладельческими
  дублями (общие серверы двух источников одного владельца в uniq не попадают),
  верхняя завышена серверами, общими с третьими источниками. Выбирать одну
  «честную» цифру нельзя — показываются обе;
- uniq сравним только внутри неизменного состава источников: при смене состава
  (история subscription-sources.txt) значения через границу несравнимы; дата
  смены попадает в примечания;
- соответствие «источник -> владелец» — статический словарь ниже; он же целиком
  выносится в weekly.json, чтобы приложение не дублировало логику;
- журнал событийный (строки пишутся при смене хеша/статуса и в суточные
  контрольные точки), поэтому err/zero — число ЗАПИСЕЙ с ошибкой/нулём,
  минимум, а не доля всех запусков; это указано в примечаниях отчёта.
"""
import argparse
import csv
import datetime
import json
import os
import subprocess

SCHEMA = "vpn-agg-weekly/1"
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_JOURNAL = "stats/sources_log.csv"
DEFAULT_OUT_MD = "stats/weekly.md"
DEFAULT_OUT_JSON = "stats/weekly.json"
DEFAULT_ARCHIVE_DIR = "stats/archive"
DEFAULT_SOURCES_FILE = "subscription-sources.txt"
WINDOW_DAYS = 7
STALE_DAYS = 7
ERR_SERIES_MIN = 3   # столько последних записей ERR/0 подряд — «под наблюдением»

# Колонки журнала (девятая ревизия, 14 колонок). Строки старых форматов
# (7 и 11 колонок) дополняются пустыми: отчёт такие поля просто пропускает.
JOURNAL_COLUMNS = ["utc", "group", "source", "lines", "hash", "in_file", "status",
                   "http", "ms", "bytes", "uniq", "src_ts", "rejected", "dup_inside"]
COL = {name: i for i, name in enumerate(JOURNAL_COLUMNS)}

# Соответствие «источник -> владелец» (п. 3.4 сверки). Имена — как их пишет
# в журнал short_source_names: у гистов пользователь, у raw-файлов репозиторий.
# Пока источников 16, отдельный токен в subscription-sources.txt не нужен;
# словарь целиком выносится в weekly.json для будущего приложения.
OWNERS = {
    # igareck (8 файлов репозитория vpn-configs-for-russia)
    "BLACK_VLESS_RUS": "igareck",
    "BLACK_VLESS_RUS_mobile": "igareck",
    "BLACK_SS+All_RUS": "igareck",
    "BLACK_SS_WEAK_DPI_RUS": "igareck",
    "Vless-Reality-White-Lists-Rus-Mobile": "igareck",
    "WHITE-CIDR-RU-checked": "igareck",
    "WHITE-CIDR-RU-all": "igareck",
    "WHITE-SNI-RU-all": "igareck",
    # zieng2 (репозиторий wl, 2 файла)
    "vless_universal": "zieng2",
    "vless_lite": "zieng2",
    # гисты и внешний сайт
    "skysph-dev/v2ray": "skysph-dev",
    "st0rer/v2ray": "st0rer",
    "wtpn.pro": "wtpn.pro",
    # Cepreu54 (3 репозитория vless-clean*)
    "vless-clean/clean": "Cepreu54",
    "vless-clean-2/clean": "Cepreu54",
    "vless-clean-3/clean": "Cepreu54",
}


def parse_ts(text):
    """UTC-время из строки журнала; None для пустого/битого (молча)."""
    if not text:
        return None
    try:
        return datetime.datetime.strptime(text, TS_FMT).replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        pass
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _int_or_none(text):
    """int из колонки журнала; пусто или мусор — None (строки старого формата)."""
    if text == "" or text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def read_journal(path):
    """Читает журнал; возвращает (строки-словари, повреждённых, описание ошибки).

    Несамодостаточность исключена: скрипт отчёта не зависит от кода сборки.
    Строки старых форматов дополняются пустыми колонками, битые время/длина
    пропускаются со счётчиком, нечитаемый файл даёт пустой отчёт с примечанием.
    """
    rows, damaged, error = [], 0, ""
    try:
        with open(path, encoding="utf-8", newline="") as f:
            for raw in csv.reader(f):
                if not raw or raw[0].strip().lower() == "utc":
                    continue
                if len(raw) > len(JOURNAL_COLUMNS):
                    damaged += 1
                    continue
                vals = raw + [""] * (len(JOURNAL_COLUMNS) - len(raw))
                if parse_ts(vals[COL["utc"]]) is None:
                    damaged += 1
                    continue
                rows.append(dict(zip(JOURNAL_COLUMNS, vals)))
    except FileNotFoundError:
        error = "журнал не найден"
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        error = f"журнал не читается ({e})"
    return rows, damaged, error


def sources_last_change_utc(sources_file=DEFAULT_SOURCES_FILE):
    """Дата последнего изменения списка источников по git-истории (п. 3.3 сверки).

    Вне git-репозитория или без коммитов файла — None: пометка просто не
    попадёт в отчёт. Любая ошибка git глушится: отчёт не должен падать.
    """
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%aI", "--", sources_file],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    stamp = out.stdout.strip()
    return stamp if parse_ts(stamp) else None


def _latest_value(rows, field):
    """Последнее непустое значение колонки по записям источника (хронологично)."""
    for r in reversed(rows):
        if r[field] != "":
            return _int_or_none(r[field])
    return None


def source_stats(rs_all, rs_window, now):
    """Метрики одного источника.

    rs_all — ВСЕ записи источника в журнале, rs_window — записи за окно.
    Разделение принципиально (п. 3.3 сверки): возраст без изменений и серия
    ошибок считаются по полной истории — смена хеша может лежать ВНЕ окна,
    и тогда окно занизило бы возраст до возраста первой записи внутри окна.
    За окно считаются только: число записей, разные хеши, ERR/0 и кандидаты
    uniq=0. Последние значения (КПД, перекрытие, дата автора) берутся из
    всей истории — это просто самые свежие данные источника.

    КПД_чистый — по определению I3 в терминах колонок журнала:
    (lines - dup_inside) / (lines + rejected): строки журнала уже без
    отклонённых, поэтому знаменатель восстанавливает сырой объём.
    Перекрытие — порядконезависимое: (lines - dup_inside - uniq) /
    (lines - dup_inside); dup_other из плана I2 выражается через имеющиеся
    колонки, отдельная колонка не потребовалась.
    """
    runs = len(rs_window)
    distinct_hashes = len({r["hash"] for r in rs_window if r["hash"]})
    err_rows = sum(1 for r in rs_window if r["status"] == "ERR")
    zero_rows = sum(1 for r in rs_window if r["status"] == "0")

    last_change = None
    last_seen = None
    for r in rs_all:
        if r["hash"] and r["hash"] != last_seen:
            last_seen = r["hash"]
            last_change = parse_ts(r["utc"])
    days_since_change = None
    if last_change:
        days_since_change = round((now - last_change).total_seconds() / 86400, 1)

    err_series = 0
    for r in reversed(rs_all):
        if r["status"] in ("ERR", "0"):
            err_series += 1
        else:
            break
    series_since = None
    if err_series >= ERR_SERIES_MIN:
        series_since = parse_ts(rs_all[-err_series]["utc"])

    lines_last = _int_or_none(rs_all[-1]["lines"])
    uniq_last = _latest_value(rs_all, "uniq")
    rejected_last = _latest_value(rs_all, "rejected")
    dup_last = _latest_value(rs_all, "dup_inside")

    kpd_clean = None
    if dup_last is not None and lines_last is not None and lines_last > 0 \
            and lines_last - dup_last >= 0:
        denom = lines_last + rejected_last if rejected_last is not None else lines_last
        if denom:
            kpd_clean = round(100 * (lines_last - dup_last) / denom, 1)

    overlap = None
    if dup_last is not None and uniq_last is not None and lines_last is not None \
            and lines_last - dup_last > 0:
        distinct = lines_last - dup_last
        overlap = round(100 * (distinct - uniq_last) / distinct, 1)

    # Кандидат «двойника/дубликата»: uniq = 0 во ВСЕХ записях со содержимым
    # (статус ok) ЗА ОКНО, где колонка заполнена. Записи ERR/0 не считаются:
    # у отказа uniq не имеет смысла. Решение — только после полного окна.
    ok_uniq = [r["uniq"] for r in rs_window if r["status"] == "ok" and r["uniq"] != ""]
    uniq_zero_window = bool(ok_uniq) and all(v == "0" for v in ok_uniq)

    src_ts_last = next((r["src_ts"] for r in reversed(rs_all) if r["src_ts"]), "")
    src_age_days = None
    ts = parse_ts(src_ts_last)
    if ts:
        src_age_days = round((now - ts).total_seconds() / 86400, 1)

    return {
        "runs": runs,
        "distinct_hashes": distinct_hashes,
        "last_change_utc": last_change.strftime(TS_FMT) if last_change else None,
        "days_since_change": days_since_change,
        "err_rows": err_rows,
        "zero_rows": zero_rows,
        "err_series": err_series,
        "series_since_utc": series_since.strftime(TS_FMT) if series_since else None,
        "lines_last": lines_last,
        "uniq_last": uniq_last,
        "rejected_last": rejected_last,
        "dup_inside_last": dup_last,
        "kpd_clean": kpd_clean,
        "overlap": overlap,
        "uniq_zero_window": uniq_zero_window,
        "src_ts_last": src_ts_last or None,
        "src_age_days": src_age_days,
        "status_last": rs_all[-1]["status"],
    }


def _concentration(rows_in_window, owners):
    """Оценка-вилка концентрации по владельцам, по самому полному срезу группы.

    Срез — момент (utc) с максимумом различных источников группы (суточная
    контрольная точка пишет ВСЮ группу, поэтому максимум даёт согласованный
    срез; при равенстве берётся поздний). Вилка: loss_min = сумма uniq
    (нижняя оценка потери при исчезновении владельца), loss_max = сумма
    in_file (верхняя). Обоснование границ — в докстринге модуля.

    Если в срезе есть записи старого формата без uniq (седьмая ревизия),
    loss_min = None («неизвестно»), а НЕ ноль: отсутствие данных и настоящий
    ноль — разные вещи; нижняя граница появится в первых суточных срезах
    девятой ревизии.
    """
    groups = []
    for group in sorted({r["group"] for r in rows_in_window}):
        snap_sources = {}
        for r in rows_in_window:
            if r["group"] == group:
                snap_sources.setdefault(r["utc"], set()).add(r["source"])
        if not snap_sources:
            continue
        best_utc = max(snap_sources, key=lambda u: (len(snap_sources[u]), u))
        srows = [r for r in rows_in_window
                 if r["group"] == group and r["utc"] == best_utc]
        total_in = sum(_int_or_none(r["in_file"]) or 0 for r in srows)
        by_owner = {}
        uniq_known = True
        for r in srows:
            entry = by_owner.setdefault(
                owners.get(r["source"], "прочие"),
                {"sources": 0, "in_file": 0, "loss_min": 0, "loss_max": 0})
            entry["sources"] += 1
            infl = _int_or_none(r["in_file"]) or 0
            entry["in_file"] += infl
            entry["loss_max"] += infl
            uniq = _int_or_none(r["uniq"])
            if uniq is None:
                uniq_known = False        # строки старого формата: uniq неизвестен
            else:
                entry["loss_min"] += uniq
        if not uniq_known:
            for entry in by_owner.values():
                entry["loss_min"] = None   # «неизвестно», не ноль
        for entry in by_owner.values():
            entry["share_pct"] = (round(100 * entry["in_file"] / total_in, 1)
                                  if total_in else None)
        groups.append({
            "name": group,
            "snapshot_utc": best_utc,
            "snapshot_sources": len(snap_sources[best_utc]),
            "in_file_total": total_in,
            "by_owner": by_owner,
        })
    return groups


def _twins(rows_in_window):
    """Совпадения наборов серверов (одинаковый непустой хеш в одном срезе)."""
    snaps = {}
    for r in rows_in_window:
        if r["hash"]:
            snaps.setdefault((r["group"], r["utc"]), {}).setdefault(
                r["hash"], set()).add(r["source"])
    merged = {}
    for (group, utc), by_hash in snaps.items():
        for h, names in by_hash.items():
            if len(names) < 2:
                continue
            key = (group, h, tuple(sorted(names)))
            entry = merged.setdefault(key, {"snapshots": 0, "last_utc": ""})
            entry["snapshots"] += 1
            if utc > entry["last_utc"]:
                entry["last_utc"] = utc
    return [
        {"group": group, "hash": h, "sources": list(names),
         "snapshots": entry["snapshots"], "last_utc": entry["last_utc"]}
        for (group, h, names), entry in sorted(merged.items())
    ]


def build_report(rows, now, window_days=WINDOW_DAYS, stale_days=STALE_DAYS,
                 owners=None, sources_changed=None, damaged=0, journal_error=""):
    """Собирает отчёт (словарь) из всех строк журнала; окно фильтрует записи.

    rows — ВСЕ валидные строки журнала (data_days считается по самой ранней),
    окно отрезает последние window_days суток. Пропускаются записи «из
    будущего» (перевод часов на раннере) — молча.
    """
    owners = OWNERS if owners is None else owners
    window_start = now - datetime.timedelta(days=window_days)
    in_window = []
    for r in rows:
        ts = parse_ts(r["utc"])
        if ts is not None and window_start <= ts <= now:
            in_window.append(r)

    if rows:
        earliest = min(parse_ts(r["utc"]) for r in rows)
        data_days = round((now - earliest).total_seconds() / 86400, 1)
    else:
        data_days = 0.0

    by_key_all, by_key_window = {}, {}
    for r in rows:
        by_key_all.setdefault((r["group"], r["source"]), []).append(r)
    for r in in_window:
        by_key_window.setdefault((r["group"], r["source"]), []).append(r)

    sources = []
    for (group, name) in sorted(by_key_window):
        # В отчёт попадают источники с записями ЗА ОКНО; возраст и серии
        # считаются по всей истории (см. source_stats).
        rs_all = sorted(by_key_all[(group, name)], key=lambda r: parse_ts(r["utc"]))
        rs_win = sorted(by_key_window[(group, name)], key=lambda r: parse_ts(r["utc"]))
        st = source_stats(rs_all, rs_win, now)
        st.update({"group": group, "name": name,
                   "owner": owners.get(name, "прочие")})
        sources.append(st)

    watch = []
    for s in sources:
        if s["days_since_change"] is not None and s["days_since_change"] >= stale_days:
            watch.append({
                "group": s["group"], "name": s["name"],
                "reason": f"без изменений {s['days_since_change']} сут (порог {stale_days})",
                "since": s["last_change_utc"],
            })
        if s["err_series"] >= ERR_SERIES_MIN:
            watch.append({
                "group": s["group"], "name": s["name"],
                "reason": f"серия ERR/0: последние {s['err_series']} записи подряд",
                "since": s["series_since_utc"],
            })
        if s["uniq_zero_window"]:
            watch.append({
                "group": s["group"], "name": s["name"],
                "reason": "uniq=0 на всём окне — кандидат в двойники/дубли "
                          "(решение за владельцем и только после полного окна)",
                "since": None,
            })

    notes = []
    groups_out = _concentration(in_window, owners)
    if any(e["loss_min"] is None
           for g in groups_out for e in g["by_owner"].values()):
        notes.append("в выбранном срезе группы есть записи старого формата без uniq — "
                     "нижняя граница вилки показана как «—»; она появится в первых "
                     "суточных срезах девятой ревизии")
    if journal_error:
        notes.append(f"журнал: {journal_error} — отчёт построен без его данных")
    if damaged:
        notes.append(f"повреждённых строк журнала пропущено: {damaged}")
    if not rows:
        notes.append("журнал пуст: отчёт построен без данных, первая запись "
                     "появится после первого запуска сборки")
    elif data_days < window_days:
        notes.append(f"данных за {data_days} сут из {window_days} — отчёт "
                     "неполный, полный будет когда журнал накроет всё окно")
    changed_ts = parse_ts(sources_changed) if sources_changed else None
    if changed_ts is not None and changed_ts >= window_start:
        notes.append(f"состав источников менялся {sources_changed} — uniq и КПД "
                     "несравнимы через эту дату (история subscription-sources.txt)")
    if any(s["uniq_zero_window"] for s in sources):
        notes.append("кандидаты uniq=0: решение — только после ПОЛНОГО недельного "
                     "окна и с учётом смен состава группы (критерий сверки 25–26.11)")
    notes.append("журнал событийный: строки пишутся при смене хеша/статуса и в "
                 "суточные контрольные точки, поэтому ERR/0 — минимумы, а не доли "
                 "всех запусков")

    return {
        "schema": SCHEMA,
        "generated_utc": now.strftime(TS_FMT),
        "window_days": window_days,
        "data_days": data_days,
        "journal": {"path": "", "rows_total": len(rows),
                    "rows_in_window": len(in_window), "damaged": damaged,
                    "error": journal_error or None},
        "owners": dict(owners),
        "sources": sources,
        "groups": groups_out,
        "twins": _twins(in_window),
        "watch": watch,
        "notes": notes,
        "sources_changed_utc": sources_changed,
    }


def _fmt(value):
    """Ячейка таблицы: None и пусто — «—»."""
    if value is None or value == "":
        return "—"
    return str(value)


def render_md(rep):
    """Markdown-отчёт: те же данные, что в weekly.json (один расчёт)."""
    out = [
        "# Недельный отчёт по источникам",
        "",
        f"Окно: {rep['window_days']} сут; данных за: {rep['data_days']} сут; "
        f"сгенерирован: {rep['generated_utc']}.",
        "",
    ]
    if rep["sources"]:
        out += [
            "## Источники за окно",
            "",
            "| Группа | Источник | Владелец | Записей | Хешей | Посл. смена (UTC) "
            "| Сут. без изм. | ERR | 0 | Строк | КПД чистый, % | Перекрытие, % "
            "| Возраст данных автора, сут |",
            "|---|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for s in rep["sources"]:
            out.append(
                f"| {_fmt(s['group'])} | {_fmt(s['name'])} | {_fmt(s['owner'])} "
                f"| {s['runs']} | {s['distinct_hashes']} | {_fmt(s['last_change_utc'])} "
                f"| {_fmt(s['days_since_change'])} | {s['err_rows']} | {s['zero_rows']} "
                f"| {_fmt(s['lines_last'])} | {_fmt(s['kpd_clean'])} "
                f"| {_fmt(s['overlap'])} | {_fmt(s['src_age_days'])} |")
        out += [
            "",
            "КПД чистый = (строки − внутренние дубли) / (строки + отклонённые при "
            "разборе) по последней записи с колонками девятой ревизии; для строк "
            "старого формата — «—». Перекрытие — порядконезависимая доля серверов, "
            "есть и у других источников: (строки − дубли − уник) / (строки − дубли). "
            "Записей/хешей/ERR/0 — за окно; сут. без изм. — от последней смены хеша "
            "по ВСЕЙ истории журнала (окно занизило бы возраст застоявшихся).",
            "",
        ]
    else:
        out += ["## Источники за окно", "", "Записей в окне нет.", ""]
    if rep["groups"]:
        out += [
            "## Концентрация по владельцам (оценка-вилка)",
            "",
            "Потеря серверов при исчезновении владельца лежит в вилке: сумма uniq "
            "его источников (нижняя граница: занижена внутривладельческими дублями) "
            "… сумма in_file (верхняя: завышена серверами, общими с третьими "
            "источниками). Срез — самый полный момент группы.",
            "",
            "| Группа | Срез (UTC) | Владелец | Источников | Потеря min (uniq) "
            "| Потеря max (in_file) | Доля in_file, % |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
        for g in rep["groups"]:
            for owner in sorted(g["by_owner"]):
                e = g["by_owner"][owner]
                out.append(
                    f"| {_fmt(g['name'])} | {_fmt(g['snapshot_utc'])} | {_fmt(owner)} "
                    f"| {e['sources']} | {e['loss_min']} | {e['loss_max']} "
                    f"| {_fmt(e['share_pct'])} |")
        out.append("")
    if rep["twins"]:
        out += [
            "## Двойники за окно (одинаковый набор серверов)",
            "",
            "| Группа | Хеш | Источники | Совпадений в окне | Последнее (UTC) |",
            "|---|---|---|---:|---|",
        ]
        for t in rep["twins"]:
            out.append(
                f"| {_fmt(t['group'])} | `{t['hash']}` | {_fmt(', '.join(t['sources']))} "
                f"| {t['snapshots']} | {_fmt(t['last_utc'])} |")
        out += ["", "Совпадение в отдельных срезах ещё не вердикт: у пары с "
                "эпизодическими совпадениями наборы расходятся в полных состояниях; "
                "устойчивость оценивает недельное окно.", ""]
    if rep["watch"]:
        out += [
            "## Под наблюдением",
            "",
            "| Группа | Источник | Причина | С (UTC) |",
            "|---|---|---|---|",
        ]
        for w in rep["watch"]:
            out.append(
                f"| {_fmt(w['group'])} | {_fmt(w['name'])} | {_fmt(w['reason'])} "
                f"| {_fmt(w['since'])} |")
        out.append("")
    if rep["notes"]:
        out += ["## Примечания", ""]
        out += [f"- {n}" for n in rep["notes"]]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _write_text(path, text):
    """Атомарная запись текстового файла; ошибка — WARN, отчёт не роняет job."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, path)
        return True
    except OSError as e:
        print(f"WARN не записан {path}: {e}", flush=True)
        return False


def archive_copy(text, archive_dir, now):
    """Копия weekly.json в stats/archive/ГГГГ-Wнн.json (для динамики приложения)."""
    iso = now.isocalendar()
    return os.path.join(archive_dir, f"{iso[0]}-W{iso[1]:02d}.json"), text


def build_parser():
    p = argparse.ArgumentParser(description="Weekly sources report (I9)")
    p.add_argument("--journal", default=DEFAULT_JOURNAL)
    p.add_argument("--out-md", default=DEFAULT_OUT_MD)
    p.add_argument("--out-json", default=DEFAULT_OUT_JSON)
    p.add_argument("--archive-dir", default=DEFAULT_ARCHIVE_DIR)
    p.add_argument("--sources-file", default=DEFAULT_SOURCES_FILE)
    p.add_argument("--window-days", type=int, default=WINDOW_DAYS)
    p.add_argument("--stale-days", type=int, default=STALE_DAYS)
    p.add_argument("--now", default=None, help="Текущее время для тестов (ISO 8601)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    now = parse_ts(args.now) if args.now else datetime.datetime.now(
        datetime.timezone.utc)
    if now is None:
        raise SystemExit(f"ERROR --now не разбирается: {args.now!r}")

    rows, damaged, journal_error = read_journal(args.journal)
    sources_changed = sources_last_change_utc(args.sources_file)

    rep = build_report(rows, now, window_days=args.window_days,
                       stale_days=args.stale_days,
                       sources_changed=sources_changed, damaged=damaged,
                       journal_error=journal_error)
    rep["journal"]["path"] = args.journal

    md = render_md(rep)
    js = json.dumps(rep, ensure_ascii=False, indent=2) + "\n"

    _write_text(args.out_md, md)
    _write_text(args.out_json, js)
    archive_path, _ = archive_copy(js, args.archive_dir, now)
    _write_text(archive_path, js)

    print(md, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        # Дописывание, а не замена: сводка job может содержать шаги до отчёта.
        try:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(md if md.endswith("\n") else md + "\n")
        except OSError as e:
            print(f"WARN не удалось записать $GITHUB_STEP_SUMMARY: {e}", flush=True)

    print(f"[weekly] отчёт: {args.out_md}, {args.out_json}, архив {archive_path}.",
          flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 — отчёт информационный, job не краснит
        print(f"ERROR недельный отчёт не построен: {e}", flush=True)
        raise SystemExit(0)
