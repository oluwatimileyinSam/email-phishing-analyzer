import datetime

import store

LEVELS = ["HIGH", "MEDIUM", "LOW", "WARNING", "INFO"]
STALE_MINUTES = 30


def count(conn, sql, args=()):
    return conn.execute(sql, args).fetchone()[0]


def read_status(conn):
    last_run = store.get_meta(conn, "last_run")
    summary = store.get_meta(conn, "last_summary") or ""
    problems_text = store.get_meta(conn, "last_problems") or ""
    problems = [line for line in problems_text.split("\n") if line]

    status = "never"
    text = "Waiting for the first run"
    minutes = None

    if last_run:
        then = datetime.datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        minutes = int((now - then).total_seconds() // 60)

        if problems:
            status = "problem"
            text = "The last run had problems"
        elif minutes > STALE_MINUTES:
            status = "late"
            text = "The watcher has not run for " + str(minutes) + " minutes"
        else:
            status = "ok"
            text = "The watcher is running"

    return {
        "status": status,
        "text": text,
        "last_run": last_run,
        "minutes": minutes,
        "summary": summary,
        "problems": problems,
    }


def read_chart(conn):
    today = datetime.datetime.now(datetime.timezone.utc).date()

    days = []
    for back in range(6, -1, -1):
        day = today - datetime.timedelta(days=back)
        total = count(
            conn,
            "SELECT COUNT(*) FROM alert_history WHERE substr(created, 1, 10) = ?",
            (day.isoformat(),),
        )
        days.append({"label": day.strftime("%a"), "date": day.isoformat(), "count": total})

    biggest = max([day["count"] for day in days] + [1])
    for day in days:
        day["percent"] = int(100 * day["count"] / biggest)

    since = (today - datetime.timedelta(days=6)).isoformat()
    levels = {name: 0 for name in LEVELS}
    rows = conn.execute(
        "SELECT level, COUNT(*) FROM alert_history WHERE substr(created, 1, 10) >= ? GROUP BY level",
        (since,),
    )
    for level, total in rows:
        if level in levels:
            levels[level] = total

    return days, levels


def read_alert_list(conn, level="", limit=200):
    if level:
        rows = conn.execute(
            "SELECT id, created, level, title FROM alert_history WHERE level = ? ORDER BY id DESC LIMIT ?",
            (level, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, created, level, title FROM alert_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    items = []
    for row in rows:
        items.append({"id": row[0], "created": row[1], "level": row[2], "title": row[3]})
    return items


def read_alert(conn, alert_id):
    row = conn.execute(
        "SELECT id, created, level, title, text FROM alert_history WHERE id = ?",
        (alert_id,),
    ).fetchone()
    if row is None:
        return None
    return {"id": row[0], "created": row[1], "level": row[2], "title": row[3], "text": row[4]}


def read_dashboard(conn):
    days, levels = read_chart(conn)

    return {
        "status": read_status(conn),
        "days": days,
        "levels": levels,
        "week_total": sum(levels.values()),
        "recent": read_alert_list(conn, "", 8),
        "pending": count(conn, "SELECT COUNT(*) FROM pending_alerts"),
        "rules": count(conn, "SELECT COUNT(*) FROM rules"),
        "messages": count(conn, "SELECT COUNT(*) FROM seen_messages"),
        "fingerprints": count(conn, "SELECT COUNT(*) FROM fingerprints"),
    }