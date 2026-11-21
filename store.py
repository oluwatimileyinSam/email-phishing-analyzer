import datetime
import json
import os
import sqlite3

from paths import path_in_app


def db_path():
    name = os.environ.get("WATCHER_DB", "watcher.db")
    if os.path.isabs(name):
        return name
    return path_in_app(name)


DB_FILE = db_path()


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("CREATE TABLE IF NOT EXISTS rules (rule_id TEXT PRIMARY KEY, name TEXT, fingerprint TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS pending_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS seen_messages (message_id TEXT PRIMARY KEY, received TEXT)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS fingerprints (message_id TEXT PRIMARY KEY, received TEXT, sender TEXT, "
        "sender_domain TEXT, subject_hash TEXT, hashes TEXT, domains TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alert_history (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, "
        "level TEXT, title TEXT, text TEXT)"
    )
    os.chmod(DB_FILE, 0o600)
    return conn


def get_known_rules(conn):
    known = {}
    for rule_id, name, fingerprint in conn.execute("SELECT rule_id, name, fingerprint FROM rules"):
        known[rule_id] = (name, fingerprint)
    return known


def save_rule(conn, rule_id, name, fingerprint):
    conn.execute(
        "INSERT OR REPLACE INTO rules (rule_id, name, fingerprint) VALUES (?, ?, ?)",
        (rule_id, name, fingerprint),
    )


def remove_rule(conn, rule_id):
    conn.execute("DELETE FROM rules WHERE rule_id = ?", (rule_id,))


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if row:
        return row[0]
    return None


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def add_pending(conn, text):
    conn.execute("INSERT INTO pending_alerts (text) VALUES (?)", (text,))

    first_line = text.split("\n", 1)[0]
    level, separator, title = first_line.partition(": ")
    conn.execute(
        "INSERT INTO alert_history (created, level, title, text) VALUES (?, ?, ?, ?)",
        (now_utc(), level, title, text),
    )
    conn.execute(
        "DELETE FROM alert_history WHERE id NOT IN (SELECT id FROM alert_history ORDER BY id DESC LIMIT 1000)"
    )


def get_pending(conn):
    return conn.execute("SELECT id, text FROM pending_alerts ORDER BY id").fetchall()


def delete_pending(conn, pending_id):
    conn.execute("DELETE FROM pending_alerts WHERE id = ?", (pending_id,))


def is_seen(conn, message_id):
    row = conn.execute("SELECT 1 FROM seen_messages WHERE message_id = ?", (message_id,)).fetchone()
    return row is not None


def mark_seen(conn, message_id, received):
    conn.execute(
        "INSERT OR REPLACE INTO seen_messages (message_id, received) VALUES (?, ?)",
        (message_id, received),
    )


def save_fingerprint(conn, fp):
    conn.execute(
        "INSERT OR REPLACE INTO fingerprints "
        "(message_id, received, sender, sender_domain, subject_hash, hashes, domains) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            fp["message_id"], fp["received"], fp["sender"], fp["sender_domain"],
            fp["subject_hash"], json.dumps(fp["hashes"]), json.dumps(fp["domains"]),
        ),
    )
    conn.execute(
        "DELETE FROM fingerprints WHERE message_id NOT IN "
        "(SELECT message_id FROM fingerprints ORDER BY received DESC LIMIT 2000)"
    )


def recent_fingerprints(conn, limit=500):
    rows = conn.execute(
        "SELECT message_id, received, sender, sender_domain, subject_hash, hashes, domains "
        "FROM fingerprints ORDER BY received DESC LIMIT ?",
        (limit,),
    ).fetchall()

    found = []
    for row in rows:
        found.append({
            "message_id": row[0],
            "received": row[1],
            "sender": row[2],
            "sender_domain": row[3],
            "subject_hash": row[4],
            "hashes": json.loads(row[5]),
            "domains": json.loads(row[6]),
        })
    return found