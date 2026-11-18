import os
import sqlite3

DB_FILE = "watcher.db"


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS rules (rule_id TEXT PRIMARY KEY, name TEXT, fingerprint TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS pending_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS seen_messages (message_id TEXT PRIMARY KEY, received TEXT)")
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