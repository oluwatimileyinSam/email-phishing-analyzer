import os
import sqlite3

DB_FILE = "watcher.db"


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS rules (rule_id TEXT PRIMARY KEY, name TEXT, fingerprint TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
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