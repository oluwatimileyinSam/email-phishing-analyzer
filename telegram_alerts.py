import json
import os
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

import store
from paths import path_in_app


def read_settings():
    load_dotenv(path_in_app(".env"))
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    return token, chat_id


def is_configured():
    token, chat_id = read_settings()
    return bool(token and chat_id)


def format_alert(alert):
    lines = [alert["level"] + ": " + alert["title"]]

    for points, reason in alert["reasons"]:
        lines.append("+" + str(points) + " " + reason)

    for note in alert.get("notes", []):
        lines.append(note)

    lines.append("")
    lines.append("What to do:")
    number = 1
    for line in alert["advice"]:
        lines.append(str(number) + ". " + line)
        number = number + 1

    return "\n".join(lines)[:4000]


def send_telegram(text):
    token, chat_id = read_settings()
    if not token or not chat_id:
        return False, "Telegram is not set up. Add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to the .env file."

    body = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        data=body,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            reply = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 401:
            return False, "Telegram refused the bot token."
        if error.code == 400:
            return False, "Telegram refused the message or the chat id."
        if error.code == 403:
            return False, "The bot was blocked, or you never pressed Start in the bot chat."
        if error.code == 429:
            return False, "Telegram asked us to slow down."
        return False, "Telegram returned code " + str(error.code) + "."
    except (OSError, ValueError):
        return False, "Telegram could not be reached."

    if reply.get("ok"):
        return True, ""
    return False, "Telegram did not accept the message."


def send_pending(conn):
    pending = store.get_pending(conn)
    if not pending:
        return 0, 0, ""

    if not is_configured():
        return 0, len(pending), "Telegram is not set up. The alerts stay saved."

    sent = 0
    for pending_id, text in pending:
        ok, reason = send_telegram(text)
        if not ok:
            return sent, len(pending) - sent, reason + " The rest stay saved and are retried on the next run."
        store.delete_pending(conn, pending_id)
        conn.commit()
        sent = sent + 1
        time.sleep(1)

    return sent, 0, ""