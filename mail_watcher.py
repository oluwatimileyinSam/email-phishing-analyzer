import datetime
import urllib.parse

import store
import telegram_alerts
from analyzer import load_email_bytes
from clone_checks import fingerprint_message
from graph_client import get_token, graph_get, graph_get_raw
from mail_checks import MIN_ALERT_SCORE, check_raw_message


def now_text():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shorten(text, size):
    return " ".join(str(text).split())[:size]


def latest_messages(token, count):
    path = (
        "/me/mailFolders/inbox/messages?$top=" + str(count)
        + "&$orderby=receivedDateTime%20desc&$select=id,receivedDateTime"
    )
    return graph_get(path, token).get("value", [])


def new_messages(token, since):
    expression = urllib.parse.quote("receivedDateTime ge " + since, safe="")
    path = (
        "/me/mailFolders/inbox/messages?$filter=" + expression
        + "&$orderby=receivedDateTime%20asc&$top=25&$select=id,receivedDateTime"
    )
    return graph_get(path, token).get("value", [])


def fetch_raw(token, message_id):
    path = "/me/messages/" + urllib.parse.quote(message_id, safe="") + "/$value"
    return graph_get_raw(path, token)


def make_mail_alert(result):
    title = "Risky email from " + shorten(result["from"], 80) + ": " + shorten(result["subject"], 80)
    return {
        "title": title,
        "level": result["level"],
        "reasons": result["reasons"],
        "notes": result["attachment_lines"],
        "advice": result["advice"],
    }


def build_baseline(token, conn):
    items = latest_messages(token, 25)

    for item in items:
        msg = load_email_bytes(fetch_raw(token, item["id"]))
        fp = fingerprint_message(msg, item["id"], item["receivedDateTime"])
        store.save_fingerprint(conn, fp)
        store.mark_seen(conn, item["id"], item["receivedDateTime"])

    if items:
        newest = items[0]["receivedDateTime"]
    else:
        newest = now_text()

    store.set_meta(conn, "mail_since", newest)
    conn.commit()


def check_new_mail(token, conn):
    entries = []
    since = store.get_meta(conn, "mail_since")

    if since is None:
        build_baseline(token, conn)
        return entries, "", True

    history = store.recent_fingerprints(conn)

    for item in new_messages(token, since):
        message_id = item["id"]
        received = item["receivedDateTime"]

        if store.is_seen(conn, message_id):
            continue

        try:
            raw = fetch_raw(token, message_id)
        except RuntimeError as error:
            return entries, str(error), False

        result = check_raw_message(raw, history, message_id, received)
        result["received"] = received

        if result["score"] >= MIN_ALERT_SCORE:
            store.add_pending(conn, telegram_alerts.format_alert(make_mail_alert(result)))

        store.save_fingerprint(conn, result["fingerprint"])
        history.insert(0, result["fingerprint"])
        store.mark_seen(conn, message_id, received)
        store.set_meta(conn, "mail_since", received)
        conn.commit()
        entries.append(result)

    return entries, "", False


def print_mail_report(entries, problem, baseline):
    if baseline:
        print("First run: the newest messages are saved as the starting point. Only mail that arrives from now on is checked.")
        return

    print("New messages checked:", len(entries))

    number = 1
    for result in entries:
        print()
        print("Message " + str(number) + ": " + shorten(result["subject"], 80))
        print("  From:", shorten(result["from"], 80))
        print("  Received:", result["received"])
        print("  Risk:", result["score"], "/ 100 (" + result["level"] + ")")
        if result["score"] >= MIN_ALERT_SCORE:
            print("  ALERT saved for Telegram")
        for points, reason in result["clone_findings"]:
            print("  +" + str(points), reason)
        for line in result["attachment_lines"]:
            print("  " + line)
        number = number + 1

    if problem:
        print()
        print("Stopped early:", problem, "The rest will be checked on the next run.")


def main():
    try:
        token = get_token()
        conn = store.connect()
        entries, problem, baseline = check_new_mail(token, conn)
    except RuntimeError as error:
        print("Stopped:", error)
        return

    print_mail_report(entries, problem, baseline)

    sent, left, note = telegram_alerts.send_pending(conn)
    if sent or left or note:
        print()
        print("Telegram: sent", sent, "and", left, "waiting.", note)

    conn.close()


if __name__ == "__main__":
    main()