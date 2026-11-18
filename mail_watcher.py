import datetime
import urllib.parse

import store
import telegram_alerts
from graph_client import get_token, graph_get, graph_get_raw
from mail_checks import MIN_ALERT_SCORE, check_raw_message


def now_text():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shorten(text, size):
    return " ".join(str(text).split())[:size]


def newest_time(token):
    path = "/me/mailFolders/inbox/messages?$top=1&$orderby=receivedDateTime%20desc&$select=receivedDateTime"
    items = graph_get(path, token).get("value", [])
    if items:
        return items[0]["receivedDateTime"]
    return now_text()


def new_messages(token, since):
    expression = urllib.parse.quote("receivedDateTime ge " + since, safe="")
    path = (
        "/me/mailFolders/inbox/messages?$filter=" + expression
        + "&$orderby=receivedDateTime%20asc&$top=25&$select=id,receivedDateTime"
    )
    return graph_get(path, token).get("value", [])


def make_mail_alert(result):
    title = "Risky email from " + shorten(result["from"], 80) + ": " + shorten(result["subject"], 80)
    return {
        "title": title,
        "level": result["level"],
        "reasons": result["reasons"],
        "notes": result["attachment_lines"],
        "advice": result["advice"],
    }


def check_new_mail(token, conn):
    entries = []
    since = store.get_meta(conn, "mail_since")

    if since is None:
        newest = newest_time(token)
        for item in new_messages(token, newest):
            store.mark_seen(conn, item["id"], item["receivedDateTime"])
        store.set_meta(conn, "mail_since", newest)
        conn.commit()
        return entries, "", True

    for item in new_messages(token, since):
        message_id = item["id"]
        received = item["receivedDateTime"]

        if store.is_seen(conn, message_id):
            continue

        try:
            path = "/me/messages/" + urllib.parse.quote(message_id, safe="") + "/$value"
            raw = graph_get_raw(path, token)
        except RuntimeError as error:
            return entries, str(error), False

        result = check_raw_message(raw)
        result["received"] = received

        if result["score"] >= MIN_ALERT_SCORE:
            store.add_pending(conn, telegram_alerts.format_alert(make_mail_alert(result)))

        store.mark_seen(conn, message_id, received)
        store.set_meta(conn, "mail_since", received)
        conn.commit()
        entries.append(result)

    return entries, "", False


def print_mail_report(entries, problem, baseline):
    if baseline:
        print("First run: only mail that arrives from now on will be checked.")
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