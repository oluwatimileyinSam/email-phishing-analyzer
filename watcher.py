import datetime
import fcntl
import logging
import logging.handlers
import sys

import store
import telegram_alerts
from graph_client import get_token
from mail_watcher import check_new_mail, make_mail_alert, print_mail_report
from rule_watcher import check_mailbox_rules, print_report

LOCK_FILE = "watcher.lock"
LOG_FILE = "watcher.log"


def setup_log():
    log = logging.getLogger("watcher")
    if not log.handlers:
        handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=500000, backupCount=2)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


def warn_sign_in(conn, reason):
    today = datetime.date.today().isoformat()
    if store.get_meta(conn, "signin_alert_day") == today:
        return

    text = (
        "WARNING: The mailbox watcher could not sign in, so it is not checking your mailbox. "
        + reason + " Run python3 show_rules.py by hand to sign in again."
    )
    store.add_pending(conn, text)
    store.set_meta(conn, "signin_alert_day", today)
    conn.commit()


def run_checks(token, conn, quiet, log):
    problems = []
    rule_count = 0
    mail_count = 0

    try:
        analyses, alerts, first_run = check_mailbox_rules(token, conn)
        for alert in alerts:
            store.add_pending(conn, telegram_alerts.format_alert(alert))
        conn.commit()
        rule_count = len(analyses)
        if not quiet:
            print_report(analyses, alerts, first_run)
    except RuntimeError as error:
        problems.append("rules: " + str(error))

    try:
        entries, problem, baseline = check_new_mail(token, conn)
        mail_count = len(entries)
        if not quiet:
            print()
            print_mail_report(entries, problem, baseline)
        if problem:
            problems.append("mail: " + problem)
    except RuntimeError as error:
        problems.append("mail: " + str(error))

    sent, left, note = telegram_alerts.send_pending(conn)
    if note:
        problems.append("telegram: " + note)

    line = "rules=" + str(rule_count) + " new_mail=" + str(mail_count) + " alerts_sent=" + str(sent) + " waiting=" + str(left)
    log.info(line)
    for problem in problems:
        log.info("problem " + problem)

    print(line)
    for problem in problems:
        print("Problem:", problem)

    if problems:
        return 1
    return 0


def main():
    quiet = "--quiet" in sys.argv
    log = setup_log()

    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log.info("skipped: another run is still active")
        print("Another run is still active. Skipped.")
        return 0

    conn = store.connect()
    try:
        try:
            token = get_token(interactive=False)
        except RuntimeError as error:
            warn_sign_in(conn, str(error))
            telegram_alerts.send_pending(conn)
            log.info("stopped: " + str(error))
            print("Stopped:", error)
            return 1

        return run_checks(token, conn, quiet, log)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())