import urllib.parse

import store
from graph_client import get_token, graph_get
from rule_checks import analyze_rule, build_rule_advice
from show_rules import describe


def folder_names_for(rules, token):
    names = {}
    for rule in rules:
        folder_id = (rule.get("actions") or {}).get("moveToFolder")
        if folder_id and folder_id not in names:
            try:
                path = "/me/mailFolders/" + urllib.parse.quote(folder_id, safe="")
                names[folder_id] = graph_get(path, token).get("displayName", folder_id)
            except RuntimeError:
                names[folder_id] = folder_id
    return names


def compare(analyses, known, first_run):
    for item in analyses:
        old = known.get(item["id"])
        if old is None:
            if first_run:
                item["status"] = "existing"
            else:
                item["status"] = "NEW"
        elif old[1] != item["fingerprint"]:
            item["status"] = "CHANGED"
        else:
            item["status"] = "unchanged"

    current_ids = [item["id"] for item in analyses]
    removed = []
    for rule_id, values in known.items():
        if rule_id not in current_ids:
            removed.append((rule_id, values[0]))
    return removed


def make_alerts(analyses, removed, first_run):
    alerts = []

    for item in analyses:
        if first_run and item["score"] >= 30:
            title = "Risky mailbox rule found on the first run: " + item["name"]
        elif item["status"] == "NEW" and item["score"] >= 1:
            title = "New mailbox rule: " + item["name"]
        elif item["status"] == "CHANGED" and item["score"] >= 1:
            title = "Mailbox rule changed: " + item["name"]
        else:
            continue

        alerts.append({
            "title": title,
            "level": item["level"],
            "reasons": item["findings"],
            "advice": build_rule_advice(item["findings"]),
        })

    for rule_id, name in removed:
        alerts.append({
            "title": "Mailbox rule removed: " + name,
            "level": "INFO",
            "reasons": [],
            "advice": ["Check that you removed this rule yourself."],
        })

    return alerts


def check_mailbox_rules(token, conn):
    data = graph_get("/me/mailFolders/inbox/messageRules", token)
    rules = data.get("value", [])
    folder_names = folder_names_for(rules, token)

    analyses = []
    for rule in rules:
        item = analyze_rule(rule, folder_names)
        actions = dict(rule.get("actions") or {})
        if "moveToFolder" in actions:
            actions["moveToFolder"] = folder_names.get(actions["moveToFolder"], actions["moveToFolder"])
        item["when"] = describe(rule.get("conditions") or {})
        item["then"] = describe(actions)
        analyses.append(item)

    known = store.get_known_rules(conn)
    first_run = store.get_meta(conn, "rules_baseline") is None
    removed = compare(analyses, known, first_run)
    alerts = make_alerts(analyses, removed, first_run)

    for item in analyses:
        store.save_rule(conn, item["id"], item["name"], item["fingerprint"])
    for rule_id, name in removed:
        store.remove_rule(conn, rule_id)
    store.set_meta(conn, "rules_baseline", "done")
    conn.commit()

    return analyses, alerts, first_run


def print_report(analyses, alerts, first_run):
    print("Mailbox rules found:", len(analyses))
    if first_run:
        print("First run: these rules are saved as the baseline. Later runs report changes.")

    number = 1
    for item in analyses:
        state = "enabled" if item["enabled"] else "disabled"
        print()
        print("Rule " + str(number) + ": " + item["name"] + " (" + state + ") [" + item["status"] + "]")
        print("  Risk:", item["score"], "/ 100 (" + item["level"] + ")")
        for line in item["when"]:
            print("  When " + line)
        for line in item["then"]:
            print("  Then " + line)
        for points, reason in item["findings"]:
            print("  +" + str(points), reason)
        number = number + 1

    print()
    print("Alerts:", len(alerts))
    for alert in alerts:
        print()
        print("ALERT (" + alert["level"] + "): " + alert["title"])
        for points, reason in alert["reasons"]:
            print("  +" + str(points), reason)
        print("  What to do:")
        number = 1
        for line in alert["advice"]:
            print("    " + str(number) + ".", line)
            number = number + 1


def main():
    try:
        token = get_token()
        conn = store.connect()
        analyses, alerts, first_run = check_mailbox_rules(token, conn)
        conn.close()
    except RuntimeError as error:
        print("Stopped:", error)
        return

    print_report(analyses, alerts, first_run)


if __name__ == "__main__":
    main()