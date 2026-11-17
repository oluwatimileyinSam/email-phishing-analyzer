from graph_client import get_token, graph_get


def names(value):
    items = []
    for item in value:
        if isinstance(item, dict):
            address = item.get("emailAddress", {}).get("address", "")
            items.append(address or str(item))
        else:
            items.append(str(item))
    return ", ".join(items)


def describe(section):
    lines = []
    for key, value in section.items():
        if isinstance(value, list):
            lines.append(key + ": " + names(value))
        elif value is True:
            lines.append(key)
        elif value is not False and value is not None:
            lines.append(key + ": " + str(value))
    return lines


def main():
    token = get_token()
    data = graph_get("/me/mailFolders/inbox/messageRules", token)
    rules = data.get("value", [])

    print("Mailbox rules found:", len(rules))

    number = 1
    for rule in rules:
        state = "enabled" if rule.get("isEnabled") else "disabled"
        print()
        print("Rule " + str(number) + ": " + str(rule.get("displayName")) + " (" + state + ")")
        for line in describe(rule.get("conditions") or {}):
            print("  When " + line)
        for line in describe(rule.get("actions") or {}):
            print("  Then " + line)
        number = number + 1


if __name__ == "__main__":
    main()