import hashlib
import json

from analyzer import get_level

FORWARD_KEYS = ["forwardTo", "forwardAsAttachmentTo", "redirectTo"]
HIDING_FOLDERS = [
    "deleted items",
    "junk email",
    "rss feeds",
    "rss subscriptions",
    "conversation history",
    "sync issues",
]
CONDITION_TEXT_KEYS = ["subjectContains", "bodyContains", "bodyOrSubjectContains", "senderContains"]
SENSITIVE_WORDS = [
    "bank", "invoice", "payment", "security", "password",
    "verify", "login", "account", "wire", "paypal", "transfer",
]


def addresses(value):
    found = []
    for item in value:
        if isinstance(item, dict):
            found.append(item.get("emailAddress", {}).get("address", "unknown"))
        else:
            found.append(str(item))
    return found


def check_rule(rule, folder_names):
    findings = []
    actions = rule.get("actions") or {}
    conditions = rule.get("conditions") or {}

    targets = []
    for key in FORWARD_KEYS:
        targets = targets + addresses(actions.get(key) or [])
    if targets:
        findings.append((50, "Sends matching mail to another address: " + ", ".join(targets)))

    if actions.get("permanentDelete"):
        findings.append((50, "Permanently deletes matching mail, so it cannot be recovered"))
    elif actions.get("delete"):
        findings.append((40, "Deletes matching mail, so you may never see it"))

    folder_id = actions.get("moveToFolder")
    if folder_id:
        folder = folder_names.get(folder_id, folder_id)
        if folder.lower() in HIDING_FOLDERS:
            findings.append((35, "Moves matching mail to a folder people rarely check: " + folder))

    hides = actions.get("delete") or actions.get("permanentDelete") or folder_id
    if actions.get("markAsRead") and hides:
        findings.append((10, "Marks matching mail as read, so you may not notice it"))

    words = []
    for key in CONDITION_TEXT_KEYS:
        for text in conditions.get(key) or []:
            for word in SENSITIVE_WORDS:
                if word in str(text).lower() and word not in words:
                    words.append(word)
    acts = targets or hides or actions.get("markAsRead")
    if words and acts:
        findings.append((20, "Targets mail about money or security: " + ", ".join(words)))

    if not conditions and (targets or hides):
        findings.append((20, "Applies to every message in the inbox"))

    return findings


def fingerprint(rule):
    parts = {
        "conditions": rule.get("conditions"),
        "actions": rule.get("actions"),
        "enabled": rule.get("isEnabled"),
    }
    text = json.dumps(parts, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def analyze_rule(rule, folder_names):
    findings = check_rule(rule, folder_names)

    score = 0
    for points, reason in findings:
        score = score + points
    score = min(score, 100)

    return {
        "id": rule.get("id", ""),
        "name": str(rule.get("displayName", "")),
        "enabled": bool(rule.get("isEnabled")),
        "score": score,
        "level": get_level(score),
        "findings": findings,
        "fingerprint": fingerprint(rule),
    }


def build_rule_advice(findings):
    reasons = ""
    for points, reason in findings:
        reasons = reasons + " " + reason.lower()

    advice = ["Open the mailbox rules and check that you created this rule yourself."]

    if "another address" in reasons:
        advice.append("A rule that sends mail to another address can leak private mail. Check whether anything was already sent there.")

    if "deletes" in reasons or "rarely check" in reasons or "marked as read" in reasons or "marks matching" in reasons:
        advice.append("Rules that hide mail are often used to hide bank messages and replies from you.")

    advice.append("If you did not create it, delete the rule, change the password and check the recent sign in activity.")
    advice.append("If someone asked you to create the rule, verify the request by a call or in person.")

    return advice