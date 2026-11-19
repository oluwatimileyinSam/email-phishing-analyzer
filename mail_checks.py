from analyzer import analyze_email, get_level, load_email_bytes
from clone_checks import find_clones, fingerprint_message
from file_scanner import scan_file

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MIN_ALERT_SCORE = 30


def scan_attachments(msg):
    results = []
    notes = []

    for part in msg.iter_attachments():
        name = part.get_filename()
        if not name:
            continue

        data = part.get_payload(decode=True)
        if not isinstance(data, bytes):
            notes.append("Attachment " + name + " was not scanned: it is an attached email or has no readable content.")
            continue

        if len(data) > MAX_ATTACHMENT_BYTES:
            notes.append("Attachment " + name + " was not scanned: it is larger than 10 MB.")
            continue

        results.append(scan_file(name, data))

    return results, notes


def check_raw_message(raw, history=None, message_id="", received=""):
    msg = load_email_bytes(raw)
    email_result = analyze_email(msg)

    fingerprint = fingerprint_message(msg, message_id, received)
    clone_findings = find_clones(fingerprint, history or [])
    findings = email_result["findings"] + clone_findings

    base_score = 0
    for points, reason in findings:
        base_score = base_score + points
    base_score = min(base_score, 100)

    attachments, notes = scan_attachments(msg)

    score = base_score
    for item in attachments:
        score = max(score, item["score"])

    attachment_lines = []
    risky_attachments = False
    for item in attachments:
        if item["score"] >= 1:
            top = max(item["findings"])[1]
            attachment_lines.append(
                "Attachment " + item["name"] + ": " + str(item["score"]) + " / 100 (" + item["level"] + "). " + top
            )
        if item["score"] >= MIN_ALERT_SCORE:
            risky_attachments = True
    attachment_lines = attachment_lines + notes

    advice = []
    if email_result["findings"]:
        advice = list(email_result["advice"])
    if clone_findings:
        advice.append("This email looks like a copy of an earlier message. Contact the sender with a phone number you already have before you click or pay.")

    if not findings:
        advice = [
            "Do not open the attachments in this email.",
            "Verify the sender and the files through a call or in person.",
            "Use a phone number you already have. Never use one from this email.",
        ]
    elif risky_attachments:
        advice.append("Do not open the attachments until the sender confirms them.")

    return {
        "from": email_result["from"],
        "subject": email_result["subject"],
        "score": score,
        "level": get_level(score),
        "reasons": findings,
        "clone_findings": clone_findings,
        "attachment_lines": attachment_lines,
        "attachments": attachments,
        "advice": advice,
        "fingerprint": fingerprint,
    }