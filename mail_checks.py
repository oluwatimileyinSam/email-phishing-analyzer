from analyzer import analyze_email, get_level, load_email_bytes
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


def check_raw_message(raw):
    msg = load_email_bytes(raw)
    email_result = analyze_email(msg)
    attachments, notes = scan_attachments(msg)

    score = email_result["score"]
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

    if email_result["findings"]:
        advice = list(email_result["advice"])
        if risky_attachments:
            advice.append("Do not open the attachments until the sender confirms them.")
    else:
        advice = [
            "Do not open the attachments in this email.",
            "Verify the sender and the files through a call or in person.",
            "Use a phone number you already have. Never use one from this email.",
        ]

    return {
        "from": email_result["from"],
        "subject": email_result["subject"],
        "score": score,
        "level": get_level(score),
        "reasons": email_result["findings"],
        "attachment_lines": attachment_lines,
        "attachments": attachments,
        "advice": advice,
    }