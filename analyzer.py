import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

BRANDS = ["northwind"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]

URGENCY_WORDS = [
    "urgent", "immediately", "right away", "act now", "final notice",
    "in 24 hours", "within 24 hours", "will be locked", "will be suspended",
    "avoid penalties",
]
PAYMENT_WORDS = [
    "bank details", "changed our bank", "change our bank", "new account number",
    "new bank account", "outstanding invoice", "wire transfer", "gift card",
]
PASSWORD_WORDS = [
    "verify your password", "confirm your password", "enter your password",
    "verify your account", "confirm your identity", "login details",
]
NO_VERIFY_WORDS = [
    "do not call", "don't call", "do not contact", "phone line is down",
]

RISKY_EXTENSIONS = [".exe", ".msi", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".hta", ".lnk", ".com"]
MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm"]
ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".iso", ".img"]
DOCUMENT_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png"]


def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)

def load_email_bytes(data):
    return BytesParser(policy=policy.default).parsebytes(data)


def get_result(auth_text, name):
    match = re.search(name + r"=(\w+)", auth_text)
    if match:
        return match.group(1)
    return None


def get_domain(address):
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower()


def get_host(url):
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    host = urlparse(url).hostname
    if host is None:
        return ""
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def get_html(msg):
    body = msg.get_body(preferencelist=("html", "plain"))
    if body is None:
        return ""
    return body.get_content()


def get_text(msg):
    subject = str(msg["Subject"] or "")
    body = re.sub(r"<[^>]+>", " ", get_html(msg))
    text = subject + " " + body
    return " ".join(text.lower().split())


def find_words(text, words):
    found = []
    for word in words:
        if word in text:
            found.append(word)
    return found


def get_extensions(filename):
    parts = filename.lower().split(".")
    extensions = []
    for part in parts[1:]:
        extensions.append("." + part)
    return extensions


def check_authentication(msg):
    findings = []
    auth = msg["Authentication-Results"]

    if auth is None:
        findings.append((10, "No sender verification results found in the headers"))
        return findings

    auth = str(auth).lower()
    spf = get_result(auth, "spf")
    dkim = get_result(auth, "dkim")
    dmarc = get_result(auth, "dmarc")

    if spf == "fail":
        findings.append((15, "SPF failed: the sending server is not allowed to send for this domain"))
    elif spf == "softfail":
        findings.append((8, "SPF soft failed: the sending server is probably not allowed"))

    if dkim == "fail":
        findings.append((15, "DKIM failed: the email signature is invalid"))
    elif dkim == "none":
        findings.append((5, "DKIM missing: the email is not signed"))

    if dmarc == "fail":
        findings.append((20, "DMARC failed: the email does not match the domain's own rules"))

    return findings


def check_sender(msg):
    findings = []

    from_name, from_addr = parseaddr(str(msg["From"]))
    from_domain = get_domain(from_addr)

    reply_to = msg["Reply-To"]
    if reply_to is not None:
        reply_name, reply_addr = parseaddr(str(reply_to))
        reply_domain = get_domain(reply_addr)
        if reply_domain != from_domain:
            findings.append((15, "Reply To goes to a different domain (" + reply_domain + ") than the sender (" + from_domain + ")"))

    for brand in BRANDS:
        if brand in from_name.lower() and brand not in from_domain:
            findings.append((20, "Display name uses '" + brand + "' but the sender domain is " + from_domain))

    return findings


def check_links(msg):
    findings = []
    html = get_html(msg)
    links = re.findall(r"""<a\s[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""", html, re.I | re.S)

    for href, text in links:
        text = re.sub(r"<[^>]+>", "", text).strip()
        real_host = get_host(href)

        shown_host = ""
        if "." in text and " " not in text:
            shown_host = get_host(text)

        if shown_host and shown_host != real_host:
            findings.append((20, "Link text shows " + shown_host + " but the link goes to " + real_host))

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", real_host):
            findings.append((20, "Link goes to a raw IP address (" + real_host + ") instead of a domain name"))

        if real_host in SHORTENERS:
            findings.append((10, "Link uses a URL shortener (" + real_host + ") that hides the real destination"))

    return findings


def check_wording(msg):
    findings = []
    text = get_text(msg)

    found = find_words(text, URGENCY_WORDS)
    if found:
        findings.append((8, "Urgency or pressure wording: " + ", ".join(found)))

    found = find_words(text, PAYMENT_WORDS)
    if found:
        findings.append((15, "Payment or bank detail request: " + ", ".join(found)))

    found = find_words(text, PASSWORD_WORDS)
    if found:
        findings.append((12, "Asks for a password or login: " + ", ".join(found)))

    found = find_words(text, NO_VERIFY_WORDS)
    if found:
        findings.append((10, "Tells you not to verify by phone: " + ", ".join(found)))

    return findings


def check_attachments(msg):
    findings = []

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if not filename:
            continue

        extensions = get_extensions(filename)
        if not extensions:
            continue

        last = extensions[-1]
        hiding_types = RISKY_EXTENSIONS + MACRO_EXTENSIONS + ARCHIVE_EXTENSIONS

        if len(extensions) >= 2 and extensions[-2] in DOCUMENT_EXTENSIONS and last in hiding_types:
            findings.append((25, "Double extension in attachment name (" + filename + "): the real file type is hidden"))

        if last in RISKY_EXTENSIONS:
            findings.append((20, "Risky attachment type (" + filename + "): programs and scripts can run code"))
        elif last in MACRO_EXTENSIONS:
            findings.append((15, "Macro enabled Office file (" + filename + "): macros can run code"))
        elif last in ARCHIVE_EXTENSIONS:
            findings.append((5, "Archive attachment (" + filename + "): archives can hide other files"))

    return findings


def get_level(score):
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NO WARNINGS"


def build_advice(level, findings):
    reasons = ""
    for points, reason in findings:
        reasons = reasons + " " + reason.lower()

    advice = []

    if level == "HIGH":
        advice.append("Do not reply, click any link or open any attachment.")
    elif level == "MEDIUM":
        advice.append("Be careful. Check the sender before you act on this email.")
    else:
        advice.append("Minor warnings found. Read the reasons above before you act.")

    advice.append("Verify the sender and the content through a call or in person.")
    advice.append("Use a phone number you already have. Never use one from this email.")

    if "payment or bank" in reasons:
        advice.append("Before any payment or bank detail change, confirm it by a call or in person.")

    if "link " in reasons:
        advice.append("Do not click the links. Type the company address yourself or use a saved bookmark.")

    if "attachment" in reasons or "macro" in reasons:
        advice.append("Do not open the attachment. Ask the sender to confirm it by a call or in person.")

    if "password" in reasons:
        advice.append("Never enter a password from an email link. Go to the official site yourself.")

    if "spf" in reasons or "dkim" in reasons or "dmarc" in reasons:
        advice.append("The mail system could not confirm the sender. Treat the sender as unconfirmed.")

    return advice


def analyze_email(msg):
    findings = []
    findings = findings + check_authentication(msg)
    findings = findings + check_sender(msg)
    findings = findings + check_links(msg)
    findings = findings + check_wording(msg)
    findings = findings + check_attachments(msg)

    score = 0
    for points, reason in findings:
        score = score + points
    score = min(score, 100)

    level = get_level(score)

    if findings:
        advice = build_advice(level, findings)
    else:
        advice = [
            "No warnings found. This does not mean the email is safe.",
            "Still verify anything about money or passwords by a call or in person.",
        ]

    return {
        "from": str(msg["From"]),
        "subject": str(msg["Subject"]),
        "score": score,
        "level": level,
        "findings": findings,
        "advice": advice,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py samples/safe.eml")
        return

    msg = load_email(sys.argv[1])
    result = analyze_email(msg)

    print("From:", result["from"])
    print("Subject:", result["subject"])
    print()
    print("Risk score:", result["score"], "/ 100 (" + result["level"] + ")")
    print()

    if result["findings"]:
        print("Reasons:")
        for points, reason in result["findings"]:
            print("  +" + str(points), reason)
        print()
        print("What to do:")
        number = 1
        for line in result["advice"]:
            print("  " + str(number) + ".", line)
            number = number + 1
    else:
        for line in result["advice"]:
            print(line)


if __name__ == "__main__":
    main()