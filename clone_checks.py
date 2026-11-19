import hashlib
import re
from email.utils import parseaddr

from analyzer import get_host, get_html

SHINGLE_SIZE = 3
SAMPLE_SIZE = 200
MIN_HASHES = 15
SIMILAR = 0.6
SAME_SUBJECT_SIMILAR = 0.4
TWO_PART_ENDINGS = ["co", "com", "org", "net", "gov", "edu", "ac"]


def hash_text(text):
    return int(hashlib.sha1(text.encode("utf-8")).hexdigest()[:15], 16)


def is_reply(subject):
    return bool(re.match(r"^\s*(re|fw|fwd)\s*:", str(subject or ""), re.I))


def normalize_subject(subject):
    text = " ".join(str(subject or "").lower().split())
    while re.match(r"^(re|fw|fwd)\s*:", text):
        text = re.sub(r"^(re|fw|fwd)\s*:\s*", "", text)
    return text


def base_domain(host):
    if re.fullmatch(r"[\d.]+", host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in TWO_PART_ENDINGS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def link_domains(html):
    urls = re.findall(r"""href=["'](https?://[^"']+)["']""", html, re.I)
    urls = urls + re.findall(r"""https?://[^\s"'<>]+""", html, re.I)

    domains = set()
    for url in urls:
        host = get_host(url)
        if host and "." in host:
            domains.add(base_domain(host))
    return sorted(domains)


def body_hashes(html):
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"https?://\S+", " ", text.lower())
    words = re.findall(r"[a-z0-9']+", text)

    hashes = set()
    for i in range(len(words) - SHINGLE_SIZE + 1):
        hashes.add(hash_text(" ".join(words[i:i + SHINGLE_SIZE])))
    return sorted(hashes)[:SAMPLE_SIZE]


def fingerprint_message(msg, message_id="", received=""):
    name, address = parseaddr(str(msg["From"]))
    address = address.lower()
    domain = ""
    if "@" in address:
        domain = base_domain(address.rsplit("@", 1)[1])

    subject = str(msg["Subject"] or "")
    html = get_html(msg)

    return {
        "message_id": message_id,
        "received": received,
        "sender": address,
        "sender_domain": domain,
        "subject_hash": str(hash_text(normalize_subject(subject))),
        "is_reply": is_reply(subject),
        "hashes": body_hashes(html),
        "domains": link_domains(html),
    }


def similarity(first, second):
    a = set(first)
    b = set(second)
    if len(a) < MIN_HASHES or len(b) < MIN_HASHES:
        return 0.0
    return len(a & b) / len(a | b)


def compare_with(fp, old):
    when = str(old["received"])[:10]

    if fp["sender"] != old["sender"]:
        if fp["sender_domain"] != old["sender_domain"]:
            return 35, "Copies an earlier email from " + old["sender"] + " (" + when + ") but comes from a different domain: " + fp["sender"]
        return 20, "Copies an earlier email from " + old["sender"] + " (" + when + ") but comes from a different address: " + fp["sender"]

    new_domains = [d for d in fp["domains"] if d not in old["domains"]]
    if new_domains:
        return 30, "Same wording as an earlier email from the same sender (" + when + "), but the links point to new domains: " + ", ".join(new_domains[:5])

    return None


def find_clones(fp, history):
    if fp["is_reply"]:
        return []

    best = None
    for old in history:
        if old["message_id"] == fp["message_id"]:
            continue

        score = similarity(fp["hashes"], old["hashes"])
        same_subject = fp["subject_hash"] == old["subject_hash"]
        if not (score >= SIMILAR or (same_subject and score >= SAME_SUBJECT_SIMILAR)):
            continue

        found = compare_with(fp, old)
        if found is None:
            continue

        if best is None or (found[0], score) > (best[0], best[2]):
            best = (found[0], found[1], score)

    if best:
        return [(best[0], best[1])]
    return []