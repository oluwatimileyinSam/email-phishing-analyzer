import hashlib
import os
import re
import sys

from analyzer import (
    ARCHIVE_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    MACRO_EXTENSIONS,
    RISKY_EXTENSIONS,
    get_extensions,
    get_level,
)

SIGNATURES = [
    (b"MZ", "exe"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x7fELF", "elf"),
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
    (b"\x1f\x8b", "gz"),
]

LABELS = {
    "exe": "Windows program",
    "elf": "Linux program",
    "pdf": "PDF document",
    "zip": "ZIP archive",
    "ole": "old style Office file or MSI installer",
    "rar": "RAR archive",
    "7z": "7z archive",
    "gz": "gzip archive",
    "jpg": "JPEG image",
    "png": "PNG image",
    "gif": "GIF image",
    "text": "plain text",
    "empty": "empty file",
    "unknown": "unknown binary data",
}

EXPECTED = {
    ".pdf": ["pdf"],
    ".exe": ["exe"],
    ".scr": ["exe"],
    ".msi": ["ole"],
    ".doc": ["ole"],
    ".xls": ["ole"],
    ".ppt": ["ole"],
    ".docx": ["zip"],
    ".xlsx": ["zip"],
    ".pptx": ["zip"],
    ".docm": ["zip"],
    ".xlsm": ["zip"],
    ".pptm": ["zip"],
    ".jar": ["zip"],
    ".zip": ["zip"],
    ".rar": ["rar"],
    ".7z": ["7z"],
    ".gz": ["gz"],
    ".jpg": ["jpg"],
    ".jpeg": ["jpg"],
    ".png": ["png"],
    ".gif": ["gif"],
    ".txt": ["text"],
    ".js": ["text"],
    ".bat": ["text"],
    ".cmd": ["text"],
    ".ps1": ["text"],
    ".vbs": ["text"],
    ".hta": ["text"],
}

PROGRAM_TYPES = ["exe", "elf"]
ARCHIVE_TYPES = ["zip", "rar", "7z", "gz"]
PROGRAM_EXTENSIONS = [".exe", ".scr", ".com", ".dll", ".sys"]

PDF_RISKS = [
    (rb"/(?:JavaScript|JS)(?![A-Za-z0-9])", 30, "PDF contains JavaScript: it can run code when the file is opened"),
    (rb"/(?:OpenAction|AA)(?![A-Za-z0-9])", 10, "PDF has an automatic open action: often harmless, but check it with the other warnings"),
    (rb"/Launch(?![A-Za-z0-9])", 35, "PDF can launch a program"),
    (rb"/EmbeddedFile(?![A-Za-z0-9])", 15, "PDF carries an embedded file"),
]

SCRIPT_EXTENSIONS = [".js", ".jse", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".wsf", ".hta"]

SCRIPT_RISKS = [
    (r"eval\(|unescape\(|fromcharcode|atob\(|invoke-expression|\biex\b|\bexecute\(", 15, "Script: builds or hides code while it runs"),
    (r"wscript\.shell|activexobject|shell\.application|createobject|powershell|cmd\.exe|\.run\(", 15, "Script: can start other programs or commands"),
    (r"invoke-webrequest|downloadstring|downloadfile|urldownloadtofile|bitsadmin|certutil|xmlhttp|\bcurl\b|\bwget\b", 20, "Script: can download files from the internet"),
    (r"-encodedcommand|-enc\b|frombase64string", 20, "Script: uses encoded commands to hide what it does"),
    (r"-executionpolicy\s+bypass|-windowstyle\s+hidden|-w\s+hidden|-nop\b", 20, "Script: tries to bypass security settings or hide its window"),
    (r"/(?:quiet|qn|qb|silent|verysilent|norestart|passive)\b", 15, "Script: installs software silently, with no window and no questions"),
]


def detect_type(data):
    if not data:
        return "empty"
    head = data[:16]
    for signature, kind in SIGNATURES:
        if head.startswith(signature):
            return kind
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text"
    if b"\x00" not in data[:2048]:
        return "text"
    return "unknown"


def check_name(filename):
    findings = []
    extensions = get_extensions(filename)
    if not extensions:
        return findings

    last = extensions[-1]
    hiding_types = RISKY_EXTENSIONS + MACRO_EXTENSIONS + ARCHIVE_EXTENSIONS

    if len(extensions) >= 2 and extensions[-2] in DOCUMENT_EXTENSIONS and last in hiding_types:
        findings.append((25, "Double extension in the file name (" + filename + "): the real file type is hidden"))

    if last in RISKY_EXTENSIONS:
        findings.append((20, "Risky file type (" + last + "): programs and scripts can run code"))
    elif last in MACRO_EXTENSIONS:
        findings.append((15, "Macro enabled Office file (" + last + "): macros can run code"))
    elif last in ARCHIVE_EXTENSIONS:
        findings.append((5, "Archive file (" + last + "): archives can hide other files"))

    return findings


def check_real_type(filename, kind):
    findings = []
    extensions = get_extensions(filename)
    last = ""
    if extensions:
        last = extensions[-1]

    if kind == "empty":
        return findings

    label = LABELS[kind]

    if kind in PROGRAM_TYPES:
        if last not in PROGRAM_EXTENSIONS:
            findings.append((35, "The file is really a " + label + ", but its name does not say so"))
        return findings

    if last in EXPECTED and kind not in EXPECTED[last]:
        if kind in ARCHIVE_TYPES:
            findings.append((30, "Disguised archive: the file is really a " + label + ", but the name ends in " + last))
        else:
            findings.append((15, "File type does not match the name: it is really " + label + ", but the name ends in " + last))

    return findings

def unhide_pdf_names(data):
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)


def check_pdf(data):
    findings = []
    text = unhide_pdf_names(data)

    for pattern, points, reason in PDF_RISKS:
        if re.search(pattern, text):
            findings.append((points, reason))

    return findings


def read_text(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="ignore").lower()
    return data.decode("utf-8", errors="ignore").lower()


def check_script(filename, data):
    findings = []
    extensions = get_extensions(filename)
    if not extensions or extensions[-1] not in SCRIPT_EXTENSIONS:
        return findings

    text = read_text(data)

    for pattern, points, reason in SCRIPT_RISKS:
        found = sorted(set(re.findall(pattern, text)))
        if found:
            findings.append((points, reason + ": " + ", ".join(found[:5])))

    if re.search(r"[a-z0-9+/=]{200,}", text):
        findings.append((15, "Script: contains a very long block of encoded text"))

    return findings


def build_file_advice(level, findings):
    reasons = ""
    for points, reason in findings:
        reasons = reasons + " " + reason.lower()

    if not findings:
        return [
            "No warnings found. This does not mean the file is safe.",
            "Check unexpected files with the sender by a call or in person, and scan them with your antivirus.",
        ]

    advice = []

    if level == "HIGH":
        advice.append("Do not open or run this file.")
    elif level == "MEDIUM":
        advice.append("Be careful. Do not open this file until you have checked it.")
    else:
        advice.append("Minor warnings found. Read the reasons above before you open it.")

    advice.append("Verify the file with the sender through a call or in person.")
    advice.append("Use a phone number you already have. Never use one from the message that came with the file.")

    if "program" in reasons or "programs" in reasons:
        advice.append("Never run a program or installer you did not expect. Download it from the official site instead.")

    if "archive" in reasons:
        advice.append("Archives can hide other files. Do not open it until the sender confirms it.")

    if "macro" in reasons:
        advice.append("Do not enable macros in Office files from unknown senders.")

    if "pdf" in reasons:
        advice.append("Do not open this PDF until the sender confirms it.")

    if "script:" in reasons:
        advice.append("Never run a script you did not write or expect. To read it, open it in a plain text editor, not by double clicking.")

    return advice


def scan_file(filename, data):
    kind = detect_type(data)

    findings = []
    findings = findings + check_name(filename)
    findings = findings + check_real_type(filename, kind)

    if kind == "pdf":
        findings = findings + check_pdf(data)

    findings = findings + check_script(filename, data)

    score = 0
    for points, reason in findings:
        score = score + points
    score = min(score, 100)

    level = get_level(score)

    return {
        "name": filename,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "type": LABELS[kind],
        "score": score,
        "level": level,
        "findings": findings,
        "advice": build_file_advice(level, findings),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 file_scanner.py file_samples/notes.txt")
        return

    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()

    result = scan_file(os.path.basename(path), data)

    print("File:", result["name"])
    print("Size:", result["size"], "bytes")
    print("Type:", result["type"])
    print("SHA256:", result["sha256"])
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