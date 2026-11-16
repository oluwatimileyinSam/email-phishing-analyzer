import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile

from dotenv import load_dotenv

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

OLE_MACRO_MARKER = "_VBA_PROJECT".encode("utf-16-le")
MAX_UNPACKED_SIZE = 100 * 1024 * 1024

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

VT_URL = "https://www.virustotal.com/api/v3/files/"

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


def check_old_office(data):
    findings = []
    if OLE_MACRO_MARKER in data:
        findings.append((30, "Old style Office file contains a macro project: macros can run code"))
    return findings


def check_zip(filename, data):
    findings = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()[:10000]
    except (zipfile.BadZipFile, NotImplementedError, ValueError):
        return [(10, "The archive structure is damaged or unusual and could not be read")]

    names = [info.filename.lower() for info in infos]

    extensions = get_extensions(filename)
    last = ""
    if extensions:
        last = extensions[-1]

    macro_parts = [n for n in names if n.endswith("vbaproject.bin")]
    if "[content_types].xml" in names and macro_parts:
        findings.append((30, "Office file contains a macro project (" + macro_parts[0] + "): macros can run code"))
        if last in [".docx", ".xlsx", ".pptx"]:
            findings.append((20, "The file name says no macros, but the file contains a macro project"))

    if any(info.flag_bits & 0x1 for info in infos):
        findings.append((20, "Archive is password protected, so its contents cannot be checked"))

    risky = []
    macro_files = []
    doubles = []
    hiding_types = RISKY_EXTENSIONS + MACRO_EXTENSIONS + ARCHIVE_EXTENSIONS

    for info in infos:
        base = info.filename.split("/")[-1]
        inner = get_extensions(base)
        if not inner:
            continue
        if inner[-1] in RISKY_EXTENSIONS:
            risky.append(base)
        if inner[-1] in MACRO_EXTENSIONS:
            macro_files.append(base)
        if len(inner) >= 2 and inner[-2] in DOCUMENT_EXTENSIONS and inner[-1] in hiding_types:
            doubles.append(base)

    if risky:
        findings.append((30, "Archive contains programs or scripts: " + ", ".join(risky[:5])))
    if macro_files:
        findings.append((15, "Archive contains macro enabled Office files: " + ", ".join(macro_files[:5])))
    if doubles:
        findings.append((25, "Archive contains a file with a double extension: " + ", ".join(doubles[:5])))

    unpacked = sum(info.file_size for info in infos)
    packed = sum(info.compress_size for info in infos)
    if unpacked > MAX_UNPACKED_SIZE and unpacked > packed * 100:
        findings.append((25, "Archive expands to a very large size when unpacked: possible zip bomb"))

    return findings


def check_eicar(data):
    findings = []
    if EICAR in data:
        findings.append((60, "Contains the EICAR test string. It is harmless, but antivirus tools are built to treat it as a virus"))
    return findings


def lookup_virustotal(sha256):
    key = os.environ.get("VT_API_KEY", "")
    if not key:
        return None, "VirusTotal lookup skipped: no VT_API_KEY found in the .env file."

    request = urllib.request.Request(
        VT_URL + sha256,
        headers={"x-apikey": key, "accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None, "VirusTotal has never seen this file hash. That is normal for new or private files. It does not mean the file is safe."
        if error.code == 401:
            return None, "VirusTotal refused the key. Check VT_API_KEY in the .env file."
        if error.code == 429:
            return None, "VirusTotal limit reached. The free key allows 4 lookups a minute and 500 a day."
        return None, "VirusTotal lookup failed with code " + str(error.code) + "."
    except (OSError, ValueError):
        return None, "VirusTotal could not be reached."

    try:
        return body["data"]["attributes"]["last_analysis_stats"], ""
    except (KeyError, TypeError):
        return None, "VirusTotal sent an answer that could not be read."


def check_virustotal(sha256):
    stats, problem = lookup_virustotal(sha256)
    if stats is None:
        return [], [problem]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0)

    if malicious >= 5:
        return [(60, "VirusTotal: " + str(malicious) + " of " + str(total) + " security vendors flag this file as malicious")], []
    if malicious >= 1:
        return [(30, "VirusTotal: " + str(malicious) + " of " + str(total) + " security vendors flag this file as malicious. A few flags can be false alarms")], []
    if suspicious >= 1:
        return [(10, "VirusTotal: " + str(suspicious) + " of " + str(total) + " security vendors flag this file as suspicious")], []

    return [], ["VirusTotal: none of " + str(total) + " security vendors flag this file. That lowers the risk but does not remove it."]


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

    if "password protected" in reasons:
        advice.append("Do not open password protected archives from people you cannot verify. Scammers use passwords so scanners cannot look inside.")

    if "zip bomb" in reasons:
        advice.append("Do not unpack this archive. It could fill your disk.")

    if "eicar" in reasons:
        advice.append("This is the standard antivirus test string. It is harmless, so it is safe to delete.")

    if "virustotal" in reasons:
        advice.append("Security vendors flagged this file. Do not open it.")

    return advice


def scan_file(filename, data, use_virustotal=False):
    kind = detect_type(data)
    sha256 = hashlib.sha256(data).hexdigest()

    findings = []
    findings = findings + check_name(filename)
    findings = findings + check_real_type(filename, kind)

    if kind == "pdf":
        findings = findings + check_pdf(data)

    findings = findings + check_script(filename, data)

    if kind == "zip":
        findings = findings + check_zip(filename, data)

    if kind == "ole":
        findings = findings + check_old_office(data)

    findings = findings + check_eicar(data)

    notes = []
    if use_virustotal:
        vt_findings, vt_notes = check_virustotal(sha256)
        findings = findings + vt_findings
        notes = notes + vt_notes

    score = 0
    for points, reason in findings:
        score = score + points
    score = min(score, 100)

    level = get_level(score)

    return {
        "name": filename,
        "size": len(data),
        "sha256": sha256,
        "type": LABELS[kind],
        "score": score,
        "level": level,
        "findings": findings,
        "advice": build_file_advice(level, findings),
        "notes": notes,
    }


def main():
    load_dotenv()

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    use_virustotal = "--vt" in sys.argv

    if not args:
        print("Usage: python3 file_scanner.py file_samples/notes.txt [--vt]")
        return

    path = args[0]
    with open(path, "rb") as f:
        data = f.read()

    result = scan_file(os.path.basename(path), data, use_virustotal)

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

    if result["notes"]:
        print()
        print("Notes:")
        for note in result["notes"]:
            print("  " + note)


if __name__ == "__main__":
    main()