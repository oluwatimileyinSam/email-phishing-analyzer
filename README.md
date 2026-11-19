# Email Phishing Analyzer and File Scanner

A Python tool that checks saved emails (.eml files) and files for signs of phishing and malware. For each one it gives a risk score, plain reasons, and advice on how to verify it. It runs from the command line and from a simple web page.

The tool warns people. It does not decide for them, and it never blocks or deletes anything. Every result tells the reader to verify the sender and the content by a call or in person.

## What it checks in emails

1. Sender verification: SPF, DKIM and DMARC results in the email headers.
2. Sender identity: a Reply To address on a different domain, and a display name that uses a brand the real domain does not match.
3. Links: link text that shows one address while the link goes to another, links that use a raw IP address, and URL shorteners.
4. Wording: urgency, payment or bank detail requests, password requests, and messages that tell you not to verify by phone.
5. Attachments: double extensions such as invoice.pdf.exe, risky file types, macro enabled Office files and archives. This check reads file names only.

## What it checks in files

1. File name: double extensions, risky file types, macro enabled Office files and archives.
2. Real file type: the first bytes of a file show what it really is. A program or archive hiding behind a document or picture name is flagged.
3. PDF files: embedded JavaScript, automatic open actions, launch actions and embedded files. Names hidden with # codes are decoded first.
4. Scripts: suspicious patterns in .js, .bat, .cmd, .ps1, .vbs and similar files, and silent install flags such as /quiet and /qn.
5. Office files: macro projects inside Word, Excel and PowerPoint files, including files whose name says they have no macros.
6. ZIP archives: password protected archives, programs or scripts hidden inside, double extensions inside, and zip bombs. Archives are never unpacked.
7. EICAR: the standard harmless antivirus test string.
8. VirusTotal, optional: the SHA256 hash of the file is looked up. Only the hash is sent, never the file.

## Requirements

1. Python 3.9 or higher
2. The packages in requirements.txt (Flask and python-dotenv). The checks themselves use only the Python standard library.

## Setup

```
git clone https://github.com/YOUR_USERNAME/email-phishing-analyzer.git
cd email-phishing-analyzer
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Settings

The web page needs a password and a secret key. Create a file named .env in the project folder:

```
SECRET_KEY=a long random value
APP_PASSWORD=a password of at least 16 characters
VT_API_KEY=your VirusTotal key
```

VT_API_KEY is optional. Without it, the VirusTotal lookup is skipped. The free VirusTotal key is limited to 4 lookups a minute and 500 a day, and it is meant for personal, noncommercial use.

Make a secret key with this command and paste the result after SECRET_KEY=:

```
python3 -c "import secrets; print(secrets.token_hex(32))"
```

The .env file is ignored by Git. Never commit it or share it.

## Usage

### Web page

```
python3 app.py
```

Open http://127.0.0.1:5001 in a browser and log in. The Scan email page takes an .eml file. The Scan file page takes any file up to 10 MB, with a box to add the VirusTotal lookup. It runs on your own computer only.

### Command line

```
python3 analyzer.py samples/safe.eml
python3 file_scanner.py file_samples/notes.txt
python3 file_scanner.py file_samples/notes.txt --vt
```

The --vt flag adds the VirusTotal lookup. It needs VT_API_KEY in .env.

## Test files

The samples folder holds four fake emails. To make harmless test files for the file scanner, run:

```
python3 make_test_files.py
```

This creates 18 fake files in file_samples, a folder that Git ignores. None of them can do any harm. If your antivirus deletes eicar_test.txt, that is normal.

## Project files

1. analyzer.py: the email checks, the scoring and the advice.
2. file_scanner.py: the file checks, the scoring, the advice and the VirusTotal lookup.
3. app.py: the Flask web app with login.
4. templates: login.html, index.html for emails and files.html for files.
5. make_test_files.py: makes the harmless test files.
6. samples: four fake emails.
7. passenger_wsgi.py: the entry file some web hosts use.
8. requirements.txt: the Python packages to install.

## Example output

```
File: install.bat
Size: 95 bytes
Type: plain text
SHA256: c9e8021b6cdb45c67c8df2a1128995a5bde11804bd59570533794bb66c163dee

Risk score: 55 / 100 (MEDIUM)

Reasons:
  +20 Risky file type (.bat): programs and scripts can run code
  +20 Script: can download files from the internet: curl
  +15 Script: installs software silently, with no window and no questions: /norestart, /qn

What to do:
  1. Be careful. Do not open this file until you have checked it.
  2. Verify the file with the sender through a call or in person.
  3. Use a phone number you already have. Never use one from the message that came with the file.
  4. Never run a program or installer you did not expect. Download it from the official site instead.
  5. Never run a script you did not write or expect. To read it, open it in a plain text editor, not by double clicking.
```

## How scoring works

Each check adds points. The total is capped at 100.

1. HIGH: 60 or more
2. MEDIUM: 30 to 59
3. LOW: 1 to 29
4. NO WARNINGS: 0

A score of 0 does not mean an email or a file is safe. Verify anything about money or passwords by a call or in person.

## Limits

This is one layer of defense, not a full antivirus.

1. It uses keyword and rule based checks. It will flag some safe items and miss some real attacks.
2. Email checks trust the authentication results already written in the headers. Links are never opened, so domain age and redirects are not checked.
3. The attachment check in the email analyzer reads file names only. It does not yet run attachments through the file scanner.
4. PDF checks read the raw bytes and do not unpack compressed parts, so hidden content can be missed.
5. Archive contents are read for ZIP files only. RAR and 7z files get only the type and name checks. Archives inside archives are not opened.
6. Any file that starts with the letters MZ counts as a Windows program.
7. VirusTotal only knows files that someone has already submitted. A file it has never seen shows no result.
8. The web page has one shared password and no lockout. It is for local use. Do not put it online as it is.

## Safety

1. The tool never opens links or attachments, and it never runs or unpacks a file.
2. Use fake or test files only. No live malware. Do not commit real emails or files to this repo.
3. The web page accepts files up to 10 MB, reads them in memory and does not keep them. Text from emails and files is escaped on the page, and a strict content policy is set.
4. A VirusTotal lookup sends only the hash, never the file.
5. Passwords and keys live in a .env file that Git ignores. Never commit that file.

## Planned next

1. Phase 3: mailbox watcher, clone phishing detection, new mailbox rule alerts and Telegram alerts.
2. Scan email attachments with the file scanner.
3. Phase 4: a redesigned web interface and dashboard.
4. Put the tool online with a domain, HTTPS and a login.