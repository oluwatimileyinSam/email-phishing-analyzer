# Email Phishing Analyzer

A small Python tool that reads a saved email (.eml file) and gives a risk score, plain reasons, and advice on how to verify it. It runs from the command line and from a simple web page.

The tool warns people. It does not decide for them, and it never blocks or deletes anything. Every result tells the reader to verify the sender and the content by a call or in person.

This is Phase 1 of a larger defensive security project.

## What it checks

1. Sender verification: SPF, DKIM and DMARC results in the email headers.
2. Sender identity: a Reply To address on a different domain, and a display name that uses a brand the real domain does not match.
3. Links: link text that shows one address while the link goes to another, links that use a raw IP address, and URL shorteners.
4. Wording: urgency, payment or bank detail requests, password requests, and messages that tell you not to verify by phone.
5. Attachments: double extensions such as invoice.pdf.exe, risky file types, macro enabled Office files and archives. It reads file names only and never opens attachments.

## Requirements

1. Python 3.9 or higher
2. Flask, for the web page. The checks themselves use only the Python standard library.

## Setup

```
git clone https://github.com/YOUR_USERNAME/email-phishing-analyzer.git
cd email-phishing-analyzer
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

### Web page

```
python3 app.py
```

Open http://127.0.0.1:5001 in a browser, choose an .eml file and click Scan email. The page shows the score, the reasons and the advice. It runs on your own computer only.

### Command line

Give the script the path to a saved .eml file:

```
python3 analyzer.py samples/safe.eml
python3 analyzer.py samples/bank_change.eml
python3 analyzer.py samples/link_phish.eml
python3 analyzer.py samples/macro_attachment.eml
```

## Project files

1. analyzer.py: the checks, the scoring and the advice.
2. app.py: the Flask web page.
3. templates/index.html: the page layout.
4. samples/: four fake emails for testing.
5. requirements.txt: the Python package to install.

## Sample data

The samples folder holds four fake emails made for testing. All names and domains are invented. The .example domain ending is reserved for testing, so none of them point to a real site. The attachments hold only harmless text.

1. safe.eml: a normal email. Score 0, NO WARNINGS.
2. bank_change.eml: a fake bank detail change with urgency. Score 100, HIGH.
3. link_phish.eml: a fake password phish with a bad link and a double extension attachment. Score 100, HIGH.
4. macro_attachment.eml: a clean sender with a macro enabled attachment. Score 15, LOW.

## Example output

```
From: Sam Bello <sam@northwindco.example>
Subject: Invoice for your review

Risk score: 15 / 100 (LOW)

Reasons:
  +15 Macro enabled Office file (Invoice_Nov.docm): macros can run code

What to do:
  1. Minor warnings found. Read the reasons above before you act.
  2. Verify the sender and the content through a call or in person.
  3. Use a phone number you already have. Never use one from this email.
  4. Do not open the attachment. Ask the sender to confirm it by a call or in person.
```

## How scoring works

Each check adds points. The total is capped at 100.

1. HIGH: 60 or more
2. MEDIUM: 30 to 59
3. LOW: 1 to 29
4. NO WARNINGS: 0

A score of 0 does not mean an email is safe. Verify anything about money or passwords by a call or in person.

## Limits

This is one layer of defense, not a full antivirus.

1. It uses keyword and rule based checks. It will flag some safe emails and miss some real attacks.
2. It trusts the authentication results already written in the email headers. It does not run its own DNS checks.
3. It trusts attachment file names, not file contents.
4. It never opens links, so it cannot check domain age or redirects.
5. The brand list is short and written by hand.
6. The web page scans one email at a time. It has no login and runs in debug mode. It is for local use only. Do not put it online as it is.

## Safety

1. The tool never opens links or attachments.
2. Use fake or test emails only. Do not commit real emails to this repo.
3. The web page accepts .eml files up to 5 MB. The app does not keep the uploaded file.
4. Text from an email is escaped on the page, so email content cannot run as code in the browser.
5. No keys or tokens are needed yet. Future keys will live in a .env file that Git ignores.

## Planned next

1. Put the web page online with a domain, HTTPS and a login.
2. Phase 2: file scanner, with file hash checks and real file type checks.
3. Phase 3: mailbox watcher, with clone phishing detection and new mailbox rule alerts.
4. Phase 4: alerts and a small dashboard.