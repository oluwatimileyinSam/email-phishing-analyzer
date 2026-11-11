# Email Phishing Analyzer

A small Python tool that reads a saved email (.eml file) and gives a risk score, plain reasons, and advice on how to verify it.

This is Phase 1 of a larger defensive security project. The tool warns people. It does not decide for them, and it never blocks or deletes anything.

## What it checks

1. Sender verification: SPF, DKIM and DMARC results in the email headers.
2. Sender identity: a Reply To address on a different domain, and a display name that uses a brand the real domain does not match.
3. Links: link text that shows one address while the link goes to another, links that use a raw IP address, and URL shorteners.
4. Wording: urgency, payment or bank detail requests, password requests, and messages that tell you not to verify by phone.
5. Attachments: double extensions such as invoice.pdf.exe, risky file types, macro enabled Office files and archives. It reads file names only and never opens attachments.

## Requirements

1. Python 3.9 or higher
2. No extra packages. It uses the Python standard library only.

## Setup

```
git clone https://github.com/YOUR_USERNAME/email-phishing-analyzer.git
cd email-phishing-analyzer
python3 -m venv venv
source venv/bin/activate
```

## Usage

Give the script the path to a saved .eml file:

```
python3 analyzer.py samples/safe.eml
python3 analyzer.py samples/bank_change.eml
python3 analyzer.py samples/link_phish.eml
python3 analyzer.py samples/macro_attachment.eml
```

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

## Safety

1. The tool never opens links or attachments.
2. Use fake or test emails only. Do not commit real emails to this repo.

## Planned next

1. Phase 2: file scanner, with file hash checks and real file type checks.
2. Phase 3: mailbox watcher, with clone phishing detection and new mailbox rule alerts.
3. Phase 4: alerts and a small dashboard.