from flask import Flask, render_template, request

from analyzer import analyze_email, load_email_bytes

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("email_file")

        if uploaded is None or uploaded.filename == "":
            error = "Please choose an .eml file first."
        elif not uploaded.filename.lower().endswith(".eml"):
            error = "Only .eml files are accepted."
        else:
            try:
                msg = load_email_bytes(uploaded.read())
                result = analyze_email(msg)
            except Exception:
                error = "This file could not be read as an email."

    return render_template("index.html", result=result, error=error)


@app.errorhandler(413)
def too_large(e):
    message = "That file is too large. The limit is 5 MB."
    return render_template("index.html", result=None, error=message), 413


if __name__ == "__main__":
    app.run(port=5001, debug=True)
    