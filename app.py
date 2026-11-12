import hmac
import os
import time
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for

from analyzer import analyze_email, load_email_bytes

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("APP_ENV") == "production"

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

if not app.config["SECRET_KEY"] or not APP_PASSWORD:
    raise RuntimeError("Set SECRET_KEY and APP_PASSWORD in the .env file.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        entered = request.form.get("password", "")
        if hmac.compare_digest(entered.encode(), APP_PASSWORD.encode()):
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("home"))
        time.sleep(1)
        error = "Wrong password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
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
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    message = "That file is too large. The limit is 5 MB."
    return render_template("index.html", result=None, error=message), 413


if __name__ == "__main__":
    app.run(port=5001, debug=True)