import hmac
import os
import time
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for

import store
from analyzer import analyze_email, load_email_bytes
from dashboard_data import LEVELS, read_alert, read_alert_list, read_dashboard
from file_scanner import scan_file
from paths import path_in_app

load_dotenv(path_in_app(".env"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
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
    if os.environ.get("APP_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=86400"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        entered = request.form.get("password", "")
        if hmac.compare_digest(entered.encode(), APP_PASSWORD.encode()):
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        time.sleep(1)
        error = "Wrong password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    conn = store.connect()
    try:
        data = read_dashboard(conn)
    finally:
        conn.close()
    return render_template("dashboard.html", d=data, active="dashboard")


@app.route("/alerts")
@login_required
def alerts():
    level = request.args.get("level", "")
    if level not in LEVELS:
        level = ""

    conn = store.connect()
    try:
        items = read_alert_list(conn, level)
    finally:
        conn.close()

    return render_template("alerts.html", items=items, level=level, levels=LEVELS, active="alerts")


@app.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    conn = store.connect()
    try:
        item = read_alert(conn, alert_id)
    finally:
        conn.close()

    if item is None:
        abort(404)
    return render_template("alert.html", item=item, active="alerts")


@app.route("/email", methods=["GET", "POST"])
@login_required
def email_page():
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

    return render_template("email.html", result=result, error=error, active="email")


@app.route("/file", methods=["GET", "POST"])
@login_required
def file_page():
    result = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("upload")

        if uploaded is None or uploaded.filename == "":
            error = "Please choose a file first."
        else:
            name = os.path.basename(uploaded.filename.replace("\\", "/"))
            data = uploaded.read()
            if not data:
                error = "The file is empty."
            else:
                use_virustotal = request.form.get("use_vt") == "on"
                result = scan_file(name, data, use_virustotal)

    return render_template("files.html", result=result, error=error, active="file")


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="Page not found."), 404


@app.errorhandler(413)
def too_large(e):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    message = "That file is too large. The limit is 10 MB."
    return render_template("email.html", result=None, error=message, active="email"), 413


if __name__ == "__main__":
    app.run(port=5001, debug=True)