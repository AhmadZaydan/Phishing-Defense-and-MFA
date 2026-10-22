"""Fictional, loopback-only phishing demonstration accepting fixed dummy inputs.

It does not store submitted passwords, collect OTPs, send email, or contact any
external service. The result displays public fixtures after a matching submission.
"""
import hmac
import secrets

from flask import Flask, abort, redirect, render_template, request, session, url_for
from demo_constants import DEMO_USERNAME, DEMO_PASSWORD, LEGITIMATE_URL


def create_fake_app(*, testing=False):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_bytes(32), TESTING=testing,
                      SESSION_COOKIE_NAME="phishing_training_session",
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      MAX_CONTENT_LENGTH=4096, TRUSTED_HOSTS=["127.0.0.1"])

    def csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'none'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.route("/login", methods=["GET", "POST"])
    def fake_login():
        error = None
        if request.method == "POST":
            if not session.get("csrf") or not hmac.compare_digest(session["csrf"].encode(), request.form.get("csrf_token", "").encode()):
                abort(400)
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            # Only public training fixtures are accepted. Never save raw input.
            if hmac.compare_digest(username.encode(), DEMO_USERNAME.encode()) and hmac.compare_digest(password.encode(), DEMO_PASSWORD.encode()):
                session["demonstrated"] = True
                return redirect(url_for("captured"))
            error = "Use only the published dummy account for this training page. Nothing was saved."
        return render_template("fake_login.html", csrf_token=csrf(), error=error,
                               demo_username=DEMO_USERNAME, demo_password=DEMO_PASSWORD), (401 if error else 200)

    @app.get("/captured")
    def captured():
        if not session.get("demonstrated"):
            return redirect(url_for("fake_login"))
        return render_template("captured.html", demo_username=DEMO_USERNAME,
                               demo_password=DEMO_PASSWORD, legitimate_url=LEGITIMATE_URL)

    return app
