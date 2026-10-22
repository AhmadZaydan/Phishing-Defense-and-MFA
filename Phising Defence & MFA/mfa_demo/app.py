"""Local password + TOTP demonstration. The Chrome extension is separate.

Only opaque session identifiers and CSRF tokens enter Flask's signed cookie.
Passwords are hashed; OTP secrets and replay state stay in the local SQLite DB.
"""

from contextlib import contextmanager
from pathlib import Path
import io
import hashlib
import hmac
import secrets
import sqlite3
import time

import pyotp
import qrcode
import qrcode.image.svg
from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from demo_constants import DEMO_PASSWORD, DEMO_USERNAME, LEGITIMATE_URL, PHISHING_URL

PENDING_SECONDS = 180
AUTH_SECONDS = 900
LOCK_SECONDS = 60
MAX_ATTEMPTS = 5


def create_app(data_dir=None, *, testing=False, clock=None):
    app = Flask(__name__)
    data = Path(data_dir) if data_dir else Path(__file__).parent / "instance"
    data.mkdir(parents=True, exist_ok=True)
    try:
        data.chmod(0o700)
    except OSError:
        pass
    key_file = data / "session.key"
    if not key_file.exists():
        # Exclusive creation prevents accidentally overwriting an existing key.
        with key_file.open("xb") as handle:
            handle.write(secrets.token_bytes(32))
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
    app.config.update(
        SECRET_KEY=key_file.read_bytes(), TESTING=testing,
        DATABASE=str(data / "lab.sqlite3"), NOW=clock or time.time,
        SESSION_COOKIE_NAME="campus_lab_session",
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        # This demonstration is bound to loopback HTTP, not deployed publicly.
        SESSION_COOKIE_SECURE=False, MAX_CONTENT_LENGTH=4096,
        TRUSTED_HOSTS=["localhost"],
    )
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, totp_secret TEXT,
                enabled INTEGER NOT NULL DEFAULT 0,
                last_step INTEGER NOT NULL DEFAULT -1,
                otp_failures INTEGER NOT NULL DEFAULT 0,
                otp_locked_until REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                stage TEXT NOT NULL, expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS limits (
                bucket TEXT PRIMARY KEY, failures INTEGER NOT NULL,
                locked_until REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, at REAL NOT NULL, event TEXT NOT NULL
            );
        """)
        if not db.execute("SELECT 1 FROM users WHERE username=?", (DEMO_USERNAME,)).fetchone():
            db.execute("INSERT INTO users(username,password_hash) VALUES (?,?)",
                       (DEMO_USERNAME, generate_password_hash(DEMO_PASSWORD)))
    try:
        Path(app.config["DATABASE"]).chmod(0o600)
    except OSError:
        pass

    def now():
        return float(app.config["NOW"]())

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], isolation_level=None, timeout=10)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop("db", None)
        if connection:
            connection.close()

    @contextmanager
    def transaction():
        connection = db()
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def log(event):
        db().execute("INSERT INTO audit(at,event) VALUES (?,?)", (now(), event))

    def csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    def token_hash():
        token = session.get("sid", "")
        return hashlib.sha256(token.encode()).hexdigest()

    def current():
        if not session.get("sid"):
            return None
        row = db().execute("""SELECT s.*, u.username, u.totp_secret, u.enabled,
            u.last_step, u.otp_failures, u.otp_locked_until
            FROM sessions s JOIN users u ON s.user_id=u.id
            WHERE s.token_hash=?""", (token_hash(),)).fetchone()
        if row and row["expires"] > now():
            return row
        db().execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(),))
        session.pop("sid", None)
        return None

    def new_session(user_id, stage):
        db().execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(),))
        token = secrets.token_urlsafe(32)
        session.clear()
        session["sid"] = token
        csrf()
        lifetime = AUTH_SECONDS if stage == "authenticated" else PENDING_SECONDS
        db().execute("INSERT INTO sessions VALUES (?,?,?,?)",
                     (hashlib.sha256(token.encode()).hexdigest(), user_id, stage, now() + lifetime))

    def render(name, **context):
        return render_template(name, csrf_token=csrf(), demo_username=DEMO_USERNAME,
                               demo_password=DEMO_PASSWORD, legitimate_url=LEGITIMATE_URL,
                               phishing_url=PHISHING_URL, **context)

    @app.before_request
    def protect_forms():
        if request.method == "POST":
            expected = session.get("csrf", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected.encode(), supplied.encode()):
                abort(400, "Missing or invalid form token. Reload the form and try again.")

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self'; "
            "script-src 'none'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.get("/")
    def home():
        return render("home.html")

    @app.get("/inbox")
    def inbox():
        return render("inbox.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        existing = current()
        if request.method == "GET" and existing:
            return redirect(url_for({"authenticated": "dashboard", "enroll": "enroll", "otp": "otp"}[existing["stage"]]))
        if request.method == "GET":
            return render("login.html")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        bucket = "password:" + (request.remote_addr or "local")
        error = None
        with transaction() as connection:
            limit = connection.execute("SELECT * FROM limits WHERE bucket=?", (bucket,)).fetchone()
            if limit and limit["locked_until"] > now():
                return render("login.html", error="Too many password attempts. Wait 60 seconds."), 429
            user = connection.execute("SELECT * FROM users WHERE username=?", (DEMO_USERNAME,)).fetchone()
            password_ok = check_password_hash(user["password_hash"], password)
            if username != DEMO_USERNAME or not password_ok:
                failures = (limit["failures"] if limit and limit["locked_until"] == 0 else 0) + 1
                locked = now() + LOCK_SECONDS if failures >= MAX_ATTEMPTS else 0
                connection.execute("INSERT OR REPLACE INTO limits VALUES (?,?,?)", (bucket, failures, locked))
                log("Password rejected")
                error = "Invalid demo username or password."
            else:
                connection.execute("DELETE FROM limits WHERE bucket=?", (bucket,))
                if not user["enabled"] and not user["totp_secret"]:
                    connection.execute("UPDATE users SET totp_secret=? WHERE id=?", (pyotp.random_base32(), user["id"]))
                stage = "otp" if user["enabled"] else "enroll"
                new_session(user["id"], stage)
                log("Password accepted; second factor required")
        if error:
            return render("login.html", error=error), 401
        return redirect(url_for("otp" if stage == "otp" else "enroll"))

    def verify_second_factor(stage):
        """Verify and consume a time step atomically, shared across sessions."""
        with transaction() as connection:
            row = current()
            if not row or row["stage"] != stage:
                return None, "The pending login expired or is missing. Start again.", 401
            if row["otp_locked_until"] > now():
                return None, "Too many authenticator attempts. Wait 60 seconds.", 429
            code = request.form.get("code", "").strip()
            step = int(now() // 30)
            matched = None
            if len(code) == 6 and code.isascii() and code.isdigit():
                totp = pyotp.TOTP(row["totp_secret"])
                # Allow one adjacent 30-second step for clock drift.
                for candidate in (step, step - 1, step + 1):
                    if hmac.compare_digest(totp.at(candidate * 30), code):
                        matched = candidate
                        break
            if matched is None or matched <= row["last_step"]:
                failures = (row["otp_failures"] if row["otp_locked_until"] == 0 else 0) + 1
                locked = now() + LOCK_SECONDS if failures >= MAX_ATTEMPTS else 0
                connection.execute("UPDATE users SET otp_failures=?,otp_locked_until=? WHERE id=?",
                                   (failures, locked, row["user_id"]))
                log("Authenticator code rejected (invalid, expired, or already used)")
                return None, "Invalid, expired, or already used code. Wait for a new code and try again.", 401
            connection.execute("UPDATE users SET enabled=1,last_step=?,otp_failures=0,otp_locked_until=0 WHERE id=?",
                               (matched, row["user_id"]))
            new_session(row["user_id"], "authenticated")
            log("MFA completed; authenticated session issued")
            return row["user_id"], None, 200

    @app.route("/enroll", methods=["GET", "POST"])
    def enroll():
        row = current()
        if not row or row["stage"] != "enroll":
            return redirect(url_for("login"))
        error = None
        status = 200
        if request.method == "POST":
            user_id, error, status = verify_second_factor("enroll")
            if user_id:
                flash("Authenticator enrolled. Both factors were verified.")
                return redirect(url_for("dashboard"))
        return render("enroll.html", secret=row["totp_secret"], error=error), status

    @app.get("/enroll/qr.svg")
    def qr():
        row = current()
        if not row or row["stage"] != "enroll":
            abort(403)
        uri = pyotp.TOTP(row["totp_secret"]).provisioning_uri(name=DEMO_USERNAME, issuer_name="Campus Lab")
        image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        output = io.BytesIO()
        image.save(output)
        return Response(output.getvalue(), mimetype="image/svg+xml")

    @app.route("/otp", methods=["GET", "POST"])
    def otp():
        row = current()
        if not row or row["stage"] != "otp":
            return redirect(url_for("login"))
        error = None
        status = 200
        if request.method == "POST":
            user_id, error, status = verify_second_factor("otp")
            if user_id:
                return redirect(url_for("dashboard"))
        return render("otp.html", error=error), status

    @app.get("/dashboard")
    def dashboard():
        row = current()
        if not row or row["stage"] != "authenticated":
            flash("Access denied: complete both password and authenticator verification.")
            return redirect(url_for("login"))
        return render("dashboard.html", username=row["username"])

    @app.get("/audit")
    def audit():
        row = current()
        if not row or row["stage"] != "authenticated":
            return redirect(url_for("login"))
        events = db().execute("SELECT at,event FROM audit ORDER BY id DESC LIMIT 40").fetchall()
        return render("audit.html", events=events)

    @app.post("/logout")
    def logout():
        with transaction():
            db().execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(),))
            log("Session signed out")
        session.clear()
        return redirect(url_for("login"))

    return app
