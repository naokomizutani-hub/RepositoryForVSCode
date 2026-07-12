"""
Patched (secure) version of the demo Flask application.

Each endpoint mirrors the vulnerable app.py but applies the fix recommended
by the security review. Used side-by-side with app.py by the regression tests
to prove the vulnerabilities are closed.
"""
import os
import re
import ipaddress
import json
import secrets
import sqlite3
import subprocess
import hashlib
import hmac
from urllib.parse import urlparse

from flask import Flask, request, redirect, abort
from markupsafe import escape

app = Flask(__name__)

# FIX (Vuln 9): secret key from the environment, strong random fallback.
app.secret_key = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)

# Configurable, confined download root (FIX Vuln 6).
FILES_DIR = os.environ.get("FILES_DIR", "/var/www/files")

# Validation allowlists.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def get_db():
    conn = sqlite3.connect(os.environ.get("APP_DB", "app.db"))
    return conn


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    cur = conn.cursor()
    # FIX (Vuln 1): parameterized query — input can no longer alter SQL.
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    if row:
        # FIX (Vuln 8): escape reflected value.
        return "Welcome %s" % escape(username)
    return "Login failed", 401


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    # FIX (Vuln 2): enforce integer + parameterized query.
    if not user_id.isdigit():
        abort(400, "id must be a positive integer")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, email FROM users WHERE id = ?", (int(user_id),))
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (Vuln 3): validate input and run without a shell (argument list).
    if not _HOSTNAME_RE.match(host):
        abort(400, "invalid host")
    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host], shell=False, timeout=5
        )
    except subprocess.SubprocessError:
        return "ping failed", 502
    return output


@app.route("/backup")
def backup():
    name = request.args.get("name", "backup")
    # FIX (Vuln 4): validate against an allowlist and avoid the shell.
    if not _NAME_RE.match(name):
        abort(400, "invalid name")
    subprocess.run(
        ["tar", "czf", "/tmp/%s.tar.gz" % name, "/var/data"],
        shell=False,
        check=False,
    )
    return "ok"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # FIX (Vuln 6): confine the resolved path to FILES_DIR.
    base = os.path.realpath(FILES_DIR)
    target = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, target]) != base:
        abort(403, "path traversal blocked")
    if not os.path.isfile(target):
        abort(404)
    with open(target, "rb") as f:
        return f.read()


@app.route("/render")
def render():
    name = request.args.get("name", "")
    # FIX (Vuln 7): escape user input before placing it in HTML.
    html = "<html><body><h1>Hello %s</h1></body></html>" % escape(name)
    return html


@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    # FIX (Vuln 5): never unpickle untrusted data — use JSON.
    try:
        obj = json.loads(data)
    except (ValueError, TypeError):
        abort(400, "invalid JSON")
    return str(obj)


def _is_public_http_url(url: str) -> bool:
    """Allow only http/https to non-private, resolvable-looking hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        # Reject literal private/loopback/link-local IPs outright.
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        # Not an IP literal (a hostname); scheme allowlist already applied.
        pass
    return True


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # FIX (Vuln 8/SSRF): enforce scheme + block private/loopback targets.
    if not _is_public_http_url(url):
        abort(400, "url not allowed")
    import urllib.request

    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
        return resp.read()


@app.route("/redirect")
def do_redirect():
    target = request.args.get("next", "/")
    # FIX (open redirect): only allow same-site relative paths.
    if not target.startswith("/") or target.startswith("//"):
        abort(400, "invalid redirect target")
    return redirect(target)


def hash_password(password, salt: bytes = None):
    # FIX (Vuln 10): salted, slow KDF (PBKDF2-HMAC-SHA256).
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return "%s$%s" % (salt.hex(), dk.hex())


def verify_password(password, stored: str) -> bool:
    salt_hex, _ = stored.split("$", 1)
    candidate = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, stored)


def generate_token():
    # FIX (Vuln 11): cryptographically secure randomness.
    return secrets.token_hex(8)


if __name__ == "__main__":
    # FIX (Vuln 14): debug off; bind loopback by default.
    app.run(host="127.0.0.1", debug=False)
