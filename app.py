"""
Intentionally vulnerable Flask application for security-scanner validation.
DO NOT USE IN PRODUCTION.
"""
import os
import sqlite3
import subprocess
import pickle
import hashlib
import random
import urllib.request

from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# --- Hardcoded secrets (should be in env/secret manager) ---
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "SuperSecretP@ssw0rd123"
API_TOKEN = "PLACEHOLDER_HARDCODED_API_TOKEN_DO_NOT_USE"

# App secret key used for signing sessions - hardcoded and weak
app.secret_key = "dev-secret-key"


def get_db():
    conn = sqlite3.connect("app.db")
    return conn


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    cur = conn.cursor()
    # VULN: SQL Injection via string formatting
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    cur.execute(query)
    row = cur.fetchone()
    if row:
        return "Welcome %s" % username  # VULN: reflected XSS (no escaping)
    return "Login failed", 401


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = get_db()
    cur = conn.cursor()
    # VULN: SQL Injection via f-string
    cur.execute(f"SELECT name, email FROM users WHERE id = {user_id}")
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: OS command injection (shell=True with user input)
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/backup")
def backup():
    name = request.args.get("name", "backup")
    # VULN: command injection via os.system
    os.system("tar czf /tmp/%s.tar.gz /var/data" % name)
    return "ok"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # VULN: Path traversal - user input joined directly into path
    path = os.path.join("/var/www/files", filename)
    with open(path, "rb") as f:
        return f.read()


@app.route("/render")
def render():
    name = request.args.get("name", "")
    # VULN: Reflected XSS - unescaped user input in HTML response
    html = "<html><body><h1>Hello " + name + "</h1></body></html>"
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    # VULN: Insecure deserialization of untrusted data
    obj = pickle.loads(data)
    return str(obj)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # VULN: SSRF - fetches arbitrary user-supplied URL
    with urllib.request.urlopen(url) as resp:
        return resp.read()


@app.route("/redirect")
def do_redirect():
    target = request.args.get("next", "/")
    # VULN: Open redirect - unvalidated redirect target
    return redirect(target)


def hash_password(password):
    # VULN: weak hashing algorithm (MD5), no salt
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    # VULN: insecure randomness for security-sensitive token
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


if __name__ == "__main__":
    # VULN: debug mode enabled + binds to all interfaces
    app.run(host="0.0.0.0", debug=True)
