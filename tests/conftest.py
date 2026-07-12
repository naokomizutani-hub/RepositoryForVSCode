"""
Shared pytest fixtures for the before/after regression suite.

Puts both the vulnerable modules (repo root) and the patched modules
(secure/) on the import path, and seeds a throwaway SQLite DB + download
directory that both apps use.
"""
import os
import sys
import sqlite3

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURE_DIR = os.path.join(REPO_ROOT, "secure")
for p in (REPO_ROOT, SECURE_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

DB_PATH = os.path.join(REPO_ROOT, "app.db")


def _seed_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
        "password TEXT, name TEXT, email TEXT)"
    )
    cur.executemany(
        "INSERT INTO users (username, password, name, email) VALUES (?,?,?,?)",
        [
            ("admin", "s3cr3t-admin-pw", "Administrator", "admin@example.com"),
            ("alice", "alice-pw", "Alice", "alice@example.com"),
        ],
    )
    conn.commit()
    conn.close()


@pytest.fixture(scope="session", autouse=True)
def _environment(tmp_path_factory):
    # Both apps read the same DB; the vulnerable app uses relative "app.db",
    # so run from the repo root and point the secure app's APP_DB there too.
    os.chdir(REPO_ROOT)
    _seed_db(DB_PATH)
    os.environ["APP_DB"] = DB_PATH

    # Confined download root for the secure app, with one public file.
    files_dir = tmp_path_factory.mktemp("files")
    (files_dir / "welcome.txt").write_text("public file\n")
    os.environ["FILES_DIR"] = str(files_dir)
    yield


@pytest.fixture()
def vuln_client():
    import app as vuln_app

    return vuln_app.app.test_client()


@pytest.fixture()
def secure_client():
    import app_secure

    return app_secure.app.test_client()
