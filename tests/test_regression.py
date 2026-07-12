"""
Before/after regression tests.

Each test sends the SAME exploit payload to the vulnerable endpoint and the
patched endpoint, asserting:
  * the vulnerable version is exploitable (documents the original bug), and
  * the patched version blocks the exploit (proves the fix).

Run:  pytest -v tests/test_regression.py
"""
import os
import io
import pickle
import random
import tempfile

MARKER = os.path.join(tempfile.gettempdir(), "regression_rce_proof.txt")


def _clear_marker():
    for suffix in ("", ".tar.gz"):
        try:
            os.remove(MARKER + suffix)
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------- #
# Vuln 1 — SQL injection: authentication bypass on /login                     #
# --------------------------------------------------------------------------- #
def test_sqli_login_bypass(vuln_client, secure_client):
    payload = {"username": "admin'--", "password": "wrong-password"}

    vuln = vuln_client.post("/login", data=payload)
    assert vuln.status_code == 200 and b"Welcome" in vuln.data  # exploited

    secure = secure_client.post("/login", data=payload)
    assert secure.status_code == 401  # fixed: no bypass


# --------------------------------------------------------------------------- #
# Vuln 2 — SQL injection: UNION data exfiltration on /user                    #
# --------------------------------------------------------------------------- #
def test_sqli_user_union(vuln_client, secure_client):
    inj = "0 UNION SELECT username, password FROM users"

    vuln = vuln_client.get("/user", query_string={"id": inj})
    assert b"s3cr3t-admin-pw" in vuln.data  # exploited: creds leaked

    secure = secure_client.get("/user", query_string={"id": inj})
    assert secure.status_code == 400  # fixed: non-integer rejected
    assert b"s3cr3t-admin-pw" not in secure.data


# --------------------------------------------------------------------------- #
# Vuln 3 — OS command injection on /ping                                      #
# --------------------------------------------------------------------------- #
def test_cmdi_ping(vuln_client, secure_client):
    inj = {"host": "127.0.0.1; id"}

    vuln = vuln_client.get("/ping", query_string=inj)
    assert b"uid=" in vuln.data  # exploited: `id` ran

    secure = secure_client.get("/ping", query_string=inj)
    assert secure.status_code == 400  # fixed: invalid host rejected
    assert b"uid=" not in secure.data


# --------------------------------------------------------------------------- #
# Vuln 4 — OS command injection on /backup                                    #
# --------------------------------------------------------------------------- #
def test_cmdi_backup(vuln_client, secure_client):
    _clear_marker()
    inj = {"name": "backup; touch %s #" % MARKER}

    vuln_client.get("/backup", query_string=inj)
    assert os.path.exists(MARKER)  # exploited: marker written
    _clear_marker()

    secure = secure_client.get("/backup", query_string=inj)
    assert secure.status_code == 400  # fixed: invalid name rejected
    assert not os.path.exists(MARKER)


# --------------------------------------------------------------------------- #
# Vuln 5 — Insecure deserialization (pickle RCE) on /load                     #
# --------------------------------------------------------------------------- #
class _PickleRCE:
    def __reduce__(self):
        return (os.system, ("touch %s" % MARKER,))


def test_pickle_rce(vuln_client, secure_client):
    _clear_marker()
    blob = pickle.dumps(_PickleRCE())

    vuln_client.post("/load", data=blob)
    assert os.path.exists(MARKER)  # exploited: code executed
    _clear_marker()

    secure = secure_client.post("/load", data=blob)
    assert secure.status_code == 400  # fixed: JSON only, no code exec
    assert not os.path.exists(MARKER)


# --------------------------------------------------------------------------- #
# Vuln 6 — Path traversal on /download                                        #
# --------------------------------------------------------------------------- #
def test_path_traversal(vuln_client, secure_client):
    inj = {"file": "../../../../../../etc/passwd"}

    vuln = vuln_client.get("/download", query_string=inj)
    assert b"root:" in vuln.data  # exploited: arbitrary file read

    secure = secure_client.get("/download", query_string=inj)
    assert secure.status_code in (403, 404)  # fixed: confined to FILES_DIR
    assert b"root:" not in secure.data


# --------------------------------------------------------------------------- #
# Vuln 7 — Reflected XSS on /render                                           #
# --------------------------------------------------------------------------- #
def test_xss_render(vuln_client, secure_client):
    xss = "<script>alert(1)</script>"

    vuln = vuln_client.get("/render", query_string={"name": xss})
    assert b"<script>alert(1)</script>" in vuln.data  # exploited: raw reflect

    secure = secure_client.get("/render", query_string={"name": xss})
    assert b"<script>alert(1)</script>" not in secure.data  # fixed: escaped
    assert b"&lt;script&gt;" in secure.data


# --------------------------------------------------------------------------- #
# Vuln 8 — SSRF on /fetch                                                     #
# --------------------------------------------------------------------------- #
def test_ssrf_fetch(vuln_client, secure_client):
    # file:// scheme demonstrates full destination control on the vuln app.
    inj = {"url": "file:///etc/hostname"}

    vuln = vuln_client.get("/fetch", query_string=inj)
    assert vuln.status_code == 200 and vuln.data.strip() != b""  # exploited

    secure = secure_client.get("/fetch", query_string=inj)
    assert secure.status_code == 400  # fixed: non-http scheme rejected

    # Loopback over http is also blocked by the secure allowlist.
    secure_lb = secure_client.get("/fetch", query_string={"url": "http://127.0.0.1/"})
    assert secure_lb.status_code == 400


# --------------------------------------------------------------------------- #
# Vuln 10 — Weak password hashing (unsalted MD5 -> salted PBKDF2)             #
# --------------------------------------------------------------------------- #
def test_weak_password_hash():
    import app as vuln_app
    import app_secure as secure_app

    # Vulnerable: unsalted MD5 is deterministic (32 hex chars) and crackable.
    h1 = vuln_app.hash_password("letmein")
    h2 = vuln_app.hash_password("letmein")
    assert h1 == h2 and len(h1) == 32  # exploited property: no salt

    # Patched: salted -> two hashes of the same password differ, and verify works.
    s1 = secure_app.hash_password("letmein")
    s2 = secure_app.hash_password("letmein")
    assert s1 != s2  # fixed: random salt
    assert secure_app.verify_password("letmein", s1)
    assert not secure_app.verify_password("wrong", s1)


# --------------------------------------------------------------------------- #
# Vuln 11 — Insecure randomness (Mersenne Twister -> secrets)                 #
# --------------------------------------------------------------------------- #
def test_insecure_randomness():
    import app as vuln_app
    import app_secure as secure_app

    # Vulnerable: seeding the PRNG makes the token reproducible/predictable.
    random.seed(1234)
    a = vuln_app.generate_token()
    random.seed(1234)
    b = vuln_app.generate_token()
    assert a == b  # exploited: predictable

    # Patched: secrets ignores the `random` seed -> not predictable.
    random.seed(1234)
    c = secure_app.generate_token()
    random.seed(1234)
    d = secure_app.generate_token()
    assert c != d  # fixed


# --------------------------------------------------------------------------- #
# Vuln 12 — Weak crypto: fixed IV -> random IV                                #
# --------------------------------------------------------------------------- #
def test_weak_crypto_iv():
    import utils as vuln_utils
    import utils_secure as secure_utils

    pt = b"SENSITIVE_VALUE"

    # Vulnerable: fixed IV -> identical plaintext yields identical ciphertext.
    assert vuln_utils.encrypt(pt) == vuln_utils.encrypt(pt)  # exploited leak

    # Patched: random IV -> ciphertext differs each call.
    assert secure_utils.encrypt(pt) != secure_utils.encrypt(pt)  # fixed


# --------------------------------------------------------------------------- #
# Vuln 15 — Command injection helper (shell -> argument list)                 #
# --------------------------------------------------------------------------- #
def test_run_command():
    import utils as vuln_utils
    import utils_secure as secure_utils

    inj = "hello; id"

    # Vulnerable: shell interprets `;` so `id` runs and uid appears.
    assert "uid=" in vuln_utils.run_command(inj)  # exploited

    # Patched: passed as a literal argument, echoed verbatim, `id` never runs.
    out = secure_utils.run_command(inj)
    assert "uid=" not in out and "hello; id" in out  # fixed


# --------------------------------------------------------------------------- #
# Vuln 18 — Broken hash (SHA-1 -> SHA-256)                                     #
# --------------------------------------------------------------------------- #
def test_checksum_algorithm():
    import utils as vuln_utils
    import utils_secure as secure_utils

    data = b"integrity-check"
    assert len(vuln_utils.checksum(data)) == 40  # SHA-1 (weak)
    assert len(secure_utils.checksum(data)) == 64  # SHA-256 (fixed)


# --------------------------------------------------------------------------- #
# Vuln 17 — Non-constant-time compare (== -> hmac.compare_digest)             #
# --------------------------------------------------------------------------- #
def test_verify_signature_behaviour():
    import utils_secure as secure_utils

    # Behaviour preserved; fix is constant-time comparison internally.
    assert secure_utils.verify_signature("abc123", "abc123") is True
    assert secure_utils.verify_signature("abc123", "abc124") is False
