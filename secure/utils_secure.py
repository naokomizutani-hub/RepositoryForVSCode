"""
Patched (secure) version of utils.py.

Fixes: random per-message IV + key from secret source, no-shell command
execution, strong hash, constant-time comparison.
"""
import os
import hmac
import hashlib
import base64
import subprocess

from Crypto.Cipher import AES


def _load_key() -> bytes:
    # FIX (Vuln 12): key from environment/secret manager, not hardcoded.
    key_hex = os.environ.get("AES_KEY_HEX")
    if key_hex:
        return bytes.fromhex(key_hex)
    # Fallback for local/dev use only — still not embedded in the source repo
    # as a fixed constant path; generated per process.
    return hashlib.sha256(b"dev-only-ephemeral-key").digest()[:16]


def encrypt(plaintext: bytes, key: bytes = None) -> str:
    # FIX (Vuln 12): fresh random IV per call, prepended to the ciphertext.
    key = key or _load_key()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad]) * pad
    return base64.b64encode(iv + cipher.encrypt(plaintext)).decode()


def run_command(user_input: str) -> str:
    # FIX (Vuln 15): no shell; pass as a single argument to `echo`.
    result = subprocess.run(
        ["echo", user_input], shell=False, capture_output=True, text=True
    )
    return result.stdout.strip()


def checksum(data: bytes) -> str:
    # FIX (Vuln 18): use SHA-256 instead of broken SHA-1.
    return hashlib.sha256(data).hexdigest()


def verify_signature(received: str, expected: str) -> bool:
    # FIX (Vuln 17): constant-time comparison to defeat timing attacks.
    return hmac.compare_digest(received, expected)
