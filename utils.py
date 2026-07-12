"""
Auxiliary helpers with intentional vulnerabilities for scanner validation.
DO NOT USE IN PRODUCTION.
"""
import hashlib
import subprocess
import base64

from Crypto.Cipher import AES  # pycryptodome


# VULN: Hardcoded encryption key and fixed IV
SECRET_KEY = b"0123456789abcdef"
FIXED_IV = b"0000000000000000"


def encrypt(plaintext: bytes) -> str:
    # VULN: ECB mode / fixed IV usage, hardcoded key
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, FIXED_IV)
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad]) * pad
    return base64.b64encode(cipher.encrypt(plaintext)).decode()


def run_command(user_input: str) -> str:
    # VULN: command injection via shell=True
    return subprocess.getoutput("echo " + user_input)


def checksum(data: bytes) -> str:
    # VULN: use of broken hash (SHA1) for integrity
    return hashlib.sha1(data).hexdigest()


def verify_signature(received: str, expected: str) -> bool:
    # VULN: non-constant-time comparison of secrets (timing attack)
    return received == expected
