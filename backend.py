"""FlashLock backend — the encryption logic, without any UI.

The frontend (frontend.py) collects and verifies the password, then calls
backend.encrypt() or backend.decrypt(). Everything else lives here.
"""

import base64
import hashlib
import hmac
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

SALT_FILE = ".flashlock_salt"
MARKER_FILE = ".flashlock_marker"
MARKER_MSG = b"flashlock-v1"
ITERATIONS = 200_000

# Files the program must never encrypt: its own source, the salt, the marker.
PROTECTED_NAMES = {
    SALT_FILE,
    MARKER_FILE,
    "flashlock", "flashlock.py", "flashlock.exe",
    "frontend.py", "backend.py",
}


def app_dir():
    """Return the folder the program sits in (the drive root)."""
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            bundle = os.path.abspath(os.path.join(sys.executable, "..", "..", ".."))
            return os.path.dirname(bundle)
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_salt(folder):
    """Read the salt file, or create a fresh 16-byte salt on first use."""
    path = os.path.join(folder, SALT_FILE)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(path, "wb") as f:
        f.write(salt)
    return salt


def derive_key(password, salt):
    """Derive 32 raw key bytes from a password and salt via PBKDF2."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32
    )


def fernet_key(raw_key):
    """Wrap raw key bytes as a Fernet key (urlsafe base64)."""
    return base64.urlsafe_b64encode(raw_key)


def make_marker(raw_key):
    """A 32-byte HMAC tag over a known constant, keyed by the derived key."""
    return hmac.new(raw_key, MARKER_MSG, hashlib.sha256).digest()


def write_marker(folder, raw_key):
    with open(os.path.join(folder, MARKER_FILE), "wb") as f:
        f.write(make_marker(raw_key))


def check_marker(folder, raw_key):
    """Return True if the stored marker matches the given key."""
    path = os.path.join(folder, MARKER_FILE)
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        stored = f.read()
    return hmac.compare_digest(stored, make_marker(raw_key))


def encrypt_folder(folder, key):
    """Encrypt every file under `folder`; name and content are both encrypted."""
    f = Fernet(key)
    count = 0
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not d.startswith(".") and not d.endswith(".app")]
        for name in files:
            if name.startswith(".") or name.endswith(".enc") or name in PROTECTED_NAMES:
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()
            enc_name = f.encrypt(name.encode("utf-8")).decode("ascii")
            with open(os.path.join(root, enc_name + ".enc"), "wb") as file:
                file.write(f.encrypt(data))
            os.remove(path)
            count += 1
    return count


def decrypt_folder(folder, key):
    """Decrypt every .enc file under `folder`; name and content are both decrypted."""
    f = Fernet(key)
    count = 0
    for root, _, files in os.walk(folder):
        for name in files:
            if not name.endswith(".enc"):
                continue
            try:
                original_name = f.decrypt(name[:-4].encode("ascii")).decode("utf-8")
            except (InvalidToken, UnicodeError):
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()
            try:
                decrypted = f.decrypt(data)
            except InvalidToken:
                raise ValueError(f"Wrong password or corrupted file: {name}")
            with open(os.path.join(root, original_name), "wb") as file:
                file.write(decrypted)
            os.remove(path)
            count += 1
    return count


def encrypt(password):
    """Encrypt the program's folder behind `password`. Returns a status message."""
    folder = app_dir()
    try:
        salt = get_salt(folder)
        raw_key = derive_key(password, salt)
        if os.path.exists(os.path.join(folder, MARKER_FILE)):
            if not check_marker(folder, raw_key):
                return "Wrong password."
        else:
            write_marker(folder, raw_key)
        key = fernet_key(raw_key)
        n = encrypt_folder(folder, key)
        return f"Encrypted files: {n}"
    except Exception as e:
        return f"Error: {e}"


def decrypt(password):
    """Decrypt the program's folder behind `password`. Returns a status message."""
    folder = app_dir()
    try:
        if not os.path.exists(os.path.join(folder, SALT_FILE)):
            return "Salt file not found."
        if not os.path.exists(os.path.join(folder, MARKER_FILE)):
            return "Marker file not found. Cannot verify password."
        salt = get_salt(folder)
        raw_key = derive_key(password, salt)
        if not check_marker(folder, raw_key):
            return "Wrong password."
        key = fernet_key(raw_key)
        n = decrypt_folder(folder, key)
        return f"Decrypted files: {n}"
    except Exception as e:
        return f"Error: {e}"
