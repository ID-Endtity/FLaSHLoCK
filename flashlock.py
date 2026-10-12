"""FlashLock — portable USB file encryption.

Encrypts the files in the folder it sits in (the drive root) behind a password,
and decrypts them back with the same password. Runs from source (Python) or as
a PyInstaller one-file build on macOS and Windows.

Design:
    password + salt --PBKDF2-HMAC-SHA256 (200k)--> 32-byte key --> Fernet key
    Fernet = AES-128-CBC + HMAC-SHA256, so each file is encrypted *and* tagged.
The salt (.flashlock_salt) sits openly on the drive; the password lives only in
the user's head. A marker file (.flashlock_marker) holds an HMAC tag keyed by the
derived key, so a wrong password is caught before any file is touched. File names
are encrypted too: each file's on-disk name is a Fernet token over the real name.
"""

import base64
import hashlib
import hmac
import os
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog

from cryptography.fernet import Fernet, InvalidToken

SALT_FILE = ".flashlock_salt"
MARKER_FILE = ".flashlock_marker"
MARKER_MSG = b"flashlock-v1"
ITERATIONS = 200_000

# Files we must never encrypt: the salt, the marker, and the program itself.
PROTECTED_NAMES = {"flashlock", "flashlock.py", "flashlock.exe",
                   SALT_FILE, MARKER_FILE}


def app_dir():
    """Return the folder next to the program (the drive root)."""
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            # sys.executable = .../FlashLock.app/Contents/MacOS/FlashLock
            # Up three levels to the .app bundle, then its parent = drive root.
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
    """Write the marker file for the given key."""
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
        # Skip hidden directories and .app bundles entirely.
        dirs[:] = [d for d in dirs if not d.startswith(".") and not d.endswith(".app")]
        for name in files:
            # Skip hidden files, .enc files, and the program's own files.
            if name.startswith(".") or name.endswith(".enc") or name in PROTECTED_NAMES:
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()
            # The on-disk name is a Fernet token over the original name.
            enc_name = f.encrypt(name.encode("utf-8")).decode("ascii")
            with open(os.path.join(root, enc_name + ".enc"), "wb") as file:
                file.write(f.encrypt(data))
            os.remove(path)
            count += 1
    return count


def decrypt_folder(folder, key):
    """Decrypt every .enc file; the name token and content are both decrypted."""
    f = Fernet(key)
    count = 0
    for root, _, files in os.walk(folder):
        for name in files:
            if not name.endswith(".enc"):
                continue
            # The filename (minus .enc) is an encrypted original name. If it
            # doesn't decrypt, it's a foreign *.enc file, not one of ours.
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
            # Write the decrypted file completely, then delete the .enc.
            with open(os.path.join(root, original_name), "wb") as file:
                file.write(decrypted)
            os.remove(path)
            count += 1
    return count


def ask_password(title, prompt="Enter password:"):
    return simpledialog.askstring(title, prompt, show="*")


def main():
    folder = app_dir()

    root = tk.Tk()
    root.title("FlashLock")
    root.geometry("380x240")
    root.resizable(False, False)

    tk.Label(root, text=f"Folder: {folder}",
             wraplength=360, justify="left").pack(pady=10)

    def do_encrypt():
        pwd = ask_password("Encrypt")
        if not pwd:
            return
        if len(pwd) < 8:
            messagebox.showwarning("Weak password", "Use at least 8 characters.")
            return
        salt = get_salt(folder)
        raw_key = derive_key(pwd, salt)
        if os.path.exists(os.path.join(folder, MARKER_FILE)):
            if not check_marker(folder, raw_key):
                messagebox.showerror("Error", "Wrong password.")
                return
        else:
            confirm = ask_password("Confirm password", "Enter password again:")
            if confirm != pwd:
                messagebox.showerror("Error", "Passwords don't match.")
                return
            write_marker(folder, raw_key)
        key = fernet_key(raw_key)
        try:
            n = encrypt_folder(folder, key)
            messagebox.showinfo("Done", f"Encrypted files: {n}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt():
        pwd = ask_password("Decrypt")
        if not pwd:
            return
        if not os.path.exists(os.path.join(folder, SALT_FILE)):
            messagebox.showerror("Error", "Salt file not found.")
            return
        if not os.path.exists(os.path.join(folder, MARKER_FILE)):
            messagebox.showerror("Error", "Marker file not found. Cannot verify password.")
            return
        salt = get_salt(folder)
        raw_key = derive_key(pwd, salt)
        if not check_marker(folder, raw_key):
            messagebox.showerror("Error", "Wrong password.")
            return
        key = fernet_key(raw_key)
        try:
            n = decrypt_folder(folder, key)
            messagebox.showinfo("Done", f"Decrypted files: {n}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    tk.Button(root, text="🔒 Encrypt", width=24, command=do_encrypt).pack(pady=5)
    tk.Button(root, text="🔓 Decrypt", width=24, command=do_decrypt).pack(pady=5)
    tk.Button(root, text="Exit", width=24, command=root.destroy).pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
