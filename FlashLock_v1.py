"""FlashLock v1 — portable USB file encryption.

Encrypts the files in the folder it sits in (the drive root) behind a password,
and decrypts them back with the same password. Runs from source (Python) or as
a PyInstaller build on macOS and Windows.

Design:
    password + salt --PBKDF2-HMAC-SHA256 (200k)--> 32-byte key --> Fernet key
    Fernet = AES-128-CBC + HMAC-SHA256, so each file is encrypted *and* tagged.
The salt (.flashlock_salt) sits openly on the drive; the password lives only in
the user's head. The HMAC tag is what confirms the password was right on decrypt.

v1 note: file names are kept in plaintext — secret.txt becomes secret.txt.enc.
(Password verification and filename encryption came later.)
"""

import base64
import hashlib
import os
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog

from cryptography.fernet import Fernet, InvalidToken

SALT_FILE = ".flashlock_salt"
ITERATIONS = 200_000

# Files the program must never encrypt: the salt and its own source/binary.
PROTECTED_NAMES = {
    SALT_FILE,
    "flashlock",          # built binary
    "flashlock.exe",      # Windows build
    "flashlock.py",       # original source name
    os.path.basename(os.path.abspath(__file__)),  # this file, whatever it's named
}


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


def make_key(password, salt):
    """Derive a Fernet key from a password and salt."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32
    )
    return base64.urlsafe_b64encode(dk)


def encrypt_folder(folder, key):
    """Encrypt every file under `folder`, replacing each with a .enc copy."""
    f = Fernet(key)
    count = 0
    for root, dirs, files in os.walk(folder):
        # Never descend into .app bundles (the macOS build).
        dirs[:] = [d for d in dirs if not d.endswith(".app")]
        for name in files:
            if name.endswith(".enc") or name in PROTECTED_NAMES:
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()
            # Write the new file completely, then delete the original.
            with open(path + ".enc", "wb") as file:
                file.write(f.encrypt(data))
            os.remove(path)
            count += 1
    return count


def decrypt_folder(folder, key):
    """Decrypt every .enc file under `folder`, replacing it with the original."""
    f = Fernet(key)
    count = 0
    for root, _, files in os.walk(folder):
        for name in files:
            if not name.endswith(".enc"):
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()
            try:
                decrypted = f.decrypt(data)
            except InvalidToken:
                raise ValueError(f"Wrong password or corrupted file: {name}")
            # Write the decrypted file completely, then delete the .enc.
            with open(path[:-4], "wb") as file:
                file.write(decrypted)
            os.remove(path)
            count += 1
    return count


def ask_password(title):
    return simpledialog.askstring(title, "Enter password:", show="*")


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
        key = make_key(pwd, salt)
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
        salt = get_salt(folder)
        key = make_key(pwd, salt)
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
