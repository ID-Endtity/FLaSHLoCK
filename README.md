# FlashLock v1

Portable USB file encryption — encrypts the files on a flash drive behind a
password, and decrypts them back with the same password. Runs on macOS and
Windows without installing Python or needing admin rights.

This is an educational project for understanding how file encryption works from
the inside (salt → PBKDF2 → key → AES + HMAC). For real secrets use VeraCrypt.

## How it works

```
password + salt --PBKDF2-HMAC-SHA256 (200k iterations)--> Fernet key
each file: Fernet (AES-128-CBC + HMAC-SHA256) -> file.enc
```

The salt (`.flashlock_salt`) sits openly on the drive; the password lives only
in your head. Together they derive the key. No password = no data, forever.

## Setup

- Python 3.10+ (from python.org — Homebrew's build on macOS lacks tkinter)

```bash
pip install -r requirements.txt
```

## Run from source

```bash
python FlashLock_v1.py
```

Press **Encrypt**, type a password (8+ chars), then **Decrypt** with the same
password to restore the files.

## Build a standalone app (optional)

```bash
# macOS
pyinstaller --windowed --name FlashLock FlashLock_v1.py
# Windows
pyinstaller --windowed --name flashlock FlashLock_v1.py
```

Copy the built app to the root of a USB drive and run it from there.

## Security notes

- This is a learning project, not production security — use VeraCrypt for real data.
- A forgotten password means the data is unrecoverable. There is no reset.
- v1 encrypts the *contents* of files; file names stay visible (`secret.txt` → `secret.txt.enc`).
