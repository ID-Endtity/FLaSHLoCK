# FlashLock v2

Portable USB file encryption — encrypts the files on a flash drive behind a
password, and decrypts them back with the same password. Runs on macOS and
Windows without installing Python or needing admin rights.

This is an educational project for understanding how file encryption works from
the inside (salt → PBKDF2 → key → AES + HMAC). For real secrets, use VeraCrypt.

## What's new in v2

- **Password check** — a `.flashlock_marker` file (an HMAC tag keyed by the
  derived key) verifies the password before encrypting or decrypting, so a typo
  can't encrypt your files under the wrong password. The first time, you type
  the password twice to confirm it.
- **Filename encryption** — file names are hidden too. Each file's on-disk name
  becomes a random-looking Fernet token instead of `secret.txt.enc`.
- **Hidden files skipped** — `.`-prefixed files and folders are left untouched.
- **Foreign `.enc` files skipped** — a stray `.enc` file that isn't ours no
  longer crashes decryption.

## How it works

```
password + salt --PBKDF2-HMAC-SHA256 (200k iterations)--> Fernet key
each file: Fernet (AES-128-CBC + HMAC-SHA256) -> <random-name>.enc
```

The salt (`.flashlock_salt`) and marker (`.flashlock_marker`) sit openly on the
drive; the password lives only in your head. No password = no data, forever.

## Setup

- Python 3.10+ (from python.org — Homebrew's build on macOS lacks tkinter)

```bash
pip install -r requirements.txt
```

## Run from source

```bash
python flashlock.py
```

Press **Encrypt**, type a password (8+ chars; twice the first time), then
**Decrypt** with the same password.

## Build a standalone app (optional)

```bash
# macOS
pyinstaller --windowed --name FlashLock flashlock.py
# Windows
pyinstaller --windowed --name flashlock flashlock.py
```

Copy the built app to the root of a USB drive and run it from there.

## Security notes

- This is a learning project, not production security — use VeraCrypt for real data.
- A forgotten password means the data is unrecoverable. There is no reset.
- Folder names stay visible (only file names are encrypted); the directory
  structure is not hidden.
