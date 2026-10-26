"""Tests for flashlock_backend.py.

Run with:  pytest test_backend.py -v
"""

import importlib.util
import os
import stat

import pytest

BACKEND_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flashlock_backend.py")


def _load_backend():
    spec = importlib.util.spec_from_file_location("flashlock_backend", BACKEND_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


backend = _load_backend()


@pytest.fixture
def d(monkeypatch, tmp_path):
    """A temp directory that the backend treats as its app_dir."""
    folder = str(tmp_path)
    monkeypatch.setattr(backend, "app_dir", lambda: folder)
    return folder


def write(path, content):
    with open(path, "wb") as f:
        f.write(content)


# ---------- crypto helpers ----------

def test_get_salt_creates_and_reuses(d):
    salt1 = backend.get_salt(d)
    assert os.path.exists(os.path.join(d, backend.SALT_FILE))
    salt2 = backend.get_salt(d)
    assert salt1 == salt2  # salt must never change once created


def test_derive_key_deterministic():
    salt = b"x" * 16
    assert backend.derive_key("pw", salt) == backend.derive_key("pw", salt)


def test_derive_key_differs_by_password():
    salt = b"x" * 16
    assert backend.derive_key("pw1", salt) != backend.derive_key("pw2", salt)


def test_derive_key_differs_by_salt():
    assert backend.derive_key("pw", b"a" * 16) != backend.derive_key("pw", b"b" * 16)


def test_marker_round_trip(d):
    raw = backend.derive_key("password123", backend.get_salt(d))
    backend.write_marker(d, raw)
    assert backend.check_marker(d, raw) is True
    wrong = backend.derive_key("wrongpass", backend.get_salt(d))
    assert backend.check_marker(d, wrong) is False


# ---------- encrypt / decrypt ----------

def test_round_trip_file(d):
    write(os.path.join(d, "secret.txt"), b"hello world")
    ok, msg = backend.encrypt("password123")
    assert ok and "Encrypted files: 1" in msg
    assert not os.path.exists(os.path.join(d, "secret.txt"))
    ok, msg = backend.decrypt("password123")
    assert ok and "Decrypted files: 1" in msg
    with open(os.path.join(d, "secret.txt"), "rb") as f:
        assert f.read() == b"hello world"


def test_wrong_password_rejected(d):
    write(os.path.join(d, "secret.txt"), b"data")
    backend.encrypt("password123")
    ok, msg = backend.encrypt("wrongpass1")
    assert ok is False and "Wrong password" in msg
    ok, msg = backend.decrypt("wrongpass1")
    assert ok is False and "Wrong password" in msg


def test_filename_is_hidden(d):
    write(os.path.join(d, "secret.txt"), b"data")
    backend.encrypt("password123")
    names = os.listdir(d)
    assert "secret.txt" not in names
    assert any(name.endswith(".enc") for name in names)


def test_hidden_files_skipped(d):
    write(os.path.join(d, ".hidden"), b"hidden")
    write(os.path.join(d, "visible.txt"), b"visible")
    os.makedirs(os.path.join(d, ".hiddendir"))
    write(os.path.join(d, ".hiddendir", "x.txt"), b"x")
    ok, msg = backend.encrypt("password123")
    assert "Encrypted files: 1" in msg  # only visible.txt
    assert os.path.exists(os.path.join(d, ".hidden"))
    assert os.path.exists(os.path.join(d, ".hiddendir", "x.txt"))


def test_foreign_enc_skipped(d):
    write(os.path.join(d, "big5.enc"), b"plaintext tcl encoding")  # a foreign .enc file
    write(os.path.join(d, "real.txt"), b"real data")
    backend.encrypt("password123")
    backend.decrypt("password123")
    assert os.path.exists(os.path.join(d, "big5.enc"))  # untouched, no crash
    with open(os.path.join(d, "real.txt"), "rb") as f:
        assert f.read() == b"real data"


# ---------- metadata preservation ----------

def test_symlink_preserved(d):
    write(os.path.join(d, "target.txt"), b"target content")
    os.symlink("target.txt", os.path.join(d, "link"))
    backend.encrypt("password123")
    backend.decrypt("password123")
    assert os.path.islink(os.path.join(d, "link"))
    assert os.readlink(os.path.join(d, "link")) == "target.txt"


def test_permissions_preserved(d):
    p = os.path.join(d, "run.sh")
    write(p, b"#!/bin/sh\necho hi\n")
    os.chmod(p, 0o755)
    backend.encrypt("password123")
    backend.decrypt("password123")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o755


def test_mtime_preserved(d):
    p = os.path.join(d, "f.txt")
    write(p, b"data")
    os.utime(p, (1000000.0, 2000000.0))
    backend.encrypt("password123")
    backend.decrypt("password123")
    assert abs(os.stat(p).st_mtime - 2000000.0) < 0.01


# ---------- reset ----------

def test_reset_blocked_while_encrypted(d):
    write(os.path.join(d, "secret.txt"), b"data")
    backend.encrypt("password123")
    ok, msg = backend.reset_password()
    assert ok is False and "Decrypt your files first" in msg
    assert backend.has_marker()


def test_reset_after_decrypt(d):
    write(os.path.join(d, "secret.txt"), b"data")
    backend.encrypt("password123")
    backend.decrypt("password123")
    ok, msg = backend.reset_password()
    assert ok is True and "Password reset" in msg
    assert backend.has_marker() is False
    assert not os.path.exists(os.path.join(d, backend.SALT_FILE))
    assert not os.path.exists(os.path.join(d, backend.MARKER_FILE))


def test_has_marker(d):
    assert backend.has_marker() is False
    write(os.path.join(d, "x.txt"), b"data")
    backend.encrypt("password123")
    assert backend.has_marker() is True


def test_has_encrypted_files(d):
    assert backend.has_encrypted_files() is False
    write(os.path.join(d, "x.txt"), b"data")
    backend.encrypt("password123")
    assert backend.has_encrypted_files() is True
