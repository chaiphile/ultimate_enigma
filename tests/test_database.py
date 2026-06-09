"""Comprehensive unit tests for database.py – SQLite & secret encryption."""

import json
import secrets
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import database


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Redirect DB_PATH to a temporary directory for every test."""
    fake_db = tmp_path / "test_enigma.db"
    with patch.object(database, "DB_PATH", fake_db):
        yield fake_db


@pytest.fixture
def initialized_db():
    """Initialize the schema and return the connection."""
    database.init_db()
    return database.get_connection()


# ---------------------------------------------------------------------------
# Tests: init_db
# ---------------------------------------------------------------------------

class TestInitDB:
    def test_creates_tables(self, initialized_db):
        cur = initialized_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cur.fetchall()}
        assert "settings" in tables
        assert "friends" in tables

    def test_idempotent(self):
        """Calling init_db twice must not raise."""
        database.init_db()
        database.init_db()

    def test_x25519_column_exists(self, initialized_db):
        cur = initialized_db.execute("PRAGMA table_info(friends)")
        columns = {row[1] for row in cur.fetchall()}
        assert "x25519_public_key_b64" in columns


# ---------------------------------------------------------------------------
# Tests: get_connection
# ---------------------------------------------------------------------------

class TestGetConnection:
    def test_returns_connection(self):
        conn = database.get_connection()
        assert conn is not None
        conn.close()

    def test_wal_mode(self):
        conn = database.get_connection()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        conn.close()

    def test_foreign_keys_on(self):
        conn = database.get_connection()
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
        conn.close()


# ---------------------------------------------------------------------------
# Tests: encrypt_secret / decrypt_secret
# ---------------------------------------------------------------------------

class TestSecretEncryption:
    def test_roundtrip(self):
        plain = secrets.token_bytes(32)
        password = "strongpassword123"
        enc = database.encrypt_secret(plain, password)
        dec = database.decrypt_secret(enc, password)
        assert dec == plain

    def test_wrong_password_fails(self):
        plain = secrets.token_bytes(32)
        enc = database.encrypt_secret(plain, "correct")
        with pytest.raises(Exception):
            database.decrypt_secret(enc, "wrong")

    def test_enc_dict_structure(self):
        enc = database.encrypt_secret(b"data", "pw")
        assert "salt" in enc
        assert "nonce" in enc
        assert "ct" in enc

    def test_different_ciphertext_each_time(self):
        plain = b"same data"
        enc1 = database.encrypt_secret(plain, "pw")
        enc2 = database.encrypt_secret(plain, "pw")
        # Different salt/nonce → different ciphertext
        assert enc1["ct"] != enc2["ct"]

    def test_empty_data(self):
        enc = database.encrypt_secret(b"", "pw")
        dec = database.decrypt_secret(enc, "pw")
        assert dec == b""

    def test_large_data(self):
        plain = secrets.token_bytes(10000)
        enc = database.encrypt_secret(plain, "pw")
        dec = database.decrypt_secret(enc, "pw")
        assert dec == plain

    def test_unicode_password(self):
        plain = b"secret"
        password = "пароль密码🔑"
        enc = database.encrypt_secret(plain, password)
        dec = database.decrypt_secret(enc, password)
        assert dec == plain

    def test_tampered_ciphertext_fails(self):
        enc = database.encrypt_secret(b"data", "pw")
        import base64
        ct = bytearray(base64.b64decode(enc["ct"]))
        ct[-1] ^= 0xFF
        enc["ct"] = base64.b64encode(bytes(ct)).decode()
        with pytest.raises(Exception):
            database.decrypt_secret(enc, "pw")
