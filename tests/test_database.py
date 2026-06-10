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


# ---------------------------------------------------------------------------
# Tests: Granular Error Handling
# ---------------------------------------------------------------------------

class TestGranularErrorHandling:
    def test_exception_hierarchy(self):
        """All custom DB exceptions inherit from DatabaseError."""
        assert issubclass(database.DatabaseCorruptedError, database.DatabaseError)
        assert issubclass(database.DatabaseLockedError, database.DatabaseError)
        assert issubclass(database.DatabaseIntegrityError, database.DatabaseError)
        assert issubclass(database.DatabaseConnectionError, database.DatabaseError)

    def test_classify_integrity_error(self):
        import sqlite3
        exc = sqlite3.IntegrityError("UNIQUE constraint failed")
        classified = database._classify_sqlite_error(exc)
        assert isinstance(classified, database.DatabaseIntegrityError)
        assert "constraint" in str(classified).lower()

    def test_classify_locked_error(self):
        import sqlite3
        exc = sqlite3.OperationalError("database is locked")
        classified = database._classify_sqlite_error(exc)
        assert isinstance(classified, database.DatabaseLockedError)

    def test_classify_busy_error(self):
        import sqlite3
        exc = sqlite3.OperationalError("database is busy")
        classified = database._classify_sqlite_error(exc)
        assert isinstance(classified, database.DatabaseLockedError)

    def test_classify_corrupt_operational_error(self):
        import sqlite3
        exc = sqlite3.OperationalError("file is not a database")
        classified = database._classify_sqlite_error(exc)
        assert isinstance(classified, database.DatabaseCorruptedError)

    def test_classify_malformed_error(self):
        import sqlite3
        exc = sqlite3.DatabaseError("malformed database schema")
        classified = database._classify_sqlite_error(exc)
        assert isinstance(classified, database.DatabaseCorruptedError)

    def test_classify_generic_operational_error(self):
        import sqlite3
        exc = sqlite3.OperationalError("no such table: foo")
        classified = database._classify_sqlite_error(exc)
        assert isinstance(classified, database.DatabaseError)
        assert not isinstance(classified, database.DatabaseLockedError)
        assert not isinstance(classified, database.DatabaseCorruptedError)

    def test_safe_execute_success(self, initialized_db):
        database.safe_execute(
            initialized_db,
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            ("test_key", "test_value"),
        )
        row = initialized_db.execute(
            "SELECT value FROM settings WHERE key='test_key'"
        ).fetchone()
        assert row[0] == "test_value"

    def test_safe_execute_integrity_error(self, initialized_db):
        # Insert duplicate primary key
        database.safe_execute(
            initialized_db,
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            ("dup_key", "v1"),
        )
        with pytest.raises(database.DatabaseIntegrityError):
            database.safe_execute(
                initialized_db,
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("dup_key", "v2"),
            )


# ---------------------------------------------------------------------------
# Tests: Integrity Check
# ---------------------------------------------------------------------------

class TestIntegrityCheck:
    def test_healthy_database_passes(self):
        database.init_db()
        ok, detail = database.check_integrity()
        assert ok is True
        assert detail == "ok"

    def test_corrupted_database_fails(self, tmp_path):
        """Writing garbage to the DB file should cause integrity check to fail."""
        db_file = tmp_path / "corrupt.db"
        db_file.write_bytes(b"THIS IS NOT A SQLITE DATABASE")
        with patch.object(database, "DB_PATH", db_file):
            ok, detail = database.check_integrity()
            assert ok is False
            assert len(detail) > 0

    def test_nonexistent_database_fails(self, tmp_path):
        """A missing DB file should report failure gracefully."""
        missing = tmp_path / "nonexistent" / "deep" / "enigma.db"
        with patch.object(database, "DB_PATH", missing):
            ok, detail = database.check_integrity()
            # Should not raise, just return False
            assert ok is False
