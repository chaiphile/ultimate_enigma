"""SQLite database for Enigma Messenger."""

import sqlite3
import base64
import secrets
import logging
from pathlib import Path
from typing import List, Tuple, Optional
from contextlib import closing

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".ultimate_enigma" / "enigma.db"

# KDF iterations for secret encryption (PBKDF2-HMAC-SHA256)
SECRET_KDF_ITERATIONS = 300_000


# ---------------------------------------------------------------------------
# Granular Database Exception Hierarchy
# ---------------------------------------------------------------------------

class DatabaseError(Exception):
    """Base exception for all database-related errors."""


class DatabaseCorruptedError(DatabaseError):
    """Raised when the SQLite database file is corrupted or fails integrity check.
    
    This typically means the user should restore from backup.
    """


class DatabaseLockedError(DatabaseError):
    """Raised when the database is locked by another process or connection.
    
    Usually transient; retrying after a short delay may succeed.
    """


class DatabaseIntegrityError(DatabaseError):
    """Raised when a constraint violation occurs (e.g., UNIQUE, FOREIGN KEY)."""


class DatabaseConnectionError(DatabaseError):
    """Raised when a connection to the database cannot be established."""


def _classify_sqlite_error(exc: sqlite3.Error) -> DatabaseError:
    """Map a raw sqlite3 exception to a granular DatabaseError subclass."""
    msg = str(exc).lower()
    if isinstance(exc, sqlite3.IntegrityError):
        return DatabaseIntegrityError(
            f"Database constraint violation: {exc}"
        ) from exc
    if isinstance(exc, sqlite3.OperationalError):
        if "locked" in msg or "busy" in msg:
            return DatabaseLockedError(
                f"Database is locked by another operation. Please try again: {exc}"
            ) from exc
        if "corrupt" in msg or "malformed" in msg or "not a database" in msg:
            return DatabaseCorruptedError(
                f"Database file appears corrupted. Restore from backup: {exc}"
            ) from exc
        return DatabaseError(f"Database operational error: {exc}") from exc
    if isinstance(exc, sqlite3.DatabaseError):
        if "corrupt" in msg or "malformed" in msg:
            return DatabaseCorruptedError(
                f"Database file is corrupted. Restore from backup: {exc}"
            ) from exc
        return DatabaseError(f"Database error: {exc}") from exc
    return DatabaseError(f"Unexpected database error: {exc}") from exc


def get_connection() -> sqlite3.Connection:
    """Get a database connection with proper pragmas.
    
    Raises:
        DatabaseConnectionError: If the connection cannot be established.
        DatabaseCorruptedError: If the database file is corrupt.
    
    Note: Always use contextlib.closing() or 'with' statement to ensure
    connections are properly closed after use.
    """
    try:
        DB_PATH.parent.mkdir(exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except sqlite3.DatabaseError as exc:
        raise _classify_sqlite_error(exc)
    except OSError as exc:
        raise DatabaseConnectionError(
            f"Cannot access database file at {DB_PATH}: {exc}"
        ) from exc


def check_integrity() -> Tuple[bool, str]:
    """Run SQLite integrity_check on the database.
    
    Returns:
        (True, "ok") if the database passes integrity checks.
        (False, details) if corruption is detected.
    """
    try:
        with closing(get_connection()) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result and result[0] == "ok":
                return True, "ok"
            detail = result[0] if result else "unknown"
            return False, detail
    except DatabaseError as exc:
        return False, str(exc)


def safe_execute(conn: sqlite3.Connection, sql: str, params: tuple = ()):
    """Execute a SQL statement with granular error classification.
    
    Raises appropriate DatabaseError subclass on failure.
    """
    try:
        return conn.execute(sql, params)
    except sqlite3.Error as exc:
        raise _classify_sqlite_error(exc)

def init_db():
    """Initialize database schema. Raises DatabaseError on failure."""
    try:
        with closing(get_connection()) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS friends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    public_key_pem TEXT NOT NULL,
                    has_shared_secret INTEGER NOT NULL DEFAULT 0,
                    shared_secret_encrypted TEXT,   -- JSON: {salt, nonce, ct}
                    x25519_public_key_b64 TEXT       -- NEW: raw 32-byte X25519 public key as Base64
                );
            """)
            # Ensure column exists even for older databases (ignore error if already present)
            try:
                conn.execute("ALTER TABLE friends ADD COLUMN x25519_public_key_b64 TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists
            conn.commit()
    except DatabaseError:
        raise
    except sqlite3.Error as exc:
        raise _classify_sqlite_error(exc)

SECRET_KDF_ITERATIONS = 300_000

def encrypt_secret(plain_bytes: bytes, password: str) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=SECRET_KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plain_bytes, None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode()
    }

def decrypt_secret(enc_dict: dict, password: str) -> bytes:
    salt = base64.b64decode(enc_dict["salt"])
    nonce = base64.b64decode(enc_dict["nonce"])
    ct = base64.b64decode(enc_dict["ct"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=SECRET_KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)