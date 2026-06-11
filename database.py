"""SQLite database for Enigma Messenger."""

import json
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
from argon2.low_level import hash_secret_raw, Type

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".ultimate_enigma" / "enigma.db"

# Legacy KDF iterations for secret encryption (PBKDF2-HMAC-SHA256)
# Retained for backward-compatible decryption of existing databases
SECRET_KDF_ITERATIONS = 300_000

# Argon2id parameters (military-grade, memory-hard KDF)
# time_cost=3, memory_cost=65536 (64 MB), parallelism=4
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536    # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16
ARGON2_TYPE = Type.ID          # Argon2id - best for password hashing


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
    """Map a raw sqlite3 exception to a granular DatabaseError subclass.
    
    Note: 'raise ... from' cannot be used here because this is not inside
    an except block. We set __cause__ manually to preserve the chain.
    """
    msg = str(exc).lower()
    classified: DatabaseError
    if isinstance(exc, sqlite3.IntegrityError):
        classified = DatabaseIntegrityError(
            f"Database constraint violation: {exc}"
        )
    elif isinstance(exc, sqlite3.OperationalError):
        if "locked" in msg or "busy" in msg:
            classified = DatabaseLockedError(
                f"Database is locked by another operation. Please try again: {exc}"
            )
        elif "corrupt" in msg or "malformed" in msg or "not a database" in msg:
            classified = DatabaseCorruptedError(
                f"Database file appears corrupted. Restore from backup: {exc}"
            )
        else:
            classified = DatabaseError(f"Database operational error: {exc}")
    elif isinstance(exc, sqlite3.DatabaseError):
        if "corrupt" in msg or "malformed" in msg:
            classified = DatabaseCorruptedError(
                f"Database file is corrupted. Restore from backup: {exc}"
            )
        else:
            classified = DatabaseError(f"Database error: {exc}")
    else:
        classified = DatabaseError(f"Unexpected database error: {exc}")
    classified.__cause__ = exc
    return classified


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
            # Ensure columns exist even for older databases (ignore error if already present)
            for col_sql in [
                "ALTER TABLE friends ADD COLUMN x25519_public_key_b64 TEXT",
                "ALTER TABLE friends ADD COLUMN ratchet_state_json TEXT",
                "ALTER TABLE friends ADD COLUMN capabilities_json TEXT",
                "ALTER TABLE friends ADD COLUMN pqc_combined_pub_b64 TEXT",
                "ALTER TABLE friends ADD COLUMN hybrid_sig_pub_b64 TEXT",
            ]:
                try:
                    conn.execute(col_sql)
                except sqlite3.OperationalError:
                    pass  # column already exists
            conn.commit()
    except DatabaseError:
        raise
    except sqlite3.Error as exc:
        raise _classify_sqlite_error(exc)

def _derive_key_argon2id(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=ARGON2_TYPE
    )


def encrypt_secret(plain_bytes: bytes, password: str) -> dict:
    """Encrypt bytes using AES-GCM with Argon2id-derived key.

    Returns a dict tagged with kdf='argon2id' for version tracking.
    """
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    nonce = secrets.token_bytes(12)
    key = _derive_key_argon2id(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plain_bytes, None)
    return {
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode()
    }


def decrypt_secret(enc_dict: dict, password: str) -> bytes:
    """Decrypt bytes with automatic KDF detection.

    Supports both Argon2id (new) and PBKDF2-HMAC-SHA256 (legacy).
    Legacy entries are identified by the absence of the 'kdf' tag.
    """
    kdf_type = enc_dict.get("kdf", "pbkdf2")
    salt = base64.b64decode(enc_dict["salt"])
    nonce = base64.b64decode(enc_dict["nonce"])
    ct = base64.b64decode(enc_dict["ct"])

    if kdf_type == "argon2id":
        key = _derive_key_argon2id(password, salt)
    else:
        # Legacy PBKDF2 path - auto-migrate on next save
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


def migrate_secrets_to_argon2id(password: str) -> int:
    """Re-encrypt all legacy PBKDF2 secrets with Argon2id.

    Should be called after first successful login post-upgrade.
    Returns the number of secrets migrated.
    """
    migrated = 0
    try:
        with closing(get_connection()) as conn:
            # Migrate global_secret
            row = conn.execute(
                "SELECT value FROM settings WHERE key='global_secret'"
            ).fetchone()
            if row:
                enc_dict = json.loads(row[0])
                if enc_dict.get("kdf") != "argon2id":
                    plain = decrypt_secret(enc_dict, password)
                    new_enc = encrypt_secret(plain, password)
                    conn.execute(
                        "UPDATE settings SET value=? WHERE key='global_secret'",
                        (json.dumps(new_enc),)
                    )
                    migrated += 1
                    logger.info("Migrated global_secret to Argon2id")

            # Migrate friend shared secrets
            rows = conn.execute(
                "SELECT name, shared_secret_encrypted FROM friends "
                "WHERE has_shared_secret=1 AND shared_secret_encrypted IS NOT NULL"
            ).fetchall()
            for name, sec_json in rows:
                if not sec_json:
                    continue
                enc_dict = json.loads(sec_json)
                if enc_dict.get("kdf") != "argon2id":
                    try:
                        plain = decrypt_secret(enc_dict, password)
                        new_enc = encrypt_secret(plain, password)
                        conn.execute(
                            "UPDATE friends SET shared_secret_encrypted=? WHERE name=?",
                            (json.dumps(new_enc), name)
                        )
                        migrated += 1
                        logger.info("Migrated shared secret for '%s' to Argon2id", name)
                    except Exception as e:
                        logger.warning(
                            "Could not migrate secret for '%s': %s", name, e
                        )

            conn.commit()
    except Exception as e:
        logger.error("Secret migration failed: %s", e)

    if migrated > 0:
        logger.info("Argon2id migration complete: %d secrets upgraded", migrated)
    return migrated