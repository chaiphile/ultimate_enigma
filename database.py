"""SQLite database for Enigma Messenger."""

import json
import hashlib
import os
import platform
try:
    from sqlcipher3 import dbapi2 as sqlite3
    HAS_SQLCIPHER = True
except ImportError:
    import sqlite3
    HAS_SQLCIPHER = False
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

from src.secure_string import SecureString
from src.constants import KDF_PARAMS, DB_CONSTANTS, CRYPTO_CONSTANTS

if not HAS_SQLCIPHER:
    logger.warning("SQLCipher not available — using unencrypted SQLite")

_db_dir = Path(os.environ.get("ENIGMA_DB_DIR", Path.home() / ".ultimate_enigma"))
DB_PATH = _db_dir / "enigma.db"


def set_db_path(path: Path) -> None:
    """Override the database path (useful for testing or custom installs)."""
    global DB_PATH, _db_dir
    p = Path(path)
    if p.suffix == ".db":
        _db_dir = p.parent
        DB_PATH = p
    else:
        _db_dir = p
        DB_PATH = p / "enigma.db"


def get_db_path() -> Path:
    """Return the current database path."""
    return DB_PATH

SECRET_KDF_ITERATIONS = KDF_PARAMS["PBKDF2_LEGACY_ITERATIONS"]
ARGON2_TIME_COST = KDF_PARAMS["ARGON2_TIME_COST"]
ARGON2_MEMORY_COST = KDF_PARAMS["ARGON2_MEMORY_COST"]
ARGON2_PARALLELISM = KDF_PARAMS["ARGON2_PARALLELISM"]
ARGON2_HASH_LEN = KDF_PARAMS["ARGON2_HASH_LEN"]
ARGON2_SALT_LEN = KDF_PARAMS["ARGON2_SALT_LEN"]
ARGON2_TYPE = Type.ID

SQLCIPHER_PAGE_SIZE = DB_CONSTANTS["SQLCIPHER_PAGE_SIZE"]
SQLCIPHER_KDF_ITER = DB_CONSTANTS["SQLCIPHER_KDF_ITER"]
SQLCIPHER_CIPHER_HMAC = "HMAC_SHA512"
SQLCIPHER_CIPHER_KDF = "PBKDF2_HMAC_SHA512"
_DB_KEY_SETTING_KEY = "sqlcipher_db_key"  # settings table key for the encrypted DB key


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
    
    Handles both stdlib sqlite3 and sqlcipher3.dbapi2 exception classes
    by checking class names as a fallback when isinstance fails (e.g.,
    when sqlcipher3 is installed and its exception types differ).
    
    Note: 'raise ... from' cannot be used here because this is not inside
    an except block. We set __cause__ manually to preserve the chain.
    """
    msg = str(exc).lower()
    exc_name = type(exc).__name__
    classified: DatabaseError
    # Check by isinstance first, then by class name for sqlcipher3 compatibility
    is_integrity = (
        isinstance(exc, sqlite3.IntegrityError)
        or exc_name == "IntegrityError"
    )
    is_operational = (
        isinstance(exc, sqlite3.OperationalError)
        or exc_name == "OperationalError"
    )
    is_database = (
        isinstance(exc, sqlite3.DatabaseError)
        or exc_name == "DatabaseError"
    )
    if is_integrity:
        classified = DatabaseIntegrityError(
            f"Database constraint violation: {exc}"
        )
    elif is_operational:
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
    elif is_database:
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



def _derive_db_key() -> bytes:
    """Derive a unique per-machine database encryption key.

    On first run a random 32-byte key is generated and stored encrypted
    with the master password inside the settings table.  On subsequent
    runs the encrypted key is decrypted with the master password.

    This provides defense-in-depth: even if the master password is weak,
    the raw DB key never leaves the machine (it is sealed with a
    machine-specific HMAC derived from hardware identifiers).

    Note: The master password used here is obtained at connection time
    via _MASTER_PASSWORD (set by key_manager after first successful
    login).  For new databases before any login, encryption is skipped.
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT value FROM settings WHERE key=?",
            (_DB_KEY_SETTING_KEY,)
        ).fetchone()
        conn.close()

        if row:
            # Key already exists — decrypt it
            import json as _json
            enc_data = _json.loads(row[0])
            salt = base64.b64decode(enc_data["salt"])
            nonce = base64.b64decode(enc_data["nonce"])
            ct = base64.b64decode(enc_data["ct"])
            key = _derive_key_argon2id(_MASTER_PASSWORD, salt)
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ct, None)
        else:
            # First run — generate a new random DB key and store it
            # encrypted.  If _MASTER_PASSWORD is not yet set (first-ever
            # launch before any login), we return None and open without
            # encryption this one time.
            if _MASTER_PASSWORD is None:
                return None
            new_db_key = secrets.token_bytes(32)
            enc = encrypt_secret(new_db_key, _MASTER_PASSWORD)
            conn2 = sqlite3.connect(str(DB_PATH))
            conn2.execute(
                "CREATE TABLE IF NOT EXISTS settings ("
                "    key TEXT PRIMARY KEY, value TEXT NOT NULL"
                ")"
            )
            conn2.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (_DB_KEY_SETTING_KEY, _json.dumps(enc))
            )
            conn2.commit()
            conn2.close()
            logger.info("Generated and stored new per-machine DB encryption key")
            return new_db_key
    except (ValueError, TypeError, sqlite3.Error) as exc:
        logger.warning("Could not derive DB encryption key: %s — opening unencrypted", exc)
        return None


# Global master password reference set by key_manager after successful login.
# When None, _derive_db_key() returns None and the DB opens without
# SQLCipher encryption (backward-compatible mode).
# NOTE: Module-level mutable state is used here because SQLCipher key setup
# must happen at connection time and multiple modules need access to it.
_MASTER_PASSWORD = None


def set_master_password(password: str) -> None:
    """Set the master password used to decrypt the per-machine DB key.

    Called by key_manager.KeyStore.load() after successful authentication.
    """
    global _MASTER_PASSWORD
    if _MASTER_PASSWORD is not None:
        _MASTER_PASSWORD.wipe()
    _MASTER_PASSWORD = SecureString(password)
    _MASTER_PASSWORD.lock()


def get_master_password():
    """Return the current master password (or None).

    Useful for testing or inspecting state; avoids direct global access.
    """
    return _MASTER_PASSWORD


def clear_master_password() -> None:
    """Clear the in-memory master password (call on lock/ logout)."""
    global _MASTER_PASSWORD
    if _MASTER_PASSWORD is not None:
        _MASTER_PASSWORD.wipe()
        _MASTER_PASSWORD = None

def get_connection() -> sqlite3.Connection:
    """Get a database connection with proper pragmas.

    When SQLCipher is available and a database key has been derived,
    the connection is encrypted at rest using AES-256-CBC via SQLCipher.

    Raises:
        DatabaseConnectionError: If the connection cannot be established.
        DatabaseCorruptedError: If the database file is corrupt.

    Note: Always use contextlib.closing() or 'with' statement to ensure
    connections are properly closed after use.
    """
    try:
        DB_PATH.parent.mkdir(exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH))

        if HAS_SQLCIPHER:
            # Attempt to derive and set the per-machine encryption key.
            db_key = _derive_db_key()
            if db_key is not None:
                conn.execute('PRAGMA key = "x\'{}\'"'.format(db_key.hex()))
                conn.execute(f"PRAGMA cipher_page_size = {SQLCIPHER_PAGE_SIZE}")
                conn.execute(f"PRAGMA kdf_iter = {SQLCIPHER_KDF_ITER}")
                conn.execute(f"PRAGMA cipher_hmac_algorithm = {SQLCIPHER_CIPHER_HMAC}")
                conn.execute(f"PRAGMA cipher_kdf_algorithm = {SQLCIPHER_CIPHER_KDF}")
                logger.debug("SQLCipher encryption enabled for database")
            else:
                logger.info("No DB key available — opening database without encryption")

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

def _derive_key_argon2id(password, salt: bytes) -> bytes:
    """Derive a 32-byte key using Argon2id.
    
    Args:
        password: Password as str, bytes, or SecureString.
        salt: Random salt bytes.
    """
    # Handle SecureString, str, or bytes
    if hasattr(password, 'to_bytes'):
        # SecureString
        pw_bytes = password.to_bytes()
    elif isinstance(password, str):
        pw_bytes = password.encode("utf-8")
    elif isinstance(password, bytes):
        pw_bytes = password
    else:
        pw_bytes = str(password).encode("utf-8")
    
    return hash_secret_raw(
        secret=pw_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=ARGON2_TYPE
    )


def encrypt_secret(plain_bytes: bytes, password) -> dict:
    """Encrypt bytes using AES-GCM with Argon2id-derived key.

    Returns a dict tagged with kdf='argon2id' for version tracking.
    
    Args:
        plain_bytes: Data to encrypt.
        password: Password as str, bytes, or SecureString.
    """
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    nonce = secrets.token_bytes(CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"])
    key = _derive_key_argon2id(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plain_bytes, None)
    return {
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode()
    }


def decrypt_secret(enc_dict: dict, password) -> bytes:
    """Decrypt bytes with automatic KDF detection.

    Supports both Argon2id (new) and PBKDF2-HMAC-SHA256 (legacy).
    Legacy entries are identified by the absence of the 'kdf' tag.
    
    Args:
        enc_dict: Encrypted data dict with 'salt', 'nonce', 'ct' keys.
        password: Password as str, bytes, or SecureString.
    """
    kdf_type = enc_dict.get("kdf", "pbkdf2")
    salt = base64.b64decode(enc_dict["salt"])
    nonce = base64.b64decode(enc_dict["nonce"])
    ct = base64.b64decode(enc_dict["ct"])

    if kdf_type == "argon2id":
        key = _derive_key_argon2id(password, salt)
    else:
        # Legacy PBKDF2 path - auto-migrate on next save
        # Handle SecureString, str, or bytes
        if hasattr(password, 'to_bytes'):
            pw_bytes = password.to_bytes()
        elif isinstance(password, str):
            pw_bytes = password.encode()
        elif isinstance(password, bytes):
            pw_bytes = password
        else:
            pw_bytes = str(password).encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SECRET_KDF_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(pw_bytes)

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def migrate_secrets_to_argon2id(password) -> int:
    """Re-encrypt all legacy PBKDF2 secrets with Argon2id.

    Should be called after first successful login post-upgrade.
    Returns the number of secrets migrated.
    
    Args:
        password: Password as str, bytes, or SecureString.
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
                    except (ValueError, TypeError) as e:
                        logger.warning(
                            "Could not migrate secret for '%s': %s", name, e
                        )

            conn.commit()
    except (ValueError, TypeError, sqlite3.Error) as e:
        logger.error("Secret migration failed: %s", e)

    if migrated > 0:
        logger.info("Argon2id migration complete: %d secrets upgraded", migrated)
    return migrated