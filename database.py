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

def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
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