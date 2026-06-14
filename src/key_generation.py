"""RSA/PQC/hybrid key generation and database initialization."""

import json
import base64
import secrets
import logging
import sqlite3
from typing import Union
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import database
from services.pqc_service import HybridKEM, is_pqc_available
from src.secure_string import SecureString
from src.crypto_utils import pubkey_to_pem, privkey_to_encrypted_pem as _privkey_to_encrypted_pem

try:
    from services.pqc_signatures import HybridSigner
    _HYBRID_SIG_AVAILABLE = True
except (ImportError, RuntimeError, OSError):
    HybridSigner = None  # type: ignore[assignment,misc]
    _HYBRID_SIG_AVAILABLE = False

logger = logging.getLogger(__name__)

# RSA key rotation constants
MIN_RSA_KEY_SIZE = 4096       # CNSA 2.0 minimum
LEGACY_KEY_RETENTION_DAYS = 30  # Keep old key for legacy message decryption


def get_rsa_key_size(pub_key) -> int:
    """Return the bit size of an RSA public key."""
    try:
        return pub_key.key_size
    except AttributeError:
        return 0


def init_db(password: Union[str, bytes, SecureString]) -> bool:
    """Create database and first keys if missing. Returns True if new keys were generated.

    Args:
        password: Master password as str, bytes, or SecureString.
    """
    database.init_db()
    new_keys = False
    with closing(database.get_connection()) as conn:
        cur = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'")
        if cur.fetchone() is None:
            priv = rsa.generate_private_key(65537, 4096, default_backend())
            pub = priv.public_key()
            encrypted_priv = _privkey_to_encrypted_pem(priv, password)
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("public_key", pubkey_to_pem(pub)))
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("private_key_encrypted", encrypted_priv))
            global_secret = secrets.token_bytes(32)
            enc = database.encrypt_secret(global_secret, password)
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("global_secret", json.dumps(enc)))
            conn.commit()
            new_keys = True

        # Generate hybrid signing keys (Ed25519 + Dilithium3) if liboqs is available
        if _HYBRID_SIG_AVAILABLE:
            cur_hybrid = conn.execute(
                "SELECT value FROM settings WHERE key='hybrid_sig_combined_pub_b64'"
            )
            if cur_hybrid.fetchone() is None:
                try:
                    hybrid_keys = HybridSigner.generate_keys()
                    ed_priv_bytes = hybrid_keys['ed_priv'].private_bytes_raw()
                    ed_priv_enc = database.encrypt_secret(ed_priv_bytes, password)
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        ("ed25519_priv_encrypted", json.dumps(ed_priv_enc))
                    )
                    dil_priv_enc = database.encrypt_secret(hybrid_keys['dil_priv'], password)
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        ("dilithium_priv_encrypted", json.dumps(dil_priv_enc))
                    )
                    combined_pub_b64 = base64.b64encode(hybrid_keys['combined_pub']).decode()
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        ("hybrid_sig_combined_pub_b64", combined_pub_b64)
                    )
                    conn.commit()
                    logger.info("Hybrid signing keys (Ed25519 + Dilithium3) generated and stored")
                except (ValueError, TypeError, sqlite3.Error) as e:
                    logger.warning("Failed to generate hybrid signing keys: %s", e)

    return new_keys
