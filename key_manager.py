"""KeyStore using SQLite database (no JSON files)."""

import json
import base64
import secrets
import threading
import time
import logging
import gc
import struct
import hashlib
from typing import List, Tuple, Optional, Dict
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from crypto import rsa_sign, rsa_verify, sha256_fingerprint
import database
from services.pqc_service import HybridKEM, is_pqc_available

try:
    from services.pqc_signatures import HybridSigner
    _HYBRID_SIG_AVAILABLE = True
except (ImportError, RuntimeError, OSError):
    HybridSigner = None  # type: ignore[assignment,misc]
    _HYBRID_SIG_AVAILABLE = False

logger = logging.getLogger(__name__)

FILE_MAGIC = b'ENIGMA\x01'   # 7‑byte magic for shared‑secret encrypted files

# RSA key rotation constants
_MIN_RSA_KEY_SIZE = 4096       # CNSA 2.0 minimum
_LEGACY_KEY_RETENTION_DAYS = 30  # Keep old key for legacy message decryption

def _pem_to_pubkey(pem: str):
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())

def _get_rsa_key_size(pub_key) -> int:
    """Return the bit size of an RSA public key."""
    try:
        return pub_key.key_size
    except AttributeError:
        return 0

def _pem_to_privkey(pem: bytes, password: bytes):
    return serialization.load_pem_private_key(pem, password=password, backend=default_backend())

def pubkey_to_pem(pub) -> str:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')

def _privkey_to_encrypted_pem(priv, password: bytes) -> str:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    ).decode('ascii')

def init_db(password: str) -> bool:
    """Create database and first keys if missing. Returns True if new keys were generated."""
    database.init_db()
    new_keys = False
    with closing(database.get_connection()) as conn:
        cur = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'")
        if cur.fetchone() is None:
            priv = rsa.generate_private_key(65537, 4096, default_backend())
            pub = priv.public_key()
            encrypted_priv = _privkey_to_encrypted_pem(priv, password.encode())
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
                    # Encrypt and store Ed25519 private key (raw 32 bytes)
                    ed_priv_bytes = hybrid_keys['ed_priv'].private_bytes_raw()
                    ed_priv_enc = database.encrypt_secret(ed_priv_bytes, password)
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        ("ed25519_priv_encrypted", json.dumps(ed_priv_enc))
                    )
                    # Encrypt and store Dilithium3 private key
                    dil_priv_enc = database.encrypt_secret(hybrid_keys['dil_priv'], password)
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        ("dilithium_priv_encrypted", json.dumps(dil_priv_enc))
                    )
                    # Store combined public key
                    combined_pub_b64 = base64.b64encode(hybrid_keys['combined_pub']).decode()
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        ("hybrid_sig_combined_pub_b64", combined_pub_b64)
                    )
                    conn.commit()
                    logger.info("Hybrid signing keys (Ed25519 + Dilithium3) generated and stored")
                except Exception as e:
                    logger.warning("Failed to generate hybrid signing keys: %s", e)

    return new_keys

class KeyStore:
    # Exponential backoff table (seconds) indexed by consecutive failure count.
    # Indices 0-4: no delay; 5+: escalating delays up to 30 minutes.
    _BACKOFF_TABLE = [0, 0, 0, 0, 0, 5, 10, 30, 60, 120, 300, 600, 1800, 3600]
    _HARD_LOCKOUT_THRESHOLD = 15   # failures before hard lockout
    _HARD_LOCKOUT_DURATION = 3600  # 1 hour in seconds

    def __init__(self):
        self._lock = threading.RLock()
        self.failed_attempts = 0          # global brute-force counter
        self.locked_until = 0.0           # epoch timestamp; 0 means not locked
        self._duress_mode = False
        self._needs_rotation = False
        self._load_lockout_state()
        self.my_pub = None
        self.my_priv = None
        self.legacy_priv = None          # Previous RSA private key (kept for 30-day legacy decryption)
        self.global_secret: Optional[bytearray] = None   # changed to bytearray for secure wiping
        self.friends: List[Tuple[str, object, Optional[bytearray]]] = []   # (name, pub, shared_secret or None)
        self.friends_x25519: Dict[str, str] = {}   # name -> Base64 of raw X25519 public key
        self.friends_capabilities: Dict[str, dict] = {}  # name -> {"double_ratchet": bool, ...}
        self.friends_pqc_combined_pub: Dict[str, bytes] = {}  # name -> raw combined_pub bytes
        self.my_kyber_priv: Optional[bytes] = None   # Local Kyber secret key (raw bytes)
        self.my_pqc_combined_pub: Optional[bytes] = None  # Local hybrid combined public key
        self._cached_pqc_bundle: Optional[dict] = None  # Cached full PQC bundle for decryption
        # Hybrid signing keys (Ed25519 + Dilithium3)
        self.my_ed_priv = None          # Ed25519PrivateKey object
        self.my_dil_priv: Optional[bytes] = None  # Dilithium3 secret key bytes
        self.my_hybrid_sig_combined_pub: Optional[bytes] = None  # Combined public key bytes
        self.friends_hybrid_sig_pubs: Dict[str, tuple] = {}  # name -> (ed_pub_bytes, dil_pub_bytes)

    # ---------- Persistent lockout helpers ----------

    def _load_lockout_state(self) -> None:
        """Load persistent lockout state from the database."""
        try:
            conn = database.get_connection()
            row = conn.execute(
                "SELECT value FROM settings WHERE key='lockout_data'"
            ).fetchone()
            conn.close()
            if row:
                data = json.loads(row[0])
                self.failed_attempts = int(data.get("failures", 0))
                self.locked_until = float(data.get("locked_until", 0))
            else:
                self.failed_attempts = 0
                self.locked_until = 0.0
        except Exception:
            self.failed_attempts = 0
            self.locked_until = 0.0

    def _save_lockout_state(self) -> None:
        """Persist current lockout state to the database."""
        try:
            data = json.dumps({
                "failures": self.failed_attempts,
                "locked_until": self.locked_until
            })
            conn = database.get_connection()
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("lockout_data", data)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning("Failed to persist lockout state: %s", e)

    def _get_lockout_delay(self) -> float:
        """Return the number of seconds the caller must wait before the next attempt.

        If a hard-lockout timer is active its remaining time takes precedence.
        Otherwise the exponential backoff table is consulted.
        """
        now = time.time()
        if self.locked_until > now:
            return self.locked_until - now

        idx = min(self.failed_attempts, len(self._BACKOFF_TABLE) - 1)
        return float(self._BACKOFF_TABLE[idx])

    @property
    def is_duress_mode(self) -> bool:
        """True if the last successful authentication used the duress password."""
        return self._duress_mode

    def load(self, password: str) -> bool:
        """Load all keys from database. Password is used for decryption and then discarded."""
        # Ensure migration-safe columns exist
        try:
            conn = database.get_connection()
            for col_sql in [
                "ALTER TABLE friends ADD COLUMN x25519_public_key_b64 TEXT",
                "ALTER TABLE friends ADD COLUMN hybrid_sig_pub_b64 TEXT",
            ]:
                try:
                    conn.execute(col_sql)
                except Exception:
                    pass  # column already exists or other error (ignore)
            conn.close()
        except Exception:
            pass

        conn = database.get_connection()
        try:
            row = conn.execute("SELECT value FROM settings WHERE key='public_key'").fetchone()
            if not row: return False
            self.my_pub = _pem_to_pubkey(row[0])

            # Check if RSA key meets CNSA 2.0 minimum size
            current_key_size = _get_rsa_key_size(self.my_pub)
            if current_key_size < _MIN_RSA_KEY_SIZE:
                self._needs_rotation = True
                logger.warning(
                    "RSA key size %d-bit is below CNSA 2.0 minimum (%d-bit). "
                    "Key rotation recommended.",
                    current_key_size, _MIN_RSA_KEY_SIZE
                )
            else:
                self._needs_rotation = False

            row = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'").fetchone()
            if not row: return False
            self.my_priv = _pem_to_privkey(row[0].encode(), password.encode())

            # Load legacy private key if present and not expired
            self.legacy_priv = None
            row_legacy = conn.execute(
                "SELECT value FROM settings WHERE key='legacy_private_key_encrypted'"
            ).fetchone()
            if row_legacy:
                try:
                    row_expiry = conn.execute(
                        "SELECT value FROM settings WHERE key='legacy_key_expiry'"
                    ).fetchone()
                    expiry = float(row_expiry[0]) if row_expiry else 0.0
                    if time.time() < expiry:
                        self.legacy_priv = _pem_to_privkey(
                            row_legacy[0].encode(), password.encode()
                        )
                        logger.debug("Legacy RSA key loaded (expires in %.1f days)",
                                     (expiry - time.time()) / 86400)
                    else:
                        # Legacy key expired — remove from database
                        conn.execute("DELETE FROM settings WHERE key='legacy_private_key_encrypted'")
                        conn.execute("DELETE FROM settings WHERE key='legacy_key_expiry'")
                        conn.commit()
                        logger.info("Expired legacy RSA key removed from database")
                except Exception as e:
                    logger.warning("Could not load legacy private key: %s", e)

            row = conn.execute("SELECT value FROM settings WHERE key='global_secret'").fetchone()
            if row:
                enc_dict = json.loads(row[0])
                # Store as bytearray for zeroing capability
                self.global_secret = bytearray(database.decrypt_secret(enc_dict, password))
            else:
                self.global_secret = None

            # Load local PQC (Kyber) private key if present
            self.my_kyber_priv = None
            self.my_pqc_combined_pub = None
            row_kyber = conn.execute(
                "SELECT value FROM settings WHERE key='kyber_priv_encrypted'"
            ).fetchone()
            if row_kyber:
                try:
                    kyber_enc_dict = json.loads(row_kyber[0])
                    self.my_kyber_priv = database.decrypt_secret(kyber_enc_dict, password)
                    logger.debug("Local Kyber private key loaded (%d bytes)", len(self.my_kyber_priv))
                except Exception as e:
                    logger.warning("Could not decrypt local Kyber private key: %s", e)

            # Load local PQC combined public key if present
            row_pqc_pub = conn.execute(
                "SELECT value FROM settings WHERE key='pqc_combined_pub_b64'"
            ).fetchone()
            if row_pqc_pub and self.my_kyber_priv:
                try:
                    self.my_pqc_combined_pub = base64.b64decode(row_pqc_pub[0])
                except Exception as e:
                    logger.warning("Could not decode local PQC combined pub: %s", e)

            # Cache full PQC bundle for decryption if all components are available
            self._cached_pqc_bundle = None
            if self.my_kyber_priv and self.my_pqc_combined_pub:
                row_x25519 = conn.execute(
                    "SELECT value FROM settings WHERE key='pqc_x25519_priv_encrypted'"
                ).fetchone()
                if row_x25519:
                    try:
                        x25519_priv_bytes = database.decrypt_secret(
                            json.loads(row_x25519[0]), password
                        )
                        from cryptography.hazmat.primitives.asymmetric.x25519 import (
                            X25519PrivateKey,
                        )
                        x_priv = X25519PrivateKey.from_private_bytes(x25519_priv_bytes)
                        self._cached_pqc_bundle = {
                            'x25519_priv': x_priv,
                            'kyber_priv': self.my_kyber_priv,
                            'combined_pub': self.my_pqc_combined_pub,
                        }
                        logger.debug("PQC decryption bundle cached successfully")
                    except Exception as e:
                        logger.warning("Could not load PQC X25519 priv during load: %s", e)

            # Load hybrid signing keys from settings
            self.my_ed_priv = None
            self.my_dil_priv = None
            self.my_hybrid_sig_combined_pub = None
            if _HYBRID_SIG_AVAILABLE:
                row_ed = conn.execute(
                    "SELECT value FROM settings WHERE key='ed25519_priv_encrypted'"
                ).fetchone()
                row_dil = conn.execute(
                    "SELECT value FROM settings WHERE key='dilithium_priv_encrypted'"
                ).fetchone()
                row_hybrid_pub = conn.execute(
                    "SELECT value FROM settings WHERE key='hybrid_sig_combined_pub_b64'"
                ).fetchone()
                if row_ed and row_dil:
                    try:
                        ed_priv_bytes = database.decrypt_secret(
                            json.loads(row_ed[0]), password
                        )
                        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                            Ed25519PrivateKey,
                        )
                        self.my_ed_priv = Ed25519PrivateKey.from_private_bytes(ed_priv_bytes)
                        self.my_dil_priv = database.decrypt_secret(
                            json.loads(row_dil[0]), password
                        )
                        logger.debug("Hybrid signing private keys loaded")
                    except Exception as e:
                        logger.warning("Could not load hybrid signing private keys: %s", e)
                if row_hybrid_pub:
                    try:
                        self.my_hybrid_sig_combined_pub = base64.b64decode(row_hybrid_pub[0])
                    except Exception as e:
                        logger.warning("Could not decode hybrid sig combined pub: %s", e)

            rows = conn.execute(
                "SELECT name, public_key_pem, has_shared_secret, shared_secret_encrypted, "
                "x25519_public_key_b64, capabilities_json, pqc_combined_pub_b64, "
                "hybrid_sig_pub_b64 "
                "FROM friends"
            ).fetchall()
            self.friends.clear()
            self.friends_x25519.clear()
            self.friends_capabilities.clear()
            self.friends_pqc_combined_pub.clear()
            self.friends_hybrid_sig_pubs.clear()
            for name, pem, has_sec, sec_json, x_b64, cap_json, pqc_pub_b64, hybrid_sig_b64 in rows:
                pub = _pem_to_pubkey(pem)
                secret = None
                if has_sec and sec_json:
                    try:
                        sec_dict = json.loads(sec_json)
                        # Store as bytearray for zeroing capability
                        secret = bytearray(database.decrypt_secret(sec_dict, password))
                    except Exception as e:
                        logger.warning("Could not decrypt shared secret for friend '%s': %s", name, e)
                self.friends.append((name, pub, secret))
                if x_b64:
                    self.friends_x25519[name] = x_b64
                if cap_json:
                    try:
                        self.friends_capabilities[name] = json.loads(cap_json)
                    except (json.JSONDecodeError, TypeError):
                        self.friends_capabilities[name] = {}
                else:
                    self.friends_capabilities[name] = {}
                if pqc_pub_b64:
                    try:
                        self.friends_pqc_combined_pub[name] = base64.b64decode(pqc_pub_b64)
                    except Exception:
                        pass
                if hybrid_sig_b64 and _HYBRID_SIG_AVAILABLE:
                    try:
                        combined = base64.b64decode(hybrid_sig_b64)
                        ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(combined)
                        self.friends_hybrid_sig_pubs[name] = (ed_pub_bytes, dil_pub_bytes)
                    except Exception:
                        pass
        except Exception as e:
            logger.error("Key loading failed: %s", e)
            return False
        finally:
            conn.close()
        return True

    def verify_password(self, password: str) -> tuple:
        """Check if `password` matches master or duress password.

        Implements persistent exponential backoff and hard account lockout.
        Lockout state survives application restarts via the database.

        Backoff schedule (consecutive failures -> delay):
            0-4: none | 5: 5s | 6: 10s | 7: 30s | 8: 60s | 9: 2min
            10: 5min | 11: 10min | 12: 30min | 13-14: 1h
            15+: hard lockout (1 hour)

        Returns:
            (is_valid: bool, is_duress: bool)
        """
        with self._lock:
            # Enforce any active lockout / backoff delay
            delay = self._get_lockout_delay()
            if delay > 0:
                logger.warning(
                    "Account lockout active. %d consecutive failure(s). "
                    "Waiting %.1f seconds before next attempt.",
                    self.failed_attempts, delay
                )
                time.sleep(delay)

            # --- Check master password first ---
            try:
                conn = database.get_connection()
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='global_secret'"
                ).fetchone()
                conn.close()
                if row:
                    enc_dict = json.loads(row[0])
                    database.decrypt_secret(enc_dict, password)
                    # Success: reset lockout state
                    self.failed_attempts = 0
                    self.locked_until = 0.0
                    self._duress_mode = False
                    self._save_lockout_state()
                    return True, False
            except Exception:
                pass

            # --- Check duress password ---
            try:
                conn = database.get_connection()
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='duress_verifier'"
                ).fetchone()
                conn.close()
                if row:
                    duress_data = json.loads(row[0])
                    database.decrypt_secret(duress_data, password)
                    # Duress success: reset lockout but flag decoy mode
                    self.failed_attempts = 0
                    self.locked_until = 0.0
                    self._duress_mode = True
                    self._save_lockout_state()
                    logger.warning("DURESS PASSWORD USED - entering decoy mode")
                    return True, True
            except Exception:
                pass

            # --- Failed attempt: escalate lockout ---
            self.failed_attempts += 1

            if self.failed_attempts >= self._HARD_LOCKOUT_THRESHOLD:
                self.locked_until = time.time() + self._HARD_LOCKOUT_DURATION
                logger.critical(
                    "HARD LOCKOUT: %d consecutive failures. "
                    "Account locked for %d seconds.",
                    self.failed_attempts, self._HARD_LOCKOUT_DURATION
                )
            else:
                backoff = self._get_lockout_delay()
                if backoff > 0:
                    logger.warning(
                        "Failed password attempt #%d. Next attempt delayed by %.0f seconds.",
                        self.failed_attempts, backoff
                    )

            self._save_lockout_state()
            return False, False

    def set_duress_password(self, duress_password: str) -> None:
        """Set up a duress password that triggers decoy mode.

        Creates a dummy secret encrypted with the duress password.
        When this password is entered at login, verify_password() will
        succeed and flag duress mode, causing the app to load decoy data.
        """
        dummy_secret = secrets.token_bytes(32)
        enc = database.encrypt_secret(dummy_secret, duress_password)
        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("duress_verifier", json.dumps(enc))
            )
            conn.commit()
        logger.info("Duress password configured")

    def update_global_secret(self, new_secret: bytes, password: str) -> None:
        enc = database.encrypt_secret(new_secret, password)
        with closing(database.get_connection()) as conn:
            conn.execute("UPDATE settings SET value=? WHERE key='global_secret'", (json.dumps(enc),))
            conn.commit()
        # Store as bytearray for secure wiping
        self.global_secret = bytearray(new_secret)

    def save_friend(self, name: str, pem: str, shared_secret: Optional[bytes] = None,
                    password: str = "", x25519_pub_b64: Optional[str] = None,
                    capabilities: Optional[dict] = None,
                    pqc_combined_pub_b64: Optional[str] = None,
                    hybrid_sig_pub_b64: Optional[str] = None) -> None:
        """Save a friend; if shared_secret is provided, password must be the master password (non-empty).
        x25519_pub_b64 is the Base64 of the raw 32-byte X25519 public key.
        capabilities is an optional dict of supported features (e.g. {"double_ratchet": True}).
        pqc_combined_pub_b64 is the Base64 of the hybrid PQC combined public key.
        hybrid_sig_pub_b64 is the Base64 of the hybrid signing combined public key."""
        if shared_secret:
            if not password:
                raise ValueError("Master password required to encrypt friend shared secret")
            enc = database.encrypt_secret(shared_secret, password)
            has_sec = 1
            sec_enc_json = json.dumps(enc)
        else:
            has_sec = 0
            sec_enc_json = None

        cap_json = json.dumps(capabilities) if capabilities else None
        with closing(database.get_connection()) as conn:
            # Preserve existing ratchet_state_json when updating a friend row.
            # INSERT OR REPLACE deletes the old row, so we must carry forward
            # any columns not explicitly managed by this method.
            existing_row = conn.execute(
                "SELECT ratchet_state_json FROM friends WHERE name=?", (name,)
            ).fetchone()
            existing_ratchet_json = existing_row[0] if existing_row else None

            conn.execute(
                "INSERT OR REPLACE INTO friends "
                "(name, public_key_pem, has_shared_secret, shared_secret_encrypted, "
                "x25519_public_key_b64, capabilities_json, ratchet_state_json, "
                "pqc_combined_pub_b64, hybrid_sig_pub_b64) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (name, pem, has_sec, sec_enc_json, x25519_pub_b64, cap_json,
                 existing_ratchet_json, pqc_combined_pub_b64, hybrid_sig_pub_b64)
            )
            conn.commit()
        pub = _pem_to_pubkey(pem)
        # Remove old entry and add new one, storing secret as bytearray if present
        self.friends = [(n, p, s) for (n, p, s) in self.friends if n != name]
        secret_ba = bytearray(shared_secret) if shared_secret else None
        self.friends.append((name, pub, secret_ba))
        if x25519_pub_b64:
            self.friends_x25519[name] = x25519_pub_b64
        else:
            self.friends_x25519.pop(name, None)
        if capabilities:
            self.friends_capabilities[name] = capabilities
        else:
            self.friends_capabilities.pop(name, None)
        if pqc_combined_pub_b64:
            try:
                self.friends_pqc_combined_pub[name] = base64.b64decode(pqc_combined_pub_b64)
            except Exception:
                self.friends_pqc_combined_pub.pop(name, None)
        else:
            self.friends_pqc_combined_pub.pop(name, None)
        if hybrid_sig_pub_b64 and _HYBRID_SIG_AVAILABLE:
            try:
                combined = base64.b64decode(hybrid_sig_pub_b64)
                ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(combined)
                self.friends_hybrid_sig_pubs[name] = (ed_pub_bytes, dil_pub_bytes)
            except Exception:
                self.friends_hybrid_sig_pubs.pop(name, None)
        else:
            self.friends_hybrid_sig_pubs.pop(name, None)

    def remove_friend(self, name: str) -> None:
        with closing(database.get_connection()) as conn:
            conn.execute("DELETE FROM friends WHERE name=?", (name,))
            conn.commit()
        self.friends = [(n, p, s) for (n, p, s) in self.friends if n != name]
        self.friends_x25519.pop(name, None)
        self.friends_capabilities.pop(name, None)
        self.friends_pqc_combined_pub.pop(name, None)
        self.friends_hybrid_sig_pubs.pop(name, None)

    def get_friend_secret(self, name: str) -> Optional[bytes]:
        for n, _, s in self.friends:
            if n == name:
                # Return as bytes for compatibility (immutable)
                return bytes(s) if s is not None else None
        return None

    # ---------- PQC Hybrid KEM key management ----------

    def ensure_pqc_keys(self, password: str) -> bool:
        """Generate and persist hybrid PQC keys if they don't already exist.

        Creates a HybridKEM keypair (X25519 + Kyber768), stores the Kyber
        private key encrypted in settings, and caches both keys in memory.

        Args:
            password: Master password used to encrypt the Kyber private key.

        Returns:
            True if keys are available (either already existed or just generated).
        """
        if self.my_kyber_priv is not None and self.my_pqc_combined_pub is not None:
            return True  # Already loaded

        if not is_pqc_available():
            logger.warning("Cannot generate PQC keys: liboqs is not available")
            return False

        try:
            keys = HybridKEM.generate_keys()
            kyber_priv = keys['kyber_priv']
            combined_pub = keys['combined_pub']

            # Encrypt and store Kyber private key
            enc_dict = database.encrypt_secret(kyber_priv, password)
            combined_pub_b64 = base64.b64encode(combined_pub).decode()

            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("kyber_priv_encrypted", json.dumps(enc_dict))
                )
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("pqc_combined_pub_b64", combined_pub_b64)
                )
                conn.commit()

            self.my_kyber_priv = kyber_priv
            self.my_pqc_combined_pub = combined_pub
            logger.info("PQC hybrid keys generated and stored successfully")
            return True
        except Exception as e:
            logger.error("Failed to generate PQC keys: %s", e)
            return False

    def get_pqc_key_bundle(self) -> dict:
        """Return the local PQC key material needed for encaps/decaps.

        Returns:
            Dict with 'x25519_priv', 'kyber_priv' suitable for HybridKEM.decapsulate().
            Raises ValueError if PQC keys are not available.
        """
        if self.my_kyber_priv is None:
            raise ValueError("PQC keys not initialized. Call ensure_pqc_keys() first.")

        # We need to reconstruct the x25519 private key from the combined pub.
        # However, HybridKEM.generate_keys() creates an ephemeral X25519 key
        # that is NOT persisted separately. For decapsulation we need it.
        # Solution: store the full key bundle. Let's fix this by also storing
        # the X25519 private key alongside the Kyber key.
        # For now, we'll re-generate on demand and store both.
        row_x25519 = None
        try:
            conn = database.get_connection()
            row_x25519 = conn.execute(
                "SELECT value FROM settings WHERE key='pqc_x25519_priv_encrypted'"
            ).fetchone()
            conn.close()
        except Exception:
            pass

        if row_x25519:
            try:
                # This requires password - but we don't have it here.
                # The caller must provide password context.
                pass
            except Exception:
                pass

        raise ValueError(
            "Use ensure_pqc_keys_with_bundle() or pqc_decapsulate_with_password() instead."
        )

    def ensure_pqc_keys_full(self, password: str) -> Optional[dict]:
        """Generate/store full PQC key bundle including X25519 private key.

        Returns the full key dict from HybridKEM.generate_keys() on success,
        or loads existing keys from DB. Returns None on failure.
        """
        if not is_pqc_available():
            logger.warning("Cannot generate full PQC bundle: liboqs is not available")
            return None

        # Check if we already have everything in memory
        if (self.my_kyber_priv is not None and
                self.my_pqc_combined_pub is not None):
            # Try to load X25519 priv from DB
            try:
                conn = database.get_connection()
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='pqc_x25519_priv_encrypted'"
                ).fetchone()
                conn.close()
                if row:
                    enc_dict = json.loads(row[0])
                    x25519_priv_bytes = database.decrypt_secret(enc_dict, password)
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                    x_priv = X25519PrivateKey.from_private_bytes(x25519_priv_bytes)
                    return {
                        'x25519_priv': x_priv,
                        'kyber_priv': self.my_kyber_priv,
                        'combined_pub': self.my_pqc_combined_pub,
                    }
            except Exception as e:
                logger.warning("Could not load X25519 priv for PQC bundle: %s", e)

        # Generate fresh keys
        try:
            keys = HybridKEM.generate_keys()

            # Encrypt and store all private material
            kyber_enc = database.encrypt_secret(keys['kyber_priv'], password)
            x25519_priv_bytes = keys['x25519_priv'].private_bytes_raw()
            x25519_enc = database.encrypt_secret(x25519_priv_bytes, password)
            combined_pub_b64 = base64.b64encode(keys['combined_pub']).decode()

            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("kyber_priv_encrypted", json.dumps(kyber_enc))
                )
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("pqc_x25519_priv_encrypted", json.dumps(x25519_enc))
                )
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("pqc_combined_pub_b64", combined_pub_b64)
                )
                conn.commit()

            self.my_kyber_priv = keys['kyber_priv']
            self.my_pqc_combined_pub = keys['combined_pub']
            logger.info("Full PQC hybrid key bundle generated and stored")
            return keys
        except Exception as e:
            logger.error("Failed to generate full PQC key bundle: %s", e)
            return None

    def load_pqc_bundle(self, password: str) -> Optional[dict]:
        """Load existing PQC key bundle from database.

        Returns the key dict suitable for HybridKEM.decapsulate(), or None.
        """
        try:
            conn = database.get_connection()
            row_kyber = conn.execute(
                "SELECT value FROM settings WHERE key='kyber_priv_encrypted'"
            ).fetchone()
            row_x25519 = conn.execute(
                "SELECT value FROM settings WHERE key='pqc_x25519_priv_encrypted'"
            ).fetchone()
            row_pub = conn.execute(
                "SELECT value FROM settings WHERE key='pqc_combined_pub_b64'"
            ).fetchone()
            conn.close()

            if not (row_kyber and row_x25519 and row_pub):
                return None

            kyber_priv = database.decrypt_secret(json.loads(row_kyber[0]), password)
            x25519_priv_bytes = database.decrypt_secret(json.loads(row_x25519[0]), password)
            combined_pub = base64.b64decode(row_pub[0])

            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            x_priv = X25519PrivateKey.from_private_bytes(x25519_priv_bytes)

            self.my_kyber_priv = kyber_priv
            self.my_pqc_combined_pub = combined_pub

            return {
                'x25519_priv': x_priv,
                'kyber_priv': kyber_priv,
                'combined_pub': combined_pub,
            }
        except Exception as e:
            logger.warning("Could not load PQC bundle: %s", e)
            return None

    @property
    def pqc_decryption_bundle(self) -> Optional[dict]:
        """Return the cached PQC key bundle for decapsulation, or None if unavailable."""
        return self._cached_pqc_bundle

    @property
    def needs_key_rotation(self) -> bool:
        """True if the current RSA key is below CNSA 2.0 minimum size (4096-bit)."""
        return self._needs_rotation

    def rotate_rsa_key(self, password: str) -> bool:
        """Generate a new 4096-bit RSA key pair and retire the current key.

        The old private key is stored encrypted as 'legacy_private_key_encrypted'
        with a 30-day expiry so that messages encrypted to the old public key can
        still be decrypted during the transition period.

        Args:
            password: Master password used to encrypt the new and legacy keys.

        Returns:
            True on success, False on failure (database rolled back).
        """
        with self._lock:
            conn = database.get_connection()
            try:
                # Verify current password works before making changes
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='global_secret'"
                ).fetchone()
                if not row:
                    logger.error("rotate_rsa_key: global_secret not found")
                    return False
                enc_dict = json.loads(row[0])
                try:
                    database.decrypt_secret(enc_dict, password)
                except Exception:
                    logger.error("rotate_rsa_key: password verification failed")
                    return False

                # Store current private key as legacy (if not already legacy)
                row_current_pk = conn.execute(
                    "SELECT value FROM settings WHERE key='private_key_encrypted'"
                ).fetchone()
                if not row_current_pk:
                    logger.error("rotate_rsa_key: current private key not found")
                    return False

                # Calculate legacy key expiry (30 days from now)
                legacy_expiry = time.time() + (_LEGACY_KEY_RETENTION_DAYS * 86400)

                # Save current key as legacy
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("legacy_private_key_encrypted", row_current_pk[0])
                )
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("legacy_key_expiry", str(legacy_expiry))
                )

                # Generate new 4096-bit RSA key pair
                new_priv = rsa.generate_private_key(65537, _MIN_RSA_KEY_SIZE, default_backend())
                new_pub = new_priv.public_key()
                new_encrypted_priv = _privkey_to_encrypted_pem(new_priv, password.encode())

                # Update primary key pair in database
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='public_key'",
                    (pubkey_to_pem(new_pub),)
                )
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='private_key_encrypted'",
                    (new_encrypted_priv,)
                )

                conn.commit()

                # Update in-memory state
                self.my_priv = new_priv
                self.my_pub = new_pub
                self.legacy_priv = _pem_to_privkey(
                    row_current_pk[0].encode(), password.encode()
                )
                self._needs_rotation = False

                logger.info(
                    "RSA key rotated to %d-bit. Legacy key retained for %d days.",
                    _MIN_RSA_KEY_SIZE, _LEGACY_KEY_RETENTION_DAYS
                )
                return True

            except Exception as e:
                conn.rollback()
                logger.error("rotate_rsa_key failed (rolled back): %s", e)
                return False
            finally:
                conn.close()

    def get_decryption_snapshot(self):
        """Thread-safe snapshot for background decryption.

        Returns a tuple of (my_priv, friends_for_sig, secrets, legacy_priv).
        legacy_priv may be None if no legacy key exists or it has expired.
        """
        with self._lock:
            my_priv = self.my_priv
            legacy_priv = self.legacy_priv
            friends_for_sig = [(name, pub) for name, pub, _ in self.friends]
            # Build secrets list: global_secret (bytes-like) and each friend secret (bytes-like)
            secrets = []
            if self.global_secret is not None:
                secrets.append(self.global_secret)   # bytearray is bytes-like
            for _, _, sec in self.friends:
                if sec is not None:
                    secrets.append(sec)
            return my_priv, friends_for_sig, secrets, legacy_priv

    def change_password(self, old_password: str, new_password: str) -> bool:
        """Re-encrypt all stored secrets with a new master password.

        Steps:
          1. Verify old_password can decrypt global_secret.
          2. Decrypt every secret (global, friends, private key, TOTP).
          3. Re-encrypt each with new_password.
          4. Update in-memory state.

        Returns True on success, False on failure.
        On failure the database is left unchanged (atomic via transaction).
        """
        with self._lock:
            conn = database.get_connection()
            try:
                # --- 1. Verify old password ---
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='global_secret'"
                ).fetchone()
                if not row:
                    logger.error("change_password: global_secret not found")
                    return False
                enc_dict = json.loads(row[0])
                try:
                    database.decrypt_secret(enc_dict, old_password)
                except Exception:
                    logger.warning("change_password: old password verification failed")
                    return False

                # --- 2. Decrypt all secrets with old password ---
                # Global secret
                gs_plain = database.decrypt_secret(enc_dict, old_password)

                # Private key
                row_pk = conn.execute(
                    "SELECT value FROM settings WHERE key='private_key_encrypted'"
                ).fetchone()
                if not row_pk:
                    logger.error("change_password: private_key_encrypted not found")
                    return False
                try:
                    priv_key = _pem_to_privkey(row_pk[0].encode(), old_password.encode())
                except Exception as e:
                    logger.error("change_password: cannot decrypt private key: %s", e)
                    return False

                # Friend shared secrets
                friend_rows = conn.execute(
                    "SELECT name, shared_secret_encrypted FROM friends "
                    "WHERE has_shared_secret=1 AND shared_secret_encrypted IS NOT NULL"
                ).fetchall()
                friend_secrets = {}  # name -> plaintext bytes
                for fname, sec_json in friend_rows:
                    if not sec_json:
                        continue
                    try:
                        sec_dict = json.loads(sec_json)
                        friend_secrets[fname] = database.decrypt_secret(sec_dict, old_password)
                    except Exception as e:
                        logger.warning(
                            "change_password: could not decrypt secret for '%s': %s",
                            fname, e
                        )

                # TOTP secret (optional)
                totp_plain = None
                row_totp = conn.execute(
                    "SELECT value FROM settings WHERE key='totp_secret_encrypted'"
                ).fetchone()
                if row_totp:
                    try:
                        totp_dict = json.loads(row_totp[0])
                        totp_plain = database.decrypt_secret(totp_dict, old_password)
                    except Exception as e:
                        logger.warning("change_password: could not decrypt TOTP secret: %s", e)

                # --- 3. Re-encrypt everything with new password ---
                # Global secret
                new_gs_enc = database.encrypt_secret(gs_plain, new_password)
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='global_secret'",
                    (json.dumps(new_gs_enc),)
                )

                # Private key
                new_pk_pem = _privkey_to_encrypted_pem(priv_key, new_password.encode())
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='private_key_encrypted'",
                    (new_pk_pem,)
                )

                # Friend shared secrets
                for fname, sec_plain in friend_secrets.items():
                    new_sec_enc = database.encrypt_secret(sec_plain, new_password)
                    conn.execute(
                        "UPDATE friends SET shared_secret_encrypted=? WHERE name=?",
                        (json.dumps(new_sec_enc), fname)
                    )

                # TOTP secret
                if totp_plain is not None:
                    new_totp_enc = database.encrypt_secret(totp_plain, new_password)
                    conn.execute(
                        "UPDATE settings SET value=? WHERE key='totp_secret_encrypted'",
                        (json.dumps(new_totp_enc),)
                    )

                conn.commit()

                # --- 4. Update in-memory state ---
                self.global_secret = bytearray(gs_plain)
                # Reload private key reference (already decrypted above)
                self.my_priv = priv_key
                # Update friend secrets in memory
                updated_friends = []
                for name, pub, sec in self.friends:
                    if name in friend_secrets:
                        updated_friends.append((name, pub, bytearray(friend_secrets[name])))
                    else:
                        updated_friends.append((name, pub, sec))
                self.friends = updated_friends

                logger.info("Master password changed successfully (%d friend secrets re-encrypted)",
                            len(friend_secrets))
                return True

            except Exception as e:
                conn.rollback()
                logger.error("change_password failed (rolled back): %s", e)
                return False
            finally:
                conn.close()

    def wipe(self):
        """Securely erase all sensitive keys from memory."""
        with self._lock:
            if self.global_secret is not None:
                # Zero out the bytearray
                for i in range(len(self.global_secret)):
                    self.global_secret[i] = 0
                self.global_secret = None

            wiped_friends = []
            for name, pub, sec in self.friends:
                if isinstance(sec, bytearray):
                    for i in range(len(sec)):
                        sec[i] = 0
                    wiped_friends.append((name, pub, None))
                else:
                    wiped_friends.append((name, pub, None))
            self.friends = wiped_friends

            self.friends_x25519.clear()
            self.friends_capabilities.clear()
            self.friends_pqc_combined_pub.clear()
            if self.my_kyber_priv is not None:
                self.my_kyber_priv = b'\x00' * len(self.my_kyber_priv)
                self.my_kyber_priv = None
            self.my_pqc_combined_pub = None
            # Wipe hybrid signing private keys
            if self.my_dil_priv is not None:
                self.my_dil_priv = b'\x00' * len(self.my_dil_priv)
                self.my_dil_priv = None
            self.my_ed_priv = None
            self.my_hybrid_sig_combined_pub = None
            self.friends_hybrid_sig_pubs.clear()
            self.my_priv = None
            self.my_pub = None
            gc.collect()

    def load_duress_decoy(self) -> bool:
        """Load decoy/empty state for duress mode.

        Wipes all real keys and populates the store with empty/fake data
        so the application appears functional but contains no real information.

        Returns True on success.
        """
        with self._lock:
            # Wipe all real secrets first
            self.wipe()

            # Generate a throwaway RSA key pair so the app doesn't crash
            # when code paths expect my_pub/my_priv to exist
            decoy_priv = rsa.generate_private_key(65537, 2048, default_backend())
            self.my_priv = decoy_priv
            self.my_pub = decoy_priv.public_key()

            # Empty friends list (already cleared by wipe)
            # Empty global secret replaced with random bytes so length checks pass
            self.global_secret = bytearray(secrets.token_bytes(32))

            self._duress_mode = True
            logger.warning("Duress decoy state loaded - no real data accessible")
            return True


# KDF version tag for password-based file encryption
_FILE_KDF_VERSION_ARGON2ID = b'A2ID'  # 4-byte magic for Argon2id files
_FILE_KDF_LEGACY_PBKDF2_ITERATIONS = 300_000


# ---------- Password‑based file encryption ----------
def file_encrypt(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a file using AES-GCM with Argon2id-derived key.

    File format: A2ID(4) + salt(16) + nonce(12) + ciphertext
    """
    salt = secrets.token_bytes(database.ARGON2_SALT_LEN)
    key = database._derive_key_argon2id(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    ct = aesgcm.encrypt(nonce, plaintext, None)
    with open(output_path, 'wb') as f:
        f.write(_FILE_KDF_VERSION_ARGON2ID)
        f.write(salt)
        f.write(nonce)
        f.write(ct)


def file_decrypt(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a file with automatic KDF detection.

    Supports Argon2id (new, tagged with A2ID header) and
    PBKDF2-HMAC-SHA256 (legacy, no header).
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    with open(input_path, 'rb') as f:
        header = f.read(4)
        if header == _FILE_KDF_VERSION_ARGON2ID:
            # New Argon2id format
            salt = f.read(16)
            nonce = f.read(12)
            ct = f.read()
            key = database._derive_key_argon2id(password, salt)
        else:
            # Legacy PBKDF2 format: header is actually first 4 bytes of salt
            salt = header + f.read(12)  # remaining 12 bytes of 16-byte salt
            nonce = f.read(12)
            ct = f.read()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=_FILE_KDF_LEGACY_PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted file")
    with open(output_path, 'wb') as f:
        f.write(plaintext)


# ---------- Shared‑secret file encryption ----------
def file_encrypt_shared(
    input_path: str,
    output_path: str,
    shared_secret: bytes,
    sign: bool = False,
    my_priv=None
) -> None:
    salt = secrets.token_bytes(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"enigma-file-v1",
        backend=default_backend()
    )
    key = hkdf.derive(shared_secret)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    flags = 0
    signature = b""
    if sign and my_priv:
        signature = rsa_sign(plaintext, my_priv)
        flags |= 1

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)

    fp = hashlib.sha256(shared_secret).digest()[:16]

    with open(output_path, 'wb') as f:
        f.write(FILE_MAGIC)
        f.write(bytes([flags]))
        f.write(fp)
        f.write(salt)
        f.write(nonce)
        if signature:
            f.write(struct.pack(">H", len(signature)))
            f.write(signature)
        f.write(ct)


def file_decrypt_shared(
    input_path: str,
    output_path: str,
    secrets_dict: Dict[bytes, Tuple[bytes, Optional[str]]],
    friends_for_sig: Optional[List[Tuple[str, object]]] = None
) -> str:
    with open(input_path, 'rb') as f:
        magic = f.read(len(FILE_MAGIC))
        if magic != FILE_MAGIC:
            raise ValueError("Not a shared‑secret encrypted file (invalid magic)")

        flags_byte = f.read(1)
        if len(flags_byte) < 1:
            raise ValueError("File too short")
        flags = flags_byte[0]
        has_sign = bool(flags & 1)

        fp = f.read(16)
        salt = f.read(16)
        nonce = f.read(12)

        signature = b""
        if has_sign:
            siglen_bytes = f.read(2)
            if len(siglen_bytes) < 2:
                raise ValueError("File too short")
            siglen = struct.unpack(">H", siglen_bytes)[0]
            signature = f.read(siglen)
            if len(signature) != siglen:
                raise ValueError("File too short")
        ct = f.read()

    if fp not in secrets_dict:
        raise ValueError("No matching shared secret found – fingerprint unknown")

    secret, owner = secrets_dict[fp]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"enigma-file-v1",
        backend=default_backend()
    )
    key = hkdf.derive(secret)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed – wrong shared secret or corrupted file")

    sig_msg = ""
    if has_sign and signature and friends_for_sig:
        verified = False
        for name, pub in friends_for_sig:
            if rsa_verify(plaintext, signature, pub):
                verified = True
                sig_msg = f"✅ Signature verified from {name}"
                pem = pubkey_to_pem(pub)
                fp_key = sha256_fingerprint(pem.encode())
                sig_msg += f" (key fingerprint: {fp_key})"
                break
        if not verified:
            sig_msg = "⚠️ Signature INVALID or sender unknown"

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return sig_msg