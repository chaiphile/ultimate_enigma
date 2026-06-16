"""KeyStore using SQLite database (no JSON files).

This module is a thin orchestrator that composes:
  - security/lockout.py — LockoutManager for auth attempt lockout
  - src/key_generation.py — RSA/PQC/hybrid key generation and DB init
  - src/crypto_utils.py — PEM/key conversion helpers

The KeyStore class itself remains here as the primary interface.
"""

import json
import base64
import secrets
import threading
import time
import logging
import gc
import hashlib
try:
    from sqlcipher3 import dbapi2 as sqlite3
except ImportError:
    import sqlite3
from typing import List, Tuple, Optional, Dict, Union
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

import database
from services.pqc_service import HybridKEM, is_pqc_available
from src.exceptions import KeyStoreError
from src.secure_string import SecureString
from security.guarded_buffer import GuardedBuffer
from security.lockout import LockoutManager
from src.key_generation import (
    init_db,
    get_rsa_key_size,
    MIN_RSA_KEY_SIZE,
    LEGACY_KEY_RETENTION_DAYS,
    _HYBRID_SIG_AVAILABLE,
)

try:
    from services.pqc_signatures import HybridSigner
except (ImportError, RuntimeError, OSError):
    HybridSigner = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

from src.crypto_utils import (
    pem_to_pubkey as _pem_to_pubkey,
    pem_to_privkey as _pem_to_privkey,
    pubkey_to_pem,
    privkey_to_encrypted_pem as _privkey_to_encrypted_pem,
)

def _to_bytes(pw):
    if isinstance(pw, SecureString):
        return pw.to_bytes()
    if isinstance(pw, bytes):
        return pw
    return pw.encode()


class KeyStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._lockout = LockoutManager()
        self._duress_mode = False
        self._needs_rotation = False
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
        self._rsa_key_bytes: Optional[GuardedBuffer] = None
        self._ratchet_storage_key: Optional[bytes] = None  # Derived from master password during load()

    # ---------- Persistent lockout helpers ----------

    @property
    def failed_attempts(self) -> int:
        """Number of consecutive failed authentication attempts."""
        return self._lockout.failed_attempts

    @failed_attempts.setter
    def failed_attempts(self, value: int) -> None:
        self._lockout.failed_attempts = value

    @property
    def locked_until(self) -> float:
        """Epoch timestamp until which the account is locked (0 = not locked)."""
        return self._lockout.locked_until

    @locked_until.setter
    def locked_until(self, value: float) -> None:
        self._lockout.locked_until = value

    @property
    def is_duress_mode(self) -> bool:
        """True if the last successful authentication used the duress password."""
        return self._duress_mode

    def load(self, password: Union[str, bytes, SecureString]) -> bool:
        """Load all keys from database. Password is used for decryption and then discarded.
        
        Args:
            password: Master password as str, bytes, or SecureString.
        """
        # Ensure migration-safe columns exist
        try:
            with closing(database.get_connection()) as conn:
                for col_sql in [
                    "ALTER TABLE friends ADD COLUMN x25519_public_key_b64 TEXT",
                    "ALTER TABLE friends ADD COLUMN hybrid_sig_pub_b64 TEXT",
                ]:
                    try:
                        conn.execute(col_sql)
                    except Exception as e:
                        if "duplicate column" not in str(e).lower():
                            logger.debug("ALTER TABLE for schema migration: %s", e)
        except Exception as e:
            logger.debug("Schema migration failed (likely already applied): %s", e)

        conn = database.get_connection()
        try:
            row = conn.execute("SELECT value FROM settings WHERE key='public_key'").fetchone()
            if not row:
                raise KeyStoreError("Public key not found in database")
            self.my_pub = _pem_to_pubkey(row[0])

            # Check if RSA key meets CNSA 2.0 minimum size
            current_key_size = get_rsa_key_size(self.my_pub)
            if current_key_size < MIN_RSA_KEY_SIZE:
                self._needs_rotation = True
                logger.warning(
                    "RSA key size %d-bit is below CNSA 2.0 minimum (%d-bit). "
                    "Key rotation recommended.",
                    current_key_size, MIN_RSA_KEY_SIZE
                )
            else:
                self._needs_rotation = False

            row = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'").fetchone()
            if not row:
                raise KeyStoreError("Encrypted private key not found in database")
            try:
                self.my_priv = _pem_to_privkey(row[0].encode(), _to_bytes(password))
            except (ValueError, TypeError) as e:
                logger.error("Failed to decrypt private key: %s", e)
                return False

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
                            row_legacy[0].encode(), _to_bytes(password)
                        )
                        logger.debug("Legacy RSA key loaded (expires in %.1f days)",
                                     (expiry - time.time()) / 86400)
                    else:
                        # Legacy key expired — remove from database
                        conn.execute("DELETE FROM settings WHERE key='legacy_private_key_encrypted'")
                        conn.execute("DELETE FROM settings WHERE key='legacy_key_expiry'")
                        conn.commit()
                        logger.info("Expired legacy RSA key removed from database")
                except (ValueError, TypeError, sqlite3.Error) as e:
                    logger.warning("Could not load legacy private key: %s", e)

            row = conn.execute("SELECT value FROM settings WHERE key='global_secret'").fetchone()
            if row:
                enc_dict = json.loads(row[0])
                # Store as GuardedBuffer for secure wiping
                try:
                    old = self.global_secret
                    decrypted = database.decrypt_secret(enc_dict, password)
                    self.global_secret = GuardedBuffer(len(decrypted))
                    self.global_secret.write(bytes(decrypted) if isinstance(decrypted, bytearray) else decrypted)
                    # Zero old bytearray
                    if isinstance(old, bytearray):
                        for i in range(len(old)):
                            old[i] = 0
                except (ValueError, TypeError) as e:
                    logger.error("Failed to decrypt global secret: %s", e)
                    return False
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
                    kyber_plain = database.decrypt_secret(kyber_enc_dict, password)
                    # Store in a GuardedBuffer so wipe() can overwrite it; raw
                    # bytes are immutable and cannot be zeroized on lock.
                    self.my_kyber_priv = GuardedBuffer(len(kyber_plain))
                    self.my_kyber_priv.write(kyber_plain)
                    if isinstance(kyber_plain, bytearray):
                        kyber_plain[:] = b'\x00' * len(kyber_plain)
                    logger.debug("Local Kyber private key loaded (%d bytes)", len(self.my_kyber_priv))
                except (ValueError, TypeError, json.JSONDecodeError) as e:
                    logger.warning("Could not decrypt local Kyber private key: %s", e)

            # Load local PQC combined public key if present
            row_pqc_pub = conn.execute(
                "SELECT value FROM settings WHERE key='pqc_combined_pub_b64'"
            ).fetchone()
            if row_pqc_pub and self.my_kyber_priv:
                try:
                    self.my_pqc_combined_pub = base64.b64decode(row_pqc_pub[0])
                except (ValueError, TypeError) as e:
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
                    except (ValueError, TypeError, json.JSONDecodeError) as e:
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
                        if isinstance(ed_priv_bytes, bytearray):
                            ed_priv_bytes[:] = b'\x00' * len(ed_priv_bytes)
                        dil_plain = database.decrypt_secret(
                            json.loads(row_dil[0]), password
                        )
                        # GuardedBuffer so wipe() can zeroize the Dilithium
                        # secret key; raw bytes cannot be overwritten in place.
                        self.my_dil_priv = GuardedBuffer(len(dil_plain))
                        self.my_dil_priv.write(dil_plain)
                        if isinstance(dil_plain, bytearray):
                            dil_plain[:] = b'\x00' * len(dil_plain)
                        logger.debug("Hybrid signing private keys loaded")
                    except (ValueError, TypeError, json.JSONDecodeError) as e:
                        logger.warning("Could not load hybrid signing private keys: %s", e)
                if row_hybrid_pub:
                    try:
                        self.my_hybrid_sig_combined_pub = base64.b64decode(row_hybrid_pub[0])
                    except (ValueError, TypeError) as e:
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
                        # Store as GuardedBuffer for secure wiping
                        decrypted = database.decrypt_secret(sec_dict, password)
                        secret = GuardedBuffer(len(decrypted))
                        secret.write(bytes(decrypted) if isinstance(decrypted, bytearray) else decrypted)
                    except (ValueError, TypeError, json.JSONDecodeError) as e:
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
                    except (ValueError, TypeError) as e:
                        logger.warning("Could not decode friend PQC combined pub for %s: %s", name, e)
                if hybrid_sig_b64 and _HYBRID_SIG_AVAILABLE:
                    try:
                        combined = base64.b64decode(hybrid_sig_b64)
                        ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(combined)
                        self.friends_hybrid_sig_pubs[name] = (ed_pub_bytes, dil_pub_bytes)
                    except (ValueError, TypeError) as e:
                        logger.warning("Could not decode hybrid sig pub for %s: %s", name, e)
        except KeyStoreError:
            raise
        except Exception as e:
            logger.error("Key loading failed: %s", e)
            raise KeyStoreError(f"Key loading failed: {e}") from e
        finally:
            conn.close()

        # Log what was loaded
        logger.info(
            "Keys loaded: RSA=%d-bit, global_secret=%s, friends=%d, "
            "pqc=%s, hybrid_sig=%s",
            get_rsa_key_size(self.my_pub),
            "yes" if self.global_secret else "no",
            len(self.friends),
            "yes" if self.my_kyber_priv else "no",
            "yes" if self.my_hybrid_sig_combined_pub else "no",
        )

        # Derive ratchet storage key from master password (never persisted).
        # This key is distinct from global_secret so an attacker with DB
        # access alone cannot derive it.
        pw_bytes = password.encode() if isinstance(password, str) else (
            password.to_bytes() if isinstance(password, SecureString) else password
        )
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as _hashes
        import base64 as _b64
        import secrets as _secrets

        # NOTE: open a fresh connection here. The connection used above is
        # already closed in the finally block, so reusing it silently failed
        # and left the salt as None — meaning the storage key degenerated to
        # HKDF(password, salt=None) on every run, defeating the salt.
        with closing(database.get_connection()) as _salt_conn:
            _salt_row = _salt_conn.execute(
                "SELECT value FROM settings WHERE key='ratchet_hkdf_salt'"
            ).fetchone()
            if _salt_row:
                _ratchet_salt = _b64.b64decode(_salt_row[0])
            else:
                _ratchet_salt = _secrets.token_bytes(32)
                _salt_conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("ratchet_hkdf_salt", _b64.b64encode(_ratchet_salt).decode())
                )
                _salt_conn.commit()

        _hkdf = HKDF(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=_ratchet_salt,
            info=b"enigma-ratchet-storage-key-v1",
        )
        self._ratchet_storage_key = _hkdf.derive(pw_bytes)
        # Wipe intermediate password bytes
        if isinstance(pw_bytes, bytearray):
            for i in range(len(pw_bytes)):
                pw_bytes[i] = 0

        return True

    def verify_password(self, password: Union[str, bytes, SecureString]) -> bool:
        """Check if `password` matches master or duress password.

        Implements persistent exponential backoff and hard account lockout.
        Lockout state survives application restarts via the database.

        Backoff schedule (consecutive failures -> delay):
            0-4: none | 5: 5s | 6: 10s | 7: 30s | 8: 60s | 9: 2min
            10: 5min | 11: 10min | 12: 30min | 13-14: 1h
            15+: hard lockout (1 hour)

        Args:
            password: Password as str, bytes, or SecureString.

        Returns:
            is_valid (bool): True if password matches master or duress password.
        """
        with self._lock:
            # Enforce any active lockout / backoff delay
            delay = self._lockout.get_delay()
            if delay > 0:
                logger.warning(
                    "Account lockout active. %d consecutive failure(s). "
                    "Waiting %.1f seconds before next attempt.",
                    self.failed_attempts, delay
                )
                time.sleep(delay)
                # TODO: This blocks the calling thread. If called from the GUI thread,
                #       replace with a non-blocking timer / polling approach.

            # Load both verifiers up front so the DB access pattern is the
            # same regardless of which password (if any) matches.
            master_enc = None
            duress_enc = None
            try:
                conn = database.get_connection()
                row_master = conn.execute(
                    "SELECT value FROM settings WHERE key='global_secret'"
                ).fetchone()
                row_duress = conn.execute(
                    "SELECT value FROM settings WHERE key='duress_verifier'"
                ).fetchone()
                conn.close()
                if row_master:
                    master_enc = json.loads(row_master[0])
                if row_duress:
                    duress_enc = json.loads(row_duress[0])
            except (ValueError, TypeError, sqlite3.Error) as e:
                logger.debug("Password verifier load failed: %s", e)

            # Always attempt BOTH derivations (no early return) so that a
            # duress login and a real login perform the same amount of work.
            # Otherwise an adversary timing the unlock could distinguish the
            # decoy password from the real one — defeating duress mode.
            master_ok = False
            duress_ok = False
            if master_enc is not None:
                try:
                    database.decrypt_secret(master_enc, password)
                    master_ok = True
                except (ValueError, TypeError, InvalidTag) as e:
                    logger.debug("Master password verification failed: %s", e)
            if duress_enc is not None:
                try:
                    database.decrypt_secret(duress_enc, password)
                    duress_ok = True
                except (ValueError, TypeError, InvalidTag) as e:
                    logger.debug("Duress password verification failed: %s", e)

            if master_ok:
                self._lockout.reset()
                self._duress_mode = False
                return True
            if duress_ok:
                self._lockout.reset()
                self._duress_mode = True
                return True

            # --- Failed attempt: escalate lockout ---
            self._lockout.record_failure()

            backoff = self._lockout.get_delay()
            if backoff > 0:
                logger.warning(
                    "Failed password attempt #%d. Next attempt delayed by %.0f seconds.",
                    self.failed_attempts, backoff
                )

            return False

    def set_duress_password(self, duress_password: Union[str, bytes, SecureString]) -> None:
        """Set up a duress password that triggers decoy mode.

        Creates a dummy secret encrypted with the duress password.
        When this password is entered at login, verify_password() will
        succeed and flag duress mode, causing the app to load decoy data.
        
        Args:
            duress_password: Duress password as str, bytes, or SecureString.
        """
        dummy_secret = secrets.token_bytes(32)
        enc = database.encrypt_secret(dummy_secret, duress_password)
        # Pre-generate the decoy RSA key now so that entering duress mode later
        # *loads* a key (fast) like a real login, rather than generating one
        # (slow). Generation latency at unlock time would be a timing tell that
        # distinguishes a duress login from a real one.
        decoy_priv = rsa.generate_private_key(65537, MIN_RSA_KEY_SIZE, default_backend())
        decoy_pem = _privkey_to_encrypted_pem(decoy_priv, duress_password)
        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("duress_verifier", json.dumps(enc))
            )
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("duress_decoy_privkey", decoy_pem)
            )
            conn.commit()
        logger.info("Duress password configured")

    def update_global_secret(self, new_secret: bytes, password: Union[str, bytes, SecureString]) -> None:
        """Update the global secret with a new value.
        
        Args:
            new_secret: New secret bytes.
            password: Master password as str, bytes, or SecureString.
        """
        enc = database.encrypt_secret(new_secret, password)
        with closing(database.get_connection()) as conn:
            conn.execute("UPDATE settings SET value=? WHERE key='global_secret'", (json.dumps(enc),))
            conn.commit()
        # Store in GuardedBuffer for secure memory
        gb = GuardedBuffer(len(new_secret))
        gb.write(new_secret)
        self.global_secret = gb

    def save_friend(self, name: str, pem: str, shared_secret: Optional[bytes] = None,
                    password: Union[str, bytes, SecureString] = "", x25519_pub_b64: Optional[str] = None,
                    capabilities: Optional[dict] = None,
                    pqc_combined_pub_b64: Optional[str] = None,
                    hybrid_sig_pub_b64: Optional[str] = None) -> None:
        """Save a friend; if shared_secret is provided, password must be the master password (non-empty).
        x25519_pub_b64 is the Base64 of the raw 32-byte X25519 public key.
        capabilities is an optional dict of supported features (e.g. {"double_ratchet": True}).
        pqc_combined_pub_b64 is the Base64 of the hybrid PQC combined public key.
        hybrid_sig_pub_b64 is the Base64 of the hybrid signing combined public key.
        
        Args:
            password: Master password as str, bytes, or SecureString.
        """
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
        # Remove old entry and add new one, storing secret as GuardedBuffer if present
        self.friends = [(n, p, s) for (n, p, s) in self.friends if n != name]
        if shared_secret:
            secret_gb = GuardedBuffer(len(shared_secret))
            secret_gb.write(bytes(shared_secret) if isinstance(shared_secret, bytearray) else shared_secret)
        else:
            secret_gb = None
        self.friends.append((name, pub, secret_gb))
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
            except (ValueError, TypeError):
                self.friends_pqc_combined_pub.pop(name, None)
        else:
            self.friends_pqc_combined_pub.pop(name, None)
        if hybrid_sig_pub_b64 and _HYBRID_SIG_AVAILABLE:
            try:
                combined = base64.b64decode(hybrid_sig_pub_b64)
                ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(combined)
                self.friends_hybrid_sig_pubs[name] = (ed_pub_bytes, dil_pub_bytes)
            except (ValueError, TypeError):
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
                if s is None:
                    return None
                if isinstance(s, GuardedBuffer):
                    return s.read()
                return bytes(s)
        return None

    # ---------- PQC Hybrid KEM key management ----------

    @staticmethod
    def _guard(secret) -> GuardedBuffer:
        """Wrap a secret in a GuardedBuffer so it can be zeroized on wipe().

        Raw ``bytes`` are immutable and cannot be overwritten in place, so
        long-lived private keys are stored guarded instead.
        """
        buf = GuardedBuffer(len(secret))
        buf.write(bytes(secret))
        return buf

    def ensure_pqc_keys(self, password: Union[str, bytes, SecureString]) -> None:
        """Generate and persist hybrid PQC keys if they don't already exist.

        Creates a HybridKEM keypair (X25519 + Kyber768), stores the Kyber
        private key encrypted in settings, and caches both keys in memory.

        Args:
            password: Master password as str, bytes, or SecureString used to encrypt the Kyber private key.

        Raises:
            KeyStoreError: If PQC is unavailable or key generation/storage fails.
        """
        if self.my_kyber_priv is not None and self.my_pqc_combined_pub is not None:
            return  # Already loaded

        if not is_pqc_available():
            raise KeyStoreError("Cannot generate PQC keys: liboqs is not available")

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

            self.my_kyber_priv = self._guard(kyber_priv)
            self.my_pqc_combined_pub = combined_pub
            logger.info("PQC hybrid keys generated and stored successfully")
        except KeyStoreError:
            raise
        except (ValueError, TypeError, sqlite3.Error) as e:
            logger.error("Failed to generate PQC keys: %s", e)
            raise KeyStoreError(f"Failed to generate PQC keys: {e}") from e

    def ensure_pqc_keys_full(self, password: Union[str, bytes, SecureString]) -> Optional[dict]:
        """Generate/store full PQC key bundle including X25519 private key.

        Returns the full key dict from HybridKEM.generate_keys() on success,
        or loads existing keys from DB. Returns None on failure.
        
        Args:
            password: Master password as str, bytes, or SecureString.
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
            except (ValueError, TypeError, sqlite3.Error, json.JSONDecodeError) as e:
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

            self.my_kyber_priv = self._guard(keys['kyber_priv'])
            self.my_pqc_combined_pub = keys['combined_pub']
            logger.info("Full PQC hybrid key bundle generated and stored")
            return keys
        except (ValueError, TypeError, sqlite3.Error) as e:
            logger.error("Failed to generate full PQC key bundle: %s", e)
            return None

    def load_pqc_bundle(self, password: Union[str, bytes, SecureString]) -> Optional[dict]:
        """Load existing PQC key bundle from database.

        Returns the key dict suitable for HybridKEM.decapsulate(), or None.
        
        Args:
            password: Master password as str, bytes, or SecureString.
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

            self.my_kyber_priv = self._guard(kyber_priv)
            self.my_pqc_combined_pub = combined_pub

            return {
                'x25519_priv': x_priv,
                'kyber_priv': kyber_priv,
                'combined_pub': combined_pub,
            }
        except (ValueError, TypeError, sqlite3.Error, json.JSONDecodeError) as e:
            logger.warning("Could not load PQC bundle: %s", e)
            return None

    @property
    def pqc_decryption_bundle(self) -> Optional[dict]:
        """Return the cached PQC key bundle for decapsulation, or None if unavailable."""
        return self._cached_pqc_bundle

    @property
    def my_name(self) -> str:
        """Return the user's display name for ratchet envelope identification.

        Reads from the 'my_name' setting in the database. If not set,
        falls back to a truncated SHA-256 fingerprint of the public key
        so that ratchet messages always carry a valid sender identifier.
        """
        try:
            conn = database.get_connection()
            row = conn.execute(
                "SELECT value FROM settings WHERE key='my_name'"
            ).fetchone()
            conn.close()
            if row and row[0]:
                return row[0]
        except sqlite3.Error:
            pass

        # Fallback: derive a short identifier from the public key
        if self.my_pub is not None:
            try:
                pem = pubkey_to_pem(self.my_pub)
                fp = hashlib.sha256(pem.encode()).hexdigest()[:8]
                return f"user-{fp}"
            except (ValueError, TypeError, AttributeError):
                pass
        return "anonymous"

    def set_my_name(self, name: str) -> None:
        """Persist the user's display name to the settings table.

        Args:
            name: Display name to use as sender identity in ratchet envelopes.
        """
        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("my_name", name)
            )
            conn.commit()
        logger.info("User display name set to '%s'", name)

    @property
    def needs_key_rotation(self) -> bool:
        """True if the current RSA key is below CNSA 2.0 minimum size (4096-bit)."""
        return self._needs_rotation

    def rotate_rsa_key(self, password: Union[str, bytes, SecureString]) -> None:
        """Generate a new 4096-bit RSA key pair and retire the current key.

        The old private key is stored encrypted as 'legacy_private_key_encrypted'
        with a 30-day expiry so that messages encrypted to the old public key can
        still be decrypted during the transition period.

        Args:
            password: Master password as str, bytes, or SecureString used to encrypt the new and legacy keys.

        Raises:
            KeyStoreError: If rotation fails (database rolled back).
        """
        with self._lock:
            conn = database.get_connection()
            try:
                # Verify current password works before making changes
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='global_secret'"
                ).fetchone()
                if not row:
                    raise KeyStoreError("rotate_rsa_key: global_secret not found")
                enc_dict = json.loads(row[0])
                try:
                    database.decrypt_secret(enc_dict, password)
                except (ValueError, TypeError) as e:
                    raise KeyStoreError(
                        "rotate_rsa_key: password verification failed"
                    ) from e

                # Store current private key as legacy (if not already legacy)
                row_current_pk = conn.execute(
                    "SELECT value FROM settings WHERE key='private_key_encrypted'"
                ).fetchone()
                if not row_current_pk:
                    raise KeyStoreError(
                        "rotate_rsa_key: current private key not found"
                    )

                # Calculate legacy key expiry (30 days from now)
                legacy_expiry = time.time() + (LEGACY_KEY_RETENTION_DAYS * 86400)

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
                new_priv = rsa.generate_private_key(65537, MIN_RSA_KEY_SIZE, default_backend())
                new_pub = new_priv.public_key()
                new_encrypted_priv = _privkey_to_encrypted_pem(new_priv, _to_bytes(password))

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
                    row_current_pk[0].encode(), _to_bytes(password)
                )
                self._needs_rotation = False

                logger.info(
                    "RSA key rotated to %d-bit. Legacy key retained for %d days.",
                    MIN_RSA_KEY_SIZE, LEGACY_KEY_RETENTION_DAYS
                )

            except KeyStoreError:
                conn.rollback()
                raise
            except (ValueError, TypeError, sqlite3.Error) as e:
                conn.rollback()
                logger.error("rotate_rsa_key failed (rolled back): %s", e)
                raise KeyStoreError(f"rotate_rsa_key failed: {e}") from e
            finally:
                conn.close()

    def get_decryption_snapshot(self):
        """Thread-safe snapshot for background decryption.

        Returns a tuple of (my_priv, friends_for_crypto, secrets_to_try, legacy_priv):
            - my_priv: Current RSA private key (or None)
            - friends_for_crypto: List of friend tuples (name, pub, secret) for
              signature verification and decryption. Includes the user's own
              public key (labeled "myself") so that self-signed RSA signatures
              can be verified.
            - secrets_to_try: List of shared secrets to try for decryption
            - legacy_priv: Legacy RSA private key for backward compatibility (or None)
        """
        with self._lock:
            my_priv = self.my_priv
            legacy_priv = self.legacy_priv
            # Return full (name, pub, secret) tuples for crypto module compatibility
            friends_for_crypto = list(self.friends)
            # Include own public key for self-signature verification
            if self.my_pub is not None:
                friends_for_crypto.append(("myself", self.my_pub, None))
            # Build secrets list: global_secret (bytes-like) and each friend secret (bytes-like)
            secrets_to_try = []
            if self.global_secret is not None:
                if isinstance(self.global_secret, GuardedBuffer):
                    secrets_to_try.append(self.global_secret.read())
                else:
                    secrets_to_try.append(bytes(self.global_secret))
            for _, _, sec in self.friends:
                if sec is not None:
                    if isinstance(sec, GuardedBuffer):
                        secrets_to_try.append(sec.read())
                    else:
                        secrets_to_try.append(bytes(sec))
            return my_priv, friends_for_crypto, secrets_to_try, legacy_priv

    def change_password(self, old_password: Union[str, bytes, SecureString], new_password: Union[str, bytes, SecureString]) -> bool:
        """Re-encrypt all stored secrets with a new master password.

        Steps:
          1. Verify old_password can decrypt global_secret.
          2. Decrypt every secret (global, friends, private key, TOTP).
          3. Re-encrypt each with new_password.
          4. Update in-memory state.

        Args:
            old_password: Current master password as str, bytes, or SecureString.
            new_password: New master password as str, bytes, or SecureString.

        Raises:
            KeyStoreError: If verification fails or re-encryption encounters an error.
                The database is left unchanged on failure (atomic via transaction).
        """
        with self._lock:
            conn = database.get_connection()
            gs_plain = None
            totp_plain = None
            friend_plain = None
            try:
                # --- 1. Verify old password ---
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='global_secret'"
                ).fetchone()
                if not row:
                    raise KeyStoreError("change_password: global_secret not found")
                enc_dict = json.loads(row[0])
                try:
                    database.decrypt_secret(enc_dict, old_password)
                except (ValueError, TypeError) as e:
                    raise KeyStoreError(
                        "change_password: old password verification failed"
                    ) from e

                # --- 2. Decrypt all secrets with old password ---
                # Global secret
                gs_plain = database.decrypt_secret(enc_dict, old_password)

                # Private key
                row_pk = conn.execute(
                    "SELECT value FROM settings WHERE key='private_key_encrypted'"
                ).fetchone()
                if not row_pk:
                    raise KeyStoreError(
                        "change_password: private_key_encrypted not found"
                    )
                try:
                    priv_key = _pem_to_privkey(row_pk[0].encode(), _to_bytes(old_password))
                except (ValueError, TypeError) as e:
                    raise KeyStoreError(
                        f"change_password: cannot decrypt private key: {e}"
                    ) from e

                # Friend shared secrets
                friend_rows = conn.execute(
                    "SELECT name, shared_secret_encrypted FROM friends "
                    "WHERE has_shared_secret=1 AND shared_secret_encrypted IS NOT NULL"
                ).fetchall()
                # Process each friend: decrypt, re-encrypt, and store in
                # GuardedBuffer without accumulating raw plaintext.
                friend_updates = {}
                friend_plain = None
                for fname, sec_json in friend_rows:
                    if not sec_json:
                        continue
                    try:
                        sec_dict = json.loads(sec_json)
                        friend_plain = database.decrypt_secret(sec_dict, old_password)
                        new_sec_enc = database.encrypt_secret(friend_plain, new_password)
                        conn.execute(
                            "UPDATE friends SET shared_secret_encrypted=? WHERE name=?",
                            (json.dumps(new_sec_enc), fname)
                        )
                        gb = GuardedBuffer(len(friend_plain))
                        gb.write(friend_plain)
                        friend_updates[fname] = gb
                    except (ValueError, TypeError, json.JSONDecodeError) as e:
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
                    except (ValueError, TypeError, json.JSONDecodeError) as e:
                        logger.warning("change_password: could not decrypt TOTP secret: %s", e)

                # --- 3. Re-encrypt everything with new password ---
                # Global secret
                new_gs_enc = database.encrypt_secret(gs_plain, new_password)
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='global_secret'",
                    (json.dumps(new_gs_enc),)
                )

                # Private key
                new_pk_pem = _privkey_to_encrypted_pem(priv_key, _to_bytes(new_password))
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='private_key_encrypted'",
                    (new_pk_pem,)
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
                # Wipe old global_secret if it's a GuardedBuffer
                if isinstance(self.global_secret, GuardedBuffer):
                    self.global_secret.wipe_and_free()
                gs_gb = GuardedBuffer(len(gs_plain))
                gs_gb.write(bytes(gs_plain) if isinstance(gs_plain, bytearray) else gs_plain)
                self.global_secret = gs_gb
                # Reload private key reference (already decrypted above)
                self.my_priv = priv_key
                # Update friend secrets in memory
                updated_friends = []
                for name, pub, sec in self.friends:
                    if name in friend_updates:
                        if isinstance(sec, GuardedBuffer):
                            sec.wipe_and_free()
                        updated_friends.append((name, pub, friend_updates[name]))
                    else:
                        updated_friends.append((name, pub, sec))
                self.friends = updated_friends

                logger.info("Master password changed successfully (%d friend secrets re-encrypted)",
                            len(friend_updates))

            except KeyStoreError:
                conn.rollback()
                raise
            except (ValueError, TypeError, sqlite3.Error) as e:
                conn.rollback()
                logger.error("change_password failed (rolled back): %s", e)
                raise KeyStoreError(f"change_password failed: {e}") from e
            finally:
                # Wipe plaintext secrets from memory
                if gs_plain is not None:
                    if isinstance(gs_plain, bytearray):
                        gs_plain[:] = b'\x00' * len(gs_plain)
                    del gs_plain
                if totp_plain is not None:
                    if isinstance(totp_plain, bytearray):
                        totp_plain[:] = b'\x00' * len(totp_plain)
                    del totp_plain
                if friend_plain is not None:
                    if isinstance(friend_plain, bytearray):
                        friend_plain[:] = b'\x00' * len(friend_plain)
                    del friend_plain
                conn.close()

        return True

    def reset_with_recovery_key(self, new_password: Union[str, bytes, SecureString]) -> bool:
        """Reset all crypto material using a new password (recovery flow.

        Generates fresh RSA, global secret, and hybrid signing keys encrypted
        with new_password. Clears friend shared secrets (cannot be decrypted
        without the old password). Preserves friend public keys, trust
        certificates, and held shares (stored as plaintext).

        Args:
            new_password: New master password as str, bytes, or SecureString.

        Raises:
            KeyStoreError: If key generation or DB update fails.
        """
        with self._lock:
            try:
                conn = database.get_connection()

                # --- 1. Generate new RSA key pair ---
                priv = rsa.generate_private_key(65537, 4096, default_backend())
                pub = priv.public_key()
                encrypted_priv = _privkey_to_encrypted_pem(priv, new_password)

                conn.execute(
                    "UPDATE settings SET value=? WHERE key='public_key'",
                    (pubkey_to_pem(pub),)
                )
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='private_key_encrypted'",
                    (encrypted_priv,)
                )

                # Remove any legacy key
                conn.execute("DELETE FROM settings WHERE key='legacy_private_key_encrypted'")
                conn.execute("DELETE FROM settings WHERE key='legacy_key_expiry'")

                # --- 2. Generate new global secret ---
                new_gs = secrets.token_bytes(32)
                enc_gs = database.encrypt_secret(new_gs, new_password)
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='global_secret'",
                    (json.dumps(enc_gs),)
                )

                # --- 3. Generate new hybrid signing keys if available ---
                if _HYBRID_SIG_AVAILABLE:
                    try:
                        hybrid_keys = HybridSigner.generate_keys()
                        ed_priv_bytes = hybrid_keys['ed_priv'].private_bytes_raw()
                        ed_priv_enc = database.encrypt_secret(ed_priv_bytes, new_password)
                        conn.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            ("ed25519_priv_encrypted", json.dumps(ed_priv_enc))
                        )
                        dil_priv_enc = database.encrypt_secret(hybrid_keys['dil_priv'], new_password)
                        conn.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            ("dilithium_priv_encrypted", json.dumps(dil_priv_enc))
                        )
                        combined_pub_b64 = base64.b64encode(hybrid_keys['combined_pub']).decode()
                        conn.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            ("hybrid_sig_combined_pub_b64", combined_pub_b64)
                        )
                        logger.info("New hybrid signing keys generated")
                    except Exception as e:
                        logger.warning("Failed to generate hybrid signing keys: %s", e)

                # --- 4. Clear friend shared secrets (can't decrypt without old password) ---
                conn.execute(
                    "UPDATE friends SET has_shared_secret=0, shared_secret_encrypted=NULL"
                )

                # --- 5. Clear TOTP (can't decrypt without old password) ---
                conn.execute("DELETE FROM settings WHERE key='totp_secret_encrypted'")
                conn.execute("DELETE FROM settings WHERE key='totp_setup_complete'")
                conn.execute("DELETE FROM settings WHERE key='totp_enabled'")

                # --- 6. Clear duress verifier ---
                conn.execute("DELETE FROM settings WHERE key='duress_verifier'")

                conn.commit()
                conn.close()

                # --- 7. Load new keys into memory ---
                self.wipe()
                self.my_pub = pub
                self.my_priv = priv
                self.legacy_priv = None
                gs_gb = GuardedBuffer(len(new_gs))
                gs_gb.write(new_gs)
                self.global_secret = gs_gb
                self._duress_mode = False
                self._needs_rotation = False

                # Reload hybrid signing keys into memory
                if _HYBRID_SIG_AVAILABLE:
                    try:
                        self.my_ed_priv = hybrid_keys['ed_priv']
                        self.my_dil_priv = GuardedBuffer(len(hybrid_keys['dil_priv']))
                        self.my_dil_priv.write(hybrid_keys['dil_priv'])
                        self.my_hybrid_sig_combined_pub = hybrid_keys['combined_pub']
                    except Exception:
                        pass

                # Clear friend secrets from memory
                self.friends = [(name, pub_key, None) for name, pub_key, _ in self.friends]

                # Set master password in database module
                database.set_master_password(new_password)

                logger.info("KeyStore reset with new password (recovery flow)")
                return True

            except (ValueError, TypeError) as e:
                logger.error("reset_with_recovery_key failed: %s", e)
                raise KeyStoreError(f"Recovery reset failed: {e}") from e
            except Exception as e:
                logger.error("reset_with_recovery_key failed: %s", e)
                raise KeyStoreError(f"Recovery reset failed: {e}") from e

    def wipe(self):
        """Securely erase all sensitive keys from memory."""
        with self._lock:
            if self.global_secret is not None:
                if isinstance(self.global_secret, GuardedBuffer):
                    self.global_secret.wipe_and_free()
                self.global_secret = None

            # Wipe ratchet storage key (derived from master password)
            if self._ratchet_storage_key is not None:
                ba = bytearray(self._ratchet_storage_key)
                for i in range(len(ba)):
                    ba[i] = 0
                self._ratchet_storage_key = None

            wiped_friends = []
            for name, pub, sec in self.friends:
                if isinstance(sec, GuardedBuffer):
                    sec.wipe_and_free()
                elif isinstance(sec, bytearray):
                    for i in range(len(sec)):
                        sec[i] = 0
                wiped_friends.append((name, pub, None))
            self.friends = wiped_friends

            self.friends_x25519.clear()
            self.friends_capabilities.clear()
            self.friends_pqc_combined_pub.clear()
            if self.my_kyber_priv is not None:
                if isinstance(self.my_kyber_priv, GuardedBuffer):
                    self.my_kyber_priv.wipe_and_free()
                self.my_kyber_priv = None
            self.my_pqc_combined_pub = None
            # Wipe hybrid signing private keys
            if self.my_dil_priv is not None:
                if isinstance(self.my_dil_priv, GuardedBuffer):
                    self.my_dil_priv.wipe_and_free()
                self.my_dil_priv = None
            if self.my_ed_priv is not None:
                if isinstance(self.my_ed_priv, GuardedBuffer):
                    self.my_ed_priv.wipe_and_free()
                self.my_ed_priv = None
            self.my_hybrid_sig_combined_pub = None
            self.friends_hybrid_sig_pubs.clear()
            if self.my_priv is not None:
                if isinstance(self.my_priv, GuardedBuffer):
                    self.my_priv.wipe_and_free()
                self.my_priv = None
            self.my_pub = None
            if self._cached_pqc_bundle is not None:
                if isinstance(self._cached_pqc_bundle, GuardedBuffer):
                    self._cached_pqc_bundle.wipe_and_free()
                self._cached_pqc_bundle = None
            gc.collect()

    def load_duress_decoy(self, password: Union[str, bytes, SecureString, None] = None) -> bool:
        """Load decoy/empty state for duress mode.

        Wipes all real keys and populates the store with empty/fake data
        so the application appears functional but contains no real information.

        If ``password`` (the duress password) is supplied, the pre-generated
        decoy RSA key stored at setup time is loaded so that entering duress
        mode is as fast as a real login (no telltale keygen latency).

        Returns True on success.
        """
        with self._lock:
            # Wipe all real secrets first
            self.wipe()

            decoy_priv = None
            if password is not None:
                try:
                    with closing(database.get_connection()) as conn:
                        row = conn.execute(
                            "SELECT value FROM settings WHERE key='duress_decoy_privkey'"
                        ).fetchone()
                    if row:
                        decoy_priv = _pem_to_privkey(row[0].encode(), _to_bytes(password))
                except Exception as e:
                    logger.debug("Could not load stored decoy key: %s", e)
                    decoy_priv = None

            if decoy_priv is None:
                # No stored decoy key (e.g. duress configured before this
                # feature existed). Generate one, and persist it under the
                # duress password if we have it so subsequent logins are fast.
                decoy_priv = rsa.generate_private_key(65537, MIN_RSA_KEY_SIZE, default_backend())
                if password is not None:
                    try:
                        decoy_pem = _privkey_to_encrypted_pem(decoy_priv, password)
                        with closing(database.get_connection()) as conn:
                            conn.execute(
                                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                                ("duress_decoy_privkey", decoy_pem)
                            )
                            conn.commit()
                    except Exception as e:
                        logger.debug("Could not persist decoy key: %s", e)

            self.my_priv = decoy_priv
            self.my_pub = decoy_priv.public_key()

            # Empty friends list (already cleared by wipe).
            # Empty global secret replaced with random bytes so length checks
            # pass. Stored as a GuardedBuffer to match the real path — an
            # unguarded bytearray here would itself be a duress tell.
            gb = GuardedBuffer(32)
            gb.write(secrets.token_bytes(32))
            self.global_secret = gb

            self._duress_mode = True
            return True

