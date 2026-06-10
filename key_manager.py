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

logger = logging.getLogger(__name__)

FILE_MAGIC = b'ENIGMA\x01'   # 7‑byte magic for shared‑secret encrypted files

def _pem_to_pubkey(pem: str):
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())

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
    with closing(database.get_connection()) as conn:
        cur = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'")
        if cur.fetchone() is None:
            priv = rsa.generate_private_key(65537, 3072, default_backend())
            pub = priv.public_key()
            encrypted_priv = _privkey_to_encrypted_pem(priv, password.encode())
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("public_key", pubkey_to_pem(pub)))
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("private_key_encrypted", encrypted_priv))
            global_secret = secrets.token_bytes(32)
            enc = database.encrypt_secret(global_secret, password)
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("global_secret", json.dumps(enc)))
            conn.commit()
            return True
    return False

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
        self._load_lockout_state()
        self.my_pub = None
        self.my_priv = None
        self.global_secret: Optional[bytearray] = None   # changed to bytearray for secure wiping
        self.friends: List[Tuple[str, object, Optional[bytearray]]] = []   # (name, pub, shared_secret or None)
        self.friends_x25519: Dict[str, str] = {}   # name -> Base64 of raw X25519 public key

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
        # Ensure x25519 column exists (migration)
        try:
            conn = database.get_connection()
            try:
                conn.execute("ALTER TABLE friends ADD COLUMN x25519_public_key_b64 TEXT")
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

            row = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'").fetchone()
            if not row: return False
            self.my_priv = _pem_to_privkey(row[0].encode(), password.encode())

            row = conn.execute("SELECT value FROM settings WHERE key='global_secret'").fetchone()
            if row:
                enc_dict = json.loads(row[0])
                # Store as bytearray for zeroing capability
                self.global_secret = bytearray(database.decrypt_secret(enc_dict, password))
            else:
                self.global_secret = None

            rows = conn.execute(
                "SELECT name, public_key_pem, has_shared_secret, shared_secret_encrypted, x25519_public_key_b64 "
                "FROM friends"
            ).fetchall()
            self.friends.clear()
            self.friends_x25519.clear()
            for name, pem, has_sec, sec_json, x_b64 in rows:
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
                    password: str = "", x25519_pub_b64: Optional[str] = None) -> None:
        """Save a friend; if shared_secret is provided, password must be the master password (non-empty).
        x25519_pub_b64 is the Base64 of the raw 32-byte X25519 public key."""
        if shared_secret:
            if not password:
                raise ValueError("Master password required to encrypt friend shared secret")
            enc = database.encrypt_secret(shared_secret, password)
            has_sec = 1
            sec_enc_json = json.dumps(enc)
        else:
            has_sec = 0
            sec_enc_json = None

        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO friends "
                "(name, public_key_pem, has_shared_secret, shared_secret_encrypted, x25519_public_key_b64) "
                "VALUES (?,?,?,?,?)",
                (name, pem, has_sec, sec_enc_json, x25519_pub_b64)
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

    def remove_friend(self, name: str) -> None:
        with closing(database.get_connection()) as conn:
            conn.execute("DELETE FROM friends WHERE name=?", (name,))
            conn.commit()
        self.friends = [(n, p, s) for (n, p, s) in self.friends if n != name]
        self.friends_x25519.pop(name, None)

    def get_friend_secret(self, name: str) -> Optional[bytes]:
        for n, _, s in self.friends:
            if n == name:
                # Return as bytes for compatibility (immutable)
                return bytes(s) if s is not None else None
        return None

    def get_decryption_snapshot(self):
        """Thread-safe snapshot for background decryption."""
        with self._lock:
            my_priv = self.my_priv
            friends_for_sig = [(name, pub) for name, pub, _ in self.friends]
            # Build secrets list: global_secret (bytes-like) and each friend secret (bytes-like)
            secrets = []
            if self.global_secret is not None:
                secrets.append(self.global_secret)   # bytearray is bytes-like
            for _, _, sec in self.friends:
                if sec is not None:
                    secrets.append(sec)
            return my_priv, friends_for_sig, secrets

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