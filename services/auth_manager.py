"""Authentication manager service.

Handles password verification, password changes, duress password management,
and lockout logic. Decoupled from KeyStore to enforce MVC separation:
KeyStore is a pure data/persistence model, while AuthManager owns the
authentication business logic.
"""

import json
import time
import secrets
import logging
from typing import Tuple, Optional, Union
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import database
from src.constants import SECURITY
from src.exceptions import KeyStoreError
from src.secure_string import SecureString

logger = logging.getLogger(__name__)


def _pem_to_privkey(pem: bytes, password: Union[str, bytes, SecureString]):
    """Load a PEM private key, decrypting with the given password.
    
    Args:
        pem: PEM-encoded private key bytes.
        password: Password as str, bytes, or SecureString.
    """
    # Convert password to bytes
    if hasattr(password, 'to_bytes'):
        pw_bytes = password.to_bytes()
    elif isinstance(password, str):
        pw_bytes = password.encode('utf-8')
    elif isinstance(password, bytes):
        pw_bytes = password
    else:
        pw_bytes = str(password).encode('utf-8')
    return serialization.load_pem_private_key(pem, password=pw_bytes, backend=default_backend())


def _privkey_to_encrypted_pem(priv, password: Union[str, bytes, SecureString]) -> str:
    """Encrypt a private key to PEM format.
    
    Args:
        priv: Private key object.
        password: Password as str, bytes, or SecureString.
    """
    # Convert password to bytes
    if hasattr(password, 'to_bytes'):
        pw_bytes = password.to_bytes()
    elif isinstance(password, str):
        pw_bytes = password.encode('utf-8')
    elif isinstance(password, bytes):
        pw_bytes = password
    else:
        pw_bytes = str(password).encode('utf-8')
    
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pw_bytes)
    ).decode('ascii')


class AuthManager:
    """Manages authentication workflows including password verification,
    password changes, duress passwords, and account lockout.

    This class operates on a KeyStore instance for key persistence but
    owns all authentication-related business logic.
    """

    # Exponential backoff table (seconds) indexed by consecutive failure count.
    _BACKOFF_TABLE = list(SECURITY.backoff_table)
    _HARD_LOCKOUT_THRESHOLD = SECURITY.hard_lockout_threshold
    _HARD_LOCKOUT_DURATION = SECURITY.hard_lockout_duration

    def __init__(self, key_store):
        """
        Args:
            key_store: A KeyStore instance that exposes load(), wipe(),
                       and key attributes (my_priv, my_pub, global_secret, friends).
        """
        self._ks = key_store

    # ------------------------------------------------------------------
    # Lockout helpers
    # ------------------------------------------------------------------

    def load_lockout_state(self) -> None:
        """Load persistent lockout state from the database into the KeyStore."""
        try:
            conn = database.get_connection()
            row = conn.execute(
                "SELECT value FROM settings WHERE key='lockout_data'"
            ).fetchone()
            conn.close()
            if row:
                data = json.loads(row[0])
                self._ks.failed_attempts = int(data.get("failures", 0))
                self._ks.locked_until = float(data.get("locked_until", 0))
            else:
                self._ks.failed_attempts = 0
                self._ks.locked_until = 0.0
        except Exception:
            self._ks.failed_attempts = 0
            self._ks.locked_until = 0.0

    def save_lockout_state(self) -> None:
        """Persist current lockout state to the database."""
        try:
            data = json.dumps({
                "failures": self._ks.failed_attempts,
                "locked_until": self._ks.locked_until
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

    def get_lockout_delay(self) -> float:
        """Return seconds the caller must wait before the next attempt."""
        now = time.time()
        if self._ks.locked_until > now:
            return self._ks.locked_until - now
        idx = min(self._ks.failed_attempts, len(self._BACKOFF_TABLE) - 1)
        return float(self._BACKOFF_TABLE[idx])

    # ------------------------------------------------------------------
    # Password verification
    # ------------------------------------------------------------------

    def verify_password(self, password: Union[str, bytes, SecureString]) -> Tuple[bool, bool]:
        """Check if password matches master or duress password.

        Implements persistent exponential backoff and hard account lockout.

        Args:
            password: Password as str, bytes, or SecureString.

        Returns:
            (is_valid, is_duress)
        """
        # Enforce any active lockout / backoff delay
        delay = self.get_lockout_delay()
        if delay > 0:
            logger.warning(
                "Account lockout active. %d consecutive failure(s). "
                "Waiting %.1f seconds before next attempt.",
                self._ks.failed_attempts, delay
            )
            time.sleep(delay)

        # Check master password
        try:
            conn = database.get_connection()
            row = conn.execute(
                "SELECT value FROM settings WHERE key='global_secret'"
            ).fetchone()
            conn.close()
            if row:
                enc_dict = json.loads(row[0])
                database.decrypt_secret(enc_dict, password)
                self._ks.failed_attempts = 0
                self._ks.locked_until = 0.0
                self._ks._duress_mode = False
                self.save_lockout_state()
                return True, False
        except Exception as e:
            logger.debug("Password verification exception: %s", e)

        # Check duress password
        try:
            conn = database.get_connection()
            row = conn.execute(
                "SELECT value FROM settings WHERE key='duress_verifier'"
            ).fetchone()
            conn.close()
            if row:
                duress_data = json.loads(row[0])
                database.decrypt_secret(duress_data, password)
                self._ks.failed_attempts = 0
                self._ks.locked_until = 0.0
                self._ks._duress_mode = True
                self.save_lockout_state()
                return True, True
        except Exception as e:
            logger.debug("Duress verification exception: %s", e)

        # Failed attempt: escalate lockout
        self._ks.failed_attempts += 1

        if self._ks.failed_attempts >= self._HARD_LOCKOUT_THRESHOLD:
            self._ks.locked_until = time.time() + self._HARD_LOCKOUT_DURATION
            logger.critical(
                "HARD LOCKOUT: %d consecutive failures. Account locked for %d seconds.",
                self._ks.failed_attempts, self._HARD_LOCKOUT_DURATION
            )
        else:
            backoff = self.get_lockout_delay()
            if backoff > 0:
                logger.warning(
                    "Failed password attempt #%d. Next attempt delayed by %.0f seconds.",
                    self._ks.failed_attempts, backoff
                )

        self.save_lockout_state()
        return False, False

    # ------------------------------------------------------------------
    # Password change
    # ------------------------------------------------------------------

    def change_password(self, old_password: Union[str, bytes, SecureString], new_password: Union[str, bytes, SecureString]) -> None:
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
        """
        conn = database.get_connection()
        try:
            # 1. Verify old password
            row = conn.execute(
                "SELECT value FROM settings WHERE key='global_secret'"
            ).fetchone()
            if not row:
                raise KeyStoreError("change_password: global_secret not found")
            enc_dict = json.loads(row[0])
            try:
                database.decrypt_secret(enc_dict, old_password)
            except Exception as e:
                raise KeyStoreError(
                    "change_password: old password verification failed"
                ) from e

            # 2. Decrypt all secrets with old password
            gs_plain = database.decrypt_secret(enc_dict, old_password)

            row_pk = conn.execute(
                "SELECT value FROM settings WHERE key='private_key_encrypted'"
            ).fetchone()
            if not row_pk:
                raise KeyStoreError("change_password: private_key_encrypted not found")
            try:
                priv_key = _pem_to_privkey(row_pk[0].encode(), old_password.encode())
            except Exception as e:
                raise KeyStoreError(
                    f"change_password: cannot decrypt private key: {e}"
                ) from e

            friend_rows = conn.execute(
                "SELECT name, shared_secret_encrypted FROM friends "
                "WHERE has_shared_secret=1 AND shared_secret_encrypted IS NOT NULL"
            ).fetchall()
            friend_secrets = {}
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

            # 3. Re-encrypt everything with new password
            new_gs_enc = database.encrypt_secret(gs_plain, new_password)
            conn.execute(
                "UPDATE settings SET value=? WHERE key='global_secret'",
                (json.dumps(new_gs_enc),)
            )

            new_pk_pem = _privkey_to_encrypted_pem(priv_key, new_password.encode())
            conn.execute(
                "UPDATE settings SET value=? WHERE key='private_key_encrypted'",
                (new_pk_pem,)
            )

            for fname, sec_plain in friend_secrets.items():
                new_sec_enc = database.encrypt_secret(sec_plain, new_password)
                conn.execute(
                    "UPDATE friends SET shared_secret_encrypted=? WHERE name=?",
                    (json.dumps(new_sec_enc), fname)
                )

            if totp_plain is not None:
                new_totp_enc = database.encrypt_secret(totp_plain, new_password)
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='totp_secret_encrypted'",
                    (json.dumps(new_totp_enc),)
                )

            conn.commit()

            # 4. Update in-memory state
            self._ks.global_secret = bytearray(gs_plain)
            self._ks.my_priv = priv_key
            updated_friends = []
            for name, pub, sec in self._ks.friends:
                if name in friend_secrets:
                    updated_friends.append((name, pub, bytearray(friend_secrets[name])))
                else:
                    updated_friends.append((name, pub, sec))
            self._ks.friends = updated_friends

            logger.info(
                "Master password changed successfully (%d friend secrets re-encrypted)",
                len(friend_secrets)
            )

        except KeyStoreError:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            logger.error("change_password failed (rolled back): %s", e)
            raise KeyStoreError(f"change_password failed: {e}") from e
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Duress password
    # ------------------------------------------------------------------

    def set_duress_password(self, duress_password: Union[str, bytes, SecureString]) -> None:
        """Set up a duress password that triggers decoy mode.
        
        Args:
            duress_password: Duress password as str, bytes, or SecureString.
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

    def load_duress_decoy(self) -> bool:
        """Load decoy/empty state for duress mode.

        Wipes all real keys and populates the store with empty/fake data.
        Returns True on success.
        """
        self._ks.wipe()

        decoy_priv = rsa.generate_private_key(65537, 2048, default_backend())
        self._ks.my_priv = decoy_priv
        self._ks.my_pub = decoy_priv.public_key()
        self._ks.global_secret = bytearray(secrets.token_bytes(32))
        self._ks._duress_mode = True

        logger.warning("Duress decoy state loaded - no real data accessible")
        return True
