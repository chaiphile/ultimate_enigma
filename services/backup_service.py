"""
Backup service – export and import database + keys.

Export format (JSON):
{
    "version": 1,
    "exported_at": <unix_timestamp>,
    "settings": { "public_key", "private_key_encrypted", "global_secret" },
    "friends": [ { "name", "public_key_pem", "has_shared_secret",
                   "shared_secret_encrypted", "x25519_public_key_b64" } ],
    "hmac": "<HMAC-SHA256 hex of canonical JSON payload>"
}

The HMAC key is derived from the master password via HKDF so that
tampering with the export file is detected on import.
"""

import json
import time
import hmac
import hashlib
import logging
from typing import Dict, Any, List
from contextlib import closing

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import database
from key_manager import KeyStore

logger = logging.getLogger(__name__)

BACKUP_VERSION = 1


class BackupServiceError(Exception):
    """Raised when a backup operation fails."""


class BackupService:
    """Export / import the entire Enigma identity and friend store."""

    def __init__(self, key_store: KeyStore):
        self._ks = key_store

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _derive_hmac_key(password: str) -> bytes:
        """Derive an HMAC key from the master password (key separation)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"enigma-backup-hmac-v1",
            backend=default_backend(),
        )
        return hkdf.derive(password.encode("utf-8"))

    @staticmethod
    def _canonical_json(obj: Any) -> bytes:
        """Deterministic JSON serialization for HMAC computation."""
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    def _compute_hmac(self, payload: dict, hmac_key: bytes) -> str:
        """HMAC-SHA256 over the canonical JSON of *payload*."""
        data = self._canonical_json(payload)
        return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()

    def _verify_hmac(self, payload: dict, expected_hmac: str, hmac_key: bytes) -> bool:
        computed = self._compute_hmac(payload, hmac_key)
        return hmac.compare_digest(computed, expected_hmac)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_backup(self, password: str) -> dict:
        """
        Read all encrypted blobs from the database and package them
        into an export dictionary.  The caller is responsible for writing
        this to disk as JSON.
        """
        try:
            conn = database.get_connection()
        except Exception as exc:
            raise BackupServiceError(f"Cannot open database: {exc}") from exc

        try:
            # --- settings ---
            settings: Dict[str, str] = {}
            for key in ("public_key", "private_key_encrypted", "global_secret"):
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (key,)
                ).fetchone()
                if row is None:
                    raise BackupServiceError(
                        f"Required setting '{key}' not found in database"
                    )
                settings[key] = row[0]

            # --- friends ---
            rows = conn.execute(
                "SELECT name, public_key_pem, has_shared_secret, "
                "shared_secret_encrypted, x25519_public_key_b64 "
                "FROM friends"
            ).fetchall()

            friends: List[Dict[str, Any]] = []
            for name, pem, has_sec, sec_enc, x_b64 in rows:
                friends.append({
                    "name": name,
                    "public_key_pem": pem,
                    "has_shared_secret": has_sec,
                    "shared_secret_encrypted": sec_enc,
                    "x25519_public_key_b64": x_b64,
                })
        finally:
            conn.close()

        payload = {
            "version": BACKUP_VERSION,
            "exported_at": int(time.time()),
            "settings": settings,
            "friends": friends,
        }

        hmac_key = self._derive_hmac_key(password)
        payload["hmac"] = self._compute_hmac(payload, hmac_key)

        logger.info(
            "Backup exported: %d friends, version %d", len(friends), BACKUP_VERSION
        )
        return payload

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------
    def import_backup(self, data: dict, password: str) -> None:
        """
        Validate and restore a backup.

        Steps:
        1. Verify version
        2. Verify HMAC (also validates password)
        3. Wipe current in-memory keys
        4. Replace database contents atomically
        5. Reload keys into KeyStore
        """
        # --- 1. Version check ---
        version = data.get("version")
        if version != BACKUP_VERSION:
            raise BackupServiceError(
                f"Unsupported backup version {version} (expected {BACKUP_VERSION})"
            )

        # --- 2. HMAC verification ---
        stored_hmac = data.get("hmac")
        if not stored_hmac or not isinstance(stored_hmac, str):
            raise BackupServiceError("Backup file missing HMAC")

        payload = {
            "version": data["version"],
            "exported_at": data["exported_at"],
            "settings": data["settings"],
            "friends": data["friends"],
        }

        hmac_key = self._derive_hmac_key(password)
        if not self._verify_hmac(payload, stored_hmac, hmac_key):
            raise BackupServiceError(
                "HMAC verification failed – wrong password or corrupted file"
            )

        settings = data["settings"]
        friends = data["friends"]

        # Basic structural validation
        for required in ("public_key", "private_key_encrypted", "global_secret"):
            if required not in settings:
                raise BackupServiceError(f"Missing setting '{required}' in backup")

        # --- 3. Wipe in-memory secrets ---
        self._ks.wipe()

        # --- 4. Atomic database replacement ---
        try:
            conn = database.get_connection()
        except Exception as exc:
            raise BackupServiceError(f"Cannot open database: {exc}") from exc

        try:
            # Ensure schema exists
            database.init_db()

            # Clear existing data
            conn.execute("DELETE FROM settings")
            conn.execute("DELETE FROM friends")

            # Restore settings
            for key, value in settings.items():
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)", (key, value)
                )

            # Restore friends
            for fr in friends:
                conn.execute(
                    "INSERT INTO friends "
                    "(name, public_key_pem, has_shared_secret, "
                    "shared_secret_encrypted, x25519_public_key_b64) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        fr["name"],
                        fr["public_key_pem"],
                        fr["has_shared_secret"],
                        fr.get("shared_secret_encrypted"),
                        fr.get("x25519_public_key_b64"),
                    ),
                )

            conn.commit()
            logger.info(
                "Backup imported: %d friends restored", len(friends)
            )
        except Exception as exc:
            conn.rollback()
            raise BackupServiceError(f"Database restore failed: {exc}") from exc
        finally:
            conn.close()

        # --- 5. Reload keys into memory ---
        if not self._ks.load(password):
            raise BackupServiceError(
                "Import succeeded but failed to reload keys – database may be corrupted"
            )
