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

import hmac
import json
import os
import stat
import time
import hashlib
import logging
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from contextlib import closing

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import database
from key_manager import KeyStore

logger = logging.getLogger(__name__)

BACKUP_VERSION = 1


def _validate_backup_schema(data: dict) -> None:
    """Validate backup JSON structure before processing."""
    required_keys = {"version", "exported_at", "settings", "friends", "hmac"}
    if not isinstance(data, dict):
        raise ValueError("Invalid backup format: expected JSON object")
    if not required_keys.issubset(data.keys()):
        missing = required_keys - data.keys()
        raise ValueError(f"Invalid backup format: missing keys {missing}")
    if not isinstance(data.get("settings"), dict):
        raise ValueError("Invalid backup format: settings must be a dict")
    if not isinstance(data.get("friends", []), list):
        raise ValueError("Invalid backup format: friends must be a list")
DEFAULT_BACKUP_DIR = Path.home() / ".ultimate_enigma" / "backups"
DEFAULT_MAX_BACKUPS = 10
DEFAULT_REMINDER_DAYS = 7


class BackupServiceError(Exception):
    """Raised when a backup operation fails."""


class BackupService:
    """Export / import the entire Enigma identity and friend store."""

    def __init__(
        self,
        key_store: KeyStore,
        backup_dir: Optional[Path] = None,
        max_backups: int = DEFAULT_MAX_BACKUPS,
        reminder_days: int = DEFAULT_REMINDER_DAYS,
    ):
        self._ks = key_store
        self._backup_dir = backup_dir or DEFAULT_BACKUP_DIR
        self._max_backups = max_backups
        self._reminder_days = reminder_days

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
        if not self._ks.verify_password(password):
            raise BackupServiceError("Invalid master password — cannot export backup")
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
        # --- 0. Schema validation ---
        _validate_backup_schema(data)

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
            try:
                conn.rollback()
            except Exception as rb_exc:
                logger.warning("Database rollback failed during import error handling: %s", rb_exc)
            raise BackupServiceError(f"Database restore failed: {exc}") from exc
        finally:
            conn.close()

        # --- 5. Reload keys into memory ---
        if not self._ks.load(password):
            raise BackupServiceError(
                "Import succeeded but failed to reload keys – database may be corrupted"
            )

    # ------------------------------------------------------------------
    # Versioned File Backups
    # ------------------------------------------------------------------
    def export_backup_to_file(
        self, password: str, backup_dir: Optional[Path] = None
    ) -> Path:
        """
        Export a timestamped backup file and prune old versions.

        Returns the path to the newly created backup file.
        """
        target_dir = backup_dir or self._backup_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        data = self.export_backup(password)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"enigma_backup_{timestamp}.json"
        filepath = target_dir / filename

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=True)
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise BackupServiceError(f"Failed to write backup file: {exc}") from exc

        # Record last backup timestamp in settings
        self._record_backup_timestamp(int(time.time()))

        # Prune old backups
        self._prune_old_backups(target_dir)

        logger.info("Versioned backup saved to %s", filepath)
        return filepath

    def import_backup_from_file(
        self, filepath: Path, password: str
    ) -> None:
        """Load a backup JSON file and restore it."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise BackupServiceError(f"Cannot read backup file: {exc}") from exc
        self.import_backup(data, password)

    def list_backups(self, backup_dir: Optional[Path] = None) -> List[Path]:
        """Return sorted list of existing backup files (newest first)."""
        target_dir = backup_dir or self._backup_dir
        if not target_dir.exists():
            return []
        files = sorted(
            target_dir.glob("enigma_backup_*.json"),
            reverse=True,
        )
        return files

    def _prune_old_backups(self, backup_dir: Path) -> None:
        """Keep only the N most recent backup files."""
        files = self.list_backups(backup_dir)
        for old_file in files[self._max_backups:]:
            try:
                old_file.unlink()
                logger.info("Pruned old backup: %s", old_file.name)
            except OSError as exc:
                logger.warning("Could not prune %s: %s", old_file, exc)

    # ------------------------------------------------------------------
    # Backup Reminder
    # ------------------------------------------------------------------
    def get_last_backup_timestamp(self) -> Optional[int]:
        """Return the Unix timestamp of the last recorded backup, or None."""
        try:
            conn = database.get_connection()
        except Exception:
            return None
        try:
            row = conn.execute(
                "SELECT value FROM settings WHERE key='last_backup_ts'"
            ).fetchone()
            if row:
                return int(row[0])
            return None
        except Exception:
            return None
        finally:
            conn.close()

    def _record_backup_timestamp(self, ts: int) -> None:
        """Persist the last backup timestamp into the settings table."""
        try:
            conn = database.get_connection()
        except Exception as exc:
            logger.warning("Could not record backup timestamp: %s", exc)
            return
        try:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_backup_ts', ?)",
                (str(ts),),
            )
            conn.commit()
        except Exception as exc:
            logger.warning("Could not save backup timestamp: %s", exc)
        finally:
            conn.close()

    def should_remind_backup(self) -> Tuple[bool, Optional[int]]:
        """
        Check whether the user should be reminded to create a backup.

        Returns:
            (True, days_since) if a reminder is warranted.
            (False, None) if no reminder needed or no previous backup exists.
        """
        last_ts = self.get_last_backup_timestamp()
        if last_ts is None:
            # Never backed up – always remind
            return True, None
        elapsed_seconds = time.time() - last_ts
        elapsed_days = int(elapsed_seconds // 86400)
        if elapsed_days >= self._reminder_days:
            return True, elapsed_days
        return False, None
