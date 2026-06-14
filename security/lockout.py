"""Exponential backoff lockout state machine for authentication attempts.

Provides persistent lockout state that survives application restarts via the database.
"""

import json
import time
import logging
from typing import Union

try:
    from sqlcipher3 import dbapi2 as sqlite3
except ImportError:
    import sqlite3

import database
from src.secure_string import SecureString

logger = logging.getLogger(__name__)

# Exponential backoff table (seconds) indexed by consecutive failure count.
# Indices 0-4: no delay; 5+: escalating delays up to 30 minutes.
from src.constants import SECURITY

BACKOFF_TABLE = list(SECURITY.backoff_table)
HARD_LOCKOUT_THRESHOLD = SECURITY.hard_lockout_threshold
HARD_LOCKOUT_DURATION = SECURITY.hard_lockout_duration


class LockoutManager:
    """Manages authentication attempt lockout with exponential backoff.

    Lockout state is persisted to the database so it survives restarts.
    """

    def __init__(self):
        self.failed_attempts = 0
        self.locked_until = 0.0
        self._load_state()

    def _load_state(self) -> None:
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
        except (sqlite3.Error, json.JSONDecodeError, ValueError):
            self.failed_attempts = 0
            self.locked_until = 0.0

    def save_state(self) -> None:
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
        except (sqlite3.Error, TypeError) as e:
            logger.warning("Failed to persist lockout state: %s", e)

    def get_delay(self) -> float:
        """Return the number of seconds the caller must wait before the next attempt.

        If a hard-lockout timer is active its remaining time takes precedence.
        Otherwise the exponential backoff table is consulted.
        """
        now = time.time()
        if self.locked_until > now:
            return self.locked_until - now

        idx = min(self.failed_attempts, len(BACKOFF_TABLE) - 1)
        return float(BACKOFF_TABLE[idx])

    def record_failure(self) -> None:
        """Record a failed attempt and escalate lockout if threshold reached."""
        self.failed_attempts += 1
        if self.failed_attempts >= HARD_LOCKOUT_THRESHOLD:
            self.locked_until = time.time() + HARD_LOCKOUT_DURATION
            logger.critical(
                "HARD LOCKOUT: %d consecutive failures. "
                "Account locked for %d seconds.",
                self.failed_attempts, HARD_LOCKOUT_DURATION
            )
        self.save_state()

    def reset(self) -> None:
        """Reset lockout state after successful authentication."""
        self.failed_attempts = 0
        self.locked_until = 0.0
        self.save_state()
