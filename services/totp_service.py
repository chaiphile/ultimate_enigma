"""TOTP (Time-based One-Time Password) service – RFC 6238 compliant.

Uses HMAC-SHA1 with 30-second time steps and 6-digit codes.
The TOTP secret is derived from the global_secret stored in KeyStore.
"""

import hashlib
import hmac
import struct
import time
import base64
import secrets
import logging
from typing import Optional

from src.exceptions import TOTPValidationError
from security.guarded_buffer import GuardedBuffer

logger = logging.getLogger(__name__)

TOTP_DIGITS = 6
TOTP_INTERVAL = 30          # seconds per time step
TOTP_DRIFT = 1              # allow ±1 step tolerance


class TOTPService:
    """Generates and verifies TOTP codes based on a 20-byte secret."""

    def __init__(self):
        self._secret_buf: Optional[GuardedBuffer] = None
        # Highest time-step counter already accepted. Codes at this counter or
        # earlier are rejected to prevent replay of a captured code within its
        # validity window. Persisted via _persist_counter so replay protection
        # survives application restarts.
        self._last_counter: int = -1
        # Optional callback(counter:int) -> None used to persist _last_counter
        # to durable storage. Set via set_counter_persistence().
        self._persist_counter = None

    def set_counter_persistence(self, save_callback, initial_counter: int = -1) -> None:
        """Wire durable replay-counter storage.

        Args:
            save_callback: Callable invoked with the newest accepted counter
                whenever it advances, to persist it.
            initial_counter: The last accepted counter loaded from storage.
                The in-memory counter is raised to this value so previously
                consumed codes stay rejected across restarts.
        """
        self._persist_counter = save_callback
        if initial_counter > self._last_counter:
            self._last_counter = initial_counter

    # ------------------------------------------------------------------
    # Secret management
    # ------------------------------------------------------------------
    def _secret_bytes(self) -> Optional[bytes]:
        """Return a transient bytes copy of the secret, or None if not set."""
        if self._secret_buf is None:
            return None
        return bytes(self._secret_buf.read())

    def set_secret(self, secret: bytes) -> None:
        """Set the TOTP secret (must be at least 20 bytes).

        Uses the first 20 bytes directly as the TOTP key.
        The secret should be cryptographically random (from secrets.token_bytes).

        Raises:
            TOTPValidationError: If the secret is shorter than 20 bytes.
        """
        if len(secret) < 20:
            raise TOTPValidationError("TOTP secret must be at least 20 bytes")
        # Clear any existing buffer first
        if self._secret_buf is not None:
            self._secret_buf.wipe_and_free()
        # Use first 20 bytes directly – secret is already cryptographically random
        self._secret_buf = GuardedBuffer(20)
        self._secret_buf.write(bytes(secret[:20]))
        self._last_counter = -1

    def set_raw_secret(self, secret: bytes) -> None:
        """Set an exact 20-byte TOTP secret without any transformation.

        Used when loading a previously-stored derived secret from the database.

        Raises:
            TOTPValidationError: If the secret is not exactly 20 bytes.
        """
        if len(secret) != 20:
            raise TOTPValidationError(
                f"Raw TOTP secret must be exactly 20 bytes, got {len(secret)}"
            )
        # Clear any existing buffer first
        if self._secret_buf is not None:
            self._secret_buf.wipe_and_free()
        self._secret_buf = GuardedBuffer(20)
        self._secret_buf.write(bytes(secret))
        self._last_counter = -1

    def clear_secret(self) -> None:
        """Wipe the secret from memory."""
        if self._secret_buf is not None:
            self._secret_buf.wipe_and_free()
            self._secret_buf = None

    def has_secret(self) -> bool:
        return self._secret_buf is not None

    def get_b32_secret(self) -> str:
        """Return the Base32-encoded secret (for display in setup dialogs)."""
        secret_bytes = self._secret_bytes()
        if secret_bytes is None:
            return "N/A"
        return base64.b32encode(secret_bytes).decode().rstrip("=")

    def get_raw_secret(self) -> Optional[bytes]:
        """Return the raw 20-byte secret (for persistence to database)."""
        return self._secret_bytes()

    # ------------------------------------------------------------------
    # TOTP generation / verification
    # ------------------------------------------------------------------
    @staticmethod
    def _hotp(secret: bytes, counter: int) -> int:
        """HOTP algorithm (RFC 4226)."""
        msg = struct.pack(">Q", counter)
        h = hmac.new(secret, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        return code % (10 ** TOTP_DIGITS)

    def generate(self, timestamp: Optional[float] = None) -> str:
        """Generate the current 6-digit TOTP code.

        Raises:
            TOTPValidationError: If no secret has been configured.
        """
        secret_bytes = self._secret_bytes()
        if secret_bytes is None:
            raise TOTPValidationError("TOTP secret not set")
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp) // TOTP_INTERVAL
        return f"{self._hotp(secret_bytes, counter):0{TOTP_DIGITS}d}"

    def verify(self, code: str, timestamp: Optional[float] = None,
               track_replay: bool = True) -> bool:
        """Verify a TOTP code with ±1 step drift tolerance.

        Args:
            code: The 6-digit code to check.
            timestamp: Optional override for the current time (testing).
            track_replay: When True (default), enforce and advance the
                single-use replay counter and persist it. Set False for
                non-authenticating self-tests that must not consume a code.

        Raises:
            TOTPValidationError: If no secret has been configured.
        """
        secret_bytes = self._secret_bytes()
        if secret_bytes is None:
            raise TOTPValidationError("TOTP secret not set")
        code = code.strip()
        if len(code) != TOTP_DIGITS or not code.isdigit():
            return False
        if timestamp is None:
            timestamp = time.time()
        base_counter = int(timestamp) // TOTP_INTERVAL
        for offset in range(-TOTP_DRIFT, TOTP_DRIFT + 1):
            candidate_counter = base_counter + offset
            expected = f"{self._hotp(secret_bytes, candidate_counter):0{TOTP_DIGITS}d}"
            if hmac.compare_digest(code, expected):
                if not track_replay:
                    return True
                # Replay protection: never accept a counter at or below one we
                # have already accepted, even though the code is still inside
                # its drift window. The counter is persisted so a code consumed
                # in a previous session cannot be replayed after a restart.
                if candidate_counter <= self._last_counter:
                    logger.warning(
                        "TOTP code rejected: replay of counter %d", candidate_counter
                    )
                    return False
                self._last_counter = candidate_counter
                if self._persist_counter is not None:
                    try:
                        self._persist_counter(candidate_counter)
                    except Exception as e:
                        logger.error("Failed to persist TOTP counter: %s", e)
                return True
        return False

    def time_remaining(self) -> int:
        """Seconds remaining until the current code expires."""
        return TOTP_INTERVAL - (int(time.time()) % TOTP_INTERVAL)

    # ------------------------------------------------------------------
    # Provisioning URI (for QR code / authenticator app import)
    # ------------------------------------------------------------------
    def provisioning_uri(self, account: str = "UltimateEnigma",
                         issuer: str = "UltimateEnigma") -> str:
        """Return an otpauth:// URI compatible with Google Authenticator, etc.

        Raises:
            TOTPValidationError: If no secret has been configured.
        """
        secret_bytes = self._secret_bytes()
        if secret_bytes is None:
            raise TOTPValidationError("TOTP secret not set")
        b32_secret = base64.b32encode(secret_bytes).decode().rstrip("=")
        return (
            f"otpauth://totp/{issuer}:{account}"
            f"?secret={b32_secret}&issuer={issuer}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}"
        )

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------
    @staticmethod
    def generate_random_secret(length: int = 32) -> bytes:
        """Generate a cryptographically secure random secret."""
        return secrets.token_bytes(length)
