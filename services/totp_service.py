"""TOTP (Time-based One-Time Password) service – RFC 6238 compliant.

Uses HMAC-SHA1 with 30-second time steps and 6-digit codes.
The TOTP secret is derived from the global_secret stored in KeyStore.
"""

import hmac
import hashlib
import struct
import time
import base64
import secrets
import logging
from typing import Optional

logger = logging.getLogger(__name__)

TOTP_DIGITS = 6
TOTP_INTERVAL = 30          # seconds per time step
TOTP_DRIFT = 1              # allow ±1 step tolerance


class TOTPService:
    """Generates and verifies TOTP codes based on a 20-byte secret."""

    def __init__(self):
        self._secret: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Secret management
    # ------------------------------------------------------------------
    def set_secret(self, secret: bytes) -> None:
        """Set the TOTP secret (should be at least 20 bytes)."""
        if len(secret) < 20:
            raise ValueError("TOTP secret must be at least 20 bytes")
        # Derive a dedicated TOTP key from the first 20 bytes via HMAC
        self._secret = hmac.new(
            b"enigma-totp-v1", secret[:32], hashlib.sha256
        ).digest()[:20]

    def clear_secret(self) -> None:
        """Wipe the secret from memory."""
        if self._secret is not None:
            self._secret = b"\x00" * len(self._secret)
            self._secret = None

    def has_secret(self) -> bool:
        return self._secret is not None

    def get_b32_secret(self) -> str:
        """Return the Base32-encoded secret (for display in setup dialogs)."""
        if self._secret is None:
            return "N/A"
        return base64.b32encode(self._secret).decode().rstrip("=")

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
        """Generate the current 6-digit TOTP code."""
        if self._secret is None:
            raise RuntimeError("TOTP secret not set")
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp) // TOTP_INTERVAL
        return f"{self._hotp(self._secret, counter):0{TOTP_DIGITS}d}"

    def verify(self, code: str, timestamp: Optional[float] = None) -> bool:
        """Verify a TOTP code with ±1 step drift tolerance."""
        if self._secret is None:
            raise RuntimeError("TOTP secret not set")
        code = code.strip()
        if len(code) != TOTP_DIGITS or not code.isdigit():
            return False
        if timestamp is None:
            timestamp = time.time()
        base_counter = int(timestamp) // TOTP_INTERVAL
        for offset in range(-TOTP_DRIFT, TOTP_DRIFT + 1):
            expected = f"{self._hotp(self._secret, base_counter + offset):0{TOTP_DIGITS}d}"
            if hmac.compare_digest(code, expected):
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
        """Return an otpauth:// URI compatible with Google Authenticator, etc."""
        if self._secret is None:
            raise RuntimeError("TOTP secret not set")
        b32_secret = base64.b32encode(self._secret).decode().rstrip("=")
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
