"""
Global Secret management service – pure logic, no UI dependencies.
Handles global shared secret operations for the SecretTab.
"""

import base64
from typing import Optional, Tuple

from crypto import sha256_fingerprint


class GlobalSecretServiceError(Exception):
    """Raised when a global secret operation fails."""


class GlobalSecretService:
    """High-level API for managing the global shared secret."""

    def __init__(self, key_store):
        self._ks = key_store

    def get_fingerprint(self) -> Optional[str]:
        """Return the fingerprint of the current global secret, or None if not set."""
        if not self._ks.global_secret:
            return None
        return sha256_fingerprint(self._ks.global_secret)

    def has_secret(self) -> bool:
        """Check if a global secret is currently loaded."""
        return self._ks.global_secret is not None

    def export_secret_b64(self) -> str:
        """Return the global secret as Base64 string. Raises error if not set."""
        if not self._ks.global_secret:
            raise GlobalSecretServiceError("No global secret available")
        return base64.b64encode(self._ks.global_secret).decode('ascii')

    def validate_secret_b64(self, b64_str: str) -> bytes:
        """
        Validate and decode a Base64 secret string.
        Returns raw bytes if valid (32 bytes).
        Raises ValueError on invalid input.
        """
        try:
            raw = base64.b64decode(b64_str)
            if len(raw) != 32:
                raise ValueError("Key must be exactly 32 bytes")
            return raw
        except Exception as e:
            raise ValueError(f"Invalid secret format: {e}")

    def update_secret(self, new_secret: bytes, master_password: str) -> str:
        """
        Update the global secret.
        Returns the fingerprint of the new secret.
        Raises GlobalSecretServiceError on failure.
        """
        if not master_password:
            raise GlobalSecretServiceError("Master password required")
        if not self.verify_password(master_password):
            raise GlobalSecretServiceError("Incorrect master password")
        if len(new_secret) != 32:
            raise GlobalSecretServiceError("Secret must be 32 bytes")

        try:
            self._ks.update_global_secret(new_secret, master_password)
            return sha256_fingerprint(new_secret)
        except Exception as e:
            raise GlobalSecretServiceError(f"Failed to update secret: {e}")

    def verify_password(self, password: str) -> bool:
        """Verify the master password against the keystore."""
        return self._ks.verify_password(password)
