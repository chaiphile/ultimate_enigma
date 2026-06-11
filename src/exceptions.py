"""Centralized exception hierarchy for Ultimate Enigma.

All custom exceptions inherit from EnigmaError to allow callers to catch
the base class when broad error handling is appropriate, or catch specific
subclasses for granular control.
"""


class EnigmaError(Exception):
    """Base exception for all Ultimate Enigma errors."""


# ---------------------------------------------------------------------------
# Key Store / Authentication
# ---------------------------------------------------------------------------

class KeyStoreError(EnigmaError):
    """Raised when key loading, saving, or password operations fail."""


# ---------------------------------------------------------------------------
# Encryption / Decryption
# ---------------------------------------------------------------------------

class EncryptionError(EnigmaError):
    """Raised when encryption cannot proceed."""


class DecryptionError(EnigmaError):
    """Raised when decryption fails."""


# ---------------------------------------------------------------------------
# Double Ratchet
# ---------------------------------------------------------------------------

class RatchetStateError(EnigmaError):
    """Base exception for Double Ratchet state errors."""


class RatchetNotFoundError(RatchetStateError):
    """Raised when no active ratchet session exists for a friend."""


class RatchetInitError(RatchetStateError):
    """Raised when ratchet initialization fails."""


class RatchetServiceError(RatchetStateError):
    """General ratchet service failure (serialization, DB, etc.)."""


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------

class TOTPValidationError(EnigmaError):
    """Raised when TOTP verification or secret management fails."""


# ---------------------------------------------------------------------------
# Concurrency / Timeout
# ---------------------------------------------------------------------------

class CryptoTimeoutError(EnigmaError):
    """Raised when a cryptographic operation exceeds its allowed time limit."""


class ConcurrencyError(EnigmaError):
    """Raised when a concurrency operation fails (lock acquisition, etc.)."""
