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


# ---------------------------------------------------------------------------
# Trust Chain / Certificates
# ---------------------------------------------------------------------------

class TrustChainError(EnigmaError):
    """Base exception for trust chain and certificate operations."""


class CertificateError(TrustChainError):
    """Raised when certificate issuance, verification, or storage fails."""


class CertificateExpiredError(CertificateError):
    """Raised when a certificate has passed its expiration date."""


class CertificateRevokedError(CertificateError):
    """Raised when a certificate has been revoked by its issuer."""


class CertificateSignatureError(CertificateError):
    """Raised when a certificate's hybrid signature fails verification."""


# ---------------------------------------------------------------------------
# Shamir Secret Sharing / Key Recovery
# ---------------------------------------------------------------------------

class ShamirError(TrustChainError):
    """Base exception for Shamir secret sharing operations."""


class InsufficientSharesError(ShamirError):
    """Raised when fewer than the threshold number of shares are provided for reconstruction."""


class InvalidShareError(ShamirError):
    """Raised when a share is malformed, corrupted, or has mismatched parameters."""
