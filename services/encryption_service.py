"""Backward-compatibility shim - EncryptionService is now in services.encryption package."""

from services.encryption.encryption_facade import EncryptionService
from src.exceptions import EncryptionError, DecryptionError

# Re-export magic bytes for backward compatibility.
# New code should import directly from models.envelope.
from models.envelope import RATCHET_ENVELOPE_MAGIC, PQC_ENVELOPE_MAGIC

__all__ = [
    "EncryptionService",
    "EncryptionError",
    "DecryptionError",
    "RATCHET_ENVELOPE_MAGIC",
    "PQC_ENVELOPE_MAGIC",
]
