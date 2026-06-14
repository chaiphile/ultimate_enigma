"""EncryptionService facade - delegates to focused encryption strategies."""

import base64
import binascii
import logging
from typing import Optional, Protocol, Tuple, runtime_checkable

from services.encryption.legacy_strategy import LegacyEncryptionStrategy
from services.encryption.ratchet_strategy import RatchetEncryptionStrategy
from services.encryption.pqc_strategy import PqcEncryptionStrategy
from models.envelope import identify_envelope_type
from src.exceptions import EncryptionError, DecryptionError

logger = logging.getLogger(__name__)


@runtime_checkable
class EncryptionStrategy(Protocol):
    """Protocol defining the interface for encryption strategies.

    All encryption strategies (Legacy, Ratchet, PQC) must conform to
    this interface so new modes can be added without modifying the facade.
    """

    def encrypt(self, plaintext: str, **kwargs) -> Tuple[bytes, int]: ...

    def decrypt(self, packet: bytes) -> str: ...


class EncryptionService:
    """Thin wrapper around crypto module that holds a reference to the key store.

    Supports dual-mode encryption:
    - Legacy: static shared-secret or RSA-based encryption via crypto module
    - Double Ratchet: per-message forward-secret encryption when an active
      ratchet session exists for the target friend
    """

    def __init__(self, key_store):
        self._ks = key_store
        self._ntp_time: Optional[float] = None
        self._last_encrypt_mode: Optional[str] = None
        self._last_decrypt_mode: Optional[str] = None

        ntp_provider = lambda: self._ntp_time
        self._legacy = LegacyEncryptionStrategy(key_store, ntp_provider)
        self._ratchet = RatchetEncryptionStrategy(key_store, ntp_provider)
        self._pqc = PqcEncryptionStrategy(key_store, ntp_provider)

    def update_ntp_time(self, timestamp: Optional[float]):
        self._ntp_time = timestamp

    # ------------------------------------------------------------------
    # Public API – Encryption
    # ------------------------------------------------------------------
    def encrypt(
        self,
        plaintext: str,
        friend_name: Optional[str] = None,
        mode: str = "shared",
        sign: bool = True,
        self_destruct_seconds: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        """Encrypt plaintext according to the chosen mode."""
        if friend_name and mode == "pqc":
            self._last_encrypt_mode = "pqc"
            return self._pqc.encrypt(plaintext, friend_name)

        if (
            friend_name
            and mode == "shared"
            and self._ratchet.friend_supports_ratchet(friend_name)
        ):
            self._last_encrypt_mode = "ratchet"
            return self._ratchet.encrypt(plaintext, friend_name)

        self._last_encrypt_mode = "legacy"
        return self._legacy.encrypt(
            plaintext, friend_name, mode, sign, self_destruct_seconds
        )

    def encrypt_base64(self, **kwargs) -> str:
        """Convenience: encrypt and return base64-encoded string."""
        packet, _ = self.encrypt(**kwargs)
        return base64.b64encode(packet).decode("ascii")

    # ------------------------------------------------------------------
    # Public API – Decryption
    # ------------------------------------------------------------------
    def decrypt(self, b64_text: str) -> str:
        """Decrypt a Base64-encoded message and return the plaintext string."""
        packet = self._decode_base64_packet(b64_text)

        envelope_type = identify_envelope_type(packet)

        if envelope_type == "pqc":
            self._last_decrypt_mode = "pqc"
            return self._pqc.decrypt(packet)

        if envelope_type == "ratchet":
            self._last_decrypt_mode = "ratchet"
            return self._ratchet.decrypt(packet)

        self._last_decrypt_mode = "legacy"
        return self._legacy.decrypt(packet)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def last_encrypt_mode(self) -> Optional[str]:
        return self._last_encrypt_mode

    @property
    def last_decrypt_mode(self) -> Optional[str]:
        return self._last_decrypt_mode

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _decode_base64_packet(b64_text: str) -> bytes:
        try:
            return base64.b64decode(b64_text)
        except (binascii.Error, ValueError, TypeError):
            raise DecryptionError("Invalid Base64 input.")
