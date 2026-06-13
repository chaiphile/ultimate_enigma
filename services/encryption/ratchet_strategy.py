"""Double Ratchet encryption strategy – extracted from EncryptionService."""

import time
import logging
from typing import Optional, Tuple

from services.ratchet_service import (
    RatchetService,
    RatchetNotFoundError,
    RatchetServiceError,
)
from models.envelope import RatchetEnvelope
from src.exceptions import EncryptionError, DecryptionError

logger = logging.getLogger(__name__)


class RatchetEncryptionStrategy:
    """Encrypts/decrypts using Double Ratchet sessions."""

    def __init__(self, key_store, ntp_time_provider):
        self._ks = key_store
        self._get_ntp_time = ntp_time_provider

    def friend_supports_ratchet(self, friend_name: str) -> bool:
        """Check if a friend can use Double Ratchet encryption."""
        if RatchetService.has_active_ratchet(friend_name):
            return True
        caps = getattr(self._ks, "friends_capabilities", {})
        friend_caps = caps.get(friend_name, {})
        return bool(friend_caps.get("double_ratchet", False))

    def encrypt(
        self, plaintext: str, friend_name: str
    ) -> Tuple[bytes, int]:
        """Encrypt using Double Ratchet and wrap in a ratchet envelope."""
        try:
            header, ciphertext = RatchetService.encrypt_message(
                friend_name, plaintext.encode("utf-8")
            )
        except RatchetNotFoundError:
            raise EncryptionError(
                f"No active ratchet session for '{friend_name}'. "
                "Re-establish the ratchet before sending."
            )
        except RatchetServiceError as exc:
            raise EncryptionError(
                f"Ratchet encryption failed for '{friend_name}': {exc}"
            ) from exc

        my_name = getattr(self._ks, 'my_name', None) or friend_name
        try:
            env_model = RatchetEnvelope(
                sender_name=my_name,
                header=header,
                ciphertext=ciphertext,
            )
            envelope = env_model.build()
        except ValueError as exc:
            raise EncryptionError(str(exc)) from exc

        current_time = self._get_ntp_time() if self._get_ntp_time() is not None else time.time()
        logger.debug("Encrypted message via Double Ratchet for '%s'", friend_name)
        return envelope, int(current_time)

    def decrypt(self, packet: bytes) -> str:
        """Parse a ratchet envelope and decrypt using Double Ratchet."""
        try:
            env_model = RatchetEnvelope.parse(packet)
        except ValueError as exc:
            raise DecryptionError(
                "Malformed Double Ratchet envelope."
            ) from exc

        sender_name = env_model.sender_name
        header = env_model.header
        ciphertext = env_model.ciphertext

        if not self.friend_supports_ratchet(sender_name):
            raise DecryptionError(
                f"Received ratchet message from '{sender_name}' who has no "
                "ratchet capability registered. Possible protocol mismatch."
            )

        try:
            plaintext_bytes = RatchetService.decrypt_message(
                sender_name, header, ciphertext
            )
        except RatchetNotFoundError:
            raise DecryptionError(
                f"No active ratchet session for '{sender_name}'. "
                "The session may need to be re-established."
            )
        except RatchetServiceError as exc:
            raise DecryptionError(
                f"Ratchet decryption failed from '{sender_name}': {exc}"
            ) from exc

        logger.debug("Decrypted message via Double Ratchet from '%s'", sender_name)
        return plaintext_bytes.decode("utf-8")
