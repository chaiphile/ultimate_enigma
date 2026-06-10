import time
import base64
import struct
import logging
from typing import Optional, Tuple

from crypto import (
    encrypt_message,
    decrypt_message,
    peek_flags,
    AES_KEY_SIZE,
    SELF_DESTRUCT_FLAG,
)
from services.ratchet_service import (
    RatchetService,
    RatchetNotFoundError,
    RatchetServiceError,
)

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Raised when encryption cannot proceed."""


class DecryptionError(Exception):
    """Raised when decryption fails."""


# Magic byte identifying a Double Ratchet envelope
RATCHET_ENVELOPE_MAGIC = 0xD0


class EncryptionService:
    """Thin wrapper around crypto module that holds a reference to the key store.

    Supports dual-mode encryption:
    - Legacy: static shared-secret or RSA-based encryption via crypto module
    - Double Ratchet: per-message forward-secret encryption when an active
      ratchet session exists for the target friend
    """

    def __init__(self, key_store):
        """
        key_store must expose:
            - global_secret      : bytes (32 bytes for AES)
            - my_priv            : RSA private key object or None
            - friends            : list of (name, public_key, shared_secret) tuples
            - get_decryption_snapshot()  : returns (my_priv, friends, secrets_to_try, legacy_priv)
        """
        self._ks = key_store
        self._ntp_time: Optional[float] = None

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
        """
        Encrypt `plaintext` according to the chosen mode.
        Returns (raw_packet_bytes, timestamp).
        Raises EncryptionError on failure.
        """
        # --- Double Ratchet path ---
        if (
            friend_name
            and mode == "shared"
            and self._friend_supports_ratchet(friend_name)
            and RatchetService.has_active_ratchet(friend_name)
        ):
            return self._encrypt_with_ratchet(plaintext, friend_name)

        # --- Legacy encryption path ---
        const_key, encrypt_for_friend_pub = self._resolve_encryption_key(
            friend_name, mode
        )
        my_priv = self._ks.my_priv if sign else None

        # Use NTP time if available, otherwise fall back to local time
        current_time = self._ntp_time if self._ntp_time is not None else time.time()

        try:
            packet, ts = encrypt_message(
                plaintext.encode("utf-8"),
                const_key,
                current_time,      # corrected time
                sign=sign,
                my_priv=my_priv,
                encrypt_for_friend_pub=encrypt_for_friend_pub,
                self_destruct_seconds=self_destruct_seconds,
            )
        except Exception as exc:
            logger.error("Encryption failed: %s", exc, exc_info=True)
            raise EncryptionError("Encryption failed. Please check your keys and try again.") from exc

        return packet, ts

    def encrypt_base64(self, **kwargs) -> str:
        """Convenience: encrypt and return base64-encoded string."""
        packet, _ = self.encrypt(**kwargs)
        return base64.b64encode(packet).decode("ascii")

    # ------------------------------------------------------------------
    # Public API – Decryption
    # ------------------------------------------------------------------
    def decrypt(self, b64_text: str) -> str:
        """
        Decrypt a Base64‑encoded message and return the plaintext string.

        Automatically detects Double Ratchet envelopes (magic byte 0xD0)
        and routes to ratchet decryption. Falls back to legacy decryption
        for standard packets.

        Raises DecryptionError on failure.
        """
        packet = self._decode_base64_packet(b64_text)

        # --- Double Ratchet path ---
        if len(packet) > 1 and packet[0] == RATCHET_ENVELOPE_MAGIC:
            return self._decrypt_with_ratchet(packet)

        # --- Legacy decryption path ---
        flags = self._peek_flags(packet)
        friend_encrypted = bool(flags & 2)

        my_priv, friends_for_crypto, secrets_to_try, legacy_priv = self._ks.get_decryption_snapshot()

        if friend_encrypted:
            plaintext = self._decrypt_with_rsa(packet, my_priv, friends_for_crypto, legacy_priv)
        else:
            plaintext = self._decrypt_with_shared_secrets(
                packet, secrets_to_try, friends_for_crypto
            )

        if plaintext is None:
            raise self._build_decryption_error(flags)

        return plaintext

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_encryption_key(self, friend_name, mode):
        """Determine the symmetric key and optional RSA public key for encryption."""
        friend_pub, friend_sec = None, None
        if friend_name:
            friend_pub, friend_sec = self._get_friend_keys(friend_name)
            if friend_pub is None and friend_sec is None:
                if mode == "rsa":
                    raise EncryptionError(
                        f"No public key available for friend '{friend_name}'."
                    )
                raise EncryptionError(
                    f"Friend '{friend_name}' not found in key store."
                )

        use_shared = mode == "shared"
        if use_shared:
            const_key = friend_sec if friend_sec else self._ks.global_secret
            if len(const_key) != AES_KEY_SIZE:
                raise EncryptionError(
                    "Shared secret is missing or invalid (must be 32 bytes)."
                )
            encrypt_for_friend_pub = None
        else:  # RSA
            if not friend_pub:
                raise EncryptionError(
                    "No public key available for RSA encryption."
                )
            const_key = b"\x00" * AES_KEY_SIZE
            encrypt_for_friend_pub = friend_pub

        return const_key, encrypt_for_friend_pub

    def _get_friend_keys(self, name: str):
        """Return (public_key, shared_secret) for a friend, or (None, None)."""
        for friend_name, pub, sec in self._ks.friends:
            if friend_name == name:
                return pub, sec
        return None, None

    @staticmethod
    def _decode_base64_packet(b64_text: str) -> bytes:
        """Decode a Base64 string, raising a clear error on failure."""
        try:
            return base64.b64decode(b64_text)
        except Exception:
            raise DecryptionError("Invalid Base64 input.")

    @staticmethod
    def _peek_flags(packet: bytes) -> int:
        """Read the flags from the packet, raising a clear error on failure."""
        try:
            return peek_flags(packet)
        except Exception:
            raise DecryptionError("Corrupted packet.")

    def _decrypt_with_rsa(self, packet, my_priv, friends_for_crypto, legacy_priv=None):
        """Try RSA decryption with current key, then legacy key; returns plaintext or None."""
        if not my_priv and not legacy_priv:
            raise DecryptionError("Your private key is required for this message.")
        now = int(self._ntp_time) if self._ntp_time else None
        # Try current key first
        if my_priv:
            try:
                return decrypt_message(
                    packet,
                    b"",  # shared secret not used
                    my_priv=my_priv,
                    friends=friends_for_crypto,
                    now=now,
                )
            except Exception:
                pass
        # Fall back to legacy key (for messages encrypted before key rotation)
        if legacy_priv:
            try:
                return decrypt_message(
                    packet,
                    b"",
                    my_priv=legacy_priv,
                    friends=friends_for_crypto,
                    now=now,
                )
            except Exception:
                pass
        return None

    def _decrypt_with_shared_secrets(self, packet, secrets_to_try, friends_for_crypto):
        """Attempt decryption with a list of shared secrets; returns plaintext or None."""
        now = int(self._ntp_time) if self._ntp_time else None
        for secret in secrets_to_try:
            try:
                return decrypt_message(
                    packet,
                    secret,
                    my_priv=None,
                    friends=friends_for_crypto,
                    now=now,
                )
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------
    # Double Ratchet helpers
    # ------------------------------------------------------------------
    def _friend_supports_ratchet(self, friend_name: str) -> bool:
        """Check if a friend has advertised Double Ratchet capability."""
        caps = getattr(self._ks, "friends_capabilities", {})
        friend_caps = caps.get(friend_name, {})
        return bool(friend_caps.get("double_ratchet", False))

    def _encrypt_with_ratchet(
        self, plaintext: str, friend_name: str
    ) -> Tuple[bytes, int]:
        """Encrypt using Double Ratchet and wrap in a ratchet envelope.

        Envelope format:
            0xD0 | name_len(1B) | name(UTF-8) | hdr_len(2B BE) | header | ciphertext
        """
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

        # Build envelope
        name_bytes = friend_name.encode("utf-8")
        if len(name_bytes) > 255:
            raise EncryptionError("Friend name too long for ratchet envelope.")
        envelope = (
            bytes([RATCHET_ENVELOPE_MAGIC])
            + bytes([len(name_bytes)])
            + name_bytes
            + struct.pack(">H", len(header))
            + header
            + ciphertext
        )

        current_time = self._ntp_time if self._ntp_time is not None else time.time()
        logger.debug("Encrypted message via Double Ratchet for '%s'", friend_name)
        return envelope, int(current_time)

    def _decrypt_with_ratchet(self, packet: bytes) -> str:
        """Parse a ratchet envelope and decrypt using Double Ratchet."""
        try:
            offset = 1  # skip magic byte
            name_len = packet[offset]
            offset += 1
            sender_name = packet[offset : offset + name_len].decode("utf-8")
            offset += name_len
            header_len = struct.unpack(">H", packet[offset : offset + 2])[0]
            offset += 2
            header = packet[offset : offset + header_len]
            offset += header_len
            ciphertext = packet[offset:]
        except Exception as exc:
            raise DecryptionError(
                "Malformed Double Ratchet envelope."
            ) from exc

        if not self._friend_supports_ratchet(sender_name):
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

    @staticmethod
    def _build_decryption_error(flags) -> DecryptionError:
        """Craft a user-friendly error based on the last known failure context."""
        if flags & SELF_DESTRUCT_FLAG:
            return DecryptionError("This message has self-destructed and is no longer readable.")
        return DecryptionError("Could not decrypt. Wrong key or message expired.")