import time
import base64
import logging
from typing import Optional, Tuple

from crypto import (
    encrypt_message,
    decrypt_message,
    peek_flags,
    AES_KEY_SIZE,
    SELF_DESTRUCT_FLAG,
)

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Raised when encryption cannot proceed."""


class DecryptionError(Exception):
    """Raised when decryption fails."""


class EncryptionService:
    """Thin wrapper around crypto module that holds a reference to the key store."""

    def __init__(self, key_store):
        """
        key_store must expose:
            - global_secret      : bytes (32 bytes for AES)
            - my_priv            : RSA private key object or None
            - friends            : list of (name, public_key, shared_secret) tuples
            - get_decryption_snapshot()  : returns (my_priv, friends, secrets_to_try)
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
        Raises DecryptionError on failure.
        """
        packet = self._decode_base64_packet(b64_text)
        flags = self._peek_flags(packet)
        friend_encrypted = bool(flags & 2)

        my_priv, friends_for_crypto, secrets_to_try = self._ks.get_decryption_snapshot()

        if friend_encrypted:
            plaintext = self._decrypt_with_rsa(packet, my_priv, friends_for_crypto)
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

    def _decrypt_with_rsa(self, packet, my_priv, friends_for_crypto):
        """Try RSA decryption; returns plaintext or None."""
        if not my_priv:
            raise DecryptionError("Your private key is required for this message.")
        now = int(self._ntp_time) if self._ntp_time else None
        try:
            return decrypt_message(
                packet,
                b"",  # shared secret not used
                my_priv=my_priv,
                friends=friends_for_crypto,
                now=now,
            )
        except Exception:
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

    @staticmethod
    def _build_decryption_error(flags) -> DecryptionError:
        """Craft a user-friendly error based on the last known failure context."""
        if flags & SELF_DESTRUCT_FLAG:
            return DecryptionError("This message has self-destructed and is no longer readable.")
        return DecryptionError("Could not decrypt. Wrong key or message expired.")