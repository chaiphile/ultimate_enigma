"""Legacy encryption strategy (shared-secret + RSA hybrid) – extracted from EncryptionService."""

import time
import logging
from typing import Optional, Tuple

from crypto import (
    encrypt_message,
    decrypt_message,
    peek_flags,
    extract_key_hint,
    AES_KEY_SIZE,
    SELF_DESTRUCT_FLAG,
)
from src.exceptions import EncryptionError, DecryptionError

logger = logging.getLogger(__name__)


class LegacyEncryptionStrategy:
    """Encrypts/decrypts using shared-secret or RSA hybrid encryption."""

    def __init__(self, key_store, ntp_time_provider):
        self._ks = key_store
        self._get_ntp_time = ntp_time_provider

    def encrypt(
        self,
        plaintext: str,
        friend_name: Optional[str] = None,
        mode: str = "shared",
        sign: bool = True,
        self_destruct_seconds: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        const_key, encrypt_for_friend_pub = self._resolve_encryption_key(
            friend_name, mode
        )
        my_priv = self._ks.my_priv if sign else None

        hybrid_ed_priv = getattr(self._ks, 'my_ed_priv', None) if sign else None
        hybrid_dil_priv = getattr(self._ks, 'my_dil_priv', None) if sign else None

        current_time = self._get_ntp_time() if self._get_ntp_time() is not None else time.time()

        try:
            packet, ts = encrypt_message(
                plaintext.encode("utf-8"),
                const_key,
                current_time,
                sign=sign,
                my_priv=my_priv,
                encrypt_for_friend_pub=encrypt_for_friend_pub,
                self_destruct_seconds=self_destruct_seconds,
                hybrid_ed_priv=hybrid_ed_priv,
                hybrid_dil_priv=hybrid_dil_priv,
            )
        except Exception as exc:
            logger.error("Encryption failed: %s", exc, exc_info=True)
            raise EncryptionError("Encryption failed. Please check your keys and try again.") from exc

        return packet, ts

    def decrypt(self, packet: bytes) -> str:
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
            const_key = bytes(friend_sec if friend_sec else self._ks.global_secret)
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
        import base64
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

    def _get_friends_hybrid_list(self):
        """Build list of (name, ed_pub_bytes, dil_pub_bytes) for hybrid sig verification."""
        result = []
        hybrid_pubs = getattr(self._ks, 'friends_hybrid_sig_pubs', {})
        for name, (ed_pub, dil_pub) in hybrid_pubs.items():
            result.append((name, ed_pub, dil_pub))
        my_combined_pub = getattr(self._ks, 'my_hybrid_sig_combined_pub', None)
        if my_combined_pub:
            try:
                from services.pqc_signatures import HybridSigner
                my_ed_pub, my_dil_pub = HybridSigner.parse_combined_pub(my_combined_pub)
                result.append(("myself", my_ed_pub, my_dil_pub))
            except Exception as e:
                logger.warning("Could not parse own hybrid sig public key: %s", e)
        return result

    def _decrypt_with_rsa(self, packet, my_priv, friends_for_crypto, legacy_priv=None):
        """Try RSA decryption with current key, then legacy key; returns plaintext or None."""
        if not my_priv and not legacy_priv:
            raise DecryptionError("Your private key is required for this message.")
        now = int(self._get_ntp_time()) if self._get_ntp_time() else None
        friends_hybrid = self._get_friends_hybrid_list()
        if my_priv:
            try:
                return decrypt_message(
                    packet,
                    b"",
                    my_priv=my_priv,
                    friends=friends_for_crypto,
                    now=now,
                    friends_hybrid=friends_hybrid,
                )
            except Exception as e:
                logger.warning("RSA decryption failed with current key: %s", e)
        if legacy_priv:
            try:
                return decrypt_message(
                    packet,
                    b"",
                    my_priv=legacy_priv,
                    friends=friends_for_crypto,
                    now=now,
                    friends_hybrid=friends_hybrid,
                )
            except Exception as e:
                logger.warning("Legacy RSA decryption failed: %s", e)
        return None

    def _decrypt_with_shared_secrets(self, packet, secrets_to_try, friends_for_crypto):
        """Attempt decryption with a list of shared secrets; returns plaintext or None."""
        now = int(self._get_ntp_time()) if self._get_ntp_time() else None
        friends_hybrid = self._get_friends_hybrid_list()
        key_hint = extract_key_hint(packet)
        import hashlib
        for secret in secrets_to_try:
            if key_hint is not None:
                if hashlib.sha256(secret).digest()[:2] != key_hint:
                    continue
            try:
                return decrypt_message(
                    packet,
                    secret,
                    my_priv=None,
                    friends=friends_for_crypto,
                    now=now,
                    friends_hybrid=friends_hybrid,
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
