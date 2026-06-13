import time
import base64
import secrets
import struct
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
from services.pqc_service import HybridKEM, is_pqc_available
from models.envelope import (
    RatchetEnvelope,
    PQCEncvelope,
    identify_envelope_type,
)
from src.timeout import run_with_timeout
from src.constants import CONCURRENCY_CONSTANTS, CRYPTO_CONSTANTS

logger = logging.getLogger(__name__)


from src.exceptions import EncryptionError, DecryptionError


# Re-export magic bytes from models for backward compatibility.
# New code should import directly from models.envelope.
from models.envelope import RATCHET_ENVELOPE_MAGIC, PQC_ENVELOPE_MAGIC


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
        self._last_encrypt_mode: Optional[str] = None
        self._last_decrypt_mode: Optional[str] = None

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
        # --- Post-Quantum Hybrid KEM path ---
        if friend_name and mode == "pqc":
            self._last_encrypt_mode = "pqc"
            return self._encrypt_with_pqc(plaintext, friend_name)

        # --- Double Ratchet path ---
        if (
            friend_name
            and mode == "shared"
            and self._friend_supports_ratchet(friend_name)
        ):
            self._last_encrypt_mode = "ratchet"
            return self._encrypt_with_ratchet(plaintext, friend_name)

        # --- Legacy encryption path ---
        self._last_encrypt_mode = "legacy"
        const_key, encrypt_for_friend_pub = self._resolve_encryption_key(
            friend_name, mode
        )
        my_priv = self._ks.my_priv if sign else None

        # Hybrid signing keys (Ed25519 + Dilithium3) — used when available
        hybrid_ed_priv = getattr(self._ks, 'my_ed_priv', None) if sign else None
        hybrid_dil_priv = getattr(self._ks, 'my_dil_priv', None) if sign else None

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
                hybrid_ed_priv=hybrid_ed_priv,
                hybrid_dil_priv=hybrid_dil_priv,
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

        # --- Identify envelope type via model ---
        envelope_type = identify_envelope_type(packet)

        if envelope_type == "pqc":
            self._last_decrypt_mode = "pqc"
            return self._decrypt_with_pqc(packet)

        if envelope_type == "ratchet":
            self._last_decrypt_mode = "ratchet"
            return self._decrypt_with_ratchet(packet)

        # --- Legacy decryption path ---
        self._last_decrypt_mode = "legacy"
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

    def _get_friends_hybrid_list(self):
        """Build list of (name, ed_pub_bytes, dil_pub_bytes) for hybrid sig verification.

        Includes both friends' hybrid signing public keys AND the user's own
        hybrid signing public key, so that self-signed messages (encrypt then
        decrypt on the same machine) can be verified.
        """
        result = []
        # Friends' hybrid signing public keys
        hybrid_pubs = getattr(self._ks, 'friends_hybrid_sig_pubs', {})
        for name, (ed_pub, dil_pub) in hybrid_pubs.items():
            result.append((name, ed_pub, dil_pub))
        # Own hybrid signing public key (for self-verification)
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
        now = int(self._ntp_time) if self._ntp_time else None
        friends_hybrid = self._get_friends_hybrid_list()
        # Try current key first
        if my_priv:
            try:
                return decrypt_message(
                    packet,
                    b"",  # shared secret not used
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
            except Exception:
                pass
        return None

    def _decrypt_with_shared_secrets(self, packet, secrets_to_try, friends_for_crypto):
        """Attempt decryption with a list of shared secrets; returns plaintext or None."""
        now = int(self._ntp_time) if self._ntp_time else None
        friends_hybrid = self._get_friends_hybrid_list()
        for secret in secrets_to_try:
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

    # ------------------------------------------------------------------
    # Double Ratchet helpers
    # ------------------------------------------------------------------
    @property
    def last_encrypt_mode(self) -> Optional[str]:
        """Return the encryption mode used by the most recent encrypt() call.

        Returns 'ratchet', 'legacy', or None if no encryption has been performed.
        """
        return self._last_encrypt_mode

    @property
    def last_decrypt_mode(self) -> Optional[str]:
        """Return the decryption mode used by the most recent decrypt() call.

        Returns 'ratchet', 'legacy', or None if no decryption has been performed.
        """
        return self._last_decrypt_mode

    def _friend_supports_ratchet(self, friend_name: str) -> bool:
        """Check if a friend can use Double Ratchet encryption.

        Returns True if either:
        - The friend has an active ratchet session (definitive proof of support), or
        - The friend has advertised double_ratchet capability in their profile
        """
        if RatchetService.has_active_ratchet(friend_name):
            return True
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

        # Build envelope using structured model.
        # sender_name must be OUR identity so the recipient can look up
        # the ratchet session stored under our name on their machine.
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

        current_time = self._ntp_time if self._ntp_time is not None else time.time()
        logger.debug("Encrypted message via Double Ratchet for '%s'", friend_name)
        return envelope, int(current_time)

    def _decrypt_with_ratchet(self, packet: bytes) -> str:
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

    # ------------------------------------------------------------------
    # Post-Quantum Hybrid KEM helpers
    # ------------------------------------------------------------------
    def _encrypt_with_pqc(
        self, plaintext: str, friend_name: str
    ) -> Tuple[bytes, int]:
        """Encrypt using Post-Quantum Hybrid KEM (X25519 + Kyber768).

        Envelope format:
            0x50 | kem_ct_len(2B BE) | kem_ciphertext | nonce(12) | aes_gcm_ciphertext+tag

        The shared secret from HybridKEM.encapsulate is used directly as
        the AES-256-GCM key (it is already HKDF-derived inside HybridKEM).

        Timeout: Uses PQC_OPERATION_TIMEOUT from CONCURRENCY_CONSTANTS to
        prevent blocking the caller indefinitely during encapsulation.
        """
        if not is_pqc_available():
            raise EncryptionError(
                "Post-quantum cryptography is not available. "
                "Install liboqs native library + pip install liboqs-python."
            )

        combined_pub = self._ks.friends_pqc_combined_pub.get(friend_name)
        if not combined_pub:
            raise EncryptionError(
                f"No PQC public key stored for '{friend_name}'. "
                "Import their PQC combined public key first."
            )

        # Wrap PQC encapsulation in timeout to prevent indefinite blocking
        pqc_timeout = CONCURRENCY_CONSTANTS.get("PQC_OPERATION_TIMEOUT", 60.0)
        try:
            kem_result = run_with_timeout(
                HybridKEM.encapsulate, pqc_timeout, combined_pub
            )
        except Exception as exc:
            from src.exceptions import CryptoTimeoutError
            if isinstance(exc, CryptoTimeoutError):
                raise EncryptionError(
                    f"PQC encapsulation timed out after {pqc_timeout:.0f}s. "
                    "The system may be under heavy load."
                ) from exc
            raise EncryptionError(
                f"PQC encapsulation failed for '{friend_name}': {exc}"
            ) from exc

        shared_secret = kem_result['shared_secret']
        kem_ciphertext = kem_result['ciphertext']

        # AES-256-GCM encrypt the plaintext
        nonce = secrets.token_bytes(CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"])
        aesgcm = AESGCM(shared_secret)
        aes_ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        # Build envelope using structured model
        try:
            env_model = PQCEncvelope(
                kem_ciphertext=kem_ciphertext,
                nonce=nonce,
                aes_ciphertext=aes_ct,
            )
            envelope = env_model.build()
        except ValueError as exc:
            raise EncryptionError(str(exc)) from exc

        current_time = self._ntp_time if self._ntp_time is not None else time.time()
        logger.debug("Encrypted message via PQC Hybrid KEM for '%s'", friend_name)
        return envelope, int(current_time)

    def _decrypt_with_pqc(self, packet: bytes) -> str:
        """Parse a PQC Hybrid KEM envelope and decrypt.

        Uses the cached PQC private key bundle from KeyStore to decapsulate
        the KEM ciphertext and recover the AES key.

        Timeout: Uses PQC_OPERATION_TIMEOUT to guard against indefinite
        blocking during decapsulation.
        """
        if not is_pqc_available():
            raise DecryptionError(
                "Post-quantum cryptography is not available. "
                "Install liboqs to decrypt PQC messages."
            )

        bundle = self._ks.pqc_decryption_bundle
        if not bundle:
            raise DecryptionError(
                "PQC private keys are not loaded. "
                "Generate PQC keys via the Friends tab and restart the app."
            )

        try:
            env_model = PQCEncvelope.parse(packet)
        except ValueError as exc:
            raise DecryptionError("Malformed PQC envelope.") from exc

        kem_ciphertext = env_model.kem_ciphertext
        nonce = env_model.nonce
        aes_ct = env_model.aes_ciphertext

        # Decapsulate with timeout to prevent indefinite blocking
        pqc_timeout = CONCURRENCY_CONSTANTS.get("PQC_OPERATION_TIMEOUT", 60.0)
        try:
            shared_secret = run_with_timeout(
                HybridKEM.decapsulate, pqc_timeout, bundle, kem_ciphertext
            )
        except Exception as exc:
            from src.exceptions import CryptoTimeoutError
            if isinstance(exc, CryptoTimeoutError):
                raise DecryptionError(
                    f"PQC decapsulation timed out after {pqc_timeout:.0f}s. "
                    "The system may be under heavy load."
                ) from exc
            raise DecryptionError(
                f"PQC decapsulation failed: {exc}"
            ) from exc

        # AES-256-GCM decrypt
        try:
            aesgcm = AESGCM(shared_secret)
            plaintext_bytes = aesgcm.decrypt(nonce, aes_ct, None)
        except Exception as exc:
            raise DecryptionError(
                "PQC decryption failed: authentication tag mismatch or corrupted data."
            ) from exc

        logger.debug("Decrypted message via PQC Hybrid KEM")
        return plaintext_bytes.decode("utf-8")

    @staticmethod
    def _build_decryption_error(flags) -> DecryptionError:
        """Craft a user-friendly error based on the last known failure context."""
        if flags & SELF_DESTRUCT_FLAG:
            return DecryptionError("This message has self-destructed and is no longer readable.")
        return DecryptionError("Could not decrypt. Wrong key or message expired.")