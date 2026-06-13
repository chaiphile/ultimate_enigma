"""Post-Quantum Hybrid KEM encryption strategy – extracted from EncryptionService."""

import time
import secrets
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.pqc_service import HybridKEM, is_pqc_available
from models.envelope import PQCEncvelope
from src.timeout import run_with_timeout
from src.constants import CONCURRENCY_CONSTANTS, CRYPTO_CONSTANTS
from src.exceptions import EncryptionError, DecryptionError

logger = logging.getLogger(__name__)


class PqcEncryptionStrategy:
    """Encrypts/decrypts using Post-Quantum Hybrid KEM (X25519 + Kyber768)."""

    def __init__(self, key_store, ntp_time_provider):
        self._ks = key_store
        self._get_ntp_time = ntp_time_provider

    def encrypt(
        self, plaintext: str, friend_name: str
    ) -> Tuple[bytes, int]:
        """Encrypt using Post-Quantum Hybrid KEM (X25519 + Kyber768)."""
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

        nonce = secrets.token_bytes(CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"])
        aesgcm = AESGCM(shared_secret)
        aes_ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        try:
            env_model = PQCEncvelope(
                kem_ciphertext=kem_ciphertext,
                nonce=nonce,
                aes_ciphertext=aes_ct,
            )
            envelope = env_model.build()
        except ValueError as exc:
            raise EncryptionError(str(exc)) from exc

        current_time = self._get_ntp_time() if self._get_ntp_time() is not None else time.time()
        logger.debug("Encrypted message via PQC Hybrid KEM for '%s'", friend_name)
        return envelope, int(current_time)

    def decrypt(self, packet: bytes) -> str:
        """Parse a PQC Hybrid KEM envelope and decrypt."""
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

        try:
            aesgcm = AESGCM(shared_secret)
            plaintext_bytes = aesgcm.decrypt(nonce, aes_ct, None)
        except Exception as exc:
            raise DecryptionError(
                "PQC decryption failed: authentication tag mismatch or corrupted data."
            ) from exc

        logger.debug("Decrypted message via PQC Hybrid KEM")
        return plaintext_bytes.decode("utf-8")
