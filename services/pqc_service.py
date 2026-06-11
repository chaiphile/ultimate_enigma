"""
Hybrid Post-Quantum Key Exchange Service.

Combines classical X25519 ECDH with CRYSTALS-Kyber-768 KEM.
Both must succeed for key derivation — if either is broken,
the hybrid still provides security from the other.
"""

import struct
import logging

try:
    import oqs
    _OQS_AVAILABLE = True
except (ImportError, RuntimeError, OSError) as _oqs_err:
    oqs = None  # type: ignore[assignment]
    _OQS_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "liboqs not available (%s). Post-quantum hybrid KEM will be disabled. "
        "Install liboqs native library + pip install liboqs-python to enable.",
        _oqs_err
    )

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

KEM_ALGORITHM = "Kyber768"


def is_pqc_available() -> bool:
    """Return True if the liboqs native library is loaded and Kyber768 is supported."""
    if not _OQS_AVAILABLE or oqs is None:
        return False
    try:
        return KEM_ALGORITHM in oqs.get_enabled_kem_mechanisms()
    except Exception:
        return False


class HybridKEM:
    """Hybrid classical + post-quantum key encapsulation."""

    @staticmethod
    def _require_oqs():
        """Raise RuntimeError if liboqs is not available."""
        if not _OQS_AVAILABLE or oqs is None:
            raise RuntimeError(
                "liboqs native library is not installed or failed to load. "
                "Install it with: pip install liboqs-python  "
                "(also requires the liboqs shared library on your system)."
            )

    @staticmethod
    def generate_keys() -> dict:
        """
        Generate hybrid key pair.
        Returns: {
            'x25519_priv': X25519PrivateKey,
            'x25519_pub_bytes': bytes (32),
            'kyber_priv': bytes (Kyber secret key),
            'kyber_pub_bytes': bytes (Kyber public key),
            'combined_pub': bytes (concatenated for exchange)
        }
        """
        HybridKEM._require_oqs()
        # Classical key
        x_priv = X25519PrivateKey.generate()
        x_pub_bytes = x_priv.public_key().public_bytes_raw()

        # Post-quantum key
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ky_pub = kem.generate_keypair()
            ky_priv = kem.export_secret_key()
            ky_pub_bytes = ky_pub

        # Combined public key for exchange: [len_x(2) | x25519(32) | len_ky(2) | kyber_pub]
        combined = struct.pack(">H", len(x_pub_bytes)) + x_pub_bytes
        combined += struct.pack(">H", len(ky_pub_bytes)) + ky_pub_bytes

        logger.debug(
            "Generated hybrid keys: X25519 pub=%d bytes, Kyber768 pub=%d bytes",
            len(x_pub_bytes), len(ky_pub_bytes)
        )

        return {
            'x25519_priv': x_priv,
            'x25519_pub_bytes': x_pub_bytes,
            'kyber_priv': ky_priv,
            'kyber_pub_bytes': ky_pub_bytes,
            'combined_pub': combined
        }

    @staticmethod
    def encapsulate(remote_combined_pub: bytes) -> dict:
        """
        Encapsulate: generate shared secrets for both classical and PQ.
        Returns: {
            'ciphertext': bytes (to send to remote),
            'shared_secret': bytes (32-byte derived key)
        }
        """
        HybridKEM._require_oqs()
        offset = 0
        x_len = struct.unpack(">H", remote_combined_pub[offset:offset+2])[0]
        offset += 2
        remote_x_pub = remote_combined_pub[offset:offset+x_len]
        offset += x_len

        ky_len = struct.unpack(">H", remote_combined_pub[offset:offset+2])[0]
        offset += 2
        remote_ky_pub = remote_combined_pub[offset:offset+ky_len]

        # Classical ECDH
        x_priv = X25519PrivateKey.generate()
        x_pub_bytes = x_priv.public_key().public_bytes_raw()
        x_shared = x_priv.exchange(
            X25519PublicKey.from_public_bytes(remote_x_pub)
        )

        # PQ KEM encapsulation
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ct, pq_shared = kem.encap_secret(remote_ky_pub)

        # Combine both shared secrets via HKDF
        combined_input = x_shared + pq_shared
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"enigma-hybrid-kem-v1",
            backend=default_backend()
        )
        final_secret = hkdf.derive(combined_input)

        # Build ciphertext: [x_pub(32) | kyber_ct]
        ciphertext = x_pub_bytes + ct

        logger.debug(
            "Hybrid encapsulation complete: ciphertext=%d bytes",
            len(ciphertext)
        )

        return {
            'ciphertext': ciphertext,
            'shared_secret': final_secret
        }

    @staticmethod
    def decapsulate(keys: dict, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext.
        Returns 32-byte derived key.
        """
        HybridKEM._require_oqs()
        # Extract classical ECDH
        remote_x_pub_bytes = ciphertext[:32]
        kyber_ct = ciphertext[32:]

        x_shared = keys['x25519_priv'].exchange(
            X25519PublicKey.from_public_bytes(remote_x_pub_bytes)
        )

        # PQ KEM decapsulation
        with oqs.KeyEncapsulation(KEM_ALGORITHM, keys['kyber_priv']) as kem:
            pq_shared = kem.decap_secret(kyber_ct)

        # Combine
        combined_input = x_shared + pq_shared
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"enigma-hybrid-kem-v1",
            backend=default_backend()
        )
        final_secret = hkdf.derive(combined_input)

        logger.debug("Hybrid decapsulation complete")

        return final_secret
