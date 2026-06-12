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


# Expected key/length constants for defensive validation
X25519_PUB_KEY_LEN = 32
MIN_COMBINED_PUB_LEN = 2 + X25519_PUB_KEY_LEN + 2  # at least header + x25519 + header


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
        if len(x_pub_bytes) != X25519_PUB_KEY_LEN:
            raise RuntimeError(
                f"Unexpected X25519 public key length: {len(x_pub_bytes)} "
                f"(expected {X25519_PUB_KEY_LEN})"
            )

        # Post-quantum key
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ky_pub = kem.generate_keypair()
            ky_priv = kem.export_secret_key()
            ky_pub_bytes = ky_pub

        if len(ky_pub_bytes) == 0:
            raise RuntimeError("Kyber768 generated an empty public key")

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
    def _parse_combined_pub(combined_pub: bytes) -> tuple:
        """Parse a combined public key, returning (x25519_pub_bytes, kyber_pub_bytes).
        
        Args:
            combined_pub: Combined public key bytes in [len_x(2) | x25519(32) | len_ky(2) | kyber_pub] format.
            
        Returns:
            Tuple of (x25519_pub_bytes, kyber_pub_bytes).
            
        Raises:
            ValueError: If the combined key is malformed.
        """
        if len(combined_pub) < MIN_COMBINED_PUB_LEN:
            raise ValueError(
                f"Combined public key too short: {len(combined_pub)} bytes "
                f"(minimum {MIN_COMBINED_PUB_LEN})"
            )
        
        offset = 0
        try:
            x_len = struct.unpack(">H", combined_pub[offset:offset+2])[0]
        except struct.error as e:
            raise ValueError(f"Failed to parse X25519 key length: {e}") from e
        offset += 2
        
        if x_len != X25519_PUB_KEY_LEN:
            raise ValueError(
                f"Unexpected X25519 key length in combined pub: {x_len} "
                f"(expected {X25519_PUB_KEY_LEN})"
            )
        
        if offset + x_len > len(combined_pub):
            raise ValueError(
                f"Combined pub truncated: need {x_len} bytes at offset {offset}, "
                f"have {len(combined_pub)}"
            )
        remote_x_pub = combined_pub[offset:offset+x_len]
        offset += x_len
        
        if offset + 2 > len(combined_pub):
            raise ValueError("Combined pub truncated: missing Kyber key length")
        try:
            ky_len = struct.unpack(">H", combined_pub[offset:offset+2])[0]
        except struct.error as e:
            raise ValueError(f"Failed to parse Kyber key length: {e}") from e
        offset += 2
        
        if offset + ky_len > len(combined_pub):
            raise ValueError(
                f"Combined pub truncated: need {ky_len} bytes at offset {offset}, "
                f"have {len(combined_pub)}"
            )
        remote_ky_pub = combined_pub[offset:offset+ky_len]
        
        if len(remote_ky_pub) == 0:
            raise ValueError("Kyber public key is empty in combined pub")
        
        return remote_x_pub, remote_ky_pub

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
        
        # Defensive parsing with validation
        remote_x_pub, remote_ky_pub = HybridKEM._parse_combined_pub(remote_combined_pub)

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
        
        # Validate ciphertext length
        if len(ciphertext) < X25519_PUB_KEY_LEN + 1:
            raise ValueError(
                f"Ciphertext too short for decapsulation: {len(ciphertext)} bytes "
                f"(minimum {X25519_PUB_KEY_LEN + 1})"
            )
        
        # Extract classical ECDH
        remote_x_pub_bytes = ciphertext[:X25519_PUB_KEY_LEN]
        kyber_ct = ciphertext[X25519_PUB_KEY_LEN:]

        if 'x25519_priv' not in keys:
            raise KeyError("PQC key bundle missing 'x25519_priv'")
        if 'kyber_priv' not in keys:
            raise KeyError("PQC key bundle missing 'kyber_priv'")

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
