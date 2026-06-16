"""
Hybrid Digital Signatures Service (Ed25519 + CRYSTALS-Dilithium3).

Provides post-quantum secure digital signatures by combining classical
Ed25519 with NIST-standardized CRYSTALS-Dilithium3. Both signatures must
verify successfully — if either algorithm is broken (classical or quantum),
the hybrid still provides authenticity from the other.

Signature format: [ed_sig_len(2) | ed_sig(64) | dil_sig(variable)]
"""

import struct
import logging

try:
    import oqs
    _OQS_SIG_AVAILABLE = True
except (ImportError, RuntimeError, OSError) as _oqs_err:
    oqs = None  # type: ignore[assignment]
    _OQS_SIG_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "liboqs not available for signatures (%s). Post-quantum hybrid signatures will be disabled.",
        _oqs_err
    )

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

logger = logging.getLogger(__name__)

# Supported algorithm names in order of preference.
# "Dilithium3" is the legacy liboqs name; "ML-DSA-65" is the NIST FIPS 204 standard name.
_SIG_ALGORITHM_CANDIDATES = ["Dilithium3", "ML-DSA-65"]
SIG_ALGORITHM = None  # Resolved at runtime


def _resolve_sig_algorithm():
    """Determine which signature algorithm name liboqs supports."""
    global SIG_ALGORITHM
    if SIG_ALGORITHM is not None:
        return SIG_ALGORITHM
    if not _OQS_SIG_AVAILABLE:
        return None
    try:
        enabled = oqs.get_enabled_sig_mechanisms()
    except Exception:
        enabled = []
    for candidate in _SIG_ALGORITHM_CANDIDATES:
        if candidate in enabled:
            SIG_ALGORITHM = candidate
            logger.info("Resolved PQC signature algorithm: %s", candidate)
            return SIG_ALGORITHM
    # Fallback: try instantiating directly (some builds don't list mechanisms)
    for candidate in _SIG_ALGORITHM_CANDIDATES:
        try:
            with oqs.Signature(candidate):
                SIG_ALGORITHM = candidate
                logger.info("Resolved PQC signature algorithm via probe: %s", candidate)
                return SIG_ALGORITHM
        except Exception:
            continue
    logger.error(
        "No supported PQC signature algorithm found. Tried: %s. Enabled: %s",
        _SIG_ALGORITHM_CANDIDATES, enabled
    )
    return None


class HybridSigner:
    """Hybrid classical + post-quantum digital signatures."""

    @staticmethod
    def generate_keys() -> dict:
        """
        Generate hybrid signing key pair.

        Returns: {
            'ed_priv': Ed25519PrivateKey,
            'ed_pub_bytes': bytes (32),
            'dil_priv': bytes (Dilithium3 secret key),
            'dil_pub_bytes': bytes (Dilithium3 public key),
            'combined_pub': bytes (concatenated for exchange/verification)
        }
        """
        # Classical Ed25519 key
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub_bytes = ed_priv.public_key().public_bytes_raw()

        # Post-quantum Dilithium3 / ML-DSA-65 key
        alg = _resolve_sig_algorithm()
        if alg is None:
            raise RuntimeError(
                "No supported PQC signature algorithm available in liboqs"
            )
        try:
            with oqs.Signature(alg) as signer:
                dil_pub = signer.generate_keypair()
                # liboqs-python API varies across versions:
                #   >=0.10: export_secretkey()
                #   0.9.x:  export_secret_key()
                #   some builds: .secret_key property
                if hasattr(signer, 'export_secretkey'):
                    dil_priv = signer.export_secretkey()
                elif hasattr(signer, 'export_secret_key'):
                    dil_priv = signer.export_secret_key()
                elif hasattr(signer, 'secret_key'):
                    dil_priv = signer.secret_key
                else:
                    raise AttributeError(
                        f"Cannot extract secret key from oqs.Signature('{alg}'). "
                        f"Available attributes: {[a for a in dir(signer) if not a.startswith('_')]}"
                    )
                dil_pub_bytes = dil_pub
        except Exception as e:
            raise RuntimeError(
                f"Failed to generate {alg} keypair: {e}"
            ) from e

        # Combined public key for verification/exchange:
        # [ed_pub_len(2) | ed_pub(32) | dil_pub_len(2) | dil_pub]
        combined_pub = struct.pack(">H", len(ed_pub_bytes)) + ed_pub_bytes
        combined_pub += struct.pack(">H", len(dil_pub_bytes)) + dil_pub_bytes

        logger.debug(
            "Generated hybrid signing keys: Ed25519 pub=%d bytes, Dilithium3 pub=%d bytes",
            len(ed_pub_bytes), len(dil_pub_bytes)
        )

        return {
            'ed_priv': ed_priv,
            'ed_pub_bytes': ed_pub_bytes,
            'dil_priv': dil_priv,
            'dil_pub_bytes': dil_pub_bytes,
            'combined_pub': combined_pub
        }

    @staticmethod
    def sign(message: bytes, ed_priv: Ed25519PrivateKey, dil_priv: bytes) -> bytes:
        """
        Sign a message with both Ed25519 and Dilithium3.

        Args:
            message: The message bytes to sign
            ed_priv: Ed25519 private key object
            dil_priv: Dilithium3 secret key bytes

        Returns:
            Combined signature: [ed_sig_len(2) | ed_sig | dil_sig]
        """
        # Ed25519 signature (always 64 bytes)
        ed_sig = ed_priv.sign(message)

        # Dilithium3 / ML-DSA-65 signature. The secret key may be stored as a
        # GuardedBuffer; coerce to bytes for the liboqs C binding.
        alg = _resolve_sig_algorithm()
        if alg is None:
            raise RuntimeError("No supported PQC signature algorithm available")
        with oqs.Signature(alg, bytes(dil_priv)) as signer:
            dil_sig = signer.sign(message)

        # Combined format: [ed_sig_len(2) | ed_sig | dil_sig]
        combined = struct.pack(">H", len(ed_sig)) + ed_sig + dil_sig

        logger.debug(
            "Hybrid signature created: ed_sig=%d bytes, dil_sig=%d bytes, total=%d bytes",
            len(ed_sig), len(dil_sig), len(combined)
        )

        return combined

    @staticmethod
    def verify(
        message: bytes,
        signature: bytes,
        ed_pub: Ed25519PublicKey,
        dil_pub: bytes
    ) -> bool:
        """
        Verify a hybrid signature. BOTH Ed25519 and Dilithium3 must pass.

        Args:
            message: The original message bytes
            signature: Combined signature from sign()
            ed_pub: Ed25519 public key object
            dil_pub: Dilithium3 public key bytes

        Returns:
            True only if BOTH signatures are valid, False otherwise
        """
        if len(signature) < 2:
            logger.warning("Hybrid signature too short")
            return False

        # Parse combined signature
        try:
            ed_len = struct.unpack(">H", signature[:2])[0]
        except struct.error:
            logger.warning("Failed to parse Ed25519 signature length")
            return False

        if len(signature) < 2 + ed_len:
            logger.warning("Hybrid signature truncated (Ed25519 portion)")
            return False

        ed_sig = signature[2:2 + ed_len]
        dil_sig = signature[2 + ed_len:]

        if not dil_sig:
            logger.warning("Hybrid signature missing Dilithium3 portion")
            return False

        # Verify Ed25519
        ed_ok = False
        try:
            ed_pub.verify(ed_sig, message)
            ed_ok = True
        except Exception as e:
            logger.debug("Ed25519 verification failed: %s", e)

        # Verify Dilithium3 / ML-DSA-65
        dil_ok = False
        try:
            alg = _resolve_sig_algorithm()
            if alg is None:
                logger.warning("Cannot verify: no PQC signature algorithm available")
            else:
                with oqs.Signature(alg) as verifier:
                    dil_ok = verifier.verify(message, dil_sig, dil_pub)
        except Exception as e:
            logger.debug("PQC signature verification failed: %s", e)

        if ed_ok and dil_ok:
            logger.debug("Hybrid signature verified successfully")
        else:
            logger.warning(
                "Hybrid signature verification failed: ed_ok=%s, dil_ok=%s",
                ed_ok, dil_ok
            )

        # BOTH must succeed for the hybrid to be valid
        return ed_ok and dil_ok

    @staticmethod
    def parse_combined_pub(combined_pub: bytes) -> tuple:
        """
        Parse a combined public key into its components.

        Args:
            combined_pub: Combined public key bytes from generate_keys()

        Returns:
            (ed_pub_bytes, dil_pub_bytes) tuple
        """
        offset = 0

        ed_len = struct.unpack(">H", combined_pub[offset:offset + 2])[0]
        offset += 2
        ed_pub_bytes = combined_pub[offset:offset + ed_len]
        offset += ed_len

        dil_len = struct.unpack(">H", combined_pub[offset:offset + 2])[0]
        offset += 2
        dil_pub_bytes = combined_pub[offset:offset + dil_len]

        return ed_pub_bytes, dil_pub_bytes

    @staticmethod
    def load_ed_public_key(ed_pub_bytes: bytes) -> Ed25519PublicKey:
        """Load an Ed25519 public key from raw bytes."""
        return Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
