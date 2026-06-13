"""Comprehensive unit tests for services/pqc_signatures.py — Hybrid Digital Signatures.

Tests the HybridSigner class that combines Ed25519 with CRYSTALS-Dilithium3 (ML-DSA-65)
for post-quantum secure digital signatures.

These tests require liboqs to be available. Tests are skipped if liboqs is not installed.
"""

import struct
import pytest
from unittest.mock import patch, MagicMock

# Check if liboqs is available before importing
try:
    import oqs
    from services.pqc_signatures import HybridSigner, _resolve_sig_algorithm, SIG_ALGORITHM
    _OQS_AVAILABLE = True
except (ImportError, RuntimeError, OSError):
    _OQS_AVAILABLE = False

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)


pytestmark = pytest.mark.skipif(
    not _OQS_AVAILABLE,
    reason="liboqs not available — hybrid signature tests require liboqs native library"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_hybrid_keys():
    """Generate a full set of hybrid signing keys for testing."""
    return HybridSigner.generate_keys()


# ---------------------------------------------------------------------------
# Key Generation Tests
# ---------------------------------------------------------------------------

class TestHybridSignerKeyGeneration:
    """Tests for HybridSigner.generate_keys()."""

    def test_generate_keys_returns_dict(self):
        """generate_keys() should return a dict with expected keys."""
        keys = _generate_hybrid_keys()
        assert isinstance(keys, dict)
        assert 'ed_priv' in keys
        assert 'ed_pub_bytes' in keys
        assert 'dil_priv' in keys
        assert 'dil_pub_bytes' in keys
        assert 'combined_pub' in keys

    def test_ed25519_key_sizes(self):
        """Ed25519 keys should have correct sizes."""
        keys = _generate_hybrid_keys()
        assert isinstance(keys['ed_priv'], Ed25519PrivateKey)
        assert len(keys['ed_pub_bytes']) == 32

    def test_dilithium_keys_are_bytes(self):
        """Dilithium keys should be bytes."""
        keys = _generate_hybrid_keys()
        assert isinstance(keys['dil_priv'], bytes)
        assert isinstance(keys['dil_pub_bytes'], bytes)
        assert len(keys['dil_priv']) > 0
        assert len(keys['dil_pub_bytes']) > 0

    def test_combined_pub_format(self):
        """Combined public key should follow [len(2)|ed_pub|len(2)|dil_pub] format."""
        keys = _generate_hybrid_keys()
        combined = keys['combined_pub']
        assert isinstance(combined, bytes)

        # Parse manually
        offset = 0
        ed_len = struct.unpack(">H", combined[offset:offset+2])[0]
        offset += 2
        assert ed_len == 32  # Ed25519 public key is always 32 bytes
        ed_pub = combined[offset:offset+ed_len]
        offset += ed_len
        assert ed_pub == keys['ed_pub_bytes']

        dil_len = struct.unpack(">H", combined[offset:offset+2])[0]
        offset += 2
        dil_pub = combined[offset:offset+dil_len]
        assert dil_pub == keys['dil_pub_bytes']

    def test_generate_keys_unique(self):
        """Each key generation should produce unique keys."""
        keys1 = _generate_hybrid_keys()
        keys2 = _generate_hybrid_keys()
        assert keys1['ed_pub_bytes'] != keys2['ed_pub_bytes']
        assert keys1['dil_pub_bytes'] != keys2['dil_pub_bytes']


# ---------------------------------------------------------------------------
# Signing Tests
# ---------------------------------------------------------------------------

class TestHybridSignerSign:
    """Tests for HybridSigner.sign()."""

    def test_sign_returns_bytes(self):
        """sign() should return bytes."""
        keys = _generate_hybrid_keys()
        message = b"Hello, World!"
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])
        assert isinstance(signature, bytes)

    def test_sign_format(self):
        """Signature should follow [ed_sig_len(2)|ed_sig|dil_sig] format."""
        keys = _generate_hybrid_keys()
        message = b"Test message for signature format"
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])

        ed_len = struct.unpack(">H", signature[:2])[0]
        assert ed_len == 64  # Ed25519 signatures are always 64 bytes

        ed_sig = signature[2:2+ed_len]
        dil_sig = signature[2+ed_len:]
        assert len(ed_sig) == 64
        assert len(dil_sig) > 0

    def test_sign_different_messages_different_signatures(self):
        """Different messages should produce different signatures."""
        keys = _generate_hybrid_keys()
        sig1 = HybridSigner.sign(b"Message A", keys['ed_priv'], keys['dil_priv'])
        sig2 = HybridSigner.sign(b"Message B", keys['ed_priv'], keys['dil_priv'])
        assert sig1 != sig2

    def test_sign_same_message_deterministic_ed25519(self):
        """Ed25519 portion should be deterministic for the same message+key."""
        keys = _generate_hybrid_keys()
        msg = b"Deterministic test"
        sig1 = HybridSigner.sign(msg, keys['ed_priv'], keys['dil_priv'])
        sig2 = HybridSigner.sign(msg, keys['ed_priv'], keys['dil_priv'])

        # Ed25519 signatures are deterministic
        ed_len1 = struct.unpack(">H", sig1[:2])[0]
        ed_len2 = struct.unpack(">H", sig2[:2])[0]
        assert ed_len1 == ed_len2
        assert sig1[2:2+ed_len1] == sig2[2:2+ed_len2]

    def test_sign_empty_message(self):
        """Signing an empty message should work."""
        keys = _generate_hybrid_keys()
        signature = HybridSigner.sign(b"", keys['ed_priv'], keys['dil_priv'])
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_large_message(self):
        """Signing a large message should work."""
        keys = _generate_hybrid_keys()
        message = b"A" * 1_000_000
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])
        assert isinstance(signature, bytes)


# ---------------------------------------------------------------------------
# Verification Tests
# ---------------------------------------------------------------------------

class TestHybridSignerVerify:
    """Tests for HybridSigner.verify()."""

    def test_verify_valid_signature(self):
        """A valid signature should verify successfully."""
        keys = _generate_hybrid_keys()
        message = b"Verify this message"
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])

        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])
        result = HybridSigner.verify(message, signature, ed_pub, keys['dil_pub_bytes'])
        assert result is True

    def test_verify_wrong_message(self):
        """Verification should fail for a different message."""
        keys = _generate_hybrid_keys()
        message = b"Original message"
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])

        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])
        result = HybridSigner.verify(b"Wrong message", signature, ed_pub, keys['dil_pub_bytes'])
        assert result is False

    def test_verify_wrong_ed25519_key(self):
        """Verification should fail with wrong Ed25519 public key."""
        keys1 = _generate_hybrid_keys()
        keys2 = _generate_hybrid_keys()
        message = b"Key mismatch test"
        signature = HybridSigner.sign(message, keys1['ed_priv'], keys1['dil_priv'])

        # Use wrong Ed25519 key
        wrong_ed_pub = Ed25519PublicKey.from_public_bytes(keys2['ed_pub_bytes'])
        result = HybridSigner.verify(message, signature, wrong_ed_pub, keys1['dil_pub_bytes'])
        assert result is False

    def test_verify_wrong_dilithium_key(self):
        """Verification should fail with wrong Dilithium public key."""
        keys1 = _generate_hybrid_keys()
        keys2 = _generate_hybrid_keys()
        message = b"Key mismatch test"
        signature = HybridSigner.sign(message, keys1['ed_priv'], keys1['dil_priv'])

        ed_pub = Ed25519PublicKey.from_public_bytes(keys1['ed_pub_bytes'])
        result = HybridSigner.verify(message, signature, ed_pub, keys2['dil_pub_bytes'])
        assert result is False

    def test_verify_tampered_signature(self):
        """Verification should fail for a tampered signature."""
        keys = _generate_hybrid_keys()
        message = b"Tamper test"
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])

        # Tamper with the signature
        tampered = bytearray(signature)
        tampered[-1] ^= 0xFF
        tampered = bytes(tampered)

        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])
        result = HybridSigner.verify(message, tampered, ed_pub, keys['dil_pub_bytes'])
        assert result is False

    def test_verify_truncated_signature(self):
        """Verification should fail for a truncated signature."""
        keys = _generate_hybrid_keys()
        message = b"Truncate test"
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])

        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])
        result = HybridSigner.verify(message, signature[:10], ed_pub, keys['dil_pub_bytes'])
        assert result is False

    def test_verify_empty_signature(self):
        """Verification should fail for an empty signature."""
        keys = _generate_hybrid_keys()
        message = b"Empty sig test"
        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])
        result = HybridSigner.verify(message, b"", ed_pub, keys['dil_pub_bytes'])
        assert result is False

    def test_verify_too_short_signature(self):
        """Verification should fail for a signature shorter than 2 bytes."""
        keys = _generate_hybrid_keys()
        message = b"Short sig test"
        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])
        result = HybridSigner.verify(message, b"\x00", ed_pub, keys['dil_pub_bytes'])
        assert result is False

    def test_verify_multiple_messages(self):
        """Verify multiple messages with the same key pair."""
        keys = _generate_hybrid_keys()
        ed_pub = Ed25519PublicKey.from_public_bytes(keys['ed_pub_bytes'])

        messages = [
            b"Message 1",
            b"Message 2",
            b"Message 3",
            b"Longer message with more content",
            b"",
            b"\x00" * 100,
        ]

        for msg in messages:
            sig = HybridSigner.sign(msg, keys['ed_priv'], keys['dil_priv'])
            assert HybridSigner.verify(msg, sig, ed_pub, keys['dil_pub_bytes']) is True


# ---------------------------------------------------------------------------
# Combined Public Key Parsing Tests
# ---------------------------------------------------------------------------

class TestHybridSignerParseCombinedPub:
    """Tests for HybridSigner.parse_combined_pub()."""

    def test_parse_roundtrip(self):
        """parse_combined_pub() should extract the original keys."""
        keys = _generate_hybrid_keys()
        ed_pub, dil_pub = HybridSigner.parse_combined_pub(keys['combined_pub'])
        assert ed_pub == keys['ed_pub_bytes']
        assert dil_pub == keys['dil_pub_bytes']

    def test_parse_multiple_keys(self):
        """Parsing should work for multiple different key pairs."""
        for _ in range(3):
            keys = _generate_hybrid_keys()
            ed_pub, dil_pub = HybridSigner.parse_combined_pub(keys['combined_pub'])
            assert ed_pub == keys['ed_pub_bytes']
            assert dil_pub == keys['dil_pub_bytes']


# ---------------------------------------------------------------------------
# Load Ed25519 Public Key Tests
# ---------------------------------------------------------------------------

class TestHybridSignerLoadEdPublicKey:
    """Tests for HybridSigner.load_ed_public_key()."""

    def test_load_valid_key(self):
        """Should load a valid Ed25519 public key from bytes."""
        keys = _generate_hybrid_keys()
        pub = HybridSigner.load_ed_public_key(keys['ed_pub_bytes'])
        assert isinstance(pub, Ed25519PublicKey)

    def test_load_invalid_key_raises(self):
        """Should raise on invalid Ed25519 public key bytes (wrong length)."""
        with pytest.raises(Exception):
            HybridSigner.load_ed_public_key(b"\x00" * 16)


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestHybridSignerIntegration:
    """End-to-end integration tests."""

    def test_sign_and_verify_roundtrip(self):
        """Full roundtrip: generate keys, sign, verify."""
        keys = _generate_hybrid_keys()
        message = b"Full integration test message"

        # Sign
        signature = HybridSigner.sign(message, keys['ed_priv'], keys['dil_priv'])

        # Parse combined pub
        ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(keys['combined_pub'])

        # Load Ed25519 public key
        ed_pub = HybridSigner.load_ed_public_key(ed_pub_bytes)

        # Verify
        result = HybridSigner.verify(message, signature, ed_pub, dil_pub_bytes)
        assert result is True

    def test_cross_key_verification_fails(self):
        """Signing with key A and verifying with key B should fail."""
        keys_a = _generate_hybrid_keys()
        keys_b = _generate_hybrid_keys()
        message = b"Cross-key test"

        signature = HybridSigner.sign(message, keys_a['ed_priv'], keys_a['dil_priv'])

        ed_pub_b = HybridSigner.load_ed_public_key(keys_b['ed_pub_bytes'])
        result = HybridSigner.verify(
            message, signature, ed_pub_b, keys_b['dil_pub_bytes']
        )
        assert result is False


# ---------------------------------------------------------------------------
# crypto.py Integration Tests
# ---------------------------------------------------------------------------

class TestCryptoHybridIntegration:
    """Tests for crypto.py hybrid_sign() and hybrid_verify() wrappers."""

    def test_crypto_hybrid_sign_and_verify(self):
        """crypto.hybrid_sign() and crypto.hybrid_verify() should work together."""
        from crypto import hybrid_sign, hybrid_verify
        keys = _generate_hybrid_keys()
        message = b"Test message for crypto integration"

        signature = hybrid_sign(message, keys['ed_priv'], keys['dil_priv'])
        assert isinstance(signature, bytes)

        result = hybrid_verify(
            message, signature,
            keys['ed_pub_bytes'], keys['dil_pub_bytes']
        )
        assert result is True

    def test_crypto_hybrid_verify_wrong_message(self):
        """crypto.hybrid_verify() should fail for wrong message."""
        from crypto import hybrid_sign, hybrid_verify
        keys = _generate_hybrid_keys()
        message = b"Original"

        signature = hybrid_sign(message, keys['ed_priv'], keys['dil_priv'])

        result = hybrid_verify(
            b"Wrong", signature,
            keys['ed_pub_bytes'], keys['dil_pub_bytes']
        )
        assert result is False


# ---------------------------------------------------------------------------
# File Signature Integration Tests
# ---------------------------------------------------------------------------

class TestFileHybridSignature:
    """Tests for hybrid signatures in file operations."""

    def test_file_encrypt_decrypt_with_hybrid_sig(self, tmp_path):
        """file_encrypt_shared and file_decrypt_shared should support hybrid signatures."""
        import tempfile
        from services.file_service import file_encrypt_shared, file_decrypt_shared

        keys = _generate_hybrid_keys()
        shared_secret = secrets.token_bytes(32)

        # Create test file
        input_path = str(tmp_path / "test_input.txt")
        with open(input_path, 'wb') as f:
            f.write(b"Test file content for hybrid signature verification")

        output_encrypted = str(tmp_path / "test_encrypted.enc")
        output_decrypted = str(tmp_path / "test_decrypted.txt")

        # Encrypt with hybrid signature
        file_encrypt_shared(
            input_path, output_encrypted, shared_secret,
            sign=True,
            hybrid_ed_priv=keys['ed_priv'],
            hybrid_dil_priv=keys['dil_priv'],
        )

        # Build secrets dict for decryption
        import hashlib
        fp = hashlib.sha256(shared_secret).digest()[:16]
        secrets_dict = {fp: (shared_secret, "TestOwner")}

        # Build hybrid verification list
        friends_hybrid = [
            ("TestSigner", keys['ed_pub_bytes'], keys['dil_pub_bytes'])
        ]

        # Decrypt and verify
        sig_msg = file_decrypt_shared(
            output_encrypted, output_decrypted,
            secrets_dict,
            friends_hybrid=friends_hybrid,
        )

        # Check decrypted content
        with open(output_decrypted, 'rb') as f:
            assert f.read() == b"Test file content for hybrid signature verification"

        # Check signature message
        assert "Hybrid Signature Verified" in sig_msg
        assert "TestSigner" in sig_msg


import secrets  # for file tests
