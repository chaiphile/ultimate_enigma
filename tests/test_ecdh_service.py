"""Comprehensive unit tests for services/ecdh_service.py – X25519 ECDH."""

import base64
import secrets
import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from services.ecdh_service import ECDHService


class TestGenerateKeypair:
    def test_returns_tuple(self):
        priv, pub = ECDHService.generate_keypair()
        assert isinstance(priv, X25519PrivateKey)
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_unique_each_call(self):
        _, pub1 = ECDHService.generate_keypair()
        _, pub2 = ECDHService.generate_keypair()
        assert pub1 != pub2


class TestPrivateToPublicBytes:
    def test_length(self):
        priv = ECDHService.generate_private_key()
        pub = ECDHService.private_to_public_bytes(priv)
        assert len(pub) == 32

    def test_deterministic(self):
        priv = ECDHService.generate_private_key()
        p1 = ECDHService.private_to_public_bytes(priv)
        p2 = ECDHService.private_to_public_bytes(priv)
        assert p1 == p2


class TestPublicBytesToKey:
    def test_valid_32_bytes(self):
        priv = ECDHService.generate_private_key()
        raw = ECDHService.private_to_public_bytes(priv)
        key = ECDHService.public_bytes_to_key(raw)
        assert key is not None

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ECDHService.public_bytes_to_key(b"\x00" * 31)
        with pytest.raises(ValueError, match="32 bytes"):
            ECDHService.public_bytes_to_key(b"\x00" * 33)


class TestComputeSharedSecret:
    def test_symmetric(self):
        """Both parties must derive the same shared secret."""
        priv_a, pub_a = ECDHService.generate_keypair()
        priv_b, pub_b = ECDHService.generate_keypair()

        ss_ab = ECDHService.compute_shared_secret(priv_a, pub_b)
        ss_ba = ECDHService.compute_shared_secret(priv_b, pub_a)
        assert ss_ab == ss_ba
        assert len(ss_ab) == 32

    def test_different_peers_different_secrets(self):
        priv_a, _ = ECDHService.generate_keypair()
        _, pub_b = ECDHService.generate_keypair()
        _, pub_c = ECDHService.generate_keypair()

        ss1 = ECDHService.compute_shared_secret(priv_a, pub_b)
        ss2 = ECDHService.compute_shared_secret(priv_a, pub_c)
        assert ss1 != ss2


class TestDeriveKey:
    def test_output_length(self):
        ss = secrets.token_bytes(32)
        key = ECDHService.derive_key(ss)
        assert len(key) == 32

    def test_deterministic(self):
        ss = secrets.token_bytes(32)
        k1 = ECDHService.derive_key(ss)
        k2 = ECDHService.derive_key(ss)
        assert k1 == k2

    def test_different_inputs_different_keys(self):
        k1 = ECDHService.derive_key(secrets.token_bytes(32))
        k2 = ECDHService.derive_key(secrets.token_bytes(32))
        assert k1 != k2

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ECDHService.derive_key(b"\x00" * 16)


class TestEncodeDecodePublicKey:
    def test_roundtrip(self):
        raw = secrets.token_bytes(32)
        encoded = ECDHService.encode_public_key(raw)
        decoded = ECDHService.decode_public_key(encoded)
        assert decoded == raw

    def test_base64_format(self):
        raw = secrets.token_bytes(32)
        encoded = ECDHService.encode_public_key(raw)
        # Must be valid base64
        assert base64.b64decode(encoded) == raw

    def test_decode_invalid_base64_raises(self):
        with pytest.raises(ValueError, match="Invalid Base64"):
            ECDHService.decode_public_key("!!!not-base64!!!")

    def test_decode_wrong_length_raises(self):
        short = base64.b64encode(b"\x00" * 16).decode()
        with pytest.raises(ValueError, match="Invalid Base64"):
            ECDHService.decode_public_key(short)


class TestFingerprint:
    def test_length(self):
        raw = secrets.token_bytes(32)
        fp = ECDHService.fingerprint(raw)
        assert len(fp) == 16

    def test_deterministic(self):
        raw = secrets.token_bytes(32)
        assert ECDHService.fingerprint(raw) == ECDHService.fingerprint(raw)

    def test_different_keys_different_fingerprints(self):
        fp1 = ECDHService.fingerprint(secrets.token_bytes(32))
        fp2 = ECDHService.fingerprint(secrets.token_bytes(32))
        assert fp1 != fp2


class TestPerformExchange:
    def test_full_exchange(self):
        """Two parties perform a full exchange and derive the same key."""
        priv_a, pub_a = ECDHService.generate_keypair()
        priv_b, pub_b = ECDHService.generate_keypair()

        derived_a, our_pub_a = ECDHService.perform_exchange(pub_b, priv_a)
        derived_b, our_pub_b = ECDHService.perform_exchange(pub_a, priv_b)

        assert derived_a == derived_b
        assert len(derived_a) == 32
        assert our_pub_a == pub_a
        assert our_pub_b == pub_b

    def test_ephemeral_when_no_private_given(self):
        _, peer_pub = ECDHService.generate_keypair()
        derived, our_pub = ECDHService.perform_exchange(peer_pub)
        assert len(derived) == 32
        assert len(our_pub) == 32
