"""Comprehensive unit tests for crypto.py – Hybrid Encryption module."""

import struct
import time
import secrets
import pytest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from crypto import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    TIME_STEP,
    WINDOW_SIZE,
    SELF_DESTRUCT_FLAG,
    derive_time_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    rsa_encrypt_key,
    rsa_decrypt_key,
    rsa_sign,
    rsa_verify,
    sha256_fingerprint,
    pubkey_to_pem,
    encrypt_message,
    decrypt_message,
    peek_flags,
    _pack_bytes,
    _unpack_bytes,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rsa_keypair():
    """Generate a 3072-bit RSA key pair for testing."""
    priv = rsa.generate_private_key(65537, 3072, default_backend())
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def const_key():
    """A fixed 32-byte symmetric key for time-based encryption tests."""
    return secrets.token_bytes(AES_KEY_SIZE)


@pytest.fixture
def sample_plaintext():
    return b"Hello, Enigma! This is a secret message."


# ---------------------------------------------------------------------------
# Tests: _pack_bytes / _unpack_bytes
# ---------------------------------------------------------------------------

class TestPackUnpackBytes:
    def test_roundtrip(self):
        data = b"test data"
        packed = _pack_bytes(data)
        unpacked, offset = _unpack_bytes(packed, 0)
        assert unpacked == data
        assert offset == len(packed)

    def test_empty_data(self):
        packed = _pack_bytes(b"")
        unpacked, offset = _unpack_bytes(packed, 0)
        assert unpacked == b""
        assert offset == 2

    def test_large_data(self):
        data = secrets.token_bytes(1000)
        packed = _pack_bytes(data)
        unpacked, offset = _unpack_bytes(packed, 0)
        assert unpacked == data

    def test_unpack_with_offset(self):
        prefix = b"\x00\x00\x00"
        data = b"payload"
        packed = prefix + _pack_bytes(data)
        unpacked, offset = _unpack_bytes(packed, len(prefix))
        assert unpacked == data

    def test_unpack_invalid_short_header(self):
        with pytest.raises(ValueError, match="Invalid packet format"):
            _unpack_bytes(b"\x00", 0)

    def test_unpack_invalid_length_exceeds_packet(self):
        # Header says 100 bytes but only 2 available
        bad_packet = struct.pack(">H", 100) + b"ab"
        with pytest.raises(ValueError, match="Invalid packet format"):
            _unpack_bytes(bad_packet, 0)


# ---------------------------------------------------------------------------
# Tests: derive_time_key
# ---------------------------------------------------------------------------

class TestDeriveTimeKey:
    def test_deterministic(self, const_key):
        ts = 1700000000
        k1 = derive_time_key(const_key, ts)
        k2 = derive_time_key(const_key, ts)
        assert k1 == k2
        assert len(k1) == AES_KEY_SIZE

    def test_different_timestamps_different_keys(self, const_key):
        k1 = derive_time_key(const_key, 1700000000)
        k2 = derive_time_key(const_key, 1700000030)
        assert k1 != k2

    def test_same_time_step_same_key(self, const_key):
        """Timestamps within the same TIME_STEP bucket must yield the same key."""
        base = 1700000000
        aligned = base // TIME_STEP * TIME_STEP
        k1 = derive_time_key(const_key, aligned)
        k2 = derive_time_key(const_key, aligned + TIME_STEP - 1)
        assert k1 == k2

    def test_different_secrets_different_keys(self):
        ts = 1700000000
        k1 = derive_time_key(secrets.token_bytes(32), ts)
        k2 = derive_time_key(secrets.token_bytes(32), ts)
        assert k1 != k2


# ---------------------------------------------------------------------------
# Tests: AES-GCM encrypt / decrypt
# ---------------------------------------------------------------------------

class TestAESGCM:
    def test_roundtrip(self, const_key, sample_plaintext):
        ct = aes_gcm_encrypt(const_key, sample_plaintext)
        pt = aes_gcm_decrypt(const_key, ct)
        assert pt == sample_plaintext

    def test_nonce_prepended(self, const_key, sample_plaintext):
        ct = aes_gcm_encrypt(const_key, sample_plaintext)
        assert len(ct) == NONCE_SIZE + len(sample_plaintext) + 16  # tag=16

    def test_different_ciphertext_each_time(self, const_key, sample_plaintext):
        ct1 = aes_gcm_encrypt(const_key, sample_plaintext)
        ct2 = aes_gcm_encrypt(const_key, sample_plaintext)
        assert ct1 != ct2  # random nonce

    def test_wrong_key_fails(self, sample_plaintext):
        key1 = secrets.token_bytes(AES_KEY_SIZE)
        key2 = secrets.token_bytes(AES_KEY_SIZE)
        ct = aes_gcm_encrypt(key1, sample_plaintext)
        with pytest.raises(Exception):
            aes_gcm_decrypt(key2, ct)

    def test_tampered_ciphertext_fails(self, const_key, sample_plaintext):
        ct = aes_gcm_encrypt(const_key, sample_plaintext)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            aes_gcm_decrypt(const_key, bytes(tampered))

    def test_too_short_ciphertext(self, const_key):
        with pytest.raises(ValueError, match="Ciphertext too short"):
            aes_gcm_decrypt(const_key, b"\x00" * (NONCE_SIZE + 15))

    def test_empty_plaintext(self, const_key):
        ct = aes_gcm_encrypt(const_key, b"")
        pt = aes_gcm_decrypt(const_key, ct)
        assert pt == b""


# ---------------------------------------------------------------------------
# Tests: RSA encrypt/decrypt key
# ---------------------------------------------------------------------------

class TestRSAEncryptDecryptKey:
    def test_roundtrip(self, rsa_keypair):
        priv, pub = rsa_keypair
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        encrypted = rsa_encrypt_key(aes_key, pub)
        decrypted = rsa_decrypt_key(encrypted, priv)
        assert decrypted == aes_key

    def test_wrong_private_key_fails(self, rsa_keypair):
        _, pub = rsa_keypair
        other_priv = rsa.generate_private_key(65537, 3072, default_backend())
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        encrypted = rsa_encrypt_key(aes_key, pub)
        with pytest.raises(Exception):
            rsa_decrypt_key(encrypted, other_priv)


# ---------------------------------------------------------------------------
# Tests: RSA sign / verify
# ---------------------------------------------------------------------------

class TestRSASignVerify:
    def test_valid_signature(self, rsa_keypair):
        priv, pub = rsa_keypair
        data = b"message to sign"
        sig = rsa_sign(data, priv)
        assert rsa_verify(data, sig, pub) is True

    def test_tampered_data_fails(self, rsa_keypair):
        priv, pub = rsa_keypair
        sig = rsa_sign(b"original", priv)
        assert rsa_verify(b"tampered", sig, pub) is False

    def test_wrong_key_fails(self, rsa_keypair):
        priv, _ = rsa_keypair
        other_pub = rsa.generate_private_key(65537, 3072, default_backend()).public_key()
        sig = rsa_sign(b"data", priv)
        assert rsa_verify(b"data", sig, other_pub) is False

    def test_empty_data(self, rsa_keypair):
        priv, pub = rsa_keypair
        sig = rsa_sign(b"", priv)
        assert rsa_verify(b"", sig, pub) is True


# ---------------------------------------------------------------------------
# Tests: sha256_fingerprint & pubkey_to_pem
# ---------------------------------------------------------------------------

class TestFingerprintAndPEM:
    def test_fingerprint_length(self):
        fp = sha256_fingerprint(b"test")
        assert len(fp) == 16

    def test_fingerprint_deterministic(self):
        assert sha256_fingerprint(b"abc") == sha256_fingerprint(b"abc")

    def test_fingerprint_different_inputs(self):
        assert sha256_fingerprint(b"a") != sha256_fingerprint(b"b")

    def test_pubkey_to_pem(self, rsa_keypair):
        _, pub = rsa_keypair
        pem = pubkey_to_pem(pub)
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert "-----END PUBLIC KEY-----" in pem


# ---------------------------------------------------------------------------
# Tests: encrypt_message / decrypt_message (time-based)
# ---------------------------------------------------------------------------

class TestEncryptDecryptMessage:
    def test_basic_roundtrip(self, const_key, sample_plaintext):
        now = int(time.time())
        packet, ts = encrypt_message(sample_plaintext, const_key, now)
        result = decrypt_message(packet, const_key, now=now)
        assert sample_plaintext.decode() in result

    def test_signed_message(self, const_key, rsa_keypair, sample_plaintext):
        priv, pub = rsa_keypair
        now = int(time.time())
        packet, ts = encrypt_message(
            sample_plaintext, const_key, now,
            sign=True, my_priv=priv
        )
        friends = [("Alice", pub)]
        result = decrypt_message(packet, const_key, friends=friends, now=now)
        assert "Signature verified from Alice" in result

    def test_unsigned_message_no_sig_line(self, const_key, sample_plaintext):
        now = int(time.time())
        packet, _ = encrypt_message(sample_plaintext, const_key, now, sign=False)
        result = decrypt_message(packet, const_key, now=now)
        assert "Signature" not in result

    def test_friend_encrypted_roundtrip(self, rsa_keypair, sample_plaintext):
        priv, pub = rsa_keypair
        now = int(time.time())
        packet, _ = encrypt_message(
            sample_plaintext, b"\x00" * 32, now,
            encrypt_for_friend_pub=pub
        )
        result = decrypt_message(packet, b"", my_priv=priv, now=now)
        assert sample_plaintext.decode() in result

    def test_friend_encrypted_without_priv_key_raises(self, rsa_keypair, sample_plaintext):
        _, pub = rsa_keypair
        now = int(time.time())
        packet, _ = encrypt_message(
            sample_plaintext, b"\x00" * 32, now,
            encrypt_for_friend_pub=pub
        )
        with pytest.raises(ValueError, match="Private key required"):
            decrypt_message(packet, b"", now=now)

    def test_self_destruct_not_expired(self, const_key, sample_plaintext):
        now = int(time.time())
        packet, _ = encrypt_message(
            sample_plaintext, const_key, now,
            self_destruct_seconds=3600
        )
        result = decrypt_message(packet, const_key, now=now)
        assert sample_plaintext.decode() in result

    def test_self_destruct_expired(self, const_key, sample_plaintext):
        old_ts = int(time.time()) - 7200  # 2 hours ago
        packet, _ = encrypt_message(
            sample_plaintext, const_key, old_ts,
            self_destruct_seconds=3600  # expires after 1 hour
        )
        with pytest.raises(ValueError, match="self-destructed"):
            decrypt_message(packet, const_key, now=int(time.time()))

    def test_message_outside_time_window(self, const_key, sample_plaintext):
        # With WINDOW_SIZE=2, messages older than ±2 steps (±60s) must be rejected
        old_ts = int(time.time()) - TIME_STEP * (WINDOW_SIZE + 5)
        packet, _ = encrypt_message(sample_plaintext, const_key, old_ts)
        with pytest.raises(ValueError, match="outside acceptable window"):
            decrypt_message(packet, const_key, now=int(time.time()))

    def test_message_within_narrow_window(self, const_key, sample_plaintext):
        # Verify that messages within ±2 steps (±60s) are still accepted
        now = int(time.time())
        recent_ts = now - TIME_STEP * WINDOW_SIZE  # exactly at boundary
        packet, _ = encrypt_message(sample_plaintext, const_key, recent_ts)
        result = decrypt_message(packet, const_key, now=now)
        assert sample_plaintext.decode() in result

    def test_wrong_shared_secret_fails(self, sample_plaintext):
        key1 = secrets.token_bytes(AES_KEY_SIZE)
        key2 = secrets.token_bytes(AES_KEY_SIZE)
        now = int(time.time())
        packet, _ = encrypt_message(sample_plaintext, key1, now)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_message(packet, key2, now=now)

    def test_invalid_packet_empty(self):
        with pytest.raises(ValueError, match="Invalid message format"):
            decrypt_message(b"", b"key")

    def test_signed_and_self_destruct_combined(self, const_key, rsa_keypair, sample_plaintext):
        priv, pub = rsa_keypair
        now = int(time.time())
        packet, _ = encrypt_message(
            sample_plaintext, const_key, now,
            sign=True, my_priv=priv,
            self_destruct_seconds=3600
        )
        friends = [("Bob", pub)]
        result = decrypt_message(packet, const_key, friends=friends, now=now)
        assert "Signature verified from Bob" in result
        assert sample_plaintext.decode() in result

    def test_invalid_signature_warning(self, const_key, rsa_keypair, sample_plaintext):
        """Sign with one key, verify against another → warning."""
        priv1, _ = rsa_keypair
        other_pub = rsa.generate_private_key(65537, 3072, default_backend()).public_key()
        now = int(time.time())
        packet, _ = encrypt_message(
            sample_plaintext, const_key, now,
            sign=True, my_priv=priv1
        )
        friends = [("Eve", other_pub)]
        result = decrypt_message(packet, const_key, friends=friends, now=now)
        assert "INVALID" in result


# ---------------------------------------------------------------------------
# Tests: peek_flags
# ---------------------------------------------------------------------------

class TestPeekFlags:
    def test_normal_flags(self):
        assert peek_flags(bytes([0x05]) + b"data") == 0x05

    def test_zero_flags(self):
        assert peek_flags(bytes([0x00])) == 0

    def test_all_flags_set(self):
        assert peek_flags(bytes([0xFF])) == 0xFF

    def test_empty_packet_raises(self):
        with pytest.raises(ValueError, match="Packet too short"):
            peek_flags(b"")


# ---------------------------------------------------------------------------
# Tests: encrypt_message flags correctness
# ---------------------------------------------------------------------------

class TestEncryptMessageFlags:
    def test_no_flags(self, const_key):
        packet, _ = encrypt_message(b"test", const_key, time.time())
        from src.constants import CRYPTO_CONSTANTS
        KEY_HINT_FLAG = CRYPTO_CONSTANTS["KEY_HINT_FLAG"]
        assert packet[0] == KEY_HINT_FLAG

    def test_sign_flag(self, const_key, rsa_keypair):
        priv, _ = rsa_keypair
        packet, _ = encrypt_message(b"test", const_key, time.time(), sign=True, my_priv=priv)
        assert packet[0] & 1

    def test_friend_encrypt_flag(self, rsa_keypair):
        _, pub = rsa_keypair
        packet, _ = encrypt_message(
            b"test", b"\x00" * 32, time.time(),
            encrypt_for_friend_pub=pub
        )
        assert packet[0] & 2

    def test_self_destruct_flag(self, const_key):
        packet, _ = encrypt_message(
            b"test", const_key, time.time(),
            self_destruct_seconds=60
        )
        assert packet[0] & SELF_DESTRUCT_FLAG
