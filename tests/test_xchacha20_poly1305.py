"""Unit tests for services/xchacha20_poly1305.py – XChaCha20-Poly1305 AEAD."""

import secrets
import pytest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from services.xchacha20_poly1305 import (
    XChaCha20Poly1305,
    _hchacha20_block,
    _rotl32,
    _quarter_round,
    generate_nonce,
    XCHACHA20_KEY_SIZE,
    XCHACHA20_NONCE_SIZE,
    XCHACHA20_TAG_SIZE,
    run_self_test,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def key():
    return secrets.token_bytes(XCHACHA20_KEY_SIZE)


@pytest.fixture
def nonce():
    return secrets.token_bytes(XCHACHA20_NONCE_SIZE)


@pytest.fixture
def plaintext():
    return b"Hello, XChaCha20-Poly1305!"


# ---------------------------------------------------------------------------
# Tests: _rotl32
# ---------------------------------------------------------------------------

class TestRotl32:
    def test_zero(self):
        assert _rotl32(0, 1) == 0

    def test_one_left(self):
        assert _rotl32(1, 1) == 2

    def test_wraparound(self):
        assert _rotl32(0x80000000, 1) == 1

    def test_no_rotation(self):
        assert _rotl32(0xDEADBEEF, 0) == 0xDEADBEEF

    def test_32_bits_full_rotation(self):
        assert _rotl32(0x12345678, 32) == 0x12345678


# ---------------------------------------------------------------------------
# Tests: _quarter_round
# ---------------------------------------------------------------------------

class TestQuarterRound:
    def test_quarter_round_produces_expected_output(self):
        state = [
            0x11111111, 0x01020304, 0x9b8d6528, 0x2e4f6c39,
            0x11111111, 0x01020304, 0x9b8d6528, 0x2e4f6c39,
            0x11111111, 0x01020304, 0x9b8d6528, 0x2e4f6c39,
            0x11111111, 0x01020304, 0x9b8d6528, 0x2e4f6c39,
        ]
        _quarter_round(state, 0, 1, 2, 3)
        assert state[0] == 0xcc3b1540
        assert state[1] == 0x655f89c8
        assert state[2] == 0x2ae2be38
        assert state[3] == 0x17291cb4

    def test_mutation(self):
        state = [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        original = state.copy()
        _quarter_round(state, 0, 1, 2, 3)
        assert state != original


# ---------------------------------------------------------------------------
# Tests: _hchacha20_block
# ---------------------------------------------------------------------------

class TestHChaCha20Block:
    def test_wrong_key_length(self):
        with pytest.raises(ValueError, match="key must be 32 bytes"):
            _hchacha20_block(b"\x00" * 16, b"\x00" * 16)

    def test_wrong_nonce_length(self):
        with pytest.raises(ValueError, match="nonce must be 16 bytes"):
            _hchacha20_block(b"\x00" * 32, b"\x00" * 8)

    def test_returns_32_bytes(self):
        subkey = _hchacha20_block(secrets.token_bytes(32), secrets.token_bytes(16))
        assert len(subkey) == 32

    def test_deterministic(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        sk1 = _hchacha20_block(key, nonce)
        sk2 = _hchacha20_block(key, nonce)
        assert sk1 == sk2

    def test_different_keys_different_output(self):
        nonce = secrets.token_bytes(16)
        sk1 = _hchacha20_block(secrets.token_bytes(32), nonce)
        sk2 = _hchacha20_block(secrets.token_bytes(32), nonce)
        assert sk1 != sk2

    def test_different_nonces_different_output(self):
        key = secrets.token_bytes(32)
        sk1 = _hchacha20_block(key, secrets.token_bytes(16))
        sk2 = _hchacha20_block(key, secrets.token_bytes(16))
        assert sk1 != sk2


# ---------------------------------------------------------------------------
# Tests: XChaCha20Poly1305 constructor
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_valid_key(self):
        key = secrets.token_bytes(XCHACHA20_KEY_SIZE)
        cipher = XChaCha20Poly1305(key)
        assert cipher._key == key

    def test_wrong_key_length(self):
        with pytest.raises(ValueError, match="key must be 32 bytes"):
            XChaCha20Poly1305(b"\x00" * 16)

    def test_empty_key(self):
        with pytest.raises(ValueError, match="key must be 32 bytes"):
            XChaCha20Poly1305(b"")


# ---------------------------------------------------------------------------
# Tests: encrypt / decrypt roundtrip
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundtrip:
    def test_basic(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, None)
        pt = cipher.decrypt(nonce, ct, None)
        assert pt == plaintext

    def test_with_aad(self, key, nonce, plaintext):
        aad = b"additional data"
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, aad)
        pt = cipher.decrypt(nonce, ct, aad)
        assert pt == plaintext

    def test_empty_plaintext(self, key, nonce):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, b"", None)
        pt = cipher.decrypt(nonce, ct, None)
        assert pt == b""

    def test_large_plaintext(self, key, nonce):
        plaintext = secrets.token_bytes(1024 * 1024)
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, None)
        pt = cipher.decrypt(nonce, ct, None)
        assert pt == plaintext

    def test_ciphertext_longer_than_plaintext(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, None)
        assert len(ct) == len(plaintext) + XCHACHA20_TAG_SIZE


# ---------------------------------------------------------------------------
# Tests: Authentication failure
# ---------------------------------------------------------------------------

class TestAuthenticationFailure:
    def test_tampered_ciphertext(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, None)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, bytes(tampered), None)

    def test_tampered_tag(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, None)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, bytes(tampered), None)

    def test_wrong_key(self, key, nonce, plaintext):
        cipher1 = XChaCha20Poly1305(key)
        cipher2 = XChaCha20Poly1305(secrets.token_bytes(XCHACHA20_KEY_SIZE))
        ct = cipher1.encrypt(nonce, plaintext, None)
        with pytest.raises(InvalidTag):
            cipher2.decrypt(nonce, ct, None)

    def test_wrong_aad(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, b"correct aad")
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, ct, b"wrong aad")

    def test_missing_aad_was_used(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, b"some aad")
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, ct, None)

    def test_wrong_nonce(self, key, plaintext):
        cipher = XChaCha20Poly1305(key)
        nonce1 = secrets.token_bytes(XCHACHA20_NONCE_SIZE)
        nonce2 = secrets.token_bytes(XCHACHA20_NONCE_SIZE)
        ct = cipher.encrypt(nonce1, plaintext, None)
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce2, ct, None)


# ---------------------------------------------------------------------------
# Tests: Nonce validation
# ---------------------------------------------------------------------------

class TestNonceValidation:
    def test_wrong_nonce_length_encrypt(self, key, plaintext):
        cipher = XChaCha20Poly1305(key)
        with pytest.raises(ValueError, match="nonce must be 24 bytes"):
            cipher.encrypt(b"\x00" * 12, plaintext, None)

    def test_wrong_nonce_length_decrypt(self, key, nonce, plaintext):
        cipher = XChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, plaintext, None)
        with pytest.raises(ValueError, match="nonce must be 24 bytes"):
            cipher.decrypt(b"\x00" * 12, ct, None)


# ---------------------------------------------------------------------------
# Tests: generate_nonce
# ---------------------------------------------------------------------------

class TestGenerateNonce:
    def test_returns_correct_length(self):
        nonce = generate_nonce()
        assert len(nonce) == XCHACHA20_NONCE_SIZE

    def test_unique(self):
        nonces = {generate_nonce() for _ in range(100)}
        assert len(nonces) == 100

    def test_bytes_type(self):
        nonce = generate_nonce()
        assert isinstance(nonce, bytes)


# ---------------------------------------------------------------------------
# Tests: Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_key_size(self):
        assert XCHACHA20_KEY_SIZE == 32

    def test_nonce_size(self):
        assert XCHACHA20_NONCE_SIZE == 24

    def test_tag_size(self):
        assert XCHACHA20_TAG_SIZE == 16


# ---------------------------------------------------------------------------
# Tests: Self-test
# ---------------------------------------------------------------------------

class TestSelfTest:
    def test_run_self_test_passes(self):
        assert run_self_test() is True
