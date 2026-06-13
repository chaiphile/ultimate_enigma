"""Unit tests for services/pqc_service.py – Hybrid Post-Quantum Key Exchange."""

import struct
import secrets
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from services.pqc_service import (
    HybridKEM,
    is_pqc_available,
    KEM_ALGORITHM,
    X25519_PUB_KEY_LEN,
    MIN_COMBINED_PUB_LEN,
    _OQS_AVAILABLE,
)


# ---------------------------------------------------------------------------
# Tests: is_pqc_available
# ---------------------------------------------------------------------------

class TestIsPqcAvailable:
    def test_returns_bool(self):
        result = is_pqc_available()
        assert isinstance(result, bool)

    def test_false_when_oqs_not_installed(self):
        with patch("services.pqc_service._OQS_AVAILABLE", False):
            assert is_pqc_available() is False

    def test_false_when_oqs_is_none(self):
        with patch("services.pqc_service.oqs", None):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                assert is_pqc_available() is False

    def test_false_when_mechanism_not_enabled(self):
        mock_oqs = MagicMock()
        mock_oqs.get_enabled_kem_mechanisms.return_value = []
        with patch("services.pqc_service.oqs", mock_oqs):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                assert is_pqc_available() is False

    def test_true_when_mechanism_enabled(self):
        mock_oqs = MagicMock()
        mock_oqs.get_enabled_kem_mechanisms.return_value = [KEM_ALGORITHM]
        with patch("services.pqc_service.oqs", mock_oqs):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                assert is_pqc_available() is True

    def test_false_on_exception(self):
        mock_oqs = MagicMock()
        mock_oqs.get_enabled_kem_mechanisms.side_effect = RuntimeError("liboqs error")
        with patch("services.pqc_service.oqs", mock_oqs):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                assert is_pqc_available() is False


# ---------------------------------------------------------------------------
# Tests: HybridKEM._require_oqs
# ---------------------------------------------------------------------------

class TestRequireOqs:
    def test_raises_when_not_available(self):
        with patch("services.pqc_service._OQS_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="liboqs native library"):
                HybridKEM._require_oqs()

    def test_raises_when_oqs_is_none(self):
        with patch("services.pqc_service.oqs", None):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                with pytest.raises(RuntimeError, match="liboqs native library"):
                    HybridKEM._require_oqs()


# ---------------------------------------------------------------------------
# Tests: HybridKEM._parse_combined_pub
# ---------------------------------------------------------------------------

class TestParseCombinedPub:
    def _make_combined(self, x_pub=None, kyber_pub=None):
        if x_pub is None:
            x_pub = secrets.token_bytes(X25519_PUB_KEY_LEN)
        if kyber_pub is None:
            kyber_pub = secrets.token_bytes(1184)
        combined = struct.pack(">H", len(x_pub)) + x_pub
        combined += struct.pack(">H", len(kyber_pub)) + kyber_pub
        return combined, x_pub, kyber_pub

    def test_valid_roundtrip(self):
        combined, x_pub, kyber_pub = self._make_combined()
        rx, rky = HybridKEM._parse_combined_pub(combined)
        assert rx == x_pub
        assert rky == kyber_pub

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            HybridKEM._parse_combined_pub(b"\x00" * 5)

    def test_bad_x_length_prefix(self):
        combined = b"\x00\x00" + b"\x00" * 50
        with pytest.raises(ValueError, match="too short|Failed to parse|length"):
            HybridKEM._parse_combined_pub(combined)

    def test_wrong_x_length(self):
        x_pub = secrets.token_bytes(16)
        kyber_pub = secrets.token_bytes(1184)
        combined = struct.pack(">H", len(x_pub)) + x_pub
        combined += struct.pack(">H", len(kyber_pub)) + kyber_pub
        with pytest.raises(ValueError, match="Unexpected X25519 key length"):
            HybridKEM._parse_combined_pub(combined)

    def test_truncated_x_pub(self):
        combined = struct.pack(">H", X25519_PUB_KEY_LEN) + b"\x00" * 10
        with pytest.raises(ValueError, match="too short|truncated"):
            HybridKEM._parse_combined_pub(combined)

    def test_missing_kyber_length(self):
        x_pub = secrets.token_bytes(X25519_PUB_KEY_LEN)
        ky_len = 10
        combined = struct.pack(">H", len(x_pub)) + x_pub
        combined += struct.pack(">H", ky_len) + b"\x00"
        with pytest.raises(ValueError, match="truncated|missing Kyber key length"):
            HybridKEM._parse_combined_pub(combined)

    def test_truncated_kyber_pub(self):
        x_pub = secrets.token_bytes(X25519_PUB_KEY_LEN)
        kyber_len = 1184
        combined = struct.pack(">H", len(x_pub)) + x_pub
        combined += struct.pack(">H", kyber_len) + b"\x00" * 10
        with pytest.raises(ValueError, match="truncated"):
            HybridKEM._parse_combined_pub(combined)

    def test_empty_kyber_pub(self):
        x_pub = secrets.token_bytes(X25519_PUB_KEY_LEN)
        combined = struct.pack(">H", len(x_pub)) + x_pub
        combined += struct.pack(">H", 0)
        with pytest.raises(ValueError, match="empty"):
            HybridKEM._parse_combined_pub(combined)


# ---------------------------------------------------------------------------
# Tests: HybridKEM with mocked OQS (integration-level)
# ---------------------------------------------------------------------------

class TestHybridKEMMocked:
    @pytest.fixture
    def mock_oqs_kem(self):
        """Create a mock oqs.KeyEncapsulation that simulates Kyber768."""
        mock_kem = MagicMock()
        mock_kem.generate_keypair.return_value = secrets.token_bytes(1184)
        mock_kem.export_secret_key.return_value = secrets.token_bytes(2400)
        ct = secrets.token_bytes(1088)
        pq_shared = secrets.token_bytes(32)
        mock_kem.encap_secret.return_value = (ct, pq_shared)
        mock_kem.decap_secret.return_value = pq_shared
        return mock_kem

    @pytest.fixture
    def mock_oqs_module(self, mock_oqs_kem):
        """Patch oqs module with Kyber768 support."""
        mock_oqs = MagicMock()
        mock_oqs.get_enabled_kem_mechanisms.return_value = [KEM_ALGORITHM]
        mock_oqs.KeyEncapsulation.return_value.__enter__ = lambda s: mock_oqs_kem
        mock_oqs.KeyEncapsulation.return_value.__exit__ = MagicMock(return_value=False)
        return mock_oqs

    def test_generate_keys(self, mock_oqs_module):
        with patch("services.pqc_service.oqs", mock_oqs_module):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                keys = HybridKEM.generate_keys()

        assert "x25519_priv" in keys
        assert "x25519_pub_bytes" in keys
        assert "kyber_priv" in keys
        assert "kyber_pub_bytes" in keys
        assert "combined_pub" in keys
        assert len(keys["x25519_pub_bytes"]) == X25519_PUB_KEY_LEN
        assert len(keys["kyber_pub_bytes"]) == 1184

    def test_generate_keys_combined_pub_structure(self, mock_oqs_module):
        with patch("services.pqc_service.oqs", mock_oqs_module):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                keys = HybridKEM.generate_keys()
        combined = keys["combined_pub"]
        x_len = struct.unpack(">H", combined[:2])[0]
        assert x_len == X25519_PUB_KEY_LEN

    def test_encapsulate_requires_oqs(self):
        with patch("services.pqc_service._OQS_AVAILABLE", False):
            with pytest.raises(RuntimeError):
                HybridKEM.encapsulate(b"\x00" * 100)

    def test_decapsulate_requires_oqs(self):
        with patch("services.pqc_service._OQS_AVAILABLE", False):
            with pytest.raises(RuntimeError):
                HybridKEM.decapsulate({}, b"\x00" * 100)

    def test_decapsulate_short_ciphertext_raises(self, mock_oqs_module):
        with patch("services.pqc_service.oqs", mock_oqs_module):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                with pytest.raises(ValueError, match="too short"):
                    HybridKEM.decapsulate(
                        {"x25519_priv": MagicMock(), "kyber_priv": b"\x00"},
                        b"\x00"
                    )

    def test_decapsulate_missing_x25519_priv_raises(self, mock_oqs_module):
        with patch("services.pqc_service.oqs", mock_oqs_module):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                with pytest.raises(KeyError, match="x25519_priv"):
                    HybridKEM.decapsulate(
                        {"kyber_priv": b"\x00" * 2400},
                        b"\x00" * (X25519_PUB_KEY_LEN + 10)
                    )

    def test_decapsulate_missing_kyber_priv_raises(self, mock_oqs_module):
        with patch("services.pqc_service.oqs", mock_oqs_module):
            with patch("services.pqc_service._OQS_AVAILABLE", True):
                with pytest.raises(KeyError, match="kyber_priv"):
                    HybridKEM.decapsulate(
                        {"x25519_priv": MagicMock()},
                        b"\x00" * (X25519_PUB_KEY_LEN + 10)
                    )


# ---------------------------------------------------------------------------
# Tests: Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_x25519_pub_key_len(self):
        assert X25519_PUB_KEY_LEN == 32

    def test_min_combined_pub_len(self):
        assert MIN_COMBINED_PUB_LEN == 2 + 32 + 2

    def test_kem_algorithm(self):
        assert KEM_ALGORITHM == "Kyber768"
