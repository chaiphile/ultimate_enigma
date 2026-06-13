"""Unit tests for services/global_secret_service.py – Global Secret Management."""

import base64
import secrets
import pytest
from unittest.mock import MagicMock, PropertyMock

from crypto import sha256_fingerprint
from services.global_secret_service import (
    GlobalSecretService,
    GlobalSecretServiceError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_keystore():
    """A mock KeyStore with a 32-byte global secret."""
    ks = MagicMock()
    ks.global_secret = secrets.token_bytes(32)
    ks.verify_password.return_value = True
    return ks


@pytest.fixture
def empty_keystore():
    """A mock KeyStore with no global secret."""
    ks = MagicMock()
    ks.global_secret = None
    return ks


@pytest.fixture
def service(mock_keystore):
    return GlobalSecretService(mock_keystore)


@pytest.fixture
def empty_service(empty_keystore):
    return GlobalSecretService(empty_keystore)


# ---------------------------------------------------------------------------
# Tests: has_secret
# ---------------------------------------------------------------------------

class TestHasSecret:
    def test_true_when_secret_set(self, service):
        assert service.has_secret() is True

    def test_false_when_no_secret(self, empty_service):
        assert empty_service.has_secret() is False


# ---------------------------------------------------------------------------
# Tests: get_fingerprint
# ---------------------------------------------------------------------------

class TestGetFingerprint:
    def test_returns_string(self, service):
        fp = service.get_fingerprint()
        assert isinstance(fp, str)

    def test_returns_correct_length(self, service):
        fp = service.get_fingerprint()
        assert len(fp) == 16

    def test_matches_expected(self, service, mock_keystore):
        expected = sha256_fingerprint(mock_keystore.global_secret)
        assert service.get_fingerprint() == expected

    def test_none_when_no_secret(self, empty_service):
        assert empty_service.get_fingerprint() is None


# ---------------------------------------------------------------------------
# Tests: export_secret_b64
# ---------------------------------------------------------------------------

class TestExportSecretB64:
    def test_returns_base64_string(self, service):
        b64 = service.export_secret_b64()
        decoded = base64.b64decode(b64)
        assert isinstance(b64, str)
        assert len(decoded) == 32

    def test_matches_keystore_secret(self, service, mock_keystore):
        b64 = service.export_secret_b64()
        decoded = base64.b64decode(b64)
        assert decoded == mock_keystore.global_secret

    def test_raises_when_no_secret(self, empty_service):
        with pytest.raises(GlobalSecretServiceError, match="No global secret"):
            empty_service.export_secret_b64()


# ---------------------------------------------------------------------------
# Tests: validate_secret_b64
# ---------------------------------------------------------------------------

class TestValidateSecretB64:
    def test_valid_32_bytes(self, service):
        raw = secrets.token_bytes(32)
        b64 = base64.b64encode(raw).decode()
        result = service.validate_secret_b64(b64)
        assert result == raw

    def test_too_short(self, service):
        raw = secrets.token_bytes(16)
        b64 = base64.b64encode(raw).decode()
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            service.validate_secret_b64(b64)

    def test_too_long(self, service):
        raw = secrets.token_bytes(64)
        b64 = base64.b64encode(raw).decode()
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            service.validate_secret_b64(b64)

    def test_invalid_base64(self, service):
        with pytest.raises(ValueError, match="Invalid secret format"):
            service.validate_secret_b64("not-valid-base64!!!")


# ---------------------------------------------------------------------------
# Tests: verify_password
# ---------------------------------------------------------------------------

class TestVerifyPassword:
    def test_correct_password(self, service):
        assert service.verify_password("correct") is True
        service._ks.verify_password.assert_called_once_with("correct")

    def test_wrong_password(self, empty_service):
        empty_service._ks.verify_password.return_value = False
        assert empty_service.verify_password("wrong") is False


# ---------------------------------------------------------------------------
# Tests: update_secret
# ---------------------------------------------------------------------------

class TestUpdateSecret:
    def test_success(self, service, mock_keystore):
        new_secret = secrets.token_bytes(32)
        result = service.update_secret(new_secret, "master_password")
        mock_keystore.update_global_secret.assert_called_once_with(
            new_secret, "master_password"
        )
        assert result == sha256_fingerprint(new_secret)

    def test_empty_password_raises(self, service):
        with pytest.raises(GlobalSecretServiceError, match="Master password required"):
            service.update_secret(secrets.token_bytes(32), "")

    def test_wrong_password_raises(self, service, mock_keystore):
        mock_keystore.verify_password.return_value = False
        with pytest.raises(GlobalSecretServiceError, match="Incorrect master password"):
            service.update_secret(secrets.token_bytes(32), "wrong")

    def test_wrong_length_raises(self, service):
        with pytest.raises(GlobalSecretServiceError, match="32 bytes"):
            service.update_secret(secrets.token_bytes(16), "pw")

    def test_keystore_failure_raises(self, service, mock_keystore):
        mock_keystore.update_global_secret.side_effect = Exception("disk error")
        with pytest.raises(GlobalSecretServiceError, match="Failed to update"):
            service.update_secret(secrets.token_bytes(32), "pw")


# ---------------------------------------------------------------------------
# Tests: GlobalSecretServiceError
# ---------------------------------------------------------------------------

class TestGlobalSecretServiceError:
    def test_is_exception(self):
        assert issubclass(GlobalSecretServiceError, Exception)

    def test_message(self):
        err = GlobalSecretServiceError("test message")
        assert str(err) == "test message"
