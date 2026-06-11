"""Comprehensive unit tests for src/exceptions.py – Exception Hierarchy."""

import pytest

from src.exceptions import (
    EnigmaError,
    KeyStoreError,
    EncryptionError,
    DecryptionError,
    RatchetStateError,
    RatchetNotFoundError,
    RatchetInitError,
    RatchetServiceError,
    TOTPValidationError,
    CryptoTimeoutError,
    ConcurrencyError,
)


# ---------------------------------------------------------------------------
# Tests: Exception Hierarchy
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_base_enigma_error(self):
        """All custom exceptions should inherit from EnigmaError."""
        assert issubclass(KeyStoreError, EnigmaError)
        assert issubclass(EncryptionError, EnigmaError)
        assert issubclass(DecryptionError, EnigmaError)
        assert issubclass(RatchetStateError, EnigmaError)
        assert issubclass(TOTPValidationError, EnigmaError)
        assert issubclass(CryptoTimeoutError, EnigmaError)
        assert issubclass(ConcurrencyError, EnigmaError)

    def test_ratchet_subhierarchy(self):
        """Ratchet-specific exceptions should inherit from RatchetStateError."""
        assert issubclass(RatchetNotFoundError, RatchetStateError)
        assert issubclass(RatchetInitError, RatchetStateError)
        assert issubclass(RatchetServiceError, RatchetStateError)

    def test_all_inherit_from_exception(self):
        """All should ultimately inherit from Exception."""
        assert issubclass(EnigmaError, Exception)
        assert issubclass(KeyStoreError, Exception)
        assert issubclass(RatchetNotFoundError, Exception)

    def test_catch_base_catches_all(self):
        """Catching EnigmaError should catch all subclasses."""
        exceptions = [
            KeyStoreError("test"),
            EncryptionError("test"),
            DecryptionError("test"),
            RatchetStateError("test"),
            RatchetNotFoundError("test"),
            RatchetInitError("test"),
            RatchetServiceError("test"),
            TOTPValidationError("test"),
            CryptoTimeoutError("test"),
            ConcurrencyError("test"),
        ]
        for exc in exceptions:
            try:
                raise exc
            except EnigmaError:
                pass  # Expected
            except Exception:
                pytest.fail(f"{type(exc).__name__} not caught by EnigmaError")


# ---------------------------------------------------------------------------
# Tests: Exception Instantiation
# ---------------------------------------------------------------------------

class TestExceptionInstantiation:
    def test_enigma_error(self):
        exc = EnigmaError("base error")
        assert str(exc) == "base error"

    def test_keystore_error(self):
        exc = KeyStoreError("key loading failed")
        assert "key loading failed" in str(exc)

    def test_encryption_error(self):
        exc = EncryptionError("cannot encrypt")
        assert "cannot encrypt" in str(exc)

    def test_decryption_error(self):
        exc = DecryptionError("wrong key")
        assert "wrong key" in str(exc)

    def test_ratchet_state_error(self):
        exc = RatchetStateError("state corrupted")
        assert "state corrupted" in str(exc)

    def test_ratchet_not_found_error(self):
        exc = RatchetNotFoundError("no session")
        assert "no session" in str(exc)

    def test_ratchet_init_error(self):
        exc = RatchetInitError("init failed")
        assert "init failed" in str(exc)

    def test_ratchet_service_error(self):
        exc = RatchetServiceError("service failure")
        assert "service failure" in str(exc)

    def test_totp_validation_error(self):
        exc = TOTPValidationError("invalid code")
        assert "invalid code" in str(exc)

    def test_crypto_timeout_error(self):
        exc = CryptoTimeoutError("operation timed out")
        assert "timed out" in str(exc)

    def test_concurrency_error(self):
        exc = ConcurrencyError("lock acquisition failed")
        assert "lock acquisition failed" in str(exc)


# ---------------------------------------------------------------------------
# Tests: Exception Chaining
# ---------------------------------------------------------------------------

class TestExceptionChaining:
    def test_exception_chaining_from(self):
        """Exceptions should support chaining with 'from'."""
        try:
            try:
                raise ValueError("original error")
            except ValueError as e:
                raise KeyStoreError("wrapped error") from e
        except KeyStoreError as e:
            assert isinstance(e.__cause__, ValueError)
            assert str(e.__cause__) == "original error"

    def test_exception_chaining_context(self):
        """Exceptions should preserve context."""
        try:
            try:
                raise RuntimeError("db error")
            except RuntimeError:
                raise DecryptionError("decryption failed")
        except DecryptionError as e:
            assert e.__context__ is not None


# ---------------------------------------------------------------------------
# Tests: Exception Messages
# ---------------------------------------------------------------------------

class TestExceptionMessages:
    def test_empty_message(self):
        exc = EnigmaError()
        assert str(exc) == ""

    def test_unicode_message(self):
        exc = KeyStoreError("Ошибка ключа 密钥エラー")
        assert "Ошибка" in str(exc)
        assert "密钥" in str(exc)

    def test_long_message(self):
        long_msg = "A" * 10000
        exc = EncryptionError(long_msg)
        assert len(str(exc)) == 10000


# ---------------------------------------------------------------------------
# Tests: Exception Behavior
# ---------------------------------------------------------------------------

class TestExceptionBehavior:
    def test_raise_and_catch(self):
        with pytest.raises(EnigmaError):
            raise KeyStoreError("test")

    def test_specific_catch(self):
        with pytest.raises(RatchetNotFoundError):
            raise RatchetNotFoundError("not found")

    def test_base_does_not_catch_unrelated(self):
        """EnigmaError should not catch unrelated exceptions."""
        with pytest.raises(ValueError):
            try:
                raise ValueError("unrelated")
            except EnigmaError:
                pytest.fail("Should not catch ValueError")

    def test_multiple_exception_types(self):
        """Can catch multiple specific types."""
        exc_types = (KeyStoreError, EncryptionError, DecryptionError)
        for exc_type in [KeyStoreError, EncryptionError, DecryptionError]:
            try:
                raise exc_type("test")
            except exc_types:
                pass  # Expected


# ---------------------------------------------------------------------------
# Tests: Exception Repr
# ---------------------------------------------------------------------------

class TestExceptionRepr:
    def test_repr_includes_class_name(self):
        exc = KeyStoreError("test")
        assert "KeyStoreError" in repr(exc)

    def test_repr_includes_message(self):
        exc = EncryptionError("custom message")
        assert "custom message" in repr(exc)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
