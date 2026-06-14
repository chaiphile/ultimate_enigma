"""Tests for SecureString wrapper for secure memory management."""

import pytest
import gc
from src.secure_string import SecureString, secure_compare, wipe_bytes


class TestSecureString:
    """Tests for the SecureString class."""

    def test_create_from_string(self):
        """Test creating SecureString from a string."""
        ss = SecureString("test_password")
        assert len(ss) == 13
        assert ss.to_str() == "test_password"
        ss.wipe()

    def test_create_from_bytes(self):
        """Test creating SecureString from bytes."""
        ss = SecureString(b"test_bytes")
        assert len(ss) == 10
        assert ss.to_bytes() == b"test_bytes"
        ss.wipe()

    def test_create_from_bytearray(self):
        """Test creating SecureString from bytearray."""
        ss = SecureString(bytearray(b"test_array"))
        assert len(ss) == 10
        assert ss.to_bytes() == b"test_array"
        ss.wipe()

    def test_create_empty(self):
        """Test creating empty SecureString."""
        ss = SecureString()
        assert len(ss) == 0
        assert not ss
        ss.wipe()

    def test_bool_true_when_has_data(self):
        """Test that SecureString is truthy when it has data."""
        ss = SecureString("password")
        assert bool(ss) is True
        ss.wipe()

    def test_bool_false_when_empty(self):
        """Test that SecureString is falsy when empty."""
        ss = SecureString("")
        assert bool(ss) is False
        ss.wipe()

    def test_bool_false_after_wipe(self):
        """Test that SecureString is falsy after being wiped."""
        ss = SecureString("password")
        ss.wipe()
        assert bool(ss) is False

    def test_wipe_clears_data(self):
        """Test that wipe() clears the internal data."""
        ss = SecureString("secret_password")
        assert len(ss) == 15
        ss.wipe()
        assert ss.is_wiped
        assert len(ss) == 0

    def test_wipe_idempotent(self):
        """Test that calling wipe() multiple times is safe."""
        ss = SecureString("password")
        ss.wipe()
        ss.wipe()  # Should not raise
        assert ss.is_wiped

    def test_to_str_raises_after_wipe(self):
        """Test that to_str() raises after wipe."""
        ss = SecureString("password")
        ss.wipe()
        with pytest.raises(RuntimeError, match="wiped"):
            ss.to_str()

    def test_to_bytes_raises_after_wipe(self):
        """Test that to_bytes() raises after wipe."""
        ss = SecureString("password")
        ss.wipe()
        with pytest.raises(RuntimeError, match="wiped"):
            ss.to_bytes()

    def test_to_bytearray_raises_after_wipe(self):
        """Test that to_bytearray() raises after wipe."""
        ss = SecureString("password")
        ss.wipe()
        with pytest.raises(RuntimeError, match="wiped"):
            ss.to_bytearray()

    def test_equality_same_value(self):
        """Test equality comparison with same value."""
        ss1 = SecureString("password")
        ss2 = SecureString("password")
        assert ss1 == ss2
        ss1.wipe()
        ss2.wipe()

    def test_equality_different_value(self):
        """Test equality comparison with different values."""
        ss1 = SecureString("password1")
        ss2 = SecureString("password2")
        assert ss1 != ss2
        ss1.wipe()
        ss2.wipe()

    def test_equality_with_string(self):
        """Test equality comparison with plain string."""
        ss = SecureString("password")
        assert ss == "password"
        assert ss != "other"
        ss.wipe()

    def test_equality_with_bytes(self):
        """Test equality comparison with bytes."""
        ss = SecureString("password")
        assert ss == b"password"
        assert ss != b"other"
        ss.wipe()

    def test_equality_after_wipe_returns_false(self):
        """Test that wiped SecureString always returns False for equality."""
        ss1 = SecureString("password")
        ss2 = SecureString("password")
        ss1.wipe()
        assert not (ss1 == ss2)
        ss2.wipe()

    def test_context_manager_wipes_on_exit(self):
        """Test that context manager wipes on exit."""
        with SecureString("password") as ss:
            assert len(ss) == 8
        assert ss.is_wiped

    def test_context_manager_wipes_on_exception(self):
        """Test that context manager wipes even on exception."""
        ss_ref = None
        try:
            with SecureString("password") as ss:
                ss_ref = ss
                raise ValueError("test error")
        except ValueError:
            pass
        assert ss_ref.is_wiped

    def test_repr_does_not_expose_data(self):
        """Test that repr() does not expose the actual data."""
        ss = SecureString("secret_password")
        r = repr(ss)
        assert "secret_password" not in r
        assert "SecureString" in r
        assert "15 chars" in r or "chars" in r
        ss.wipe()

    def test_str_does_not_expose_data(self):
        """Test that str() does not expose the actual data."""
        ss = SecureString("secret_password")
        s = str(ss)
        assert "secret_password" not in s
        ss.wipe()

    def test_repr_after_wipe(self):
        """Test repr() after wipe."""
        ss = SecureString("password")
        ss.wipe()
        assert "wiped" in repr(ss)

    def test_hash_raises(self):
        """Test that hash() raises TypeError."""
        ss = SecureString("password")
        with pytest.raises(TypeError, match="unhashable"):
            hash(ss)
        ss.wipe()

    def test_append_string_raises_type_error(self):
        """Test appending a string raises TypeError to prevent non-wipeable copies."""
        ss = SecureString("hello")
        with pytest.raises(TypeError, match="non-wipeable"):
            ss.append(" world")
        ss.wipe()

    def test_append_bytes(self):
        """Test appending bytes."""
        ss = SecureString(b"hello")
        ss.append(b" world")
        assert ss.to_bytes() == b"hello world"
        ss.wipe()

    def test_append_secureString(self):
        """Test appending another SecureString."""
        ss1 = SecureString("hello")
        ss2 = SecureString(" world")
        ss1.append(ss2)
        assert ss1.to_str() == "hello world"
        ss1.wipe()
        ss2.wipe()

    def test_append_after_wipe_raises(self):
        """Test that append raises after wipe."""
        ss = SecureString("hello")
        ss.wipe()
        with pytest.raises(RuntimeError, match="wiped"):
            ss.append(" world")

    def test_copy(self):
        """Test creating a copy."""
        ss1 = SecureString("password")
        ss2 = ss1.copy()
        assert ss1 == ss2
        assert ss1 is not ss2
        ss1.wipe()
        assert ss1.is_wiped
        assert not ss2.is_wiped
        assert ss2.to_str() == "password"
        ss2.wipe()

    def test_copy_after_wipe_raises(self):
        """Test that copy raises after wipe."""
        ss = SecureString("password")
        ss.wipe()
        with pytest.raises(RuntimeError, match="wiped"):
            ss.copy()

    def test_from_str(self):
        """Test from_str class method."""
        ss = SecureString.from_str("password")
        assert ss.to_str() == "password"
        ss.wipe()

    def test_from_bytes(self):
        """Test from_bytes class method."""
        ss = SecureString.from_bytes(b"password")
        assert ss.to_bytes() == b"password"
        ss.wipe()

    def test_unicode_support(self):
        """Test Unicode string support."""
        ss = SecureString("пароль密码")  # Russian and Chinese
        assert len(ss) > 0
        result = ss.to_str()
        assert result == "пароль密码"
        ss.wipe()

    def test_type_error_on_invalid_input(self):
        """Test that invalid input types raise TypeError."""
        with pytest.raises(TypeError):
            SecureString(12345)

    def test_encode(self):
        """Test encode method."""
        ss = SecureString("password")
        encoded = ss.encode('utf-8')
        assert encoded == b"password"
        ss.wipe()

    def test_to_bytearray_returns_copy(self):
        """Test that to_bytearray returns a copy."""
        ss = SecureString("password")
        ba = ss.to_bytearray()
        ba[0] = 0  # Modify the copy
        assert ss.to_str() == "password"  # Original unchanged
        ss.wipe()


class TestSecureCompare:
    """Tests for the secure_compare function."""

    def test_equal_strings(self):
        """Test comparing equal strings."""
        assert secure_compare("password", "password") is True

    def test_different_strings(self):
        """Test comparing different strings."""
        assert secure_compare("password1", "password2") is False

    def test_equal_secure_strings(self):
        """Test comparing equal SecureStrings."""
        ss1 = SecureString("password")
        ss2 = SecureString("password")
        assert secure_compare(ss1, ss2) is True
        ss1.wipe()
        ss2.wipe()

    def test_different_secure_strings(self):
        """Test comparing different SecureStrings."""
        ss1 = SecureString("password1")
        ss2 = SecureString("password2")
        assert secure_compare(ss1, ss2) is False
        ss1.wipe()
        ss2.wipe()

    def test_mixed_types(self):
        """Test comparing SecureString with str."""
        ss = SecureString("password")
        assert secure_compare(ss, "password") is True
        assert secure_compare("password", ss) is True
        assert secure_compare(ss, "other") is False
        ss.wipe()

    def test_wiped_secure_string(self):
        """Test comparing wiped SecureString."""
        ss = SecureString("password")
        ss.wipe()
        assert secure_compare(ss, "password") is False


class TestWipeBytes:
    """Tests for the wipe_bytes function."""

    def test_wipe_bytearray(self):
        """Test wiping a bytearray."""
        ba = bytearray(b"secret")
        wipe_bytes(ba)
        assert ba == bytearray(b"\x00\x00\x00\x00\x00\x00")

    def test_wipe_none(self):
        """Test wiping None is safe."""
        wipe_bytes(None)  # Should not raise

    def test_wipe_bytes_no_op(self):
        """Test that wiping bytes is a no-op (immutable)."""
        b = b"secret"
        wipe_bytes(b)  # Should not raise (bytes are immutable)


class TestMemoryBehavior:
    """Tests for memory management behavior."""

    def test_gc_collects_wiped_secure_string(self):
        """Test that wiped SecureString can be garbage collected."""
        ss = SecureString("password")
        ss.wipe()
        del ss
        gc.collect()  # Should not raise

    def test_multiple_wipes_are_safe(self):
        """Test that multiple wipes don't cause issues."""
        ss = SecureString("password")
        for _ in range(10):
            ss.wipe()
        assert ss.is_wiped


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
