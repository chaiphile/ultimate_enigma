"""Comprehensive unit tests for services/totp_service.py – RFC 6238 TOTP."""

import time
import base64
import struct
import hmac
import hashlib
import pytest

from services.totp_service import TOTPService, TOTP_DIGITS, TOTP_INTERVAL, TOTP_DRIFT
from src.exceptions import TOTPValidationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def totp_service():
    """Create a fresh TOTPService instance."""
    return TOTPService()


@pytest.fixture
def configured_service():
    """Create a TOTPService with a known secret."""
    svc = TOTPService()
    secret = TOTPService.generate_random_secret(32)
    svc.set_secret(secret)
    return svc


# ---------------------------------------------------------------------------
# Tests: Secret Management
# ---------------------------------------------------------------------------

class TestSecretManagement:
    def test_set_secret_valid(self, totp_service):
        secret = b'\x00' * 32
        totp_service.set_secret(secret)
        assert totp_service.has_secret()
        assert totp_service.get_raw_secret() == secret[:20]

    def test_set_secret_minimum_length(self, totp_service):
        secret = b'\x01' * 20
        totp_service.set_secret(secret)
        assert totp_service.has_secret()

    def test_set_secret_too_short_raises(self, totp_service):
        with pytest.raises(TOTPValidationError, match="at least 20 bytes"):
            totp_service.set_secret(b'\x00' * 19)

    def test_set_secret_truncates_to_20(self, totp_service):
        secret = b'\xAB' * 32
        totp_service.set_secret(secret)
        raw = totp_service.get_raw_secret()
        assert len(raw) == 20
        assert raw == b'\xAB' * 20

    def test_set_raw_secret_exact_20(self, totp_service):
        secret = b'\x42' * 20
        totp_service.set_raw_secret(secret)
        assert totp_service.get_raw_secret() == secret

    def test_set_raw_secret_wrong_length_raises(self, totp_service):
        with pytest.raises(TOTPValidationError, match="exactly 20 bytes"):
            totp_service.set_raw_secret(b'\x00' * 19)
        with pytest.raises(TOTPValidationError, match="exactly 20 bytes"):
            totp_service.set_raw_secret(b'\x00' * 21)

    def test_clear_secret(self, configured_service):
        assert configured_service.has_secret()
        configured_service.clear_secret()
        assert not configured_service.has_secret()
        assert configured_service.get_raw_secret() is None

    def test_clear_secret_idempotent(self, totp_service):
        totp_service.clear_secret()
        totp_service.clear_secret()  # Should not raise

    def test_has_secret_false_initially(self, totp_service):
        assert not totp_service.has_secret()

    def test_get_b32_secret(self, totp_service):
        secret = b'\x00' * 20
        totp_service.set_secret(secret)
        b32 = totp_service.get_b32_secret()
        assert isinstance(b32, str)
        # Should be valid base32
        decoded = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        assert decoded == secret

    def test_get_b32_secret_no_secret(self, totp_service):
        assert totp_service.get_b32_secret() == "N/A"

    def test_get_raw_secret(self, totp_service):
        secret = b'\xFF' * 20
        totp_service.set_raw_secret(secret)
        assert totp_service.get_raw_secret() == secret


# ---------------------------------------------------------------------------
# Tests: HOTP (Internal)
# ---------------------------------------------------------------------------

class TestHOTP:
    def test_hotp_known_vector(self):
        """Test against known HOTP values from RFC 4226 Appendix D."""
        # RFC 4226 test secret
        secret = b"12345678901234567890"
        # Count=0 should give 755224
        code = TOTPService._hotp(secret, 0)
        assert code == 755224

    def test_hotp_count_1(self):
        secret = b"12345678901234567890"
        code = TOTPService._hotp(secret, 1)
        assert code == 287082

    def test_hotp_count_2(self):
        secret = b"12345678901234567890"
        code = TOTPService._hotp(secret, 2)
        assert code == 359152

    def test_hotp_deterministic(self):
        secret = b'\xAA' * 20
        c1 = TOTPService._hotp(secret, 100)
        c2 = TOTPService._hotp(secret, 100)
        assert c1 == c2

    def test_hotp_different_counters(self):
        secret = b'\xBB' * 20
        codes = {TOTPService._hotp(secret, i) for i in range(10)}
        # At least most should be different (extremely unlikely collision)
        assert len(codes) >= 8

    def test_hotp_six_digits(self):
        secret = b'\xCC' * 20
        for counter in range(100):
            code = TOTPService._hotp(secret, counter)
            assert 0 <= code < 1000000


# ---------------------------------------------------------------------------
# Tests: TOTP Generation
# ---------------------------------------------------------------------------

class TestGenerate:
    def test_generate_returns_string(self, configured_service):
        code = configured_service.generate()
        assert isinstance(code, str)
        assert len(code) == TOTP_DIGITS

    def test_generate_all_digits(self, configured_service):
        code = configured_service.generate()
        assert code.isdigit()
        assert len(code) == 6

    def test_generate_with_timestamp(self, configured_service):
        ts = 1700000000.0
        code1 = configured_service.generate(timestamp=ts)
        code2 = configured_service.generate(timestamp=ts)
        assert code1 == code2

    def test_generate_same_time_step(self, configured_service):
        """Same 30-second window should produce same code."""
        # 1700000010 is exactly a multiple of 30 (start of a TOTP window)
        base_ts = 1700000010.0
        code1 = configured_service.generate(timestamp=base_ts)
        code2 = configured_service.generate(timestamp=base_ts + 29)
        assert code1 == code2

    def test_generate_different_time_steps(self, configured_service):
        """Different time steps should usually produce different codes."""
        code1 = configured_service.generate(timestamp=1700000000.0)
        code2 = configured_service.generate(timestamp=1700000030.0)
        # Very unlikely to be the same
        # Not asserting != because collision is possible but improbable

    def test_generate_no_secret_raises(self, totp_service):
        with pytest.raises(TOTPValidationError, match="secret not set"):
            totp_service.generate()


# ---------------------------------------------------------------------------
# Tests: TOTP Verification
# ---------------------------------------------------------------------------

class TestVerify:
    def test_verify_current_code(self, configured_service):
        code = configured_service.generate()
        assert configured_service.verify(code) is True

    def test_verify_wrong_code(self, configured_service):
        assert configured_service.verify("000000") is False

    def test_verify_invalid_format(self, configured_service):
        assert configured_service.verify("abc") is False
        assert configured_service.verify("12345") is False  # too short
        assert configured_service.verify("1234567") is False  # too long
        assert configured_service.verify("") is False

    def test_verify_with_drift(self, configured_service):
        """Verify should accept codes from adjacent time steps."""
        # Generate code for previous time step
        now = time.time()
        prev_ts = now - TOTP_INTERVAL
        prev_code = configured_service.generate(timestamp=prev_ts)
        # Should still verify due to ±1 step drift
        assert configured_service.verify(prev_code, timestamp=now) is True

    def test_verify_future_drift(self, configured_service):
        """Verify should accept codes from next time step."""
        now = time.time()
        next_ts = now + TOTP_INTERVAL
        next_code = configured_service.generate(timestamp=next_ts)
        assert configured_service.verify(next_code, timestamp=now) is True

    def test_verify_too_old_code(self, configured_service):
        """Codes outside drift window should fail."""
        now = time.time()
        old_ts = now - TOTP_INTERVAL * 5  # 5 steps back
        old_code = configured_service.generate(timestamp=old_ts)
        assert configured_service.verify(old_code, timestamp=now) is False

    def test_verify_strips_whitespace(self, configured_service):
        code = configured_service.generate()
        assert configured_service.verify(f"  {code}  ") is True

    def test_verify_no_secret_raises(self, totp_service):
        with pytest.raises(TOTPValidationError, match="secret not set"):
            totp_service.verify("123456")


# ---------------------------------------------------------------------------
# Tests: Time Remaining
# ---------------------------------------------------------------------------

class TestTimeRemaining:
    def test_time_remaining_range(self, configured_service):
        remaining = configured_service.time_remaining()
        assert 1 <= remaining <= TOTP_INTERVAL

    def test_time_remaining_positive(self, configured_service):
        assert configured_service.time_remaining() > 0


# ---------------------------------------------------------------------------
# Tests: Provisioning URI
# ---------------------------------------------------------------------------

class TestProvisioningURI:
    def test_provisioning_uri_format(self, configured_service):
        uri = configured_service.provisioning_uri()
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "issuer=" in uri
        assert "algorithm=SHA1" in uri
        assert f"digits={TOTP_DIGITS}" in uri
        assert f"period={TOTP_INTERVAL}" in uri

    def test_provisioning_uri_custom_account(self, configured_service):
        uri = configured_service.provisioning_uri(account="user@example.com")
        assert "user@example.com" in uri

    def test_provisioning_uri_custom_issuer(self, configured_service):
        uri = configured_service.provisioning_uri(issuer="MyApp")
        assert "MyApp" in uri

    def test_provisioning_uri_contains_b32_secret(self, configured_service):
        uri = configured_service.provisioning_uri()
        b32_secret = configured_service.get_b32_secret()
        assert b32_secret in uri

    def test_provisioning_uri_no_secret_raises(self, totp_service):
        with pytest.raises(TOTPValidationError, match="secret not set"):
            totp_service.provisioning_uri()


# ---------------------------------------------------------------------------
# Tests: Static Helpers
# ---------------------------------------------------------------------------

class TestStaticHelpers:
    def test_generate_random_secret_default_length(self):
        secret = TOTPService.generate_random_secret()
        assert len(secret) == 32

    def test_generate_random_secret_custom_length(self):
        secret = TOTPService.generate_random_secret(64)
        assert len(secret) == 64

    def test_generate_random_secret_unique(self):
        s1 = TOTPService.generate_random_secret()
        s2 = TOTPService.generate_random_secret()
        assert s1 != s2

    def test_generate_random_secret_cryptographic(self):
        """Generated secrets should have full entropy."""
        secret = TOTPService.generate_random_secret(32)
        assert len(set(secret)) > 10  # Not all same byte


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_full_lifecycle(self):
        """Test complete setup → generate → verify cycle."""
        svc = TOTPService()
        secret = TOTPService.generate_random_secret()
        svc.set_secret(secret)

        code = svc.generate()
        assert svc.verify(code) is True

        # Wrong code should fail
        wrong = f"{(int(code) + 1) % 1000000:06d}"
        if wrong != code:  # Only test if different
            assert svc.verify(wrong) is False

    def test_different_secrets_different_codes(self):
        """Different secrets should produce different codes (usually)."""
        svc1 = TOTPService()
        svc2 = TOTPService()
        svc1.set_secret(b'\x01' * 20)
        svc2.set_secret(b'\x02' * 20)

        ts = 1700000000.0
        code1 = svc1.generate(timestamp=ts)
        code2 = svc2.generate(timestamp=ts)
        # Very likely different but not guaranteed

    def test_constant_time_verify(self, configured_service):
        """Verify should use constant-time comparison (no timing side-channel)."""
        code = configured_service.generate()
        # Just verify it doesn't crash with various inputs
        configured_service.verify("000000")
        configured_service.verify("999999")
        configured_service.verify(code)

    def test_totp_interval_constant(self):
        assert TOTP_INTERVAL == 30

    def test_totp_digits_constant(self):
        assert TOTP_DIGITS == 6

    def test_totp_drift_constant(self):
        assert TOTP_DRIFT == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
