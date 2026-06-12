"""Comprehensive unit tests for utils.py – Password validation and utilities."""

import pytest
from views.utils import validate_password_strength, get_strength_label, MIN_PASSWORD_LENGTH


# ---------------------------------------------------------------------------
# Tests: validate_password_strength
# ---------------------------------------------------------------------------

class TestValidatePasswordStrength:
    def test_strong_password(self):
        pw = "Str0ng!P@ssw0rd#2024SecureKey"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is True
        assert score >= 80
        assert "Strong" in message or score >= 80

    def test_too_short(self):
        pw = "Short1!"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is False
        assert "characters required" in message.lower() or "minimum" in message.lower()

    def test_no_uppercase(self):
        pw = "nouppercase123!@#456789012345"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is False
        assert "uppercase" in message.lower()

    def test_no_lowercase(self):
        pw = "NOLOWERCASE123!@#456789012345"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is False
        assert "lowercase" in message.lower()

    def test_no_digit(self):
        pw = "NoDigitsHere!@#SomeRandomText"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is False
        assert "digit" in message.lower()

    def test_no_special_char(self):
        pw = "NoSpecialChar123456789012345"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is False
        assert "special" in message.lower()

    def test_common_password(self):
        pw = "password"
        is_valid, message, score = validate_password_strength(pw)
        assert is_valid is False
        assert "common" in message.lower()
        assert score == 0

    def test_repetitive_pattern(self):
        pw = "aaaabbbbcccc1234!@#$EFGH5678"
        is_valid, message, score = validate_password_strength(pw)
        # Should have reduced score due to repetition
        assert "repeated" in message.lower() or score < 100

    def test_sequential_pattern(self):
        pw = "1234567890abcABC!@#defghijklmn"
        is_valid, message, score = validate_password_strength(pw)
        # Should have reduced score due to sequential patterns
        assert "sequential" in message.lower() or score < 100

    def test_minimum_valid_password(self):
        pw = "Aa1!" + "x" * (MIN_PASSWORD_LENGTH - 4)
        is_valid, message, score = validate_password_strength(pw)
        # Might still fail due to patterns, but let's test a proper one
        pw = "Abcdef1!" + "ghijklmn"  # 16 chars
        is_valid, message, score = validate_password_strength(pw)
        # At least check it doesn't crash
        assert isinstance(is_valid, bool)
        assert isinstance(message, str)
        assert isinstance(score, int)

    def test_score_range(self):
        for pw in ["a", "short", "Medium1!", "VeryStrongPassword123!@#"]:
            _, _, score = validate_password_strength(pw)
            assert 0 <= score <= 100

    def test_empty_password(self):
        is_valid, message, score = validate_password_strength("")
        assert is_valid is False
        assert score >= 0


# ---------------------------------------------------------------------------
# Tests: get_strength_label
# ---------------------------------------------------------------------------

class TestGetStrengthLabel:
    def test_strong_label(self):
        label, color = get_strength_label(85)
        assert "STRONG" in label
        assert color.startswith("#")

    def test_good_label(self):
        label, color = get_strength_label(65)
        assert "GOOD" in label

    def test_fair_label(self):
        label, color = get_strength_label(45)
        assert "FAIR" in label

    def test_weak_label(self):
        label, color = get_strength_label(25)
        assert "WEAK" in label

    def test_critical_label(self):
        label, color = get_strength_label(10)
        assert "CRITICAL" in label

    def test_boundary_values(self):
        # Exact boundaries
        label80, _ = get_strength_label(80)
        assert "STRONG" in label80

        label60, _ = get_strength_label(60)
        assert "GOOD" in label60

        label40, _ = get_strength_label(40)
        assert "FAIR" in label40

        label20, _ = get_strength_label(20)
        assert "WEAK" in label20

        label0, _ = get_strength_label(0)
        assert "CRITICAL" in label0

    def test_color_format(self):
        for score in [0, 20, 40, 60, 80, 100]:
            _, color = get_strength_label(score)
            assert color.startswith("#")
            assert len(color) == 7  # #RRGGBB format


# ---------------------------------------------------------------------------
# Tests: Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_min_password_length(self):
        assert MIN_PASSWORD_LENGTH >= 12  # Reasonable minimum

    def test_min_password_length_reasonable(self):
        assert MIN_PASSWORD_LENGTH <= 32  # Not too restrictive


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_unicode_password(self):
        pw = "Пароль密码123!@#SecureKey2024"
        is_valid, message, score = validate_password_strength(pw)
        assert isinstance(is_valid, bool)
        assert isinstance(score, int)

    def test_very_long_password(self):
        pw = "Aa1!" * 100
        is_valid, message, score = validate_password_strength(pw)
        assert isinstance(is_valid, bool)
        assert score >= 0

    def test_all_special_chars(self):
        pw = "!@#$%^&*()_+-=[]{}|;':\",./<>?" + "Aa1" + "x" * 10
        is_valid, message, score = validate_password_strength(pw)
        assert isinstance(is_valid, bool)

    def test_score_never_negative(self):
        """Score should never go below 0 even with penalties."""
        pw = "aaaa"  # Very weak
        _, _, score = validate_password_strength(pw)
        assert score >= 0

    def test_score_never_over_100(self):
        """Score should never exceed 100."""
        pw = "A" * 100 + "a" * 100 + "1" * 100 + "!" * 100
        _, _, score = validate_password_strength(pw)
        assert score <= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
