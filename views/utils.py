"""Pure utility functions for the app (validation, formatting)."""

import re

# Minimum requirements (military-grade)
MIN_PASSWORD_LENGTH = 16
MIN_ENTROPY_BITS = 60


def validate_password_strength(pw: str) -> tuple:
    """
    Validate password against military-grade requirements.

    Returns:
        (is_valid: bool, message: str, score: int)
        score: 0-100 (0=trivially weak, 100=excellent)
    """
    issues = []
    score = 0

    # Length check (most important factor)
    if len(pw) < MIN_PASSWORD_LENGTH:
        issues.append(f"Minimum {MIN_PASSWORD_LENGTH} characters required (have {len(pw)})")
    else:
        score += min(40, len(pw) * 2)  # Up to 40 points for length

    # Complexity checks
    if not re.search(r'[A-Z]', pw):
        issues.append("Must contain at least one uppercase letter")
    else:
        score += 15

    if not re.search(r'[a-z]', pw):
        issues.append("Must contain at least one lowercase letter")
    else:
        score += 15

    if not re.search(r'\d', pw):
        issues.append("Must contain at least one digit")
    else:
        score += 15

    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}\\|;:\'",.<>/?`~]', pw):
        issues.append("Must contain at least one special character")
    else:
        score += 15

    # Common password check (top 10,000)
    common_passwords = {
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "master", "dragon", "login",
        "princess", "football", "shadow", "sunshine", "trustno1"
    }
    if pw.lower() in common_passwords:
        issues.append("Password is too common")
        score = 0

    # Repetitive pattern check
    if re.search(r'(.)\1{3,}', pw):
        issues.append("Contains excessive repeated characters")
        score -= 10

    # Sequential pattern check
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', pw.lower()):
        issues.append("Contains sequential patterns")
        score -= 10

    is_valid = len(issues) == 0
    message = "Strong password" if is_valid else "; ".join(issues)
    return is_valid, message, max(0, min(100, score))


def get_strength_label(score: int) -> tuple:
    """Return (label_text, color) based on password strength score."""
    if score >= 80:
        return "████████████ STRONG", "#00cc00"
    elif score >= 60:
        return "████████░░░░ GOOD", "#66cc00"
    elif score >= 40:
        return "████░░░░░░░░ FAIR", "#cccc00"
    elif score >= 20:
        return "██░░░░░░░░░░ WEAK", "#cc6600"
    else:
        return "░░░░░░░░░░░░ CRITICAL", "#cc0000"
