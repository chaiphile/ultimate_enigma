"""Centralized constants for Ultimate Enigma.

This module eliminates magic numbers and strings scattered across services,
providing a single source of truth for protocol values, KDF parameters,
and UI configuration.
"""

# ---------------------------------------------------------------------------
# Protocol Magic Bytes
# ---------------------------------------------------------------------------
# Used to identify envelope types in encrypted messages and files.

PROTOCOL_MAGIC_BYTES = {
    "RATCHET_ENVELOPE": 0xD0,  # Double Ratchet encrypted message envelope
    "PQC_ENVELOPE": 0x50,      # Post-Quantum Hybrid KEM envelope
    "FILE_SHARED_SECRET": b'ENIGMA\x01',  # Shared-secret encrypted file header
    "FILE_KDF_ARGON2ID": b'A2ID',         # Argon2id KDF version tag for password-based files
}

# ---------------------------------------------------------------------------
# Key Derivation Function (KDF) Parameters
# ---------------------------------------------------------------------------
# Argon2id parameters for password-based key derivation.
# These are military-grade, memory-hard KDF settings.

KDF_PARAMS = {
    "ARGON2_TIME_COST": 3,          # Number of iterations
    "ARGON2_MEMORY_COST": 65536,    # Memory usage in KB (64 MB)
    "ARGON2_PARALLELISM": 4,        # Number of parallel threads
    "ARGON2_HASH_LEN": 32,          # Output hash length in bytes
    "ARGON2_SALT_LEN": 16,          # Salt length in bytes
    "PBKDF2_LEGACY_ITERATIONS": 300_000,  # Legacy PBKDF2 iteration count
}

# ---------------------------------------------------------------------------
# Cryptographic Constants
# ---------------------------------------------------------------------------

CRYPTO_CONSTANTS = {
    "AES_KEY_SIZE": 32,             # AES-256 key size in bytes
    "RSA_MIN_KEY_SIZE": 4096,       # CNSA 2.0 minimum RSA key size (bits)
    "LEGACY_KEY_RETENTION_DAYS": 30,  # Days to retain rotated RSA keys
    "AES_GCM_NONCE_SIZE": 12,       # AES-GCM nonce size in bytes
    "AES_GCM_TAG_SIZE": 16,         # AES-GCM authentication tag size in bytes
}

# ---------------------------------------------------------------------------
# UI Constants
# ---------------------------------------------------------------------------
# Default values and limits for the user interface.

UI_CONSTANTS = {
    "WINDOW_DEFAULT_WIDTH": 1400,
    "WINDOW_DEFAULT_HEIGHT": 850,
    "WINDOW_MIN_WIDTH": 1200,
    "WINDOW_MIN_HEIGHT": 750,
    "PASSWORD_MIN_LENGTH": 12,      # Minimum master password length
    "FRIEND_NAME_MAX_LENGTH": 64,   # Maximum friend name length
    "MESSAGE_PREVIEW_LENGTH": 100,  # Characters to show in message previews
    "CLIPBOARD_CLEAR_DELAY": 30,    # Seconds before clearing clipboard
    "LOCK_SCREEN_TIMEOUT": 300,     # Seconds of inactivity before auto-lock
}

# ---------------------------------------------------------------------------
# Security & Lockout Constants
# ---------------------------------------------------------------------------

SECURITY_CONSTANTS = {
    "BACKOFF_TABLE": [0, 0, 0, 0, 0, 5, 10, 30, 60, 120, 300, 600, 1800, 3600],
    "HARD_LOCKOUT_THRESHOLD": 15,   # Failures before hard lockout
    "HARD_LOCKOUT_DURATION": 3600,  # Hard lockout duration in seconds (1 hour)
    "MAX_TOTP_ATTEMPTS": 5,         # Maximum TOTP verification attempts
    "SESSION_TIMEOUT": 900,         # Session timeout in seconds (15 minutes)
}

# ---------------------------------------------------------------------------
# Database Constants
# ---------------------------------------------------------------------------

DB_CONSTANTS = {
    "DB_FILENAME": "enigma.db",
    "DB_DIR_NAME": ".ultimate_enigma",
    "WAL_MODE": True,               # Enable Write-Ahead Logging
    "FOREIGN_KEYS": True,           # Enable foreign key constraints
}


def get_magic_byte(envelope_type: str) -> int:
    """Retrieve a protocol magic byte by envelope type name.

    Args:
        envelope_type: Key from PROTOCOL_MAGIC_BYTES (e.g., 'RATCHET_ENVELOPE').

    Returns:
        The magic byte value as an integer.

    Raises:
        KeyError: If the envelope type is not recognized.
    """
    if envelope_type not in PROTOCOL_MAGIC_BYTES:
        raise KeyError(f"Unknown envelope type: {envelope_type}")
    value = PROTOCOL_MAGIC_BYTES[envelope_type]
    if isinstance(value, bytes):
        return value[0] if len(value) == 1 else int.from_bytes(value[:1], 'big')
    return value


def get_kdf_param(param_name: str):
    """Retrieve a KDF parameter by name.

    Args:
        param_name: Key from KDF_PARAMS (e.g., 'ARGON2_TIME_COST').

    Returns:
        The parameter value.

    Raises:
        KeyError: If the parameter name is not recognized.
    """
    if param_name not in KDF_PARAMS:
        raise KeyError(f"Unknown KDF parameter: {param_name}")
    return KDF_PARAMS[param_name]
