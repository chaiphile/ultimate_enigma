"""Centralized constants for Ultimate Enigma.

This module eliminates magic numbers and strings scattered across services,
providing a single source of truth for protocol values, KDF parameters,
and UI configuration.
"""

from dataclasses import dataclass, field
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Protocol Magic Bytes
# ---------------------------------------------------------------------------
# Used to identify envelope types in encrypted messages and files.

PROTOCOL_MAGIC_BYTES = {
    "RATCHET_ENVELOPE": 0xD0,  # Double Ratchet encrypted message envelope
    "PQC_ENVELOPE": 0x50,      # Post-Quantum Hybrid KEM envelope
    "FILE_SHARED_SECRET": b'ENIGMA\x01',  # Shared-secret encrypted file header
    "FILE_KDF_ARGON2ID": b'A2ID',         # Argon2id KDF version tag for password-based files
    "TRUST_CERT_BUNDLE": 0x74,  # Trust certificate bundle envelope
}

# ---------------------------------------------------------------------------
# Key Derivation Function (KDF) Parameters
# ---------------------------------------------------------------------------
# Argon2id parameters for password-based key derivation.
# These are military-grade, memory-hard KDF settings.

@dataclass(frozen=True)
class KDFConfig:
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4
    argon2_hash_len: int = 32
    argon2_salt_len: int = 16
    pbkdf2_legacy_iterations: int = 300_000

KDF = KDFConfig()

KDF_PARAMS = {
    "ARGON2_TIME_COST": KDF.argon2_time_cost,
    "ARGON2_MEMORY_COST": KDF.argon2_memory_cost,
    "ARGON2_PARALLELISM": KDF.argon2_parallelism,
    "ARGON2_HASH_LEN": KDF.argon2_hash_len,
    "ARGON2_SALT_LEN": KDF.argon2_salt_len,
    "PBKDF2_LEGACY_ITERATIONS": KDF.pbkdf2_legacy_iterations,
}

# ---------------------------------------------------------------------------
# Cryptographic Constants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CryptoConfig:
    aes_key_size: int = 32
    rsa_min_key_size: int = 4096
    legacy_key_retention_days: int = 30
    aes_gcm_nonce_size: int = 12
    aes_gcm_tag_size: int = 16
    xchacha20_key_size: int = 32
    xchacha20_nonce_size: int = 24
    xchacha20_tag_size: int = 16
    time_step: int = 30
    window_size: int = 2
    self_destruct_flag: int = 4
    hybrid_sig_flag: int = 8
    key_hint_flag: int = 16

CRYPTO = CryptoConfig()

CRYPTO_CONSTANTS = {
    "AES_KEY_SIZE": CRYPTO.aes_key_size,
    "RSA_MIN_KEY_SIZE": CRYPTO.rsa_min_key_size,
    "LEGACY_KEY_RETENTION_DAYS": CRYPTO.legacy_key_retention_days,
    "AES_GCM_NONCE_SIZE": CRYPTO.aes_gcm_nonce_size,
    "AES_GCM_TAG_SIZE": CRYPTO.aes_gcm_tag_size,
    "XCHACHA20_KEY_SIZE": CRYPTO.xchacha20_key_size,
    "XCHACHA20_NONCE_SIZE": CRYPTO.xchacha20_nonce_size,
    "XCHACHA20_TAG_SIZE": CRYPTO.xchacha20_tag_size,
    "TIME_STEP": CRYPTO.time_step,
    "WINDOW_SIZE": CRYPTO.window_size,
    "SELF_DESTRUCT_FLAG": CRYPTO.self_destruct_flag,
    "HYBRID_SIG_FLAG": CRYPTO.hybrid_sig_flag,
    "KEY_HINT_FLAG": CRYPTO.key_hint_flag,
}

# ---------------------------------------------------------------------------
# UI Constants
# ---------------------------------------------------------------------------
# Default values and limits for the user interface.

@dataclass(frozen=True)
class UIConfig:
    window_default_width: int = 1400
    window_default_height: int = 850
    window_min_width: int = 1200
    window_min_height: int = 750
    password_min_length: int = 16
    friend_name_max_length: int = 64
    message_preview_length: int = 100
    clipboard_clear_delay: int = 30
    lock_screen_timeout: int = 300

UI = UIConfig()

UI_CONSTANTS = {
    "WINDOW_DEFAULT_WIDTH": UI.window_default_width,
    "WINDOW_DEFAULT_HEIGHT": UI.window_default_height,
    "WINDOW_MIN_WIDTH": UI.window_min_width,
    "WINDOW_MIN_HEIGHT": UI.window_min_height,
    "PASSWORD_MIN_LENGTH": UI.password_min_length,
    "FRIEND_NAME_MAX_LENGTH": UI.friend_name_max_length,
    "MESSAGE_PREVIEW_LENGTH": UI.message_preview_length,
    "CLIPBOARD_CLEAR_DELAY": UI.clipboard_clear_delay,
    "LOCK_SCREEN_TIMEOUT": UI.lock_screen_timeout,
}

# ---------------------------------------------------------------------------
# Security & Lockout Constants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityConfig:
    backoff_table: Tuple[int, ...] = (0, 0, 0, 0, 0, 5, 10, 30, 60, 120, 300, 600, 1800, 3600)
    hard_lockout_threshold: int = 15
    hard_lockout_duration: int = 3600
    max_totp_attempts: int = 5
    session_timeout: int = 900

SECURITY = SecurityConfig()

SECURITY_CONSTANTS = {
    "BACKOFF_TABLE": list(SECURITY.backoff_table),
    "HARD_LOCKOUT_THRESHOLD": SECURITY.hard_lockout_threshold,
    "HARD_LOCKOUT_DURATION": SECURITY.hard_lockout_duration,
    "MAX_TOTP_ATTEMPTS": SECURITY.max_totp_attempts,
    "SESSION_TIMEOUT": SECURITY.session_timeout,
}

# ---------------------------------------------------------------------------
# Database Constants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DBConfig:
    db_filename: str = "enigma.db"
    db_dir_name: str = ".ultimate_enigma"
    wal_mode: bool = True
    foreign_keys: bool = True
    sqlcipher_page_size: int = 4096
    sqlcipher_kdf_iter: int = 256000

DB = DBConfig()

DB_CONSTANTS = {
    "DB_FILENAME": DB.db_filename,
    "DB_DIR_NAME": DB.db_dir_name,
    "WAL_MODE": DB.wal_mode,
    "FOREIGN_KEYS": DB.foreign_keys,
    "SQLCIPHER_PAGE_SIZE": DB.sqlcipher_page_size,
    "SQLCIPHER_KDF_ITER": DB.sqlcipher_kdf_iter,
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


# ---------------------------------------------------------------------------
# Concurrency & Timeout Constants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConcurrencyConfig:
    crypto_queue_max_workers: int = 4
    crypto_queue_default_timeout: float = 120.0
    ratchet_lock_timeout: float = 30.0
    ratchet_lock_retry_interval: float = 0.05
    pqc_operation_timeout: float = 60.0
    argon2id_timeout: float = 90.0
    file_operation_timeout: float = 300.0
    rsa_operation_timeout: float = 30.0
    lock_cleanup_interval: int = 3600
    lock_max_age: int = 7200
    backup_reminder_interval: int = 3600
    ratchet_maintenance_interval: int = 3600
    system_monitor_interval: int = 300

CONCURRENCY = ConcurrencyConfig()

CONCURRENCY_CONSTANTS = {
    "CRYPTO_QUEUE_MAX_WORKERS": CONCURRENCY.crypto_queue_max_workers,
    "CRYPTO_QUEUE_DEFAULT_TIMEOUT": CONCURRENCY.crypto_queue_default_timeout,
    "RATCHET_LOCK_TIMEOUT": CONCURRENCY.ratchet_lock_timeout,
    "RATCHET_LOCK_RETRY_INTERVAL": CONCURRENCY.ratchet_lock_retry_interval,
    "PQC_OPERATION_TIMEOUT": CONCURRENCY.pqc_operation_timeout,
    "ARGON2ID_TIMEOUT": CONCURRENCY.argon2id_timeout,
    "FILE_OPERATION_TIMEOUT": CONCURRENCY.file_operation_timeout,
    "RSA_OPERATION_TIMEOUT": CONCURRENCY.rsa_operation_timeout,
    "LOCK_CLEANUP_INTERVAL": CONCURRENCY.lock_cleanup_interval,
    "LOCK_MAX_AGE": CONCURRENCY.lock_max_age,
    "BACKUP_REMINDER_INTERVAL": CONCURRENCY.backup_reminder_interval,
    "RATCHET_MAINTENANCE_INTERVAL": CONCURRENCY.ratchet_maintenance_interval,
    "SYSTEM_MONITOR_INTERVAL": CONCURRENCY.system_monitor_interval,
}

# ---------------------------------------------------------------------------
# Anti-Tamper & Anti-Debug Constants
# ---------------------------------------------------------------------------
# Configuration for anti-tamper and anti-debugger protections.
# Only active when running as a frozen PyInstaller executable.

@dataclass(frozen=True)
class AntiTamperConfig:
    background_check_interval: int = 30
    timing_check_threshold_ns: int = 500_000
    timing_samples: int = 5
    critical_modules: Tuple[str, ...] = (
        "crypto", "database", "key_manager", "encryption_service",
        "double_ratchet", "pqc_service", "auth_manager",
    )
    debugger_processes: Tuple[str, ...] = (
        "ollydbg.exe", "olly64.exe", "x64dbg.exe", "x32dbg.exe",
        "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
        "windbg.exe", "cdb.exe", "ntsd.exe",
        "processhacker.exe", "procmon.exe", "procmon64.exe",
        "cheatengine-x86_64.exe", "cheatengine-i386.exe",
        "dnSpy.exe", "ghidra.exe", "ghidraRun.exe",
        "radare2.exe", "r2.exe", "binaryninja.exe",
    )
    hooking_frameworks: Tuple[str, ...] = (
        "frida", "cuckoo", "cuckoomon", "pythonhooker",
        "detours", "minhook", "easyhook",
    )
    silent_exit: bool = True
    exit_code: int = 1
    hide_threads: bool = True

ANTI_TAMPER = AntiTamperConfig()

ANTI_TAMPER_CONSTANTS = {
    "BACKGROUND_CHECK_INTERVAL": ANTI_TAMPER.background_check_interval,
    "TIMING_CHECK_THRESHOLD_NS": ANTI_TAMPER.timing_check_threshold_ns,
    "TIMING_SAMPLES": ANTI_TAMPER.timing_samples,
    "CRITICAL_MODULES": list(ANTI_TAMPER.critical_modules),
    "DEBUGGER_PROCESSES": list(ANTI_TAMPER.debugger_processes),
    "HOOKING_FRAMEWORKS": list(ANTI_TAMPER.hooking_frameworks),
    "SILENT_EXIT": ANTI_TAMPER.silent_exit,
    "EXIT_CODE": ANTI_TAMPER.exit_code,
    "HIDE_THREADS": ANTI_TAMPER.hide_threads,
}

# ---------------------------------------------------------------------------
# Trust Chain & Certificate Constants
# ---------------------------------------------------------------------------
# Configuration for the trust chain certificate system and Shamir secret sharing.

@dataclass(frozen=True)
class TrustChainConfig:
    default_cert_validity_days: int = 365
    max_cert_validity_days: int = 3650
    min_cert_validity_days: int = 1
    trust_level_basic: int = 1
    trust_level_verified: int = 2
    trust_level_trusted: int = 3
    max_shares: int = 10
    min_shares: int = 2
    min_threshold: int = 2
    max_threshold: int = 10
    share_size: int = 32
    recovery_key_size: int = 32
    recovery_share_expiry_days: int = 365
    cert_type_identity: str = "identity"
    cert_type_recovery: str = "recovery"
    cert_type_delegation: str = "delegation"

TRUST_CHAIN = TrustChainConfig()

TRUST_CHAIN_CONSTANTS = {
    "DEFAULT_CERT_VALIDITY_DAYS": TRUST_CHAIN.default_cert_validity_days,
    "MAX_CERT_VALIDITY_DAYS": TRUST_CHAIN.max_cert_validity_days,
    "MIN_CERT_VALIDITY_DAYS": TRUST_CHAIN.min_cert_validity_days,
    "TRUST_LEVEL_BASIC": TRUST_CHAIN.trust_level_basic,
    "TRUST_LEVEL_VERIFIED": TRUST_CHAIN.trust_level_verified,
    "TRUST_LEVEL_TRUSTED": TRUST_CHAIN.trust_level_trusted,
    "MAX_SHARES": TRUST_CHAIN.max_shares,
    "MIN_SHARES": TRUST_CHAIN.min_shares,
    "MIN_THRESHOLD": TRUST_CHAIN.min_threshold,
    "MAX_THRESHOLD": TRUST_CHAIN.max_threshold,
    "SHARE_SIZE": TRUST_CHAIN.share_size,
    "RECOVERY_KEY_SIZE": TRUST_CHAIN.recovery_key_size,
    "RECOVERY_SHARE_EXPIRY_DAYS": TRUST_CHAIN.recovery_share_expiry_days,
    "CERT_TYPE_IDENTITY": TRUST_CHAIN.cert_type_identity,
    "CERT_TYPE_RECOVERY": TRUST_CHAIN.cert_type_recovery,
    "CERT_TYPE_DELEGATION": TRUST_CHAIN.cert_type_delegation,
}
