"""Comprehensive unit tests for src/constants.py – Centralized constants."""

import pytest

from src.constants import (
    PROTOCOL_MAGIC_BYTES,
    KDF_PARAMS,
    CRYPTO_CONSTANTS,
    UI_CONSTANTS,
    SECURITY_CONSTANTS,
    DB_CONSTANTS,
    CONCURRENCY_CONSTANTS,
    get_magic_byte,
    get_kdf_param,
)


# ---------------------------------------------------------------------------
# Tests: PROTOCOL_MAGIC_BYTES
# ---------------------------------------------------------------------------

class TestProtocolMagicBytes:
    def test_ratchet_envelope_exists(self):
        assert "RATCHET_ENVELOPE" in PROTOCOL_MAGIC_BYTES
        assert PROTOCOL_MAGIC_BYTES["RATCHET_ENVELOPE"] == 0xD0

    def test_pqc_envelope_exists(self):
        assert "PQC_ENVELOPE" in PROTOCOL_MAGIC_BYTES
        assert PROTOCOL_MAGIC_BYTES["PQC_ENVELOPE"] == 0x50

    def test_file_shared_secret_exists(self):
        assert "FILE_SHARED_SECRET" in PROTOCOL_MAGIC_BYTES
        assert isinstance(PROTOCOL_MAGIC_BYTES["FILE_SHARED_SECRET"], bytes)

    def test_file_kdf_argon2id_exists(self):
        assert "FILE_KDF_ARGON2ID" in PROTOCOL_MAGIC_BYTES
        assert isinstance(PROTOCOL_MAGIC_BYTES["FILE_KDF_ARGON2ID"], bytes)

    def test_magic_bytes_unique(self):
        """All integer magic bytes should be unique."""
        int_values = [
            v for v in PROTOCOL_MAGIC_BYTES.values()
            if isinstance(v, int)
        ]
        assert len(int_values) == len(set(int_values))


# ---------------------------------------------------------------------------
# Tests: KDF_PARAMS
# ---------------------------------------------------------------------------

class TestKDFParams:
    def test_argon2_time_cost(self):
        assert KDF_PARAMS["ARGON2_TIME_COST"] >= 1

    def test_argon2_memory_cost(self):
        assert KDF_PARAMS["ARGON2_MEMORY_COST"] >= 8192  # At least 8 MB

    def test_argon2_parallelism(self):
        assert KDF_PARAMS["ARGON2_PARALLELISM"] >= 1

    def test_argon2_hash_len(self):
        assert KDF_PARAMS["ARGON2_HASH_LEN"] == 32

    def test_argon2_salt_len(self):
        assert KDF_PARAMS["ARGON2_SALT_LEN"] >= 8

    def test_pbkdf2_legacy_iterations(self):
        assert KDF_PARAMS["PBKDF2_LEGACY_ITERATIONS"] >= 100_000


# ---------------------------------------------------------------------------
# Tests: CRYPTO_CONSTANTS
# ---------------------------------------------------------------------------

class TestCryptoConstants:
    def test_aes_key_size(self):
        assert CRYPTO_CONSTANTS["AES_KEY_SIZE"] == 32

    def test_rsa_min_key_size(self):
        assert CRYPTO_CONSTANTS["RSA_MIN_KEY_SIZE"] >= 2048

    def test_legacy_key_retention_days(self):
        assert CRYPTO_CONSTANTS["LEGACY_KEY_RETENTION_DAYS"] > 0

    def test_aes_gcm_nonce_size(self):
        assert CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"] == 12

    def test_aes_gcm_tag_size(self):
        assert CRYPTO_CONSTANTS["AES_GCM_TAG_SIZE"] == 16


# ---------------------------------------------------------------------------
# Tests: UI_CONSTANTS
# ---------------------------------------------------------------------------

class TestUIConstants:
    def test_window_dimensions(self):
        assert UI_CONSTANTS["WINDOW_DEFAULT_WIDTH"] > 0
        assert UI_CONSTANTS["WINDOW_DEFAULT_HEIGHT"] > 0
        assert UI_CONSTANTS["WINDOW_MIN_WIDTH"] > 0
        assert UI_CONSTANTS["WINDOW_MIN_HEIGHT"] > 0

    def test_min_less_than_default(self):
        assert UI_CONSTANTS["WINDOW_MIN_WIDTH"] <= UI_CONSTANTS["WINDOW_DEFAULT_WIDTH"]
        assert UI_CONSTANTS["WINDOW_MIN_HEIGHT"] <= UI_CONSTANTS["WINDOW_DEFAULT_HEIGHT"]

    def test_password_min_length(self):
        assert UI_CONSTANTS["PASSWORD_MIN_LENGTH"] >= 8

    def test_clipboard_clear_delay(self):
        assert UI_CONSTANTS["CLIPBOARD_CLEAR_DELAY"] > 0

    def test_lock_screen_timeout(self):
        assert UI_CONSTANTS["LOCK_SCREEN_TIMEOUT"] > 0


# ---------------------------------------------------------------------------
# Tests: SECURITY_CONSTANTS
# ---------------------------------------------------------------------------

class TestSecurityConstants:
    def test_backoff_table(self):
        table = SECURITY_CONSTANTS["BACKOFF_TABLE"]
        assert isinstance(table, list)
        assert len(table) > 0
        # Should be non-decreasing
        for i in range(1, len(table)):
            assert table[i] >= table[i - 1]

    def test_hard_lockout_threshold(self):
        assert SECURITY_CONSTANTS["HARD_LOCKOUT_THRESHOLD"] > 0

    def test_hard_lockout_duration(self):
        assert SECURITY_CONSTANTS["HARD_LOCKOUT_DURATION"] > 0

    def test_max_totp_attempts(self):
        assert SECURITY_CONSTANTS["MAX_TOTP_ATTEMPTS"] > 0

    def test_session_timeout(self):
        assert SECURITY_CONSTANTS["SESSION_TIMEOUT"] > 0


# ---------------------------------------------------------------------------
# Tests: DB_CONSTANTS
# ---------------------------------------------------------------------------

class TestDBConstants:
    def test_db_filename(self):
        assert DB_CONSTANTS["DB_FILENAME"].endswith(".db")

    def test_db_dir_name(self):
        assert isinstance(DB_CONSTANTS["DB_DIR_NAME"], str)
        assert len(DB_CONSTANTS["DB_DIR_NAME"]) > 0

    def test_wal_mode(self):
        assert isinstance(DB_CONSTANTS["WAL_MODE"], bool)

    def test_foreign_keys(self):
        assert isinstance(DB_CONSTANTS["FOREIGN_KEYS"], bool)


# ---------------------------------------------------------------------------
# Tests: CONCURRENCY_CONSTANTS
# ---------------------------------------------------------------------------

class TestConcurrencyConstants:
    def test_max_workers(self):
        assert CONCURRENCY_CONSTANTS["CRYPTO_QUEUE_MAX_WORKERS"] >= 1

    def test_default_timeout(self):
        assert CONCURRENCY_CONSTANTS["CRYPTO_QUEUE_DEFAULT_TIMEOUT"] > 0

    def test_ratchet_lock_timeout(self):
        assert CONCURRENCY_CONSTANTS["RATCHET_LOCK_TIMEOUT"] > 0

    def test_pqc_operation_timeout(self):
        assert CONCURRENCY_CONSTANTS["PQC_OPERATION_TIMEOUT"] > 0

    def test_argon2id_timeout(self):
        assert CONCURRENCY_CONSTANTS["ARGON2ID_TIMEOUT"] > 0

    def test_file_operation_timeout(self):
        assert CONCURRENCY_CONSTANTS["FILE_OPERATION_TIMEOUT"] > 0

    def test_lock_max_age(self):
        assert CONCURRENCY_CONSTANTS["LOCK_MAX_AGE"] > 0


# ---------------------------------------------------------------------------
# Tests: get_magic_byte
# ---------------------------------------------------------------------------

class TestGetMagicByte:
    def test_ratchet_envelope(self):
        assert get_magic_byte("RATCHET_ENVELOPE") == 0xD0

    def test_pqc_envelope(self):
        assert get_magic_byte("PQC_ENVELOPE") == 0x50

    def test_unknown_raises(self):
        with pytest.raises(KeyError, match="Unknown envelope type"):
            get_magic_byte("NONEXISTENT")

    def test_file_shared_secret(self):
        result = get_magic_byte("FILE_SHARED_SECRET")
        assert isinstance(result, int)


# ---------------------------------------------------------------------------
# Tests: get_kdf_param
# ---------------------------------------------------------------------------

class TestGetKDFParam:
    def test_argon2_time_cost(self):
        assert get_kdf_param("ARGON2_TIME_COST") == 3

    def test_argon2_memory_cost(self):
        assert get_kdf_param("ARGON2_MEMORY_COST") == 65536

    def test_unknown_raises(self):
        with pytest.raises(KeyError, match="Unknown KDF parameter"):
            get_kdf_param("NONEXISTENT_PARAM")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
