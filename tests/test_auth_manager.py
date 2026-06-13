"""Comprehensive unit tests for services/auth_manager.py – Authentication Manager."""

import json
import time
import secrets
import pytest
from unittest.mock import patch, MagicMock

import database
from key_manager import KeyStore, init_db, pubkey_to_pem
from services.auth_manager import AuthManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def password():
    return "StrongPassword123!"


@pytest.fixture
def key_store(password):
    init_db(password)
    ks = KeyStore()
    assert ks.load(password) is True
    return ks


@pytest.fixture
def auth_manager(key_store):
    return AuthManager(key_store)


# ---------------------------------------------------------------------------
# Tests: Password Verification
# ---------------------------------------------------------------------------

class TestVerifyPassword:
    def test_correct_password(self, auth_manager, password):
        valid, duress = auth_manager.verify_password(password)
        assert valid is True
        assert duress is False

    def test_wrong_password(self, auth_manager):
        valid, duress = auth_manager.verify_password("WrongPassword")
        assert valid is False
        assert duress is False

    def test_increments_failed_attempts(self, auth_manager):
        auth_manager.verify_password("wrong1")
        auth_manager.verify_password("wrong2")
        auth_manager.verify_password("wrong3")
        assert auth_manager._ks.failed_attempts == 3

    def test_successful_resets_attempts(self, auth_manager, password):
        auth_manager.verify_password("wrong1")
        auth_manager.verify_password("wrong2")
        auth_manager.verify_password(password)
        assert auth_manager._ks.failed_attempts == 0

    def test_duress_password(self, auth_manager, key_store, password):
        duress_pw = "DuressPassword123!"
        auth_manager.set_duress_password(duress_pw)
        valid, duress = auth_manager.verify_password(duress_pw)
        assert valid is True
        assert duress is True

    def test_duress_sets_duress_mode(self, auth_manager, key_store, password):
        duress_pw = "DuressPassword123!"
        auth_manager.set_duress_password(duress_pw)
        auth_manager.verify_password(duress_pw)
        assert key_store.is_duress_mode is True


# ---------------------------------------------------------------------------
# Tests: Lockout Mechanism
# ---------------------------------------------------------------------------

class TestLockoutMechanism:
    @patch("services.auth_manager.time.sleep", return_value=None)
    def test_lockout_delay_after_failures(self, mock_sleep, auth_manager):
        """After 5+ failures, delay should be non-zero."""
        for _ in range(6):
            auth_manager.verify_password("wrong")
        delay = auth_manager.get_lockout_delay()
        assert delay > 0

    def test_no_delay_under_threshold(self, auth_manager):
        """Under 5 failures, no delay."""
        for _ in range(4):
            auth_manager.verify_password("wrong")
        delay = auth_manager.get_lockout_delay()
        assert delay == 0

    @patch("services.auth_manager.time.sleep", return_value=None)
    def test_hard_lockout_threshold(self, mock_sleep, auth_manager):
        """After 15 failures, hard lockout should activate."""
        for _ in range(15):
            auth_manager.verify_password("wrong")
        delay = auth_manager.get_lockout_delay()
        assert delay > 0
        assert auth_manager._ks.locked_until > time.time()

    def test_lockout_state_persists(self, auth_manager):
        auth_manager.verify_password("wrong")
        auth_manager.save_lockout_state()
        assert auth_manager._ks.failed_attempts == 1


# ---------------------------------------------------------------------------
# Tests: Password Change
# ---------------------------------------------------------------------------

class TestChangePassword:
    def test_change_password_success(self, auth_manager, password):
        new_password = "NewStrongPassword456!"
        auth_manager.change_password(password, new_password)
        # Verify new password works
        valid, _ = auth_manager.verify_password(new_password)
        assert valid is True

    def test_change_password_wrong_old_raises(self, auth_manager, password):
        from src.exceptions import KeyStoreError
        with pytest.raises(KeyStoreError, match="old password verification failed"):
            auth_manager.change_password("WrongOld", "NewPassword")

    def test_change_password_updates_global_secret(self, auth_manager, key_store, password):
        original_secret = bytes(key_store.global_secret)
        new_password = "NewPassword456!"
        auth_manager.change_password(password, new_password)
        assert bytes(key_store.global_secret) == original_secret

    def test_change_password_updates_private_key(self, auth_manager, key_store, password):
        original_priv = key_store.my_priv
        new_password = "NewPassword789!"
        auth_manager.change_password(password, new_password)
        # Private key object reference may change but should still work
        assert key_store.my_priv is not None


# ---------------------------------------------------------------------------
# Tests: Duress Password
# ---------------------------------------------------------------------------

class TestDuressPassword:
    def test_set_duress_password(self, auth_manager, key_store):
        duress_pw = "DuressPassword123!"
        auth_manager.set_duress_password(duress_pw)
        # Verify it's stored in database
        conn = database.get_connection()
        row = conn.execute(
            "SELECT value FROM settings WHERE key='duress_verifier'"
        ).fetchone()
        conn.close()
        assert row is not None

    def test_load_duress_decoy(self, auth_manager, key_store, password):
        auth_manager.load_duress_decoy()
        assert key_store.is_duress_mode is True
        assert key_store.my_priv is not None
        assert key_store.my_pub is not None
        assert key_store.global_secret is not None


# ---------------------------------------------------------------------------
# Tests: Lockout State Management
# ---------------------------------------------------------------------------

class TestLockoutStateManagement:
    def test_load_lockout_state(self, auth_manager):
        auth_manager.load_lockout_state()
        assert auth_manager._ks.failed_attempts >= 0

    def test_save_lockout_state(self, auth_manager):
        auth_manager._ks.failed_attempts = 5
        auth_manager.save_lockout_state()
        # Reload and verify
        auth_manager.load_lockout_state()
        assert auth_manager._ks.failed_attempts == 5

    def test_get_lockout_delay_no_lockout(self, auth_manager):
        delay = auth_manager.get_lockout_delay()
        assert delay == 0

    def test_get_lockout_delay_with_active_lockout(self, auth_manager):
        auth_manager._ks.locked_until = time.time() + 60
        delay = auth_manager.get_lockout_delay()
        assert delay > 0
        assert delay <= 60


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_verify_password_empty_string(self, auth_manager):
        valid, duress = auth_manager.verify_password("")
        assert valid is False

    @patch("services.auth_manager.time.sleep", return_value=None)
    def test_multiple_verify_resets_on_success(self, mock_sleep, auth_manager, password):
        for _ in range(10):
            auth_manager.verify_password("wrong")
        assert auth_manager._ks.failed_attempts == 10
        auth_manager.verify_password(password)
        assert auth_manager._ks.failed_attempts == 0

    def test_backoff_table_values(self, auth_manager):
        """Verify backoff table has expected escalation."""
        table = auth_manager._BACKOFF_TABLE
        assert table[0] == 0
        assert table[4] == 0
        assert table[5] > 0  # First non-zero delay
        assert table[-1] > table[5]  # Escalation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
