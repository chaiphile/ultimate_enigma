"""Unit tests for controllers/auth_controller.py."""

import json
import secrets
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from controllers.auth_controller import AuthController
from services.totp_persistence import TOTP_SETUP_KEY, TOTP_ENABLED_KEY
from services.event_bus import Events
from src.secure_string import SecureString


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Redirect DB_PATH to a temporary directory for every test."""
    import database
    fake_db = tmp_path / "test_enigma.db"
    with patch.object(database, "DB_PATH", fake_db):
        database.init_db()
        yield fake_db


@pytest.fixture
def mock_ks():
    ks = MagicMock()
    ks.verify_password.return_value = True
    ks.is_duress_mode = False
    ks.load.return_value = True
    ks.global_secret = None
    return ks


@pytest.fixture
def mock_ui():
    ui = MagicMock()
    ui.password_dialog.return_value = SecureString("test_password")
    return ui


@pytest.fixture
def mock_root():
    return MagicMock()


@pytest.fixture
def mock_totp_service():
    ts = MagicMock()
    ts.has_secret.return_value = False
    ts.generate.return_value = "123456"
    ts.verify.return_value = True
    return ts


@pytest.fixture
def controller(mock_root, mock_ks, mock_ui):
    with patch("controllers.auth_controller.AuthManager"), \
         patch("controllers.auth_controller.TOTPService") as MockTotp:
        MockTotp.return_value = MagicMock()
        ctrl = AuthController(mock_root, mock_ks, ui=mock_ui)
        ctrl.auth_manager = MagicMock()
        ctrl.auth_manager.verify_password.return_value = (True, False)
        ctrl.totp_service = MagicMock()
        ctrl.totp_service.has_secret.return_value = False
        ctrl.totp_service.verify.return_value = True
        ctrl.totp_service.generate.return_value = "123456"
        ctrl.totp_service.get_raw_secret.return_value = b"raw_secret"
        ctrl.totp_service.set_secret = MagicMock()
        ctrl.totp_service.set_raw_secret = MagicMock()
        ctrl.totp_service.clear_secret = MagicMock()
        return ctrl


# ---------------------------------------------------------------------------
# Tests: load_keys
# ---------------------------------------------------------------------------

class TestLoadKeys:
    def test_first_run_success(self, controller, mock_ks):
        """first_run=True: calls init_db, loads keys, sets master_password_hash."""
        pw = SecureString("new_master_pw")
        controller._ui.password_dialog.return_value = pw

        with patch("key_manager.init_db") as mock_init_db, \
             patch.object(controller, "init_totp"):
            result = controller.load_keys(first_run=True)

        assert result is True
        mock_init_db.assert_called_once()
        mock_ks.load.assert_called_once_with(pw)
        assert controller.master_password_hash is not None

    def test_first_run_user_cancels(self, controller):
        """first_run=True: user cancels password dialog returns False."""
        controller._ui.password_dialog.return_value = None
        with patch("key_manager.init_db"):
            result = controller.load_keys(first_run=True)
        assert result is False

    def test_first_run_load_fails(self, controller, mock_ks):
        """first_run=True: ks.load returns False triggers error."""
        mock_ks.load.return_value = False
        pw = SecureString("pw")
        controller._ui.password_dialog.return_value = pw

        with patch("key_manager.init_db"), \
             patch.object(controller, "init_totp"):
            result = controller.load_keys(first_run=True)

        assert result is False
        pw.wipe()

    def test_existing_user_login_success(self, controller, mock_ks):
        """first_run=False: successful login on first attempt."""
        pw = SecureString("correct_pw")
        controller._ui.password_dialog.return_value = pw
        mock_ks.is_duress_mode = False

        with patch.object(controller, "init_totp"):
            result = controller.load_keys(first_run=False)

        assert result is True
        assert controller.master_password_hash is not None
        pw.wipe()

    def test_existing_user_wrong_password_then_success(self, controller, mock_ks):
        """first_run=False: wrong password on first attempt, correct on second."""
        pw_wrong = SecureString("wrong_pw")
        pw_correct = SecureString("correct_pw")
        call_count = [0]

        def dialog_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return pw_wrong
            return pw_correct

        controller._ui.password_dialog.side_effect = dialog_side_effect
        controller.auth_manager.verify_password.side_effect = lambda p: (p.to_str() == "correct_pw", False)

        with patch.object(controller, "init_totp"):
            result = controller.load_keys(first_run=False)

        assert result is True
        assert controller._ui.show_error.call_count == 1

    def test_existing_user_too_many_attempts(self, controller, mock_ks):
        """first_run=False: 3 wrong attempts shows 'Access Denied'."""
        controller.auth_manager.verify_password.return_value = (False, False)
        controller._ui.password_dialog.side_effect = lambda *a, **kw: SecureString("wrong")

        with patch.object(controller, "init_totp"):
            result = controller.load_keys(first_run=False)

        assert result is False
        controller._ui.show_error.assert_called()
        last_call = controller._ui.show_error.call_args_list[-1]
        assert "Access Denied" in str(last_call)

    def test_existing_user_cancels_returns_false(self, controller, mock_ks):
        """first_run=False: user cancels password dialog returns False."""
        controller._ui.password_dialog.return_value = None
        with patch.object(controller, "init_totp"):
            result = controller.load_keys(first_run=False)
        assert result is False

    def test_existing_user_duress_mode(self, controller, mock_ks):
        """first_run=False: duress mode triggers enter_duress_mode."""
        pw = SecureString("duress_pw")
        controller._ui.password_dialog.return_value = pw
        controller.auth_manager.verify_password.return_value = (True, True)
        mock_ks.is_duress_mode = True

        with patch.object(controller, "enter_duress_mode") as mock_enter:
            result = controller.load_keys(first_run=False)

        assert result is True
        mock_enter.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: change_password
# ---------------------------------------------------------------------------

class TestChangePassword:
    def test_change_password_success(self, controller, mock_ks):
        """Successful password change path."""
        old_pw = SecureString("old_password")
        new_pw = SecureString("new_password")

        call_count = [0]
        def dialog_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return old_pw
            if call_count[0] == 2:
                return new_pw
            return None

        controller._ui.password_dialog.side_effect = dialog_side_effect
        mock_ks.verify_password.return_value = True
        mock_ks.change_password.return_value = True

        with patch.object(controller, "persist_totp_secret"):
            result = controller.change_password()

        assert result is True
        mock_ks.change_password.assert_called_once_with(old_pw, new_pw)
        assert controller.master_password_hash is not None

    def test_change_password_wrong_old_password(self, controller, mock_ks):
        """Wrong current password returns False."""
        controller._ui.password_dialog.return_value = SecureString("wrong_old")
        mock_ks.verify_password.return_value = False

        result = controller.change_password()

        assert result is False
        controller._ui.show_error.assert_called()

    def test_change_password_user_cancels_old(self, controller):
        """User cancels old password dialog."""
        controller._ui.password_dialog.return_value = None
        assert controller.change_password() is False

    def test_change_password_user_cancels_new(self, controller, mock_ks):
        """User cancels new password dialog after verifying old."""
        old_pw = SecureString("old")
        dialog_count = [0]
        def side_effect(*args, **kwargs):
            dialog_count[0] += 1
            if dialog_count[0] == 1:
                return old_pw
            return None

        controller._ui.password_dialog.side_effect = side_effect
        mock_ks.verify_password.return_value = True

        result = controller.change_password()
        assert result is False

    def test_change_password_same_password(self, controller, mock_ks):
        """New password same as old returns False."""
        pw = SecureString("same_password")

        call_count = [0]
        def dialog_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                return pw
            return None

        controller._ui.password_dialog.side_effect = dialog_side_effect
        mock_ks.verify_password.return_value = True

        result = controller.change_password()
        assert result is False
        controller._ui.show_warning.assert_called()


# ---------------------------------------------------------------------------
# Tests: set_duress_password
# ---------------------------------------------------------------------------

class TestSetDuressPassword:
    def test_set_duress_password_success(self, controller, mock_ks):
        """Successful duress password setup."""
        master_pw = SecureString("master")
        duress_pw = SecureString("duress")
        call_count = [0]

        def dialog_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return master_pw
            return duress_pw

        controller._ui.password_dialog.side_effect = dialog_side_effect
        mock_ks.verify_password.return_value = True
        mock_ks.is_duress_mode = False

        result = controller.set_duress_password()

        assert result is True
        mock_ks.set_duress_password.assert_called_once()

    def test_set_duress_password_user_cancels_master(self, controller):
        """User cancels master password dialog."""
        controller._ui.password_dialog.return_value = None
        assert controller.set_duress_password() is False

    def test_set_duress_password_wrong_master(self, controller, mock_ks):
        """Wrong master password."""
        controller._ui.password_dialog.return_value = SecureString("wrong")
        mock_ks.verify_password.return_value = False
        assert controller.set_duress_password() is False

    def test_set_duress_password_same_as_master(self, controller, mock_ks):
        """Duress password same as master returns False."""
        master_pw = SecureString("master")
        call_count = [0]

        def dialog_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return master_pw
            return SecureString("master")

        controller._ui.password_dialog.side_effect = dialog_side_effect
        mock_ks.verify_password.return_value = True
        mock_ks.is_duress_mode = False

        result = controller.set_duress_password()
        assert result is False
        controller._ui.show_warning.assert_called()

    def test_set_duress_password_when_already_duress(self, controller, mock_ks):
        """Cannot set duress password while in duress mode."""
        controller._ui.password_dialog.return_value = SecureString("master")
        mock_ks.verify_password.return_value = True
        mock_ks.is_duress_mode = True

        result = controller.set_duress_password()
        assert result is False


# ---------------------------------------------------------------------------
# Tests: enter_duress_mode
# ---------------------------------------------------------------------------

class TestEnterDuressMode:
    def test_enter_duress_mode_publishes_event(self, controller, mock_ks):
        """enter_duress_mode publishes DURESS_MODE_ENTERED."""
        published_events = []
        from services.event_bus import event_bus
        event_bus.subscribe(Events.DURESS_MODE_ENTERED, lambda **kw: published_events.append(kw))

        controller.enter_duress_mode()

        mock_ks.load_duress_decoy.assert_called_once()
        mock_ks.clear_secret.assert_not_called()
        assert len(published_events) == 1
        event_bus.unsubscribe(Events.DURESS_MODE_ENTERED, lambda **kw: published_events.append(kw))


# ---------------------------------------------------------------------------
# Tests: is_totp_setup_complete / is_totp_enabled
# ---------------------------------------------------------------------------

class TestTOTPSettings:
    def test_is_totp_setup_complete_true(self, controller):
        """Returns True when totp_setup_complete = '1'."""
        import database
        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (TOTP_SETUP_KEY, "1")
            )
            conn.commit()

        assert controller.is_totp_setup_complete() is True

    def test_is_totp_setup_complete_false(self, controller):
        """Returns False when key missing."""
        assert controller.is_totp_setup_complete() is False

    def test_is_totp_enabled_true(self, controller):
        """Returns True when totp_enabled = '1'."""
        import database
        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (TOTP_ENABLED_KEY, "1")
            )
            conn.commit()

        assert controller.is_totp_enabled() is True

    def test_is_totp_enabled_false_when_not_set(self, controller):
        """Returns False when key missing."""
        assert controller.is_totp_enabled() is False

    def test_is_totp_enabled_falls_back_to_setup(self, controller):
        """When totp_enabled key missing, falls back to totp_setup_complete."""
        import database
        with closing(database.get_connection()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (TOTP_SETUP_KEY, "1")
            )
            conn.commit()

        assert controller.is_totp_enabled() is True


# Needed for the context manager in TestTOTPSettings
from contextlib import closing
