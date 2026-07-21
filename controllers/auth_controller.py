"""Authentication controller.

Coordinates login, unlock, TOTP verification, password management,
and duress mode. Acts as the intermediary between the View layer (EnigmaApp/UI)
and the Model/Service layers (KeyStore, AuthManager, TOTPService).
"""

import gc
import logging

from typing import Union

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from key_manager import KeyStore
from services.auth_manager import AuthManager
from services.totp_service import TOTPService
from services.totp_persistence import TotpPersistence

from src.secure_string import SecureString
from services.event_bus import event_bus, Events


logger = logging.getLogger(__name__)


class _DefaultUI:
    """Default UI callbacks using tkinter messagebox/password_dialog."""

    def __init__(self, root):
        self.root = root

    def password_dialog(self, title, confirm=False, **kwargs):
        from views.dialogs import password_dialog
        return password_dialog(self.root, title, confirm=confirm, **kwargs)

    def show_error(self, title, message):
        from tkinter import messagebox
        messagebox.showerror(title, message)

    def show_info(self, title, message):
        from tkinter import messagebox
        messagebox.showinfo(title, message)

    def show_warning(self, title, message):
        from tkinter import messagebox
        messagebox.showwarning(title, message)


_DURESS_PLACEHOLDER = "duress_placeholder"


class AuthController:
    """Manages all authentication workflows."""

    def __init__(self, root, key_store: KeyStore, ui=None, totp_persistence: TotpPersistence = None):
        self.root = root
        self.ks = key_store
        self.auth_manager = AuthManager(key_store)
        self.totp_service = TOTPService()
        self._totp_persistence = totp_persistence or TotpPersistence(key_store)
        self._ph = PasswordHasher()
        self._master_password_hash = None
        self._ui = ui or _DefaultUI(root)
        self._recovery_requested = False

    def set_key_store(self, key_store: KeyStore) -> None:
        """Retarget auth helpers to the currently active KeyStore."""
        self.ks = key_store
        self.auth_manager = AuthManager(key_store)
        self._totp_persistence.ks = key_store

    @property
    def master_password_hash(self):
        return self._master_password_hash

    @master_password_hash.setter
    def master_password_hash(self, value):
        self._master_password_hash = value

    # ------------------------------------------------------------------
    # Initial Key Loading (Startup)
    # ------------------------------------------------------------------
    def load_keys(self, first_run: bool) -> bool:
        """Handle initial key loading and password setup/verification.
        
        Returns True if keys are loaded successfully, False otherwise.
        """
        if first_run:
            return self._first_run_setup()
        else:
            return self._existing_user_login()

    def _first_run_setup(self) -> bool:
        from key_manager import init_db
        
        pw = self._ui.password_dialog("Set Master Password", confirm=True)
        if not pw:
            logger.warning("First run: user cancelled password dialog")
            return False
            
        try:
            init_db(pw)
            if not self.ks.load(pw):
                self._ui.show_error("Error", "Failed to load new keys.")
                return False
                
            self._master_password_hash = self._ph.hash(pw.to_str() if isinstance(pw, SecureString) else pw)
            self.init_totp(pw)
            logger.info("Master password hash set (first run)")

            return True
        finally:
            # Securely wipe the password from memory
            if isinstance(pw, SecureString):
                pw.wipe()
            pw = None
            gc.collect()

    def _existing_user_login(self) -> bool:
        for attempt in range(3):
            self._recovery_requested = False
            pw = self._ui.password_dialog(
                "Unlock Private Key", confirm=False,
                on_recover=self._on_startup_recover,
            )
            if self._recovery_requested:
                self._recovery_requested = False
                success, new_ks, new_totp = self.request_recovery_unlock()
                if success and new_ks is not None:
                    self.set_key_store(new_ks)
                    if new_totp is not None:
                        self.totp_service = new_totp
                    return True
                continue
            if not pw:
                logger.warning("User cancelled password dialog (attempt %d)", attempt + 1)
                return False
            
            try:
                is_valid, is_duress = self.auth_manager.verify_password(pw)
                if not is_valid:
                    self._ui.show_error("Wrong Password", "Incorrect password.")
                    continue

                if is_duress:
                    self.enter_duress_mode(pw)
                    return True

                if self.ks.load(pw):
                    self._master_password_hash = self._ph.hash(pw.to_str() if isinstance(pw, SecureString) else pw)
                    self.init_totp(pw)
                    logger.info("Master password hash set (existing DB)")

                    return True
                else:
                    self._ui.show_error("Error", "Failed to load keys.")
                    return False
            finally:
                # Securely wipe the password from memory
                if isinstance(pw, SecureString):
                    pw.wipe()
                pw = None
                gc.collect()
                
        self._ui.show_error("Access Denied", "Too many attempts.")
        return False

    def _on_startup_recover(self) -> None:
        """Callback for recovery button in startup password dialog."""
        self._recovery_requested = True

    # ------------------------------------------------------------------
    # Unlock Flow
    # ------------------------------------------------------------------
    def request_unlock(self, current_ks: KeyStore) -> tuple[bool, KeyStore | None, TOTPService | None]:
        """Execute the full unlock sequence.
        
        Returns:
            (success, new_key_store, new_totp_service)
        """
        if self._master_password_hash is None:
            if not self._recover_password_hash():
                return False, None, None

        pw = self._unlock_password_dialog()
        if not pw:
            return False, None, None

        try:
            pw_str = pw.to_str() if isinstance(pw, SecureString) else pw
            try:
                self._ph.verify(self._master_password_hash, pw_str)
            except VerifyMismatchError:
                # Check if this is a duress password
                is_valid, is_duress = self.auth_manager.verify_password(pw)
                if is_valid and is_duress:
                    temp_ks = KeyStore()
                    temp_ks.load_duress_decoy(pw)
                    self._master_password_hash = self._ph.hash(_DURESS_PLACEHOLDER)
                    temp_totp = TOTPService()
                    return True, temp_ks, temp_totp
                self._ui.show_error("Failed", "Incorrect master password.")
                logger.warning("Unlock failed: incorrect password")
                return False, None, None
            except Exception as e:
                self._ui.show_error("Error", f"Password verification failed: {e}")
                logger.error("Unlock failed: Argon2 verification error: %s", e)
                return False, None, None

            # Reload keys
            temp_ks = KeyStore()
            if not temp_ks.load(pw):
                self._ui.show_error("Error", "Failed to reload keys.\nPassword may be correct but keys corrupted.")
                logger.error("Unlock failed: KeyStore.load() returned False")
                return False, None, None

            # TOTP verification
            temp_totp = TOTPService()
            if self.is_totp_enabled() and self.is_totp_setup_complete():
                loaded = self.load_totp_secret(temp_totp, password=pw, ks=temp_ks)
                if not loaded:
                    self._ui.show_error("Error", "Failed to load TOTP secret from database.\nTOTP may need to be reconfigured.")
                    logger.error("Unlock failed: could not load TOTP secret from DB")
                    temp_ks.wipe()
                    return False, None, None

                if not self._totp_verify_dialog(temp_totp):
                    temp_totp.clear_secret()
                    temp_ks.wipe()
                    return False, None, None
            else:
                self.load_totp_secret(temp_totp, password=pw, ks=temp_ks)

            return True, temp_ks, temp_totp
        finally:
            # Securely wipe the password from memory
            if isinstance(pw, SecureString):
                pw.wipe()
            pw = None
            gc.collect()

    def request_recovery_unlock(self) -> tuple[bool, KeyStore | None, TOTPService | None]:
        """Execute recovery unlock using Shamir shares (no old password needed).

        Shows the RecoveryUnlockDialog which lets the user reconstruct shares
        and set a new password. Calls KeyStore.reset_with_recovery_key() to
        regenerate all crypto material.

        Returns:
            (success, new_key_store, new_totp_service)
        """
        from components.recovery_unlock_dialog import RecoveryUnlockDialog
        from src.secure_string import SecureString

        result_state = {"success": False, "ks": None, "totp": None}

        def on_recovered(new_password_str):
            try:
                new_pw = SecureString(new_password_str)

                # Reset the keystore with the new password
                temp_ks = KeyStore()
                temp_ks.reset_with_recovery_key(new_pw)

                result_state["success"] = True
                result_state["ks"] = temp_ks
                result_state["totp"] = TOTPService()

                self._master_password_hash = self._ph.hash(
                    new_pw.to_str() if isinstance(new_pw, SecureString) else new_pw
                )

                new_pw.wipe()
            except Exception as e:
                logger.error("Recovery unlock failed: %s", e)
                self._ui.show_error("Recovery Failed", f"Failed to complete recovery:\n{e}")

        dlg = RecoveryUnlockDialog(self.root, on_recovered=on_recovered)
        dlg.show()

        return result_state["success"], result_state["ks"], result_state["totp"]

    def _recover_password_hash(self) -> bool:
        logger.warning("Password hash is None, attempting recovery")
        pw = self._unlock_password_dialog()
        if not pw:
            return False
        
        try:
            temp_ks = KeyStore()
            if temp_ks.verify_password(pw) and temp_ks.load(pw):
                self._master_password_hash = self._ph.hash(pw.to_str() if isinstance(pw, SecureString) else pw)
                logger.info("Password hash recovered successfully")
                temp_ks.wipe()
                return True
            else:
                self._ui.show_error("Error", "Unable to verify password.\nPlease restart the application.")
                logger.error("Unlock failed: could not recover password hash")
                temp_ks.wipe()
                return False
        finally:
            if isinstance(pw, SecureString):
                pw.wipe()
            pw = None
            gc.collect()

    def _unlock_password_dialog(self) -> SecureString | None:
        return self._ui.password_dialog("Unlock - Master Password", confirm=False, topmost=True, bg="#1a1a1a", fg="#ffffff")

    def _totp_verify_dialog(self, totp_service: TOTPService) -> bool:
        from components.totp_dialogs import TOTPVerifyDialog
        verify_dlg = TOTPVerifyDialog(self.root, totp_service)
        return verify_dlg.show()

    # ------------------------------------------------------------------
    # TOTP Management
    # ------------------------------------------------------------------
    def load_totp_secret(self, totp_service: TOTPService, password: str = None, ks=None) -> bool:
        return self._totp_persistence.load_totp_secret(totp_service, password, ks)

    def persist_totp_secret(self, secret_bytes: bytes, password: str = None) -> None:
        self._totp_persistence.persist_totp_secret(secret_bytes, password)

    def init_totp(self, password: str = None) -> None:
        """Initialize TOTP: load existing secret or generate new one."""
        try:
            loaded = self.load_totp_secret(self.totp_service, password)
            if not loaded:
                self.generate_new_totp(password)
        except Exception as e:
            logger.warning("TOTP init failed, generating new secret: %s", e)
            self.generate_new_totp(password)

    def generate_new_totp(self, password: str = None) -> None:
        """Generate and persist a new TOTP secret."""
        new_secret = TOTPService.generate_random_secret(32)
        self.totp_service.set_secret(new_secret)
        actual_secret = self.totp_service.get_raw_secret()
        self.persist_totp_secret(actual_secret, password)
        logger.info("New TOTP secret generated and persisted")

    def enforce_mandatory_totp_setup(self) -> bool:
        """Force TOTP setup if not complete. Returns True if setup is valid."""
        from components.totp_dialogs import TOTPSetupDialog
        
        if self.is_totp_setup_complete():
            return True

        logger.info("TOTP setup not complete - enforcing mandatory setup")
        if not self.totp_service.has_secret():
            self.generate_new_totp()
            
        uri = self.totp_service.provisioning_uri()
        setup_dlg = TOTPSetupDialog(
            self.root, self.totp_service, uri,
            on_regenerate=lambda: self.regenerate_totp()
        )
        
        if setup_dlg.show():
            self.set_totp_setup_complete(True)
            self.set_totp_enabled(True)
            logger.info("Mandatory TOTP setup completed successfully")

            return True
        else:
            self._ui.show_error(
                "Mandatory Setup",
                "TOTP two-factor authentication is MANDATORY.\n"
                "The application cannot be used without completing TOTP setup.\n\n"
                "Application will now exit."
            )
            self.totp_service.clear_secret()
            return False

    def verify_startup_totp(self) -> bool:
        """Verify TOTP on startup if enabled. Returns True if verified or not required."""
        from components.totp_dialogs import TOTPVerifyDialog
        
        if self.is_totp_enabled() and self.is_totp_setup_complete() and self.totp_service.has_secret():
            verify_dlg = TOTPVerifyDialog(self.root, self.totp_service)
            if not verify_dlg.show():
                self._ui.show_error("Access Denied", "TOTP verification failed.\nApplication will now exit.")
                self.totp_service.clear_secret()
                return False

        elif self.is_totp_enabled() and self.is_totp_setup_complete() and not self.totp_service.has_secret():
            logger.warning("TOTP setup marked complete but secret not loaded - skipping verification")
            
        return True

    def regenerate_totp(self) -> None:
        """Regenerate TOTP secret (called from setup dialog)."""
        new_secret = TOTPService.generate_random_secret(32)
        self.totp_service.set_secret(new_secret)
        actual_secret = self.totp_service.get_raw_secret()
        self.persist_totp_secret(actual_secret)
        logger.info("TOTP secret regenerated and persisted")


    def show_totp_setup(self) -> None:
        """Show TOTP setup dialog."""
        from components.totp_dialogs import TOTPSetupDialog
        
        if not self.totp_service.has_secret():
            self.generate_new_totp()
        uri = self.totp_service.provisioning_uri()
        setup_dlg = TOTPSetupDialog(
            self.root, self.totp_service, uri,
            on_regenerate=lambda: self.regenerate_totp()
        )
        if setup_dlg.show():
            self.set_totp_setup_complete(True)
            if not self.is_totp_enabled():
                self.set_totp_enabled(True)
                logger.info("TOTP automatically enabled after setup completion")


    # ------------------------------------------------------------------
    # TOTP Settings Accessors
    # ------------------------------------------------------------------
    def is_totp_setup_complete(self) -> bool:
        return self._totp_persistence.is_totp_setup_complete()

    def set_totp_setup_complete(self, value: bool) -> None:
        self._totp_persistence.set_totp_setup_complete(value)

    def is_totp_enabled(self) -> bool:
        return self._totp_persistence.is_totp_enabled()

    def set_totp_enabled(self, value: bool) -> None:
        self._totp_persistence.set_totp_enabled(value)

    # ------------------------------------------------------------------
    # Password & Duress Management
    # ------------------------------------------------------------------
    def change_password(self) -> bool:
        """Orchestrate master password change. Returns True on success."""
        old_pw = self._ui.password_dialog("Change Password - Verify Current", confirm=False)
        if not old_pw:
            return False

        try:
            is_valid, is_duress = self.auth_manager.verify_password(old_pw)
            if not is_valid:
                self._ui.show_error("Verification Failed", "Current password is incorrect.")
                return False

            if is_duress:
                self._ui.show_error("Verification Failed", "Cannot change password while in duress mode.")
                logger.warning("Password change rejected: duress password used")
                return False

            new_pw = self._ui.password_dialog("Change Password - Set New Password", confirm=True, enforce_strength=True)
            if not new_pw:
                return False

            try:
                # Compare passwords using SecureString's constant-time comparison
                if old_pw == new_pw:
                    self._ui.show_warning("Same Password", "New password must be different from the current password.")
                    return False

                success = self.ks.change_password(old_pw, new_pw)
                if not success:
                    self._ui.show_error("Password Change Failed", "An error occurred while changing the password.")
                    return False

                self._master_password_hash = self._ph.hash(new_pw.to_str() if isinstance(new_pw, SecureString) else new_pw)
                
                if self.totp_service.has_secret():
                    actual_secret = self.totp_service.get_raw_secret()
                    self.persist_totp_secret(actual_secret, new_pw)

                self._ui.show_info("Password Changed", "Master password has been changed successfully.")
                logger.info("Master password changed successfully via UI")

                return True
            finally:
                if isinstance(new_pw, SecureString):
                    new_pw.wipe()
                new_pw = None
                gc.collect()
        finally:
            if isinstance(old_pw, SecureString):
                old_pw.wipe()
            old_pw = None
            gc.collect()

    def set_duress_password(self) -> bool:
        """Orchestrate duress password setup. Returns True on success."""
        master_pw = self._ui.password_dialog("Set Duress Password - Verify Master", confirm=False)
        if not master_pw:
            return False

        try:
            is_valid, is_duress = self.auth_manager.verify_password(master_pw)
            if not is_valid or is_duress:
                self._ui.show_error("Verification Failed", "Master password is incorrect.")
                return False

            duress_pw = self._ui.password_dialog("Set Duress Password", confirm=True, enforce_strength=True)
            if not duress_pw:
                return False

            try:
                # Compare passwords using SecureString's constant-time comparison
                if duress_pw == master_pw:
                    self._ui.show_warning("Invalid Choice", "Duress password must be different from the master password.")
                    return False

                try:
                    self.ks.set_duress_password(duress_pw)
                    self._ui.show_info("Duress Password Set", "Duress password has been configured successfully.")
                    logger.info("Duress password set via UI")
                    return True
                except Exception as e:
                    self._ui.show_error("Error", f"Failed to set duress password:\n{e}")
                    logger.error("Failed to set duress password: %s", e)
                    return False
            finally:
                if isinstance(duress_pw, SecureString):
                    duress_pw.wipe()
                duress_pw = None
                gc.collect()
        finally:
            if isinstance(master_pw, SecureString):
                master_pw.wipe()
            master_pw = None
            gc.collect()

    def enter_duress_mode(self, password=None) -> None:
        """Enter decoy mode with fake data."""
        self.ks.load_duress_decoy(password)
        self._master_password_hash = self._ph.hash(_DURESS_PLACEHOLDER)
        self.totp_service.clear_secret()
        event_bus.publish(Events.DURESS_MODE_ENTERED, source="auth_controller")


    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def wipe_sensitive_data(self):
        """Clear all sensitive authentication data from memory."""
        self.totp_service.clear_secret()
        self.ks.wipe()

