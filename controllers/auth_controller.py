"""Authentication controller.

Coordinates login, unlock, TOTP verification, password management,
and duress mode. Acts as the intermediary between the View layer (EnigmaApp/UI)
and the Model/Service layers (KeyStore, AuthManager, TOTPService).

Publishes Events:
    PASSWORD_CHANGED - after master password is changed.
    TOTP_SETUP_COMPLETE - after TOTP setup is completed.
    TOTP_VERIFIED - after TOTP verification succeeds.
    TOTP_CHANGED - after TOTP secret is regenerated.
    DURESS_MODE_ENTERED - when duress mode is activated.
    KEYS_LOADED - after keys are loaded successfully.
"""

import base64
import gc
import json
import logging
from contextlib import closing

from typing import Union

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import database
from key_manager import KeyStore
from services.auth_manager import AuthManager
from services.totp_service import TOTPService
from services.event_bus import event_bus, Events
from src.secure_string import SecureString


logger = logging.getLogger(__name__)


class _DefaultUI:
    """Default UI callbacks using tkinter messagebox/password_dialog."""

    def __init__(self, root):
        self.root = root

    def password_dialog(self, title, confirm=False, **kwargs):
        from views.utils import password_dialog
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


# Database keys for TOTP settings
TOTP_SECRET_KEY = "totp_secret_encrypted"
TOTP_SETUP_KEY = "totp_setup_complete"
TOTP_ENABLED_KEY = "totp_enabled"

_DURESS_PLACEHOLDER = "duress_placeholder"


class AuthController:
    """Manages all authentication workflows."""

    def __init__(self, root, key_store: KeyStore, ui=None):
        self.root = root
        self.ks = key_store
        self.auth_manager = AuthManager(key_store)
        self.totp_service = TOTPService()
        self._ph = PasswordHasher()
        self._master_password_hash = None
        self._ui = ui or _DefaultUI(root)

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
            event_bus.publish(Events.KEYS_LOADED, source="auth_controller", first_run=True)
            return True
        finally:
            # Securely wipe the password from memory
            if isinstance(pw, SecureString):
                pw.wipe()
            pw = None
            gc.collect()

    def _existing_user_login(self) -> bool:
        for attempt in range(3):
            pw = self._ui.password_dialog("Unlock Private Key", confirm=False)
            if not pw:
                logger.warning("User cancelled password dialog (attempt %d)", attempt + 1)
                return False
            
            try:
                is_valid = self.ks.verify_password(pw)
                if not is_valid:
                    self._ui.show_error("Wrong Password", "Incorrect password.")
                    continue

                if self.ks.is_duress_mode:
                    self.enter_duress_mode()
                    return True

                if self.ks.load(pw):
                    self._master_password_hash = self._ph.hash(pw.to_str() if isinstance(pw, SecureString) else pw)
                    self.init_totp(pw)
                    logger.info("Master password hash set (existing DB)")
                    event_bus.publish(Events.KEYS_LOADED, source="auth_controller", first_run=False)
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
            # Verify password hash
            pw_str = pw.to_str() if isinstance(pw, SecureString) else pw
            try:
                self._ph.verify(self._master_password_hash, pw_str)
            except VerifyMismatchError:
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

    def _unlock_password_dialog(self) -> str | None:
        return self._ui.password_dialog("Unlock - Master Password", confirm=False, topmost=True, bg="#1a1a1a", fg="#ffffff")

    def _totp_verify_dialog(self, totp_service: TOTPService) -> bool:
        from components.totp_dialogs import TOTPVerifyDialog
        verify_dlg = TOTPVerifyDialog(self.root, totp_service)
        return verify_dlg.show()

    # ------------------------------------------------------------------
    # TOTP Management
    # ------------------------------------------------------------------
    def load_totp_secret(self, totp_service: TOTPService, password: str = None, ks=None) -> bool:
        """Load TOTP secret from DB using multiple decryption strategies."""
        if ks is None:
            ks = self.ks

        with closing(database.get_connection()) as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key=?", (TOTP_SECRET_KEY,)
            ).fetchone()

        if row:
            enc_dict = json.loads(row[0])
            
            # Strategy 1: decrypt with master password
            if password:
                try:
                    totp_secret = database.decrypt_secret(enc_dict, password)
                    if len(totp_secret) == 20:
                        totp_service.set_raw_secret(totp_secret)
                    else:
                        totp_service.set_secret(totp_secret)
                    test_code = totp_service.generate()
                    if totp_service.verify(test_code):
                        logger.info("TOTP secret loaded (password) - self-test OK")
                        return True
                except Exception as e:
                    logger.debug("Strategy 1 (password) failed: %s", e)

            # Strategy 2: decrypt with global_secret hex
            if ks.global_secret:
                try:
                    gs_key = bytes(ks.global_secret).hex()
                    totp_secret = database.decrypt_secret(enc_dict, gs_key)
                    if len(totp_secret) == 20:
                        totp_service.set_raw_secret(totp_secret)
                    else:
                        totp_service.set_secret(totp_secret)
                    test_code = totp_service.generate()
                    if totp_service.verify(test_code):
                        logger.info("TOTP secret loaded (global_secret) - self-test OK")
                        return True
                except Exception as e:
                    logger.debug("Strategy 2 (gs_hex) failed: %s", e)
                finally:
                    # Wipe the hex string key from memory
                    if 'gs_key' in locals() and isinstance(gs_key, str):
                        gs_key = None
                    import gc
                    gc.collect()

            logger.warning("All decryption strategies failed for stored TOTP secret")
        else:
            logger.debug("No TOTP secret found in database")

        # Strategy 3: legacy
        if ks.global_secret and not row:
            try:
                totp_service.set_secret(bytes(ks.global_secret))
                logger.info("TOTP secret derived from global_secret (legacy mode)")
                return True
            except Exception as e:
                logger.warning("Legacy TOTP derivation failed: %s", e)

        return False

    def persist_totp_secret(self, secret_bytes: bytes, password: str = None) -> None:
        """Encrypt and store the TOTP secret in the database."""
        enc_key = None
        key_label = "none"
        if password:
            enc_key = password
            key_label = "password"
        elif self.ks.global_secret:
            enc_key = bytes(self.ks.global_secret).hex()
            key_label = "global_secret_hex"

        if enc_key is None:
            logger.warning("TOTP secret NOT persisted - no encryption key available")
            return

        try:
            enc_dict = database.encrypt_secret(secret_bytes, enc_key)
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_SECRET_KEY, json.dumps(enc_dict))
                )
                conn.commit()
            logger.info("TOTP secret persisted (%d bytes, key=%s)", len(secret_bytes), key_label)
        except Exception as e:
            logger.error("Failed to persist TOTP secret: %s", e)

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
            event_bus.publish(Events.TOTP_SETUP_COMPLETE, source="auth_controller", mandatory=True)
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
            event_bus.publish(Events.TOTP_VERIFIED, source="auth_controller")
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
        event_bus.publish(Events.TOTP_CHANGED, source="auth_controller")

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
            event_bus.publish(Events.TOTP_SETUP_COMPLETE, source="auth_controller", mandatory=False)

    # ------------------------------------------------------------------
    # TOTP Settings Accessors
    # ------------------------------------------------------------------
    def is_totp_setup_complete(self) -> bool:
        try:
            with closing(database.get_connection()) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
                ).fetchone()
                return row is not None and row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP setup status: %s", e)
            return False

    def set_totp_setup_complete(self, value: bool) -> None:
        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_SETUP_KEY, "1" if value else "0")
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to set TOTP setup status: %s", e)

    def is_totp_enabled(self) -> bool:
        try:
            with closing(database.get_connection()) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (TOTP_ENABLED_KEY,)
                ).fetchone()
                if row is None:
                    setup_row = conn.execute(
                        "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
                    ).fetchone()
                    return setup_row is not None and setup_row[0] == "1"
                return row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP enabled status: %s", e)
            return False

    def set_totp_enabled(self, value: bool) -> None:
        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_ENABLED_KEY, "1" if value else "0")
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to set TOTP enabled status: %s", e)

    # ------------------------------------------------------------------
    # Password & Duress Management
    # ------------------------------------------------------------------
    def change_password(self) -> bool:
        """Orchestrate master password change. Returns True on success."""
        old_pw = self._ui.password_dialog("Change Password - Verify Current", confirm=False)
        if not old_pw:
            return False

        try:
            is_valid = self.ks.verify_password(old_pw)
            if not is_valid:
                self._ui.show_error("Verification Failed", "Current password is incorrect.")
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
                event_bus.publish(Events.PASSWORD_CHANGED, source="auth_controller")
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
            is_valid = self.ks.verify_password(master_pw)
            is_duress = self.ks.is_duress_mode if is_valid else False
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

    def enter_duress_mode(self) -> None:
        """Enter decoy mode with fake data."""
        logger.warning("Entering DURESS / DECOY mode")
        self.ks.load_duress_decoy()
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
        event_bus.publish(Events.KEYS_WIPED, source="auth_controller")
