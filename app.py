"""EnigmaApp – main application window, header, tabs orchestration."""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
from queue import Queue, Empty
import base64
import logging
import gc
import time
import threading
import json
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from visual_enigma import VisualEnigma
from key_manager import KeyStore, init_db
from utils import password_dialog
from services.encryption_service import EncryptionService
from services.file_service import FileService  # new service
from services.friends_service import FriendsService
from services.clipboard_service import ClipboardService
from services.global_secret_service import GlobalSecretService
from services.totp_service import TOTPService
from services.hotkey_service import HotkeyService, MOD_CTRL, MOD_SHIFT, VK_L, VK_U
from encrypt_tab import EncryptTab
from decrypt_tab import DecryptTab
from friends_tab import FriendsTab
from secret_tab import SecretTab
from file_tab import FileTab
from about_tab import AboutTab
from ntp_tab import NtpTab
from ntp_client import get_ntp_time
from lock_screen import LockScreen
from components.totp_dialogs import TOTPVerifyDialog, TOTPSetupDialog

logger = logging.getLogger(__name__)

# Hotkey IDs (must be unique per registration)
HOTKEY_ID_LOCK   = 1
HOTKEY_ID_UNLOCK = 2

# Path for storing TOTP secret in database settings
TOTP_SECRET_KEY = "totp_secret_encrypted"
TOTP_SETUP_KEY = "totp_setup_complete"
TOTP_ENABLED_KEY = "totp_enabled"


class EnigmaApp:
    def __init__(self, root):
        self.root = root
        root.geometry("1400x850")
        root.minsize(1200, 750)

        icon = tk.PhotoImage(width=1, height=1)
        root.iconphoto(True, icon)

        self.style = ttk.Style()
        self.bg = self.style.colors.bg
        self.fg = self.style.colors.fg
        self.accent = self.style.colors.primary
        self.secondary = self.style.colors.secondary
        self.dark = self.style.colors.dark

        # Check first-run BEFORE creating KeyStore (which touches the DB)
        self._first_run = not (Path.home() / ".ultimate_enigma" / "enigma.db").exists()

        # 1. KeyStore and queue
        self.ks = KeyStore()
        self.task_queue = Queue()
        self.process_queue()
        self._master_password_hash = None
        self._ph = PasswordHasher()
        self._service_lock = threading.RLock()  # Protects service replacement during unlock

        # TOTP service must exist BEFORE _load_keys() since _init_totp() uses it
        self.totp_service = TOTPService()

        if not self._load_keys():
            root.destroy()
            return

        # 2. Build services
        self.encryption_service = EncryptionService(self.ks)
        self.file_service = FileService(self.ks)
        self.friends_service = FriendsService(self.ks)
        self.clipboard_service = ClipboardService(root)
        self.global_secret_service = GlobalSecretService(self.ks)

        # 2a. Mandatory TOTP setup enforcement
        #     If TOTP setup has not been completed, force the setup dialog.
        #     The user CANNOT proceed without completing TOTP configuration.
        #     Uses a single-pass check (no while loop) to avoid any risk of
        #     infinite looping if DB writes fail silently.
        if not self._is_totp_setup_complete():
            logger.info("TOTP setup not complete – enforcing mandatory setup")
            if not self.totp_service.has_secret():
                # Ensure a secret exists before showing setup dialog
                self._generate_new_totp()
            uri = self.totp_service.provisioning_uri()
            setup_dlg = TOTPSetupDialog(
                root, self.totp_service, uri,
                on_regenerate=self._regenerate_totp
            )
            if setup_dlg.show():
                self._set_totp_setup_complete(True)
                self._set_totp_enabled(True)
                logger.info("Mandatory TOTP setup completed successfully")
            else:
                messagebox.showerror(
                    "Mandatory Setup",
                    "TOTP two-factor authentication is MANDATORY.\n"
                    "The application cannot be used without completing TOTP setup.\n\n"
                    "Application will now exit."
                )
                self.totp_service.clear_secret()
                self.ks.wipe()
                root.destroy()
                return

        # 2b. TOTP verification on startup (only if TOTP is enabled AND setup complete)
        #     The TOTP secret was already loaded by _init_totp() during _load_keys().
        #     If the secret is missing (DB corruption, etc.), skip verification gracefully.
        if self._is_totp_enabled() and self._is_totp_setup_complete() and self.totp_service.has_secret():
            verify_dlg = TOTPVerifyDialog(root, self.totp_service)
            if not verify_dlg.show():
                messagebox.showerror("Access Denied", "TOTP verification failed.\nApplication will now exit.")
                self.totp_service.clear_secret()
                self.ks.wipe()
                root.destroy()
                return
        elif self._is_totp_enabled() and self._is_totp_setup_complete() and not self.totp_service.has_secret():
            logger.warning("TOTP setup marked complete but secret not loaded – skipping verification")

        # 3. NTP sync thread
        self._ntp_thread = threading.Thread(target=self._ntp_sync_loop, daemon=True)
        self._ntp_thread.start()

        # 4. State
        self.last_sent_b64 = ""
        self.vis_enigma = VisualEnigma()
        self.rotor_positions = [0, 0, 0]
        self._is_locked = False

        # 5. UI
        self._setup_header()
        self._setup_tabs()
        self._start_rotor_animation()

        # 6. Lock screen
        self.lock_screen = LockScreen(root, on_unlock_request=self._request_unlock)

        # 7. Global hotkeys
        self.hotkey_service = HotkeyService()
        self.hotkey_service.register(HOTKEY_ID_LOCK, MOD_CTRL | MOD_SHIFT, VK_L,
                                     callback=lambda: self.root.after(0, self._emergency_lock))
        self.hotkey_service.register(HOTKEY_ID_UNLOCK, MOD_CTRL | MOD_SHIFT, VK_U,
                                     callback=lambda: self.root.after(0, self._request_unlock))
        self.hotkey_service.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------------------
    # Window close & queue processing
    # ------------------------------------------------------------------
    def on_close(self):
        self.clipboard_service.shutdown()
        self.hotkey_service.stop()
        self.totp_service.clear_secret()
        self.ks.wipe()
        self.root.destroy()

    def _ntp_sync_loop(self):
        while True:
            t = get_ntp_time()
            if t is not None:
                with self._service_lock:
                    self.encryption_service.update_ntp_time(t)
            else:
                logger.warning("NTP sync failed, falling back to system time")
                with self._service_lock:
                    self.encryption_service.update_ntp_time(None)
            time.sleep(1800)

    def process_queue(self):
        try:
            while True:
                task = self.task_queue.get_nowait()
                task()
        except Empty:
            pass
        self.root.after(100, self.process_queue)

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------
    def _load_keys(self) -> bool:
        first_run = self._first_run
        if first_run:
            pw = password_dialog(self.root, "Set Master Password", confirm=True)
            if not pw:
                logger.warning("First run: user cancelled password dialog")
                return False
            init_db(pw)
            if not self.ks.load(pw):
                messagebox.showerror("Error", "Failed to load new keys.")
                pw = None; gc.collect()
                return False
            # Store a password verifier for unlock using Argon2id
            self._master_password_hash = self._ph.hash(pw)
            # Initialize TOTP with master password
            self._init_totp(pw)
            logger.info("Master password hash set (first run)")
            pw = None; gc.collect()
            return True
        else:
            for attempt in range(3):
                pw = password_dialog(self.root, "Unlock Private Key", confirm=False)
                if not pw:
                    logger.warning("User cancelled password dialog (attempt %d)", attempt + 1)
                    return False
                is_valid, is_duress = self.ks.verify_password(pw)
                if not is_valid:
                    messagebox.showerror("Wrong Password", "Incorrect password.")
                    continue

                if is_duress:
                    # Enter decoy mode - app appears functional with no real data
                    self._enter_duress_mode()
                    pw = None; gc.collect()
                    return True

                if self.ks.load(pw):
                    self._master_password_hash = self._ph.hash(pw)
                    # Initialize TOTP with master password
                    self._init_totp(pw)
                    logger.info("Master password hash set (existing DB)")
                    pw = None; gc.collect()
                    return True
                else:
                    messagebox.showerror("Error", "Failed to load keys.")
                    return False
            messagebox.showerror("Access Denied", "Too many attempts.")
            return False

    # ------------------------------------------------------------------
    # TOTP initialisation
    # ------------------------------------------------------------------
    def _load_totp_secret(self, totp_service: TOTPService, password: str = None,
                          ks=None) -> bool:
        """Load TOTP secret from DB, trying multiple decryption strategies.
        
        The stored value is the exact 20-byte secret used for TOTP generation.
        On load, it is set directly via set_raw_secret() to avoid any
        transformation mismatch.
        
        Tries in order:
          1. Decrypt with master password
          2. Decrypt with global_secret hex (used when regenerated while unlocked)
          3. Legacy: use first 20 bytes of global_secret
        
        Returns True if an existing secret was loaded, False otherwise.
        """
        import database
        from contextlib import closing

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
                    logger.debug("Strategy 1 (password): decrypted %d bytes", len(totp_secret))
                    if len(totp_secret) == 20:
                        totp_service.set_raw_secret(totp_secret)
                    else:
                        # Older format: 32-byte raw secret, take first 20
                        totp_service.set_secret(totp_secret)
                    # Self-test: generate and verify a code
                    test_code = totp_service.generate()
                    if totp_service.verify(test_code):
                        logger.info("TOTP secret loaded (password) – self-test OK, b32=%s",
                                    totp_service.get_b32_secret()[:8] + "...")
                        return True
                    else:
                        logger.error("TOTP self-test FAILED after password decrypt")
                except Exception as e:
                    logger.debug("Strategy 1 (password) failed: %s", e)

            # Strategy 2: decrypt with global_secret hex
            if ks.global_secret:
                try:
                    gs_key = bytes(ks.global_secret).hex()
                    totp_secret = database.decrypt_secret(enc_dict, gs_key)
                    logger.debug("Strategy 2 (gs_hex): decrypted %d bytes", len(totp_secret))
                    if len(totp_secret) == 20:
                        totp_service.set_raw_secret(totp_secret)
                    else:
                        totp_service.set_secret(totp_secret)
                    test_code = totp_service.generate()
                    if totp_service.verify(test_code):
                        logger.info("TOTP secret loaded (global_secret) – self-test OK, b32=%s",
                                    totp_service.get_b32_secret()[:8] + "...")
                        return True
                    else:
                        logger.error("TOTP self-test FAILED after global_secret decrypt")
                except Exception as e:
                    logger.debug("Strategy 2 (gs_hex) failed: %s", e)

            logger.warning("All decryption strategies failed for stored TOTP secret")
        else:
            logger.debug("No TOTP secret found in database")

        # Strategy 3: legacy – use global_secret directly (only if no DB row)
        if ks.global_secret and not row:
            try:
                totp_service.set_secret(bytes(ks.global_secret))
                logger.info("TOTP secret derived from global_secret (legacy mode)")
                return True
            except Exception as e:
                logger.warning("Legacy TOTP derivation failed: %s", e)

        return False

    def _persist_totp_secret(self, secret_bytes: bytes, password: str = None) -> None:
        """Encrypt and store the exact 20-byte TOTP secret in the database.
        
        Stores the actual secret used for TOTP generation (not the original
        random input), ensuring perfect roundtrip consistency.
        
        Uses master password if available, otherwise falls back to
        global_secret hex so the secret can still be persisted while
        the app is unlocked (password already wiped from memory).
        """
        import database
        from contextlib import closing

        enc_key = None
        key_label = "none"
        if password:
            enc_key = password
            key_label = "password"
        elif self.ks.global_secret:
            enc_key = bytes(self.ks.global_secret).hex()
            key_label = "global_secret_hex"

        if enc_key is None:
            logger.warning("TOTP secret NOT persisted – no encryption key available")
            return

        try:
            enc_dict = database.encrypt_secret(secret_bytes, enc_key)
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_SECRET_KEY, json.dumps(enc_dict))
                )
                conn.commit()
            logger.info("TOTP secret persisted (%d bytes, key=%s, b32=%s...)",
                        len(secret_bytes), key_label,
                        base64.b32encode(secret_bytes).decode().rstrip("=")[:8])
        except Exception as e:
            logger.error("Failed to persist TOTP secret: %s", e)

    def _init_totp(self, password: str = None) -> None:
        """Initialise TOTP: load secret from DB or generate a new one.
        
        Args:
            password: Master password for decrypting/generating TOTP secret.
                      Required for first-time setup or loading existing secret.
        """
        try:
            loaded = self._load_totp_secret(self.totp_service, password)
            if not loaded:
                self._generate_new_totp(password)
        except Exception as e:
            logger.warning("TOTP init failed, generating new secret: %s", e)
            self._generate_new_totp(password)

    def _generate_new_totp(self, password: str = None) -> None:
        """Generate a new independent TOTP secret and store it encrypted.
        
        Generates 32 random bytes, sets them in the TOTP service (which uses
        the first 20 bytes), then persists the exact 20-byte secret that will
        be used for code generation.
        """
        new_secret = TOTPService.generate_random_secret(32)
        self.totp_service.set_secret(new_secret)
        # Persist the EXACT 20-byte secret used for TOTP (not the 32-byte input)
        actual_secret = self.totp_service.get_raw_secret()
        self._persist_totp_secret(actual_secret, password)
        logger.info("New TOTP secret generated and persisted (b32=%s...)",
                    self.totp_service.get_b32_secret()[:8])

    # ------------------------------------------------------------------
    # Header & tab setup
    # ------------------------------------------------------------------
    def _setup_header(self):
        header = ttk.Frame(self.root, bootstyle="dark", height=80)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        ttk.Label(header, text="ULTIMATE ENIGMA MESSENGER",
                  font=("Segoe UI", 16, "bold"),
                  bootstyle="inverse-warning").pack(side=tk.LEFT, padx=20, pady=10)

        ttk.Label(header, text="Hybrid Encryption · AES‑GCM + RSA‑OAEP · Time‑based keys",
                  font=("Segoe UI", 8),
                  bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)

        # ── Emergency Lock Button ──
        lock_btn = tk.Button(
            header, text="🔒 EMERGENCY\nLOCK",
            font=("Segoe UI", 9, "bold"),
            bg="#cc0000", fg="white", activebackground="#ff0000",
            activeforeground="white", bd=0, padx=10, pady=5,
            cursor="hand2", command=self._emergency_lock
        )
        lock_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

        # ── TOTP Setup Button ──
        self._totp_setup_btn = tk.Button(
            header, text="🔑 TOTP\nSetup",
            font=("Segoe UI", 9, "bold"),
            bg="#2266aa", fg="white", activebackground="#3388cc",
            activeforeground="white", bd=0, padx=10, pady=5,
            cursor="hand2", command=self._show_totp_setup
        )
        self._totp_setup_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

        # ── TOTP Enable/Disable Toggle Button ──
        self._totp_toggle_btn = tk.Button(
            header, font=("Segoe UI", 9, "bold"),
            bd=0, padx=10, pady=5, cursor="hand2",
            command=self._toggle_totp
        )
        self._totp_toggle_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)
        self._update_totp_toggle_button()

        self.header_canvas = tk.Canvas(
            header,
            bg=self.style.colors.dark,
            height=70, width=210,
            highlightthickness=0
        )
        self.header_canvas.pack(side=tk.RIGHT, padx=10, pady=5)

    def _setup_tabs(self):
        notebook = ttk.Notebook(self.root, bootstyle="dark")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Inject services into tabs instead of passing entire app instance
        style_config = {'bg': self.bg, 'fg': self.fg}
        
        self.encrypt_tab = EncryptTab(
            notebook, 
            self.encryption_service, 
            self.friends_service,
            self.clipboard_service
        )
        notebook.add(self.encrypt_tab.frame, text="✉️ Encrypt & Send")

        self.decrypt_tab = DecryptTab(notebook, self)
        notebook.add(self.decrypt_tab.frame, text="📥 Decrypt & Receive")

        self.secret_tab = SecretTab(
            notebook, 
            self.global_secret_service,
            self.clipboard_service
        )
        notebook.add(self.secret_tab.frame, text="🔗 Shared Secret")

        self.file_tab = FileTab(notebook, self, self.file_service)
        notebook.add(self.file_tab.frame, text="🔐 File Encryption")

        self.friends_tab = FriendsTab(
            notebook, 
            self.friends_service,
            style_config
        )
        notebook.add(self.friends_tab.frame, text="👥 Friends")

        self.ntp_tab = NtpTab(notebook, self)
        notebook.add(self.ntp_tab.frame, text="🕐 NTP")

        self.about_tab = AboutTab(notebook, self)
        notebook.add(self.about_tab.frame, text="ℹ️ About")

        # Bind tab change event to auto-refresh Friends tab
        self._notebook = notebook
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _on_tab_changed(self, event):
        """Handle tab change events to auto-refresh content."""
        try:
            selected = self._notebook.select()
            if selected:
                tab_text = self._notebook.tab(selected, "text")
                if "Friends" in tab_text:
                    self.friends_tab.refresh_list()
                elif "File" in tab_text:
                    self.file_tab.refresh_list()
                elif "Encrypt" in tab_text:
                    self.encrypt_tab._update_friend_list()
        except Exception as e:
            logger.debug("Tab change handler error (non-critical): %s", e)

    # ------------------------------------------------------------------
    # Emergency Lock
    # ------------------------------------------------------------------
    def _emergency_lock(self) -> None:
        """Immediately wipe keys and lock the application."""
        if self._is_locked:
            return

        logger.warning("EMERGENCY LOCK triggered")
        logger.debug("Password hash before lock: %s", self._master_password_hash[:8] + "..." if self._master_password_hash else "None")
        self._is_locked = True

        # Wipe sensitive data (but keep password hash for unlock)
        self.ks.wipe()
        self.totp_service.clear_secret()

        # Clear clipboard
        self.clipboard_service.shutdown()

        # Show lock screen
        self.lock_screen.lock()
        logger.debug("Password hash after lock: %s", self._master_password_hash[:8] + "..." if self._master_password_hash else "None")

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------
    def _request_unlock(self) -> None:
        """Show the unlock dialog (password + TOTP)."""
        if not self._is_locked:
            return

        logger.debug("Unlock requested. Password hash available: %s", self._master_password_hash is not None)
        
        # Check if we have the password hash
        if self._master_password_hash is None:
            # Try to recover by asking for password and reloading
            logger.warning("Password hash is None, attempting recovery")
            pw = self._unlock_password_dialog()
            if not pw:
                return
            
            # Try to load keys directly
            temp_ks = KeyStore()
            if temp_ks.verify_password(pw) and temp_ks.load(pw):
                self._master_password_hash = self._ph.hash(pw)
                logger.info("Password hash recovered successfully")
                temp_ks.wipe()
                pw = None; gc.collect()
            else:
                messagebox.showerror("Error", "Unable to verify password.\nPlease restart the application.")
                logger.error("Unlock failed: could not recover password hash")
                temp_ks.wipe()
                pw = None; gc.collect()
                return

        # Step 1: Ask for master password using a dedicated unlock password dialog
        pw = self._unlock_password_dialog()
        if not pw:
            return

        # Step 2: Verify password hash using Argon2
        try:
            self._ph.verify(self._master_password_hash, pw)
        except VerifyMismatchError:
            messagebox.showerror("Failed", "Incorrect master password.")
            logger.warning("Unlock failed: incorrect password")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Password verification failed: {e}")
            logger.error("Unlock failed: Argon2 verification error: %s", e)
            return

        # Step 3: Reload keys with the verified password
        temp_ks = KeyStore()
        if not temp_ks.load(pw):
            messagebox.showerror("Error", "Failed to reload keys.\nPassword may be correct but keys corrupted.")
            logger.error("Unlock failed: KeyStore.load() returned False")
            return

        # Step 4: TOTP verification (only if TOTP is enabled AND setup complete)
        temp_totp = TOTPService()
        if self._is_totp_enabled() and self._is_totp_setup_complete():
            # Load the independent TOTP secret from DB (same logic as _init_totp)
            loaded = self._load_totp_secret(temp_totp, password=pw, ks=temp_ks)
            if not loaded:
                messagebox.showerror("Error",
                    "Failed to load TOTP secret from database.\n"
                    "TOTP may need to be reconfigured.")
                logger.error("Unlock failed: could not load TOTP secret from DB")
                temp_ks.wipe()
                return

            # Step 5: TOTP verification dialog
            totp_ok = self._totp_verify_dialog(temp_totp)
            if not totp_ok:
                temp_totp.clear_secret()
                temp_ks.wipe()
                return
        else:
            # TOTP not set up – still need the service instance but skip verification
            self._load_totp_secret(temp_totp, password=pw, ks=temp_ks)

        # Step 6: Success – restore keys and rebuild services
        self.ks = temp_ks
        self.totp_service = temp_totp  # reuse instance (already has secret)

        # Rebuild services with restored keys (thread-safe)
        with self._service_lock:
            self.encryption_service = EncryptionService(self.ks)
            self.file_service = FileService(self.ks)
            self.friends_service = FriendsService(self.ks)
            self.clipboard_service = ClipboardService(self.root)

            # Rebuild secret service with restored keys
            self.global_secret_service = GlobalSecretService(self.ks)
            
            # Update tab service references
            self.encrypt_tab.service = self.encryption_service
            self.encrypt_tab.friends_service = self.friends_service
            self.encrypt_tab.clipboard_service = self.clipboard_service
            self.file_tab.file_service = self.file_service
            self.secret_tab.service = self.global_secret_service
            self.secret_tab.clipboard_service = self.clipboard_service
            self.friends_tab.service = self.friends_service

        self._is_locked = False
        self.lock_screen.unlock()

        messagebox.showinfo("Unlocked", "Application unlocked successfully.\n"
                                        "All keys restored.")
        logger.info("Application unlocked successfully")

    def _unlock_password_dialog(self) -> str | None:
        """Show a password dialog specifically for unlocking.
        Uses consolidated password_dialog with topmost flag for lock screen."""
        return password_dialog(
            self.root,
            "Unlock – Master Password",
            confirm=False,
            topmost=True,
            bg="#1a1a1a",
            fg="#ffffff"
        )

    def _totp_verify_dialog(self, totp_service: TOTPService) -> bool:
        """Show a TOTP verification dialog using the centralized component."""
        verify_dlg = TOTPVerifyDialog(self.root, totp_service)
        return verify_dlg.show()

    # ------------------------------------------------------------------
    # TOTP Setup Dialog
    # ------------------------------------------------------------------
    def _is_totp_setup_complete(self) -> bool:
        """Check whether the user has completed TOTP setup (scanned QR / saved secret)."""
        import database
        from contextlib import closing
        try:
            with closing(database.get_connection()) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
                ).fetchone()
                return row is not None and row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP setup status: %s", e)
            return False

    def _set_totp_setup_complete(self, value: bool) -> None:
        """Mark TOTP setup as complete (or reset it)."""
        import database
        from contextlib import closing
        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_SETUP_KEY, "1" if value else "0")
                )
                conn.commit()
            logger.info("TOTP setup complete flag set to %s", value)
        except Exception as e:
            logger.error("Failed to set TOTP setup status: %s", e)

    def _is_totp_enabled(self) -> bool:
        """Check whether TOTP verification is currently enabled.
        
        Returns False if the key doesn't exist or if setup hasn't been completed.
        This prevents showing TOTP as 'ON' before the user has configured it.
        For backward compatibility with existing databases that have a TOTP secret
        but no explicit enabled flag, we check whether setup was completed as well.
        """
        import database
        from contextlib import closing
        try:
            with closing(database.get_connection()) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (TOTP_ENABLED_KEY,)
                ).fetchone()
                if row is None:
                    # No explicit flag set – only consider enabled if setup was
                    # previously completed (backward compat for existing installs)
                    setup_row = conn.execute(
                        "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
                    ).fetchone()
                    return setup_row is not None and setup_row[0] == "1"
                return row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP enabled status: %s", e)
            return False

    def _set_totp_enabled(self, value: bool) -> None:
        """Enable or disable TOTP verification."""
        import database
        from contextlib import closing
        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_ENABLED_KEY, "1" if value else "0")
                )
                conn.commit()
            logger.info("TOTP enabled flag set to %s", value)
        except Exception as e:
            logger.error("Failed to set TOTP enabled status: %s", e)

    def _update_totp_toggle_button(self) -> None:
        """Update the TOTP toggle button appearance based on current state.
        
        TOTP is only considered 'enabled' when both the enabled flag is set
        AND setup has been completed. This prevents showing TOTP as ON when
        the user has not yet configured their authenticator app.
        """
        enabled = self._is_totp_enabled() and self._is_totp_setup_complete()
        if enabled:
            self._totp_toggle_btn.config(
                text="✅ TOTP\nON",
                bg="#28a745", fg="white",
                activebackground="#34d058", activeforeground="white"
            )
        else:
            self._totp_toggle_btn.config(
                text="❌ TOTP\nOFF",
                bg="#6c757d", fg="white",
                activebackground="#5a6268", activeforeground="white"
            )

    def _toggle_totp(self) -> None:
        """Toggle TOTP verification on/off with confirmation.
        
        Note: In military-grade deployments, TOTP is mandatory and cannot be disabled.
        This implementation enforces that policy.
        """
        if self._is_locked:
            messagebox.showwarning("Locked", "Unlock the app first.")
            return

        currently_enabled = self._is_totp_enabled()

        if currently_enabled:
            # TOTP is mandatory - cannot be disabled in this security model
            messagebox.showwarning(
                "Mandatory 2FA",
                "TOTP two-factor authentication is MANDATORY and cannot be disabled.\n\n"
                "This is a security requirement for all users of Ultimate Enigma.\n"
                "Your TOTP secret is preserved and active."
            )
            logger.info("User attempted to disable TOTP - denied (mandatory policy)")
        else:
            # Enabling TOTP
            if not self.totp_service.has_secret():
                # No secret exists – need to run setup first
                messagebox.showinfo("TOTP Setup Required",
                                    "No TOTP secret found. Please set up TOTP first.")
                self._show_totp_setup()
                # After setup, enable TOTP
                if self._is_totp_setup_complete() and self.totp_service.has_secret():
                    self._set_totp_enabled(True)
                    logger.info("TOTP verification ENABLED by user (after setup)")
            else:
                self._set_totp_enabled(True)
                logger.info("TOTP verification ENABLED by user")
                messagebox.showinfo("TOTP Enabled", "TOTP verification has been enabled.\n"
                                    "You will be required to enter a TOTP code on startup and unlock.")

        self._update_totp_toggle_button()

    def _show_totp_setup(self) -> None:
        """Show the TOTP setup dialog with provisioning URI."""
        if self._is_locked:
            messagebox.showwarning("Locked", "Unlock the app first.")
            return
        if not self.totp_service.has_secret():
            # Auto-generate a secret if one doesn't exist yet
            self._generate_new_totp()
        uri = self.totp_service.provisioning_uri()
        setup_dlg = TOTPSetupDialog(self.root, self.totp_service, uri,
                                    on_regenerate=self._regenerate_totp)
        if setup_dlg.show():
            self._set_totp_setup_complete(True)
            # Ensure TOTP is enabled after successful setup
            if not self._is_totp_enabled():
                self._set_totp_enabled(True)
                logger.info("TOTP automatically enabled after setup completion")
            self._update_totp_toggle_button()

    def _regenerate_totp(self) -> None:
        """Regenerate the TOTP secret (called from setup dialog).
        
        Generates a new cryptographically secure secret, sets it in the
        TOTP service, and persists the exact 20-byte secret to the database.
        Uses global_secret for encryption since the master password is
        not available while the app is unlocked.
        """
        new_secret = TOTPService.generate_random_secret(32)
        self.totp_service.set_secret(new_secret)
        # Persist the EXACT 20-byte secret used for TOTP
        actual_secret = self.totp_service.get_raw_secret()
        self._persist_totp_secret(actual_secret)
        logger.info("TOTP secret regenerated and persisted (b32=%s...)",
                    self.totp_service.get_b32_secret()[:8])

    # ------------------------------------------------------------------
    # Duress Mode
    # ------------------------------------------------------------------
    def _enter_duress_mode(self) -> None:
        """Enter decoy mode with fake data when duress password is used.

        The application will appear fully functional but contain no real
        keys, friends, or messages. All real secrets are wiped from memory.
        """
        logger.warning("Entering DURESS / DECOY mode")
        self.ks.load_duress_decoy()
        # Set a dummy password hash so unlock flow doesn't fail
        self._master_password_hash = self._ph.hash("duress_placeholder")
        # Clear any existing TOTP secret
        self.totp_service.clear_secret()

    def _set_duress_password(self) -> None:
        """Orchestrate setting a duress password via UI dialogs."""
        if self._is_locked:
            messagebox.showwarning("Locked", "Unlock the app first.")
            return

        # Step 1: Verify master password before allowing duress setup
        master_pw = password_dialog(
            self.root,
            "Set Duress Password - Verify Master",
            confirm=False
        )
        if not master_pw:
            return

        is_valid, is_duress = self.ks.verify_password(master_pw)
        if not is_valid or is_duress:
            messagebox.showerror(
                "Verification Failed",
                "Master password is incorrect.\n"
                "Duress password cannot be set without master verification."
            )
            master_pw = None; gc.collect()
            return

        # Step 2: Enter duress password with confirmation
        duress_pw = password_dialog(
            self.root,
            "Set Duress Password",
            confirm=True,
            enforce_strength=True
        )
        if not duress_pw:
            master_pw = None; gc.collect()
            return

        # Prevent duress password matching master password
        if duress_pw == master_pw:
            messagebox.showwarning(
                "Invalid Choice",
                "Duress password must be different from the master password."
            )
            master_pw = None; duress_pw = None; gc.collect()
            return

        # Step 3: Store the duress password verifier
        try:
            self.ks.set_duress_password(duress_pw)
            messagebox.showinfo(
                "Duress Password Set",
                "Duress password has been configured successfully.\n\n"
                "When entered at login, the application will appear\n"
                "fully functional but will contain no real data."
            )
            logger.info("Duress password set via UI")
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to set duress password:\n{e}"
            )
            logger.error("Failed to set duress password: %s", e)
        finally:
            master_pw = None; duress_pw = None; gc.collect()

    # ------------------------------------------------------------------
    # Change Master Password
    # ------------------------------------------------------------------
    def _change_password(self) -> None:
        """Orchestrate master password change with verification and strength enforcement."""
        if self._is_locked:
            messagebox.showwarning("Locked", "Unlock the app first.")
            return

        # Step 1: Verify current password
        old_pw = password_dialog(
            self.root,
            "Change Password – Verify Current",
            confirm=False
        )
        if not old_pw:
            return

        is_valid, _ = self.ks.verify_password(old_pw)
        if not is_valid:
            messagebox.showerror("Verification Failed", "Current password is incorrect.")
            old_pw = None; gc.collect()
            return

        # Step 2: Enter new password with confirmation + strength enforcement
        new_pw = password_dialog(
            self.root,
            "Change Password – Set New Password",
            confirm=True,
            enforce_strength=True
        )
        if not new_pw:
            old_pw = None; gc.collect()
            return

        # Prevent reusing the same password
        if new_pw == old_pw:
            messagebox.showwarning(
                "Same Password",
                "New password must be different from the current password."
            )
            old_pw = None; new_pw = None; gc.collect()
            return

        # Step 3: Perform the password change (re-encrypts all secrets)
        success = self.ks.change_password(old_pw, new_pw)
        if not success:
            messagebox.showerror(
                "Password Change Failed",
                "An error occurred while changing the password.\n"
                "Your original password is still valid.\n"
                "Check the log for details."
            )
            old_pw = None; new_pw = None; gc.collect()
            return

        # Step 4: Update in-memory password hash for lock/unlock
        self._master_password_hash = self._ph.hash(new_pw)

        # Step 5: Re-persist TOTP secret with new password
        if self.totp_service.has_secret():
            actual_secret = self.totp_service.get_raw_secret()
            self._persist_totp_secret(actual_secret, new_pw)

        old_pw = None; new_pw = None; gc.collect()

        messagebox.showinfo(
            "Password Changed",
            "Master password has been changed successfully.\n\n"
            "All secrets have been re-encrypted with the new password.\n"
            "Use the new password for future unlocks."
        )
        logger.info("Master password changed successfully via UI")

    # ------------------------------------------------------------------
    # Header rotor animation
    # ------------------------------------------------------------------
    def _start_rotor_animation(self):
        self._draw_header_rotors()
        self._animate_header_rotors()

    def _draw_header_rotors(self):
        self.header_canvas.delete("all")
        self.vis_enigma.draw_compact(self.header_canvas, self.rotor_positions)

    def _animate_header_rotors(self):
        self.rotor_positions[0] = (self.rotor_positions[0] + 0.5) % 26
        if self.rotor_positions[0] < 0.5:
            self.rotor_positions[1] = (self.rotor_positions[1] + 0.5) % 26
            if self.rotor_positions[1] < 0.5:
                self.rotor_positions[2] = (self.rotor_positions[2] + 0.5) % 26
        self._draw_header_rotors()
        self.root.after(200, self._animate_header_rotors)
