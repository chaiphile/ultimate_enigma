"""EnigmaApp – main application window, header, tabs orchestration."""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
from queue import Queue, Empty
import logging
import gc
import time
import threading
import json
import hashlib
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from visual_enigma import VisualEnigma
from key_manager import KeyStore, init_db
from utils import password_dialog
from services.encryption_service import EncryptionService
from services.file_service import FileService  # new service
from services.friends_service import FriendsService
from services.clipboard_service import ClipboardService
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
from unlock_dialog import unlock_dialog, totp_setup_dialog

logger = logging.getLogger(__name__)

# Hotkey IDs (must be unique per registration)
HOTKEY_ID_LOCK   = 1
HOTKEY_ID_UNLOCK = 2

# Path for storing TOTP secret in database settings
TOTP_SECRET_KEY = "totp_secret_encrypted"
TOTP_SETUP_KEY = "totp_setup_complete"


class EnigmaApp:
    def __init__(self, root):
        self.root = root
        root.geometry("1100x750")
        root.minsize(900, 600)

        icon = tk.PhotoImage(width=1, height=1)
        root.iconphoto(True, icon)

        self.style = ttk.Style()
        self.bg = self.style.colors.bg
        self.fg = self.style.colors.fg
        self.accent = self.style.colors.primary
        self.secondary = self.style.colors.secondary
        self.dark = self.style.colors.dark

        # 1. KeyStore and queue
        self.ks = KeyStore()
        self.task_queue = Queue()
        self.process_queue()
        self._master_password_hash = None

        if not self._load_keys():
            root.destroy()
            return

        # 2. Build services
        self.encryption_service = EncryptionService(self.ks)
        self.file_service = FileService(self.ks)
        self.friends_service = FriendsService(self.ks)
        self.clipboard_service = ClipboardService(root)

        # TOTP service
        self.totp_service = TOTPService()
        self._init_totp()

        # 2b. TOTP verification on startup (only if user completed TOTP setup)
        if self._is_totp_setup_complete():
            if not self._totp_verify_dialog(self.totp_service):
                messagebox.showerror("Access Denied", "TOTP verification failed.\nApplication will now exit.")
                self.totp_service.clear_secret()
                self.ks.wipe()
                root.destroy()
                return

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
                self.encryption_service.update_ntp_time(t)
            else:
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
        first_run = not (Path.home() / ".ultimate_enigma" / "enigma.db").exists()
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
            # Store a password verifier for unlock
            self._master_password_hash = hashlib.sha256(pw.encode()).hexdigest()
            logger.info("Master password hash set (first run)")
            pw = None; gc.collect()
            return True
        else:
            for attempt in range(3):
                pw = password_dialog(self.root, "Unlock Private Key", confirm=False)
                if not pw:
                    logger.warning("User cancelled password dialog (attempt %d)", attempt + 1)
                    return False
                if not self.ks.verify_password(pw):
                    messagebox.showerror("Wrong Password", "Incorrect password.")
                    continue
                if self.ks.load(pw):
                    self._master_password_hash = hashlib.sha256(pw.encode()).hexdigest()
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
    def _init_totp(self) -> None:
        """Initialise TOTP: load secret from DB or generate a new one."""
        import database
        conn = database.get_connection()
        try:
            row = conn.execute(
                "SELECT value FROM settings WHERE key=?", (TOTP_SECRET_KEY,)
            ).fetchone()
            if row:
                # Decrypt the stored TOTP secret
                enc_dict = json.loads(row[0])
                # We need the master password to decrypt – use global_secret as proxy
                # The TOTP secret is encrypted with the same master password
                # We'll derive it from global_secret instead (simpler & more secure)
                if self.ks.global_secret:
                    self.totp_service.set_secret(bytes(self.ks.global_secret))
                else:
                    self._generate_new_totp()
            else:
                self._generate_new_totp()
        except Exception as e:
            logger.warning("TOTP init failed, generating new secret: %s", e)
            self._generate_new_totp()
        finally:
            conn.close()

    def _generate_new_totp(self) -> None:
        """Generate a new TOTP secret and store it."""
        import database
        if self.ks.global_secret:
            self.totp_service.set_secret(bytes(self.ks.global_secret))
        else:
            # Fallback: generate random secret
            secret = TOTPService.generate_random_secret()
            self.totp_service.set_secret(secret)

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
        totp_btn = tk.Button(
            header, text="🔑 TOTP\nSetup",
            font=("Segoe UI", 9, "bold"),
            bg="#2266aa", fg="white", activebackground="#3388cc",
            activeforeground="white", bd=0, padx=10, pady=5,
            cursor="hand2", command=self._show_totp_setup
        )
        totp_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

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

        self.encrypt_tab = EncryptTab(notebook, self, self.encryption_service)
        notebook.add(self.encrypt_tab.frame, text="✉️ Encrypt & Send")

        self.decrypt_tab = DecryptTab(notebook, self)
        notebook.add(self.decrypt_tab.frame, text="📥 Decrypt & Receive")

        self.secret_tab = SecretTab(notebook, self)
        notebook.add(self.secret_tab.frame, text="🔗 Shared Secret")

        # Pass the file service to FileTab
        self.file_tab = FileTab(notebook, self, self.file_service)
        notebook.add(self.file_tab.frame, text="🔐 File Encryption")

        self.friends_tab = FriendsTab(notebook, self)
        notebook.add(self.friends_tab.frame, text="👥 Friends")

        self.ntp_tab = NtpTab(notebook, self)
        notebook.add(self.ntp_tab.frame, text="🕐 NTP")

        self.about_tab = AboutTab(notebook, self)
        notebook.add(self.about_tab.frame, text="ℹ️ About")

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
                self._master_password_hash = hashlib.sha256(pw.encode()).hexdigest()
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

        # Step 2: Verify password hash
        entered_hash = hashlib.sha256(pw.encode('utf-8')).hexdigest()
        if entered_hash != self._master_password_hash:
            messagebox.showerror("Failed", "Incorrect master password.")
            logger.warning("Unlock failed: incorrect password")
            return

        # Step 3: Reload keys with the verified password
        temp_ks = KeyStore()
        if not temp_ks.load(pw):
            messagebox.showerror("Error", "Failed to reload keys.\nPassword may be correct but keys corrupted.")
            logger.error("Unlock failed: KeyStore.load() returned False")
            return

        # Step 4: TOTP verification (only if user completed TOTP setup)
        temp_totp = TOTPService()
        if self._is_totp_setup_complete():
            try:
                temp_totp.set_secret(bytes(temp_ks.global_secret))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to initialize TOTP: {e}")
                logger.error("Unlock failed: TOTP init error: %s", e)
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
            try:
                temp_totp.set_secret(bytes(temp_ks.global_secret))
            except Exception:
                pass  # Non-critical if TOTP wasn't configured

        # Step 6: Success – restore keys and rebuild services
        self.ks = temp_ks
        self.totp_service = temp_totp  # reuse instance (already has secret)

        # Rebuild services with restored keys
        self.encryption_service = EncryptionService(self.ks)
        self.file_service = FileService(self.ks)
        self.friends_service = FriendsService(self.ks)
        self.clipboard_service = ClipboardService(self.root)

        # Update tab service references
        self.encrypt_tab.service = self.encryption_service
        self.file_tab.file_service = self.file_service

        self._is_locked = False
        self.lock_screen.unlock()

        messagebox.showinfo("Unlocked", "Application unlocked successfully.\n"
                                        "All keys restored.")
        logger.info("Application unlocked successfully")

    def _unlock_password_dialog(self) -> str | None:
        """Show a password dialog specifically for unlocking.
        Ensures the dialog is above the lock screen overlay."""
        dlg = tk.Toplevel(self.root, bg="#1a1a1a")
        dlg.title("Unlock – Master Password")
        dlg.geometry("380x180")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.attributes("-topmost", True)  # Ensure above lock screen
        dlg.grab_set()

        tk.Label(
            dlg, text="🔓 Enter Master Password", font=("Segoe UI", 14, "bold"),
            bg="#1a1a1a", fg="#ffffff"
        ).pack(pady=(15, 10))

        pwd_var = tk.StringVar()
        pwd_entry = ttk.Entry(dlg, textvariable=pwd_var, show="•", width=35,
                              bootstyle="primary", font=("Segoe UI", 12))
        pwd_entry.pack(pady=5)
        pwd_entry.focus_set()

        result = []

        def ok():
            pw = pwd_var.get()
            if not pw:
                messagebox.showerror("Error", "Password is required.", parent=dlg)
                return
            result.append(pw)
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btn_frame = tk.Frame(dlg, bg="#1a1a1a")
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="OK", command=ok,
                   bootstyle="success").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=cancel,
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

        dlg.bind("<Return>", lambda e: ok())
        dlg.bind("<Escape>", lambda e: cancel())

        self.root.wait_window(dlg)
        return result[0] if result else None

    def _totp_verify_dialog(self, totp_service: TOTPService) -> bool:
        """Show a TOTP verification dialog."""
        dlg = tk.Toplevel(self.root, bg="#1a1a1a")
        dlg.title("TOTP Verification")
        dlg.geometry("380x260")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.attributes("-topmost", True)  # Ensure above lock screen
        dlg.grab_set()

        tk.Label(
            dlg, text="🔐 TOTP Verification", font=("Segoe UI", 16, "bold"),
            bg="#1a1a1a", fg="#ffffff"
        ).pack(pady=(20, 10))

        tk.Label(
            dlg, text="Enter the 6-digit code from your authenticator app:",
            font=("Segoe UI", 10), bg="#1a1a1a", fg="#cccccc"
        ).pack()

        totp_var = tk.StringVar()
        totp_entry = ttk.Entry(dlg, textvariable=totp_var, width=20,
                               bootstyle="warning", font=("Consolas", 18),
                               justify="center")
        totp_entry.pack(pady=10)
        totp_entry.focus_set()

        # Timer
        timer_var = tk.StringVar()
        timer_label = tk.Label(
            dlg, textvariable=timer_var, font=("Segoe UI", 9),
            bg="#1a1a1a", fg="#ffaa00"
        )
        timer_label.pack()

        def update_timer():
            if not dlg.winfo_exists():
                return
            try:
                remaining = totp_service.time_remaining()
                timer_var.set(f"⏱ Expires in: {remaining}s")
                if remaining <= 5:
                    timer_label.config(fg="#ff4444")
                else:
                    timer_label.config(fg="#ffaa00")
                dlg.after(500, update_timer)
            except Exception:
                pass

        update_timer()

        result = {"ok": False}

        def verify():
            code = totp_var.get().strip()
            if len(code) != 6 or not code.isdigit():
                messagebox.showerror("Invalid", "Enter a 6-digit code.", parent=dlg)
                return
            if totp_service.verify(code):
                result["ok"] = True
                dlg.destroy()
            else:
                messagebox.showerror("Failed", "Invalid TOTP code.", parent=dlg)
                totp_var.set("")

        def cancel():
            dlg.destroy()

        btn_frame = tk.Frame(dlg, bg="#1a1a1a")
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="✅ Verify", command=verify,
                   bootstyle="success").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=cancel,
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

        dlg.bind("<Return>", lambda e: verify())
        dlg.bind("<Escape>", lambda e: cancel())

        self.root.wait_window(dlg)
        return result["ok"]

    # ------------------------------------------------------------------
    # TOTP Setup Dialog
    # ------------------------------------------------------------------
    def _is_totp_setup_complete(self) -> bool:
        """Check whether the user has completed TOTP setup (scanned QR / saved secret)."""
        import database
        try:
            conn = database.get_connection()
            row = conn.execute(
                "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
            ).fetchone()
            conn.close()
            return row is not None and row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP setup status: %s", e)
            return False

    def _set_totp_setup_complete(self, value: bool) -> None:
        """Mark TOTP setup as complete (or reset it)."""
        import database
        try:
            conn = database.get_connection()
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (TOTP_SETUP_KEY, "1" if value else "0")
            )
            conn.commit()
            conn.close()
            logger.info("TOTP setup complete flag set to %s", value)
        except Exception as e:
            logger.error("Failed to set TOTP setup status: %s", e)

    def _show_totp_setup(self) -> None:
        """Show the TOTP setup dialog with provisioning URI."""
        if self._is_locked:
            messagebox.showwarning("Locked", "Unlock the app first.")
            return
        if not self.totp_service.has_secret():
            messagebox.showerror("Error", "TOTP not initialised.")
            return
        uri = self.totp_service.provisioning_uri()
        ok = totp_setup_dialog(self.root, self.totp_service, uri,
                               on_regenerate=self._regenerate_totp)
        if ok:
            self._set_totp_setup_complete(True)

    def _regenerate_totp(self) -> None:
        """Regenerate the TOTP secret (called from setup dialog)."""
        import database
        import secrets
        # Generate a new random secret
        new_secret = secrets.token_bytes(32)
        self.totp_service.set_secret(new_secret)
        logger.info("TOTP secret regenerated")

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
