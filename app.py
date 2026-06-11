"""EnigmaApp – main application window, header, tabs orchestration.

Refactored to use MVC controllers for lifecycle, authentication, and service management.
Integrates EventBus for decoupled cross-component communication.
"""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import logging
import gc
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from visual_enigma import VisualEnigma
from key_manager import KeyStore
from encrypt_tab import EncryptTab
from decrypt_tab import DecryptTab
from friends_tab import FriendsTab
from secret_tab import SecretTab
from file_tab import FileTab
from about_tab import AboutTab
from ntp_tab import NtpTab
from lock_screen import LockScreen
from controllers.application_controller import ApplicationController
from controllers.auth_controller import AuthController
from controllers.service_orchestrator import ServiceOrchestrator
from services.event_bus import event_bus, Events

logger = logging.getLogger(__name__)


class EnigmaApp:
    def __init__(self, root):
        self.root = root
        root.geometry("1400x850")
        root.minsize(1200, 750)

        icon = tk.PhotoImage(width=1, height=1)
        root.iconphoto(True, icon)

        # Configure event bus with Tkinter root for thread-safe dispatch
        event_bus.set_root(root)

        self.style = ttk.Style()
        self.bg = self.style.colors.bg
        self.fg = self.style.colors.fg
        self.accent = self.style.colors.primary
        self.secondary = self.style.colors.secondary
        self.dark = self.style.colors.dark

        # Check first-run BEFORE creating KeyStore (which touches the DB)
        self._first_run = not (Path.home() / ".ultimate_enigma" / "enigma.db").exists()

        # 1. Initialize KeyStore
        self.ks = KeyStore()

        # 2. Initialize Controllers
        self.app_controller = ApplicationController(root)
        self.auth_controller = AuthController(root, self.ks)
        
        # Start task queue processing
        self.app_controller.start_queue_processing()

        # 3. Authentication & Key Loading
        if not self.auth_controller.load_keys(self._first_run):
            root.destroy()
            return

        # Update local reference to KeyStore (may have changed in auth controller)
        self.ks = self.auth_controller.ks

        # 4. Initialize Service Orchestrator
        self.service_orchestrator = ServiceOrchestrator(
            root, self.ks, crypto_queue=self.app_controller.crypto_queue
        )

        # 5. Mandatory TOTP setup enforcement
        if not self.auth_controller.enforce_mandatory_totp_setup():
            self.ks.wipe()
            root.destroy()
            return

        # 6. Startup TOTP verification
        if not self.auth_controller.verify_startup_totp():
            self.ks.wipe()
            root.destroy()
            return

        # 7. NTP sync – deferred until AFTER GUI renders
        self.app_controller.start_ntp_sync(
            self.service_orchestrator.encryption_service,
            self.service_orchestrator.service_lock
        )

        # 8. State
        self.last_sent_b64 = ""
        self.vis_enigma = VisualEnigma()
        self.rotor_positions = [0, 0, 0]
        self._is_locked = False

        # 9. UI
        self._setup_header()
        self._setup_tabs()
        self._start_rotor_animation()

        # 10. Lock screen
        self.lock_screen = LockScreen(root, on_unlock_request=self._request_unlock)

        # 11. Subscribe to events for decoupled communication
        self._setup_event_subscriptions()

        # 12. Global hotkeys
        self.app_controller.register_hotkeys(
            lock_callback=self._emergency_lock,
            unlock_callback=self._request_unlock
        )

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------------------
    # Window close
    # ------------------------------------------------------------------
    def on_close(self):
        self.service_orchestrator.shutdown()
        self.auth_controller.wipe_sensitive_data()
        self.app_controller.shutdown()
        # Unsubscribe all app-level handlers
        event_bus.unsubscribe_all(self._on_friend_list_changed)
        event_bus.unsubscribe_all(self._on_services_rebuilt)
        event_bus.publish(Events.APP_SHUTDOWN, source="app")
        self.root.destroy()

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

        # Emergency Lock Button
        lock_btn = tk.Button(
            header, text="🔒 EMERGENCY\nLOCK",
            font=("Segoe UI", 9, "bold"),
            bg="#cc0000", fg="white", activebackground="#ff0000",
            activeforeground="white", bd=0, padx=10, pady=5,
            cursor="hand2", command=self._emergency_lock
        )
        lock_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

        # TOTP Setup Button
        totp_setup_btn = tk.Button(
            header, text="🔑 TOTP\nSetup",
            font=("Segoe UI", 9, "bold"),
            bg="#007bff", fg="white", activebackground="#0056b3",
            activeforeground="white", bd=0, padx=10, pady=5,
            cursor="hand2", command=lambda: self.auth_controller.show_totp_setup()
        )
        totp_setup_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

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

        style_config = {'bg': self.bg, 'fg': self.fg}
        
        self.encrypt_tab = EncryptTab(
            notebook, 
            self.service_orchestrator.encryption_service, 
            self.service_orchestrator.friends_service,
            self.service_orchestrator.clipboard_service,
            self.app_controller.crypto_queue
        )
        notebook.add(self.encrypt_tab.frame, text="✉️ Encrypt & Send")

        self.decrypt_tab = DecryptTab(
            notebook,
            self.service_orchestrator.encryption_service,
            self.service_orchestrator.clipboard_service,
            self.app_controller.task_queue
        )
        notebook.add(self.decrypt_tab.frame, text="📥 Decrypt & Receive")

        self.secret_tab = SecretTab(
            notebook, 
            self.service_orchestrator.global_secret_service,
            self.service_orchestrator.clipboard_service
        )
        notebook.add(self.secret_tab.frame, text="🔗 Shared Secret")

        self.file_tab = FileTab(
            notebook,
            self.service_orchestrator.file_service,
            self.service_orchestrator.friends_service,
            self.service_orchestrator.global_secret_service,
            self.root,
            self.app_controller.task_queue
        )
        notebook.add(self.file_tab.frame, text="🔐 File Encryption")

        self.friends_tab = FriendsTab(
            notebook, 
            self.service_orchestrator.friends_service,
            style_config
        )
        notebook.add(self.friends_tab.frame, text="👥 Friends")

        self.ntp_tab = NtpTab(
            notebook,
            self.service_orchestrator.encryption_service
        )
        notebook.add(self.ntp_tab.frame, text="🕐 NTP")

        self.about_tab = AboutTab(
            notebook,
            self.ks,
            self.auth_controller
        )
        notebook.add(self.about_tab.frame, text="ℹ️ About")

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
        self._is_locked = True

        self.auth_controller.wipe_sensitive_data()
        self.service_orchestrator.clipboard_service.shutdown()
        self.lock_screen.lock()
        event_bus.publish(Events.EMERGENCY_LOCK, source="app")
        event_bus.publish(Events.LOCKED, source="app")

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------
    def _request_unlock(self) -> None:
        """Coordinate unlock flow through AuthController and ServiceOrchestrator."""
        if not self._is_locked:
            return

        success, new_ks, new_totp = self.auth_controller.request_unlock(self.ks)
        
        if not success:
            return

        # Restore keys and services
        self.ks = new_ks
        self.auth_controller.ks = new_ks
        self.auth_controller.totp_service = new_totp

        # Rebuild services with restored keys
        tab_refs = {
            "encrypt": self.encrypt_tab,
            "decrypt": self.decrypt_tab,
            "file": self.file_tab,
            "secret": self.secret_tab,
            "friends": self.friends_tab,
            "ntp": self.ntp_tab
        }
        self.service_orchestrator.rebuild_services(new_ks, tab_refs)

        self._is_locked = False
        self.lock_screen.unlock()

        messagebox.showinfo("Unlocked", "Application unlocked successfully.\nAll keys restored.")
        logger.info("Application unlocked successfully")
        event_bus.publish(Events.UNLOCKED, source="app")

    # ------------------------------------------------------------------
    # Event subscriptions (decoupled cross-component communication)
    # ------------------------------------------------------------------
    def _setup_event_subscriptions(self):
        """Register event handlers for cross-component communication.

        Views publish events; this method wires up the app-level reactions
        so that individual components stay decoupled.
        """
        # When friend list changes, update EncryptTab and FileTab dropdowns
        event_bus.subscribe(
            Events.FRIEND_LIST_CHANGED,
            self._on_friend_list_changed,
            thread_safe=True
        )

        # When services are rebuilt, refresh tabs that depend on them
        event_bus.subscribe(
            Events.SERVICES_REBUILT,
            self._on_services_rebuilt,
            thread_safe=True
        )

        logger.debug("Event subscriptions registered")

    def _on_friend_list_changed(self, **kwargs):
        """React to friend list changes by updating dependent tabs."""
        try:
            self.encrypt_tab.notify_friend_list_changed()
            self.file_tab.refresh_list()
            logger.debug("Friend list change propagated to tabs")
        except Exception as e:
            logger.debug("Friend list change handler error (non-critical): %s", e)

    def _on_services_rebuilt(self, **kwargs):
        """React to service rebuild by refreshing tab data."""
        try:
            self.encrypt_tab.notify_friend_list_changed()
            self.friends_tab.refresh_list()
            self.file_tab.refresh_list()
            logger.debug("Service rebuild propagated to tabs")
        except Exception as e:
            logger.debug("Service rebuild handler error (non-critical): %s", e)

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
