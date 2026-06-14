"""EnigmaApp – main application window, header, tabs orchestration.

Refactored to use MVC controllers for lifecycle, authentication, and service management.
Integrates EventBus for decoupled cross-component communication.
"""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import logging
import ttkbootstrap as ttk

from views.visual_enigma import VisualEnigma
import database
from key_manager import KeyStore
from views.encrypt_tab import EncryptTab
from views.decrypt_tab import DecryptTab
from views.friends_tab import FriendsTab
from views.secret_tab import SecretTab
from views.file_tab import FileTab
from views.about_tab import AboutTab
from views.ntp_tab import NtpTab
from views.trust_tab import TrustTab
from services.trust_chain_service import TrustChainService
from views.lock_screen import LockScreen
from controllers.application_controller import ApplicationController
from controllers.auth_controller import AuthController
from controllers.service_orchestrator import ServiceOrchestrator
from services.event_bus import event_bus, Events
from services.totp_persistence import TotpPersistence
from builders.app_builder import AppBuilder

logger = logging.getLogger(__name__)


class EnigmaApp:
    def __init__(self, root):
        self.root = root

        builder = AppBuilder(root)
        built = builder.build()
        if built is None:
            return

        self.ks = built["ks"]
        self.app_controller = built["app_controller"]
        self.auth_controller = built["auth_controller"]
        self.totp_persistence = built["totp_persistence"]
        self.service_orchestrator = built["service_orchestrator"]
        self.trust_chain_service = built["trust_chain_service"]
        self._first_run = built["first_run"]
        self.style = built["style"]
        self.bg = built["bg"]
        self.fg = built["fg"]
        self.accent = built["accent"]
        self.secondary = built["secondary"]
        self.dark = built["dark"]

        self.last_sent_b64 = ""
        self.vis_enigma = VisualEnigma()
        self.rotor_positions = [0, 0, 0]
        self._is_locked = False

        from services.backup_service import BackupService
        self._backup_service = BackupService(self.ks)

        self._setup_header()
        self._setup_tabs()
        self._start_rotor_animation()

        self.lock_screen = LockScreen(root, on_unlock_request=self._request_unlock)

        self._setup_event_subscriptions()

        self.app_controller.register_hotkeys(
            lock_callback=self._emergency_lock,
            unlock_callback=self._request_unlock
        )

        self._start_background_agents()

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
        event_bus.unsubscribe_all(self._on_trust_changed)
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
            self.app_controller.task_queue,
            self.app_controller.crypto_queue
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
            self.app_controller.task_queue,
            self.app_controller.crypto_queue
        )
        notebook.add(self.file_tab.frame, text="🔐 File Encryption")

        self.friends_tab = FriendsTab(
            notebook, 
            self.service_orchestrator.friends_service,
            style_config,
            trust_chain_service=self.trust_chain_service
        )
        notebook.add(self.friends_tab.frame, text="👥 Friends")

        self.trust_tab = TrustTab(
            notebook,
            self.trust_chain_service,
            self.service_orchestrator.friends_service,
            style_config
        )
        notebook.add(self.trust_tab.frame, text="🔗 Trust Chain")

        self.ntp_tab = NtpTab(
            notebook,
            self.service_orchestrator.encryption_service
        )
        notebook.add(self.ntp_tab.frame, text="🕐 NTP")

        self.about_tab = AboutTab(
            notebook,
            self.ks,
            self.auth_controller,
            backup_service=self._backup_service
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
                elif "Trust" in tab_text:
                    self.trust_tab.refresh_list()
                elif "Encrypt" in tab_text:
                    self.encrypt_tab._update_friend_list()
        except Exception as e:
            logger.warning("Tab change handler error (non-critical): %s", e)

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
        self.totp_persistence.ks = new_ks

        # Rebuild services with restored keys
        tab_refs = {
            "encrypt": self.encrypt_tab,
            "decrypt": self.decrypt_tab,
            "file": self.file_tab,
            "secret": self.secret_tab,
            "friends": self.friends_tab,
            "trust": self.trust_tab,
            "ntp": self.ntp_tab
        }
        self.service_orchestrator.rebuild_services(new_ks, tab_refs)

        # Rebuild trust chain service with restored keys
        self.trust_chain_service = TrustChainService(new_ks)
        self.service_orchestrator.friends_service.set_trust_chain_service(self.trust_chain_service)

        # Update trust tab with fresh services
        self.trust_tab.trust_service = self.trust_chain_service
        self.trust_tab.friends_service = self.service_orchestrator.friends_service

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

        # Trust chain events
        event_bus.subscribe(
            Events.CERTIFICATE_ISSUED,
            self._on_trust_changed,
            thread_safe=True
        )
        event_bus.subscribe(
            Events.CERTIFICATE_REVOKED,
            self._on_trust_changed,
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
            logger.warning("Friend list change handler error (non-critical): %s", e)

    def _on_services_rebuilt(self, **kwargs):
        """React to service rebuild by refreshing tab data."""
        try:
            self.encrypt_tab.notify_friend_list_changed()
            self.friends_tab.refresh_list()
            self.file_tab.refresh_list()
            logger.debug("Service rebuild propagated to tabs")
        except Exception as e:
            logger.warning("Service rebuild handler error (non-critical): %s", e)

    def _on_trust_changed(self, **kwargs):
        """React to trust chain changes."""
        try:
            if hasattr(self, 'trust_tab'):
                self.trust_tab.refresh_list()
        except Exception as e:
            logger.warning("Trust change handler error (non-critical): %s", e)

    # ------------------------------------------------------------------
    # Background agents
    # ------------------------------------------------------------------
    def _start_background_agents(self):
        """Initialize and start background agents.

        The BackupService was created earlier (in __init__) and stored as
        self._backup_service. Here it is wired to the orchestrator's
        backup reminder agent.
        """
        try:
            self.service_orchestrator.set_backup_agent(self._backup_service)
        except Exception as e:
            logger.warning("Could not initialize BackupService for agent: %s", e)

        # Start all agents via the app controller
        self.app_controller.start_agents()
        logger.debug("Background agents started")

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
