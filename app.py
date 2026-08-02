"""EnigmaApp – main application window, header, tabs orchestration.

Refactored to use MVC controllers for lifecycle, authentication, and service management.
Integrates EventBus for decoupled cross-component communication.
"""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import logging
import ttkbootstrap as ttk

import database
from key_manager import KeyStore
from views.encrypt_tab import EncryptTab
from views.decrypt_tab import DecryptTab
from views.friends_tab import FriendsTab
from views.secret_tab import SecretTab
from views.file_tab import FileTab
from views.about_tab import AboutTab
from views.help_tab import HelpTab
from views.ntp_tab import NtpTab
from views.trust_tab import TrustTab
from services.trust_chain_service import TrustChainService
from views.lock_screen import LockScreen
from controllers.application_controller import ApplicationController
from controllers.auth_controller import AuthController
from controllers.service_orchestrator import ServiceOrchestrator
from services.event_bus import event_bus, Events
from services.background_agents import BackupReminderAgent
from services.totp_persistence import TotpPersistence
from builders.app_builder import AppBuilder, StartupCancelled
from views.utils import friendly_error
from ttkbootstrap.toast import ToastNotification

logger = logging.getLogger(__name__)

# Cross-platform UI fonts (avoid hardcoding Windows-only families/sizes inline).
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_SUBTITLE = ("Segoe UI", 10)
FONT_BUTTON = ("Segoe UI", 9, "bold")

# Notification timing (ms) and thresholds for app-level user alerts.
NOTIFY_TOAST_DURATION_MS = 8000
NOTIFY_BANNER_DURATION_MS = 10000
NOTIFY_STATUS_DURATION_MS = 8000
KEY_ROTATION_WARN_DAYS = 30


class EnigmaApp:
    def __init__(self, root):
        self.root = root

        builder = AppBuilder(root)
        try:
            built = builder.build()
        except StartupCancelled:
            logger.info("Startup cancelled before application initialization completed")
            return
        except Exception as e:
            logger.exception("Application build failed; aborting startup")
            messagebox.showerror(
                "Startup error",
                "The application could not be started and is closing.\n\n"
                + friendly_error(e)
            )
            try:
                self.root.destroy()
            except Exception:
                pass
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

        self._is_locked = False
        self._anomaly_banner = None
        self._warning_banner = None

        from services.backup_service import BackupService
        self._backup_service = BackupService(self.ks)
        self.service_orchestrator.set_backup_service(self._backup_service)

        self._setup_header()
        self._setup_tabs()

        self.lock_screen = LockScreen(root, on_unlock_request=self._request_unlock,
                                       on_recovery_request=self._request_recovery_unlock)

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
        event_bus.unsubscribe_all(self._on_anomaly_detected)
        event_bus.unsubscribe_all(self._on_backup_reminder)
        event_bus.unsubscribe_all(self._on_duress_mode_entered)
        event_bus.unsubscribe_all(self._on_recovery_share_created)
        event_bus.unsubscribe_all(self._on_recovery_key_reconstructed)
        event_bus.unsubscribe_all(self._on_key_info)
        event_bus.unsubscribe_all(self._on_key_fingerprint)
        # Clean up any active anomaly banner
        if hasattr(self, "_anomaly_banner") and self._anomaly_banner is not None:
            try:
                self._anomaly_banner.destroy()
            except Exception:
                pass
        # Clean up any active warning banner
        if hasattr(self, "_warning_banner") and self._warning_banner is not None:
            try:
                self._warning_banner.destroy()
            except Exception:
                pass
        self.root.destroy()

    # ------------------------------------------------------------------
    # Header & tab setup
    # ------------------------------------------------------------------
    def _setup_header(self):
        header = ttk.Frame(self.root, bootstyle="dark", height=80)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        ttk.Label(header, text="ULTIMATE ENIGMA MESSENGER",
                  font=FONT_TITLE,
                  bootstyle="inverse-warning").pack(side=tk.LEFT, padx=20, pady=10)

        ttk.Label(header, text="Hybrid Encryption · AES‑GCM + RSA‑OAEP · Time‑based keys",
                  font=FONT_SUBTITLE,
                  bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)

        # Emergency Lock Button
        lock_btn = ttk.Button(
            header, text="🔒 EMERGENCY\nLOCK",
            bootstyle="danger",
            cursor="hand2", command=self._emergency_lock
        )
        lock_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

        # TOTP Setup Button
        totp_setup_btn = ttk.Button(
            header, text="🔑 TOTP\nSetup",
            bootstyle="primary",
            cursor="hand2", command=lambda: self.auth_controller.show_totp_setup()
        )
        totp_setup_btn.pack(side=tk.RIGHT, padx=(5, 5), pady=10)

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
            style_config,
            global_secret_service=self.service_orchestrator.global_secret_service,
        )
        notebook.add(self.trust_tab.frame, text="🔗 Trust Chain")

        self.ntp_tab = NtpTab(
            notebook,
            self.service_orchestrator.encryption_service
        )
        notebook.add(self.ntp_tab.frame, text="🕐 Time Sync")

        self.help_tab = HelpTab(notebook)
        notebook.add(self.help_tab.frame, text="📚 Help")

        self.about_tab = AboutTab(
            notebook,
            self.ks,
            self.auth_controller,
            backup_service=self._backup_service
        )
        notebook.add(self.about_tab.frame, text="ℹ️ About")

        self._notebook = notebook
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Transient status bar for non-blocking feedback (e.g. unlock success).
        self._status_var = tk.StringVar(value="")
        self._status_clear_job = None
        status_bar = ttk.Label(
            self.root, textvariable=self._status_var,
            bootstyle="inverse-dark", anchor="w", font=FONT_SUBTITLE
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _set_status(self, text: str, clear_after_ms: int = 2000) -> None:
        """Show a transient status message that self-clears after a delay."""
        self._status_var.set(text)
        if self._status_clear_job is not None:
            try:
                self.root.after_cancel(self._status_clear_job)
            except Exception:
                pass
            self._status_clear_job = None
        if clear_after_ms:
            self._status_clear_job = self.root.after(
                clear_after_ms, lambda: self._status_var.set("")
            )

    def _on_tab_changed(self, event):
        """Handle tab change events to auto-refresh content.

        Matches on the selected frame's widget path (exact identity) rather than
        a substring of the display text, which is fragile to label changes.
        """
        try:
            selected = self._notebook.select()
            if not selected:
                return
            refreshers = {
                str(self.friends_tab.frame): self.friends_tab.refresh_list,
                str(self.file_tab.frame): self.file_tab.refresh_list,
                str(self.trust_tab.frame): self.trust_tab.refresh_list,
                str(self.encrypt_tab.frame): self.encrypt_tab._update_friend_list,
            }
            refresh = refreshers.get(str(selected))
            if refresh is not None:
                refresh()
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

        # The remaining steps (key restore, service rebuild, trust chain rebuild,
        # tab refresh) run synchronously and briefly freeze the UI. Show a busy
        # cursor so the freeze is communicated. These steps are security-sensitive
        # and ordering must be preserved, so they are NOT offloaded off-thread.
        try:
            self.root.configure(cursor="watch")
            self.root.update_idletasks()

            # Restore keys and services
            self.ks = new_ks
            self.auth_controller.set_key_store(new_ks)
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
                "ntp": self.ntp_tab,
                "help": self.help_tab,
                "about": self.about_tab,
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
        finally:
            try:
                self.root.configure(cursor="")
            except Exception:
                pass

        self._set_status("🔓 Unlocked — all keys restored.")
        logger.info("Application unlocked successfully")


    # ------------------------------------------------------------------
    # Recovery Unlock
    # ------------------------------------------------------------------
    def _request_recovery_unlock(self) -> None:
        """Handle recovery unlock from lock screen (forgotten password)."""
        if not self._is_locked:
            return

        success, new_ks, new_totp = self.auth_controller.request_recovery_unlock()

        if not success or new_ks is None:
            return

        try:
            self.root.configure(cursor="watch")
            self.root.update_idletasks()

            # Restore keys and services
            self.ks = new_ks
            self.auth_controller.set_key_store(new_ks)
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
                "ntp": self.ntp_tab,
                "help": self.help_tab,
                "about": self.about_tab,
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
        finally:
            try:
                self.root.configure(cursor="")
            except Exception:
                pass

        messagebox.showinfo(
            "Recovery Complete",
            "The application has been restored successfully.\n\n"
            "New encryption keys have been generated.\n"
            "You must re-exchange keys with your contacts."
        )
        logger.info("Application recovered via recovery key")


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

        # Anomaly detection alerts
        event_bus.subscribe(
            Events.ANOMALY_DETECTED,
            self._on_anomaly_detected,
            thread_safe=True
        )

        # Backup reminder from the background agent
        event_bus.subscribe(
            Events.BACKUP_REMINDER,
            self._on_backup_reminder,
            thread_safe=True
        )

        # Duress mode entry
        event_bus.subscribe(
            Events.DURESS_MODE_ENTERED,
            self._on_duress_mode_entered,
            thread_safe=True
        )

        # Recovery key operations
        event_bus.subscribe(
            Events.RECOVERY_SHARE_CREATED,
            self._on_recovery_share_created,
            thread_safe=True
        )
        event_bus.subscribe(
            Events.RECOVERY_KEY_RECONSTRUCTED,
            self._on_recovery_key_reconstructed,
            thread_safe=True
        )

        # Key inspection warnings (rotation / expiry detection)
        event_bus.subscribe(
            Events.KEY_INFO,
            self._on_key_info,
            thread_safe=True
        )
        event_bus.subscribe(
            Events.KEY_FINGERPRINT,
            self._on_key_fingerprint,
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
    # Anomaly detection alerts
    # ------------------------------------------------------------------
    def _on_anomaly_detected(self, **kwargs):
        """Handle anomaly detection event from background thread.

        Schedules the UI update on the main thread via EventBus's
        thread-safe dispatch, which calls root.after(0, ...).
        """
        score_obj = kwargs.get("score")
        if score_obj is None:
            return
        try:
            self._show_anomaly_alert(score_obj)
        except Exception as e:
            logger.warning("Anomaly alert handler error (non-critical): %s", e)

    def _show_anomaly_alert(self, score_obj) -> None:
        """Display a toast notification and red banner for anomalous messages."""
        sender = getattr(score_obj, "friend_name", "unknown")
        score_val = getattr(score_obj, "score", 0.0)
        confidence = getattr(score_obj, "confidence", 0.0)
        env_type = getattr(score_obj, "envelope_type", "unknown")
        packet_size = getattr(score_obj, "packet_size", 0)

        # Toast notification (non-blocking, auto-dismiss)
        try:
            ToastNotification(
                title="Anomaly Detected",
                message=(
                    f"Suspicious message from {sender}\n"
                    f"Confidence: {confidence:.0%}\n"
                    f"Anomaly type: {env_type}"
                ),
                duration=8000,
                bootstyle="danger",
            ).show_toast()
        except Exception:
            logger.debug("ToastNotification unavailable", exc_info=True)

        # Persistent red banner above the notebook (auto-dismiss after 10s)
        try:
            self._show_anomaly_banner(sender, score_val, confidence)
        except Exception:
            logger.debug("Anomaly banner failed", exc_info=True)

        # Also flash the status bar for extra visibility
        self._set_status(
            f"⚠️ Suspicious message from {sender}",
            clear_after_ms=10000,
        )

    def _show_anomaly_banner(self, sender: str, score: float, confidence: float) -> None:
        """Show a red warning banner that auto-dismisses after 10 seconds."""
        # Remove any existing anomaly banner
        if hasattr(self, "_anomaly_banner") and self._anomaly_banner is not None:
            try:
                self._anomaly_banner.destroy()
            except Exception:
                pass

        banner = ttk.Label(
            self.root,
            text=(
                f"⚠️ Suspicious message detected from '{sender}' "
                f"(confidence: {confidence:.0%})"
            ),
            bootstyle="danger",
            anchor="center",
            font=FONT_SUBTITLE,
            padding=(10, 4),
        )
        # Pack just below the header and above the notebook
        banner.pack(fill=tk.X, padx=0, pady=0, before=self._notebook.master)
        self._anomaly_banner = banner

        # Auto-dismiss after 10 seconds
        def _dismiss():
            try:
                if self._anomaly_banner is banner:
                    banner.destroy()
                    self._anomaly_banner = None
            except Exception:
                pass
        self._anomaly_banner = banner
        self.root.after(10000, _dismiss)

    # ------------------------------------------------------------------
    # App-level notifications (background agent / controller events)
    # ------------------------------------------------------------------
    def _on_backup_reminder(self, **kwargs):
        """Show a non-blocking backup reminder from the background agent."""
        try:
            days_since = kwargs.get("days_since")
            message = BackupReminderAgent.format_reminder_message(days_since)
            self.root.after(0, self._show_backup_reminder, message)
        except Exception as e:
            logger.warning("Backup reminder handler error (non-critical): %s", e)

    def _show_backup_reminder(self, message: str) -> None:
        """Display the backup reminder as a toast and status flash."""
        try:
            ToastNotification(
                title="Backup Reminder",
                message=message,
                duration=NOTIFY_TOAST_DURATION_MS,
                bootstyle="warning",
            ).show_toast()
        except Exception:
            logger.debug("ToastNotification unavailable", exc_info=True)
        self._set_status(
            f"Backup reminder: {message}",
            clear_after_ms=NOTIFY_STATUS_DURATION_MS,
        )

    def _on_duress_mode_entered(self, **kwargs):
        """Show a subtle, non-alarming notice when duress mode is entered."""
        try:
            self.root.after(
                0,
                self._set_status,
                "Session active in protected profile.",
                NOTIFY_STATUS_DURATION_MS,
            )
        except Exception as e:
            logger.warning("Duress mode handler error (non-critical): %s", e)

    def _on_recovery_share_created(self, **kwargs):
        """Confirm recovery share creation with a brief toast."""
        try:
            n = kwargs.get("n")
            k = kwargs.get("k")
            if n is not None and k is not None:
                message = f"Recovery key split into {n} shares (threshold: {k})."
            else:
                message = "Recovery key shares created and distributed."
            self.root.after(0, self._show_info_toast, "Recovery Shares", message)
        except Exception as e:
            logger.warning("Recovery share handler error (non-critical): %s", e)

    def _on_recovery_key_reconstructed(self, **kwargs):
        """Confirm recovery key reconstruction with a brief toast."""
        try:
            num_shares = kwargs.get("num_shares")
            if num_shares is not None:
                message = f"Recovery key reconstructed from {num_shares} shares."
            else:
                message = "Recovery key reconstructed successfully."
            self.root.after(0, self._show_info_toast, "Recovery Key", message)
        except Exception as e:
            logger.warning("Recovery key handler error (non-critical): %s", e)

    def _show_info_toast(self, title: str, message: str) -> None:
        """Display a brief, non-blocking confirmation toast."""
        try:
            ToastNotification(
                title=title,
                message=message,
                duration=NOTIFY_TOAST_DURATION_MS,
                bootstyle="info",
            ).show_toast()
        except Exception:
            logger.debug("ToastNotification unavailable", exc_info=True)
        self._set_status(message, clear_after_ms=NOTIFY_STATUS_DURATION_MS)

    def _on_key_info(self, **kwargs):
        """Handle key info events; warn when rotation/expiry is detected."""
        try:
            info = kwargs.get("info") or {}
            self._warn_on_key_issue(kwargs.get("friend_name"), info)
        except Exception as e:
            logger.warning("Key info handler error (non-critical): %s", e)

    def _on_key_fingerprint(self, **kwargs):
        """Handle key fingerprint events; warn when rotation/expiry is detected."""
        try:
            info = kwargs.get("info") or kwargs
            self._warn_on_key_issue(kwargs.get("friend_name"), info)
        except Exception as e:
            logger.warning("Key fingerprint handler error (non-critical): %s", e)

    def _warn_on_key_issue(self, friend_name, info) -> None:
        """Raise a warning banner when key rotation/expiry issues are detected.

        Tolerates payload variations by probing common field names and
        ignoring missing or malformed values.
        """
        if not isinstance(info, dict):
            return
        subject = friend_name or "local key"
        message = None

        if info.get("expired"):
            message = f"Key for '{subject}' has expired — rotate immediately."
        elif info.get("needs_rotation") or info.get("rotation_recommended"):
            message = (
                f"Key for '{subject}' is below the security minimum — "
                f"rotation recommended."
            )
        else:
            days = info.get("days_until_expiry")
            if days is None:
                days = info.get("days_to_expiry")
            if days is None:
                days = info.get("expires_days")
            if days is not None:
                try:
                    days = int(days)
                except (TypeError, ValueError):
                    days = None
            if days is not None and 0 <= days <= KEY_ROTATION_WARN_DAYS:
                message = (
                    f"Key for '{subject}' expires soon (in {days} days) — "
                    f"rotation recommended."
                )

        if message:
            self.root.after(0, self._show_key_warning, message)

    def _show_key_warning(self, message: str) -> None:
        """Display a warning banner and status flash for key issues."""
        try:
            self._show_warning_banner(message)
        except Exception:
            logger.debug("Key warning banner failed", exc_info=True)
        self._set_status(message, clear_after_ms=NOTIFY_STATUS_DURATION_MS)

    def _show_warning_banner(self, message: str) -> None:
        """Show a warning banner that auto-dismisses after 10 seconds."""
        # Remove any existing warning banner
        if hasattr(self, "_warning_banner") and self._warning_banner is not None:
            try:
                self._warning_banner.destroy()
            except Exception:
                pass

        banner = ttk.Label(
            self.root,
            text=message,
            bootstyle="warning",
            anchor="center",
            font=FONT_SUBTITLE,
            padding=(10, 4),
        )
        # Pack just below the header and above the notebook
        banner.pack(fill=tk.X, padx=0, pady=0, before=self._notebook.master)
        self._warning_banner = banner

        # Auto-dismiss after 10 seconds
        def _dismiss():
            try:
                if self._warning_banner is banner:
                    banner.destroy()
                    self._warning_banner = None
            except Exception:
                pass
        self.root.after(NOTIFY_BANNER_DURATION_MS, _dismiss)

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
            self.service_orchestrator.set_backup_service(self._backup_service)
        except Exception as e:
            logger.warning("Could not initialize BackupService for agent: %s", e)

        # Start all agents via the app controller
        self.app_controller.start_agents()
        logger.debug("Background agents started")

