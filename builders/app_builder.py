"""AppBuilder — step-by-step composition root for EnigmaApp.

Each step is independently testable with mocked dependencies.
The build() method orchestrates all steps in order.
"""

import tkinter as tk
import logging
from pathlib import Path
import ttkbootstrap as ttk

import database
from key_manager import KeyStore
from controllers.application_controller import ApplicationController
from controllers.auth_controller import AuthController
from controllers.service_orchestrator import ServiceOrchestrator
from services.event_bus import event_bus
from services.totp_persistence import TotpPersistence
from services.trust_chain_service import TrustChainService

logger = logging.getLogger(__name__)


def _db_has_keys(db_path: Path) -> bool:
    """Check if the database at db_path has actual key material.

    Returns True if the settings table exists and contains a
    'private_key_encrypted' row, meaning keys were generated during
    first-run setup. An empty schema-only DB is safe to delete.
    """
    try:
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT 1 FROM settings WHERE key='private_key_encrypted'"
            ).fetchone()
            return row is not None
        finally:
            conn.close()
    except Exception:
        return False


class StartupCancelled(Exception):
    """Raised when startup is intentionally aborted by the user."""


class AppBuilder:
    """Composes an EnigmaApp through explicit, testable build steps."""

    def __init__(self, root):
        self.root = root
        self.ks = None
        self.app_controller = None
        self.auth_controller = None
        self.totp_persistence = None
        self.service_orchestrator = None
        self.trust_chain_service = None
        self.first_run = False
        self.style = None
        self.bg = self.fg = self.accent = self.secondary = self.dark = None

    def step1_init_window(self) -> bool:
        """Configure root window, style, and event bus."""
        self.root.geometry("1400x850")
        self.root.minsize(1200, 750)
        icon = tk.PhotoImage(width=1, height=1)
        self.root.iconphoto(True, icon)
        event_bus.set_root(self.root)

        self.style = ttk.Style()
        self.bg = self.style.colors.bg
        self.fg = self.style.colors.fg
        self.accent = self.style.colors.primary
        self.secondary = self.style.colors.secondary
        self.dark = self.style.colors.dark
        return True

    def step2_init_database(self) -> bool:
        """Detect first-run and ensure DB schema exists."""
        self.first_run = not database.DB_PATH.exists()
        database.init_db()
        return True

    def step3_init_keystore(self) -> bool:
        """Create the KeyStore instance."""
        self.ks = KeyStore()
        return True

    def step4_init_controllers(self) -> bool:
        """Create ApplicationController, TotpPersistence, AuthController."""
        self.app_controller = ApplicationController(self.root)
        self.totp_persistence = TotpPersistence(self.ks)
        self.auth_controller = AuthController(
            self.root, self.ks, totp_persistence=self.totp_persistence
        )
        self.app_controller.start_queue_processing()
        return True

    def step5_authenticate(self) -> bool:
        """Load keys, enforce mandatory TOTP, verify startup TOTP.

        Returns False if any auth step fails.
        """
        if not self.auth_controller.load_keys(self.first_run):
            return False

        self.ks = self.auth_controller.ks

        if not self.auth_controller.enforce_mandatory_totp_setup():
            self.ks.wipe()
            return False

        if not self.auth_controller.verify_startup_totp():
            self.ks.wipe()
            return False

        return True

    def _cleanup_partial_startup(self) -> None:
        """Stop resources created before authentication completed."""
        if self.app_controller is not None:
            try:
                self.app_controller.shutdown()
            except Exception as e:
                logger.warning("Partial startup cleanup failed: %s", e)

        try:
            self.root.destroy()
        except Exception:
            pass

        # If first-run setup was cancelled before any keys were generated, remove
        # the empty DB file so the next launch still detects as first run instead
        # of asking for a password that was never set.
        if self.first_run:
            try:
                db_path = database.DB_PATH
                if db_path.exists() and not _db_has_keys(db_path):
                    db_path.unlink()
                    logger.info("Removed empty database from cancelled first-run setup")
            except Exception as e:
                logger.warning("Could not remove first-run database: %s", e)

    def step6_init_services(self) -> bool:
        """Create ServiceOrchestrator, TrustChainService, wire them together."""
        self.service_orchestrator = ServiceOrchestrator(
            self.root, self.ks, crypto_queue=self.app_controller.crypto_queue
        )
        self.app_controller.set_service_orchestrator(self.service_orchestrator)

        self.trust_chain_service = TrustChainService(self.ks)
        self.service_orchestrator.friends_service.set_trust_chain_service(
            self.trust_chain_service
        )

        self.app_controller.start_ntp_sync(
            self.service_orchestrator.encryption_service,
        )
        return True

    def build(self):
        """Run all steps in order, returning the composed state.

        Returns a dict of built components, or None if any step fails.
        The caller (EnigmaApp.__init__) is responsible for wiring these
        into the final application object.
        """
        steps = [
            self.step1_init_window,
            self.step2_init_database,
            self.step3_init_keystore,
            self.step4_init_controllers,
            self.step5_authenticate,
            self.step6_init_services,
        ]
        for step in steps:
            if not step():
                self._cleanup_partial_startup()
                raise StartupCancelled("Startup cancelled or authentication failed")
        return {
            "root": self.root,
            "ks": self.ks,
            "app_controller": self.app_controller,
            "auth_controller": self.auth_controller,
            "totp_persistence": self.totp_persistence,
            "service_orchestrator": self.service_orchestrator,
            "trust_chain_service": self.trust_chain_service,
            "first_run": self.first_run,
            "style": self.style,
            "bg": self.bg,
            "fg": self.fg,
            "accent": self.accent,
            "secondary": self.secondary,
            "dark": self.dark,
        }
