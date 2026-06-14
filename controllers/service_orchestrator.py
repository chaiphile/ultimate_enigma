"""Service lifecycle orchestrator.

Manages the creation, rebuilding, and dependency injection of business services.
Ensures thread-safe service replacement during unlock operations and maintains
consistent references across View components.

Also manages background agents that run independently of the GUI, providing
periodic maintenance, monitoring, and diagnostic capabilities.

Publishes Events:
    SERVICES_REBUILT - after services are rebuilt with new keys.
"""

import logging
import threading
from typing import Optional

from key_manager import KeyStore
from services.encryption import EncryptionService
from services.file_service import FileService
from services.friends import FriendsService
from services.clipboard_service import ClipboardService
from services.global_secret_service import GlobalSecretService
from services.event_bus import event_bus, Events
from services.background_agents import (
    BackupReminderAgent,
    RatchetMaintenanceAgent,
    SystemMonitorAgent,
    KeyInspectorAgent,
)

logger = logging.getLogger(__name__)


class ServiceOrchestrator:
    """Centralized manager for all business service instances."""

    def __init__(self, root, key_store: KeyStore, crypto_queue=None):
        self.root = root
        self._service_lock = threading.RLock()
        self._crypto_queue = crypto_queue
        
        # Initialize services with provided key store
        self.encryption_service = EncryptionService(key_store)
        self.file_service = FileService(key_store)
        self.friends_service = FriendsService(key_store)
        self.clipboard_service = ClipboardService(root)
        self.global_secret_service = GlobalSecretService(key_store)
        
        # Initialize background agents
        self._init_agents(key_store)
        
        # Derive and set the ratchet storage encryption key from the master secret
        self._init_ratchet_storage_key(key_store)
    
    def _init_agents(self, key_store: KeyStore) -> None:
        """Initialize background agents and wire up dependencies.

        Agents are created but not started yet. They are started separately
        after the application is fully initialized.
        """
        # Backup reminder agent - needs BackupService (created on demand)
        self._backup_agent: Optional[BackupReminderAgent] = None

        # Ratchet maintenance agent
        self.ratchet_maintenance_agent = RatchetMaintenanceAgent()
        self.ratchet_maintenance_agent.set_friends_service(self.friends_service)

        # System monitor agent
        self.system_monitor_agent = SystemMonitorAgent(
            crypto_queue=self._crypto_queue
        )

        # Key inspector agent
        self.key_inspector_agent = KeyInspectorAgent(key_store)
        self.key_inspector_agent.set_friends_service(self.friends_service)

        logger.info("Background agents initialized")

    def set_backup_agent(self, backup_service) -> None:
        """Create and configure the BackupReminderAgent.

        Called after BackupService is instantiated (typically by AboutTab).

        Args:
            backup_service: A BackupService instance.
        """
        self._backup_agent = BackupReminderAgent(backup_service)
        logger.info("BackupReminderAgent configured")

    def start_agents(self):
        """Start all background agents. Call after app initialization."""
        agents_started = 0

        if self._backup_agent is not None:
            try:
                self._backup_agent.start()
                agents_started += 1
            except Exception as e:
                logger.error("Failed to start BackupReminderAgent: %s", e)

        try:
            self.ratchet_maintenance_agent.start()
            agents_started += 1
        except Exception as e:
            logger.error("Failed to start RatchetMaintenanceAgent: %s", e)

        try:
            self.system_monitor_agent.start()
            agents_started += 1
        except Exception as e:
            logger.error("Failed to start SystemMonitorAgent: %s", e)

        logger.info("Background agents started: %d/%d", agents_started, 3)

    def stop_agents(self):
        """Stop all background agents. Call during shutdown."""
        if self._backup_agent is not None:
            try:
                self._backup_agent.stop()
            except Exception as e:
                logger.warning("Error stopping BackupReminderAgent: %s", e)

        try:
            self.ratchet_maintenance_agent.stop()
        except Exception as e:
            logger.warning("Error stopping RatchetMaintenanceAgent: %s", e)

        try:
            self.system_monitor_agent.stop()
        except Exception as e:
            logger.warning("Error stopping SystemMonitorAgent: %s", e)

        logger.info("Background agents stopped")

    @staticmethod
    def _init_ratchet_storage_key(key_store: KeyStore) -> None:
        """Derive and set the ratchet at-rest encryption key.

        The key is derived from the master password (via KeyStore.load())
        rather than global_secret, so an attacker with DB access alone
        cannot recover it.
        """
        from services.ratchet_service import RatchetService
        storage_key = getattr(key_store, '_ratchet_storage_key', None)
        if storage_key is not None:
            RatchetService.set_ratchet_storage_key(storage_key)
            logger.info("Ratchet state storage encryption key initialized")
        else:
            logger.warning(
                "No ratchet storage key available — ratchet states will not be "
                "encrypted at rest"
            )

    @property
    def service_lock(self):
        return self._service_lock

    @property
    def crypto_queue(self):
        return self._crypto_queue

    def rebuild_services(self, new_key_store: KeyStore, tab_references: dict = None):
        """Rebuild all services with a new key store (e.g., after unlock).
        
        Args:
            new_key_store: The freshly loaded KeyStore instance.
            tab_references: Optional dict mapping tab names to tab instances
                           for updating service references.
        """
        with self._service_lock:
            logger.info("Rebuilding services with restored keys")
            
            self.encryption_service = EncryptionService(new_key_store)
            self.file_service = FileService(new_key_store)
            self.friends_service = FriendsService(new_key_store)
            self.clipboard_service = ClipboardService(self.root)
            self.global_secret_service = GlobalSecretService(new_key_store)
            
            # Re-initialize ratchet storage encryption key
            self._init_ratchet_storage_key(new_key_store)

            # Update agent dependencies
            self.ratchet_maintenance_agent.set_friends_service(self.friends_service)
            self.key_inspector_agent.set_key_store(new_key_store)
            self.key_inspector_agent.set_friends_service(self.friends_service)

            # Update tab references if provided
            if tab_references:
                self._update_tab_references(tab_references)

            # Notify subscribers that services have been rebuilt
            event_bus.publish(Events.SERVICES_REBUILT, source="service_orchestrator")

    def _update_tab_references(self, tabs: dict):
        """Update service references in tab instances."""
        try:
            if "encrypt" in tabs:
                tabs["encrypt"].service = self.encryption_service
                tabs["encrypt"].friends_service = self.friends_service
                tabs["encrypt"].clipboard_service = self.clipboard_service
                if self._crypto_queue:
                    tabs["encrypt"].crypto_queue = self._crypto_queue
                
            if "decrypt" in tabs:
                tabs["decrypt"].service = self.encryption_service
                tabs["decrypt"].clipboard_service = self.clipboard_service
                if self._crypto_queue:
                    tabs["decrypt"].crypto_queue = self._crypto_queue
                
            if "file" in tabs:
                tabs["file"].file_service = self.file_service
                tabs["file"].friends_service = self.friends_service
                tabs["file"].global_secret_service = self.global_secret_service
                if self._crypto_queue:
                    tabs["file"].crypto_queue = self._crypto_queue
                
            if "secret" in tabs:
                tabs["secret"].service = self.global_secret_service
                tabs["secret"].clipboard_service = self.clipboard_service
                
            if "friends" in tabs:
                tabs["friends"].service = self.friends_service
                
            if "ntp" in tabs:
                tabs["ntp"].encryption_service = self.encryption_service
                
            logger.debug("Tab service references updated")
        except Exception as e:
            logger.error("Failed to update tab references: %s", e)

    def shutdown(self):
        """Clean up services that require explicit shutdown."""
        try:
            from services.ratchet_service import RatchetService
            RatchetService.flush_dirty_states()
            self.stop_agents()
            self.clipboard_service.shutdown()
            logger.info("ServiceOrchestrator shutdown complete")
        except Exception as e:
            logger.warning("Error during service shutdown: %s", e)
