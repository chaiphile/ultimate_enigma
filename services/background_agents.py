"""Background agents for periodic maintenance, monitoring, and diagnostics.

Implements subagent-style background tasks that run independently of the GUI.

Agents:
    BackupReminderAgent - Periodic backup age checks and reminders
    RatchetMaintenanceAgent - Stale lock cleanup and deadlock detection
    SystemMonitorAgent - Task queue and event bus health monitoring
    KeyInspectorAgent - Key fingerprint and capability inspection
"""

import logging
import threading
import time
from typing import Optional, Callable, Dict, Any, List

from services.event_bus import event_bus, Events
from src.constants import CONCURRENCY_CONSTANTS

logger = logging.getLogger(__name__)

# Re-export Events.BACKUP_COMPLETED for convenience in agent code
BACKUP_COMPLETED = Events.BACKUP_COMPLETED


# ---------------------------------------------------------------------------
# Backup Reminder Agent
# ---------------------------------------------------------------------------

class BackupReminderAgent:
    """Periodically checks backup age and publishes reminder events.

    Runs as a daemon thread, checking every CHECK_INTERVAL seconds whether
    the user should be reminded to create a backup. Publishes
    BACKUP_REMINDER events with days_since information.

    Usage::

        agent = BackupReminderAgent(backup_service)
        agent.start()
        # ... later ...
        agent.stop()
    """

    CHECK_INTERVAL = CONCURRENCY_CONSTANTS.get("BACKUP_REMINDER_INTERVAL", 3600)

    def __init__(self, backup_service):
        """
        Args:
            backup_service: A BackupService instance for querying backup state.
        """
        self._backup_service = backup_service
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self):
        """Start the background check thread."""
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="backup-reminder-agent",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info("BackupReminderAgent started (interval=%ds)", self.CHECK_INTERVAL)

    def stop(self):
        """Signal the agent to stop and wait for the thread to finish."""
        if not self._is_running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self._is_running = False
        logger.info("BackupReminderAgent stopped")

    def _loop(self):
        """Main loop: check backup status periodically."""
        # Do an initial check after a short delay (let the app finish starting)
        self._stop_event.wait(timeout=30.0)
        while not self._stop_event.is_set():
            try:
                self._check_backup_status()
            except Exception as e:
                logger.error("BackupReminderAgent check failed: %s", e)
            self._stop_event.wait(timeout=self.CHECK_INTERVAL)

    def _check_backup_status(self):
        """Query BackupService and publish reminder if needed."""
        remind, days_since = self._backup_service.should_remind_backup()
        if remind:
            event_bus.publish(Events.BACKUP_REMINDER, days_since=days_since)
            logger.info(
                "Backup reminder published (days_since=%s)", days_since
            )

    @staticmethod
    def format_reminder_message(days_since: Optional[int]) -> str:
        """Format a human-readable reminder message.

        Args:
            days_since: Days since last backup, or None if never backed up.

        Returns:
            Formatted reminder string.
        """
        if days_since is None:
            return "No backup found. Create your first backup now!"
        return f"Last backup was {days_since} day(s) ago. Consider creating a new backup."

    def check_now(self) -> Dict[str, Any]:
        """Perform an immediate backup status check (for on-demand use).

        Returns:
            Dict with 'needs_backup', 'days_since', and 'message' keys.
        """
        remind, days_since = self._backup_service.should_remind_backup()
        return {
            "needs_backup": remind,
            "days_since": days_since,
            "message": self.format_reminder_message(days_since),
        }


# ---------------------------------------------------------------------------
# Ratchet Maintenance Agent
# ---------------------------------------------------------------------------

class RatchetMaintenanceAgent:
    """Periodic maintenance for Double Ratchet lock management.

    Performs:
    - Stale lock cleanup (removes locks for deleted friends)
    - Lock statistics collection
    - Potential deadlock detection

    Runs as a daemon thread at LOCK_CLEANUP_INTERVAL (default: 1 hour).

    Usage::

        agent = RatchetMaintenanceAgent()
        agent.start()
        # ... later ...
        agent.stop()
    """

    CLEANUP_INTERVAL = CONCURRENCY_CONSTANTS.get("LOCK_CLEANUP_INTERVAL", 3600)

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self._friends_service = None

    @property
    def is_running(self) -> bool:
        return self._is_running

    def set_friends_service(self, friends_service) -> None:
        """Inject FriendsService for querying active friend list.

        Args:
            friends_service: A FriendsService instance.
        """
        self._friends_service = friends_service

    def start(self):
        """Start the background maintenance thread."""
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="ratchet-maintenance-agent",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info(
            "RatchetMaintenanceAgent started (interval=%ds)", self.CLEANUP_INTERVAL
        )

    def stop(self):
        """Signal the agent to stop."""
        if not self._is_running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self._is_running = False
        logger.info("RatchetMaintenanceAgent stopped")

    def _loop(self):
        """Main loop: periodic maintenance cycles."""
        # Initial delay to let the app finish starting
        self._stop_event.wait(timeout=60.0)
        while not self._stop_event.is_set():
            try:
                self._run_maintenance()
            except Exception as e:
                logger.error("RatchetMaintenanceAgent cycle failed: %s", e)
            self._stop_event.wait(timeout=self.CLEANUP_INTERVAL)

    def _run_maintenance(self):
        """Execute a full maintenance cycle."""
        from services.ratchet_service import RatchetService

        # 1. Cleanup stale locks
        active_names = self._get_active_friend_names()
        removed = RatchetService.cleanup_friend_locks(active_names)
        if removed > 0:
            event_bus.publish(Events.RATCHET_LOCKS_CLEANED, removed=removed)
            logger.info("RatchetMaintenance: cleaned %d stale locks", removed)

        # 2. Detect potential deadlock in ratchet lock ordering
        canonical = sorted(active_names, key=lambda n: (n.lower(), n))
        if self.detect_deadlock(active_names, canonical):
            event_bus.publish(Events.RATCHET_DEADLOCK_DETECTED, names=active_names)
            logger.warning(
                "RatchetMaintenance: potential deadlock detected in ratchet locks"
            )

        # 3. Publish lock stats
        stats = RatchetService.get_lock_stats()
        event_bus.publish(Events.RATCHET_LOCK_STATS, **stats)


    def _get_active_friend_names(self) -> List[str]:
        """Get list of currently active friend names."""
        if self._friends_service is None:
            return []
        try:
            return self._friends_service.get_friend_names()
        except Exception as e:
            logger.warning("Could not get friend names for cleanup: %s", e)
            return []

    def get_lock_stats(self) -> Dict[str, int]:
        """Get current lock statistics (on-demand).

        Returns:
            Dict with 'total_locks' and 'total_timestamps' keys.
        """
        from services.ratchet_service import RatchetService
        return RatchetService.get_lock_stats()

    def detect_deadlock(
        self, names_a: List[str], names_b: List[str]
    ) -> bool:
        """Check if two lock sets could deadlock (on-demand diagnostic).

        Args:
            names_a: First set of friend names.
            names_b: Second set of friend names.

        Returns:
            True if deadlock is possible.
        """
        from services.ratchet_service import RatchetService
        return RatchetService.detect_potential_deadlock(names_a, names_b)


# ---------------------------------------------------------------------------
# System Monitor Agent
# ---------------------------------------------------------------------------

class SystemMonitorAgent:
    """Monitors system health: task queue, event bus, and service status.

    Publishes periodic SYSTEM_STATUS events with aggregated health data.
    Useful for a diagnostics dashboard or health monitoring UI.

    Usage::

        agent = SystemMonitorAgent(crypto_queue)
        agent.start()
        # ... later ...
        agent.stop()
    """

    MONITOR_INTERVAL = CONCURRENCY_CONSTANTS.get("SYSTEM_MONITOR_INTERVAL", 300)

    def __init__(self, crypto_queue=None):
        """
        Args:
            crypto_queue: Optional CryptoTaskQueue instance to monitor.
        """
        self._crypto_queue = crypto_queue
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def set_crypto_queue(self, crypto_queue):
        """Inject or update the CryptoTaskQueue reference."""
        self._crypto_queue = crypto_queue

    def start(self):
        """Start the monitoring thread."""
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="system-monitor-agent",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info(
            "SystemMonitorAgent started (interval=%ds)", self.MONITOR_INTERVAL
        )

    def stop(self):
        """Signal the agent to stop."""
        if not self._is_running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self._is_running = False
        logger.info("SystemMonitorAgent stopped")

    def _loop(self):
        """Main loop: periodic health checks."""
        self._stop_event.wait(timeout=10.0)
        while not self._stop_event.is_set():
            try:
                self._collect_and_publish_status()
            except Exception as e:
                logger.error("SystemMonitorAgent check failed: %s", e)
            self._stop_event.wait(timeout=self.MONITOR_INTERVAL)

    def _collect_and_publish_status(self):
        """Collect health metrics and publish a status event."""
        status = self.get_status()
        is_healthy = status.get("healthy", True)
        event_bus.publish(Events.SYSTEM_STATUS, status=status, healthy=is_healthy)


    def get_status(self) -> Dict[str, Any]:
        """Collect current system status (on-demand or periodic).

        Returns:
            Dict with health metrics and overall healthy flag.
        """
        status: Dict[str, Any] = {
            "timestamp": time.time(),
            "healthy": True,
            "issues": [],
        }

        # Crypto queue status
        if self._crypto_queue is not None:
            queue_running = self._crypto_queue.is_running
            pending = self._crypto_queue.pending_tasks
            status["crypto_queue"] = {
                "running": queue_running,
                "pending_tasks": pending,
            }
            if not queue_running:
                status["healthy"] = False
                status["issues"].append("CryptoTaskQueue is not running")

        # Event bus status
        total_subscribers = event_bus.subscriber_count()
        status["event_bus"] = {
            "total_subscribers": total_subscribers,
        }

        # Ratchet lock stats
        try:
            from services.ratchet_service import RatchetService
            lock_stats = RatchetService.get_lock_stats()
            status["ratchet_locks"] = lock_stats
            # Warn if lock count is suspiciously high
            if lock_stats.get("total_locks", 0) > 100:
                status["healthy"] = False
                status["issues"].append(
                    f"High lock count: {lock_stats['total_locks']}"
                )
        except Exception:
            pass

        return status


# ---------------------------------------------------------------------------
# Key Inspector Agent
# ---------------------------------------------------------------------------

class KeyInspectorAgent:
    """Periodically inspects keys and publishes key info/fingerprint events.

    Runs as a daemon thread at CHECK_INTERVAL (default: 1 hour), checking
    key expiry/rotation needs and publishing KEY_INFO / KEY_FINGERPRINT
    events. Also supports on-demand inspection via get_key_info() and
    get_fingerprint().

    Usage::

        agent = KeyInspectorAgent(key_store)
        agent.start()
        # ... later ...
        agent.stop()
    """

    CHECK_INTERVAL = CONCURRENCY_CONSTANTS.get("KEY_INSPECTOR_INTERVAL", 3600)

    def __init__(self, key_store=None):
        """
        Args:
            key_store: Optional KeyStore instance. Can be set later.
        """
        self._key_store = key_store
        self._friends_service = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self):
        """Start the background key inspection thread."""
        if self._is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="key-inspector-agent",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        logger.info("KeyInspectorAgent started (interval=%ds)", self.CHECK_INTERVAL)

    def stop(self):
        """Signal the agent to stop."""
        if not self._is_running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self._is_running = False
        logger.info("KeyInspectorAgent stopped")

    def _loop(self):
        """Main loop: periodic key inspection cycles."""
        self._stop_event.wait(timeout=30.0)
        while not self._stop_event.is_set():
            try:
                self._run_key_inspection()
            except Exception as e:
                logger.error("KeyInspectorAgent cycle failed: %s", e)
            self._stop_event.wait(timeout=self.CHECK_INTERVAL)

    def _run_key_inspection(self):
        """Run a full key inspection cycle for local and friend keys."""
        self.publish_key_info()

        if self._friends_service is not None:
            try:
                friend_names = self._friends_service.get_friend_names()
            except Exception as e:
                logger.warning("KeyInspectorAgent could not list friends: %s", e)
                return
            for name in friend_names:
                try:
                    self.publish_key_info(name)
                except Exception as e:
                    logger.warning(
                        "KeyInspectorAgent inspection failed for '%s': %s", name, e
                    )

    def set_key_store(self, key_store) -> None:
        """Update the KeyStore reference."""
        self._key_store = key_store

    def set_friends_service(self, friends_service) -> None:
        """Inject FriendsService for friend key queries.

        Args:
            friends_service: A FriendsService instance.
        """
        self._friends_service = friends_service

    def get_key_info(self, friend_name: Optional[str] = None) -> Dict[str, Any]:
        """Get key information for a friend or the local user.

        Args:
            friend_name: Friend name to inspect. If None, returns local key info.

        Returns:
            Dict with key metadata.
        """
        if self._key_store is None:
            return {"error": "KeyStore not initialized"}

        if friend_name is None:
            return self._get_local_key_info()
        return self._get_friend_key_info(friend_name)

    def _get_local_key_info(self) -> Dict[str, Any]:
        """Get local user key information."""
        info: Dict[str, Any] = {
            "has_public_key": self._key_store.my_pub is not None,
            "has_private_key": self._key_store.my_priv is not None,
            "has_global_secret": self._key_store.global_secret is not None,
        }

        try:
            info["needs_key_rotation"] = self._key_store.needs_key_rotation
        except Exception:
            pass

        if self._key_store.my_pub is not None:
            info["public_key_fingerprint"] = self._local_public_fingerprint()

        return info

    def _get_friend_key_info(self, friend_name: str) -> Dict[str, Any]:
        """Get friend key information."""
        if self._friends_service is None:
            return {"error": "FriendsService not set"}

        try:
            details = self._friends_service.get_friend_details(friend_name)
            if details is None:
                return {"error": f"Friend '{friend_name}' not found"}

            info: Dict[str, Any] = {
                "name": friend_name,
                "has_public_key": details.get("public_key_pem") is not None,
                "has_shared_secret": details.get("has_shared_secret", False),
                "has_x25519_key": details.get("x25519_public_key_b64") is not None,
            }

            # Check capabilities
            caps = details.get("capabilities_json")
            if caps:
                import json
                try:
                    info["capabilities"] = json.loads(caps) if isinstance(caps, str) else caps
                except (json.JSONDecodeError, TypeError):
                    info["capabilities"] = {}

            # Check ratchet status
            info["has_active_ratchet"] = self._friends_service.has_active_ratchet(
                friend_name
            )

            return info
        except Exception as e:
            return {"error": str(e)}

    def _local_public_fingerprint(self) -> Optional[str]:
        """SHA-256 fingerprint of the local RSA public key, or None."""
        try:
            if self._key_store is None or self._key_store.my_pub is None:
                return None
            from crypto import sha256_fingerprint
            from key_manager import pubkey_to_pem
            return sha256_fingerprint(pubkey_to_pem(self._key_store.my_pub).encode())
        except Exception as e:
            logger.debug("Could not compute local key fingerprint: %s", e)
            return None

    def get_fingerprint(self, friend_name: Optional[str] = None) -> Optional[str]:
        """Get the fingerprint for a friend's public key or local public key.

        Args:
            friend_name: Friend name. If None, returns local fingerprint.

        Returns:
            Hex-encoded fingerprint string, or None on error.
        """
        if self._key_store is None:
            return None

        try:
            from services.ecdh_service import ECDHService
            if friend_name is None:
                return self._local_public_fingerprint()

            if self._friends_service is None:
                return None
            details = self._friends_service.get_friend_details(friend_name)
            if details and details.get("x25519_public_key_b64"):
                import base64
                pub_bytes = base64.b64decode(details["x25519_public_key_b64"])
                return ECDHService.fingerprint(pub_bytes)
        except Exception as e:
            logger.warning("Could not get fingerprint for '%s': %s", friend_name, e)
        return None

    def publish_key_info(self, friend_name: Optional[str] = None) -> None:
        """Publish key info and fingerprint events for UI consumption.

        Args:
            friend_name: Friend name, or None for local info.
        """
        info = self.get_key_info(friend_name)
        fingerprint = self.get_fingerprint(friend_name)
        event_bus.publish(Events.KEY_INFO, friend_name=friend_name, info=info, fingerprint=fingerprint)
        event_bus.publish(Events.KEY_FINGERPRINT, friend_name=friend_name, fingerprint=fingerprint)
