"""Application lifecycle controller.

Manages startup/shutdown sequences, NTP synchronization, global hotkeys,
and the main task queue. Extracted from EnigmaApp to enforce MVC separation.
"""

import logging
import threading
import time
from queue import Queue, Empty

from services.crypto_task_queue import CryptoTaskQueue, TaskPriority
from src.constants import CONCURRENCY_CONSTANTS

logger = logging.getLogger(__name__)

# Hotkey constants (duplicated here to avoid circular imports with app.py)
HOTKEY_ID_LOCK = 1
HOTKEY_ID_UNLOCK = 2


class ApplicationController:
    """Handles application-level concerns independent of UI or business logic."""

    def __init__(self, root):
        self.root = root
        self.task_queue = Queue()
        self._ntp_thread = None
        self._hotkey_service = None
        self._is_running = False
        self._queue_after_id = None
        self._service_orchestrator = None

        # Background crypto task queue for non-blocking encryption/decryption.
        # Replaces ad-hoc threading.Thread usage in View classes.
        self.crypto_queue = CryptoTaskQueue(
            root=root,
            max_workers=CONCURRENCY_CONSTANTS.get("CRYPTO_QUEUE_MAX_WORKERS", 4),
            default_timeout=CONCURRENCY_CONSTANTS.get(
                "CRYPTO_QUEUE_DEFAULT_TIMEOUT", 120.0
            ),
        )

    def set_service_orchestrator(self, orchestrator):
        """Store reference to ServiceOrchestrator for agent lifecycle management.

        Args:
            orchestrator: The ServiceOrchestrator instance.
        """
        self._service_orchestrator = orchestrator

    # ------------------------------------------------------------------
    # Task Queue
    # ------------------------------------------------------------------
    def start_queue_processing(self):
        """Begin processing the task queue on the main thread."""
        self._is_running = True
        self.crypto_queue.start()
        self._process_queue()

    def _process_queue(self):
        if not self._is_running:
            return
        try:
            while True:
                task = self.task_queue.get_nowait()
                task()
        except Empty:
            pass
        self._queue_after_id = self.root.after(100, self._process_queue)

    def enqueue(self, func):
        """Thread-safe task submission."""
        self.task_queue.put(func)

    # ------------------------------------------------------------------
    # NTP Synchronization
    # ------------------------------------------------------------------
    def start_ntp_sync(self, encryption_service, delay_ms=2000):
        """Schedule NTP sync to start after GUI is rendered."""
        self.root.after(delay_ms, lambda: self._start_ntp_thread(encryption_service))

    def _start_ntp_thread(self, encryption_service):
        if self._ntp_thread is not None:
            return
        self._ntp_thread = threading.Thread(
            target=self._ntp_sync_loop,
            args=(encryption_service,),
            daemon=True
        )
        self._ntp_thread.start()
        logger.info("NTP sync thread started (deferred)")

    def _ntp_sync_loop(self, encryption_service):
        """Background NTP sync - sequential queries, fully exception-safe."""
        try:
            from ntp_client import get_ntp_time
            while self._is_running:
                try:
                    logger.info("Starting background NTP sync...")
                    t = get_ntp_time()
                    if t is not None:
                        from datetime import datetime, timezone
                        ntp_dt = datetime.fromtimestamp(t, tz=timezone.utc)
                        local_dt = datetime.now(timezone.utc)
                        offset_ms = (ntp_dt - local_dt).total_seconds() * 1000
                        logger.info(
                            "NTP sync OK: %s (offset %+.2f ms)",
                            ntp_dt.strftime("%Y-%m-%d %H:%M:%S UTC"), offset_ms
                        )
                        encryption_service.update_ntp_time(t)

                    else:
                        logger.warning("NTP sync failed - using system time")
                        encryption_service.update_ntp_time(None)

                except Exception as e:
                    logger.error("NTP sync error (non-fatal): %s", e)
                time.sleep(1800)
        except Exception as e:
            logger.error("NTP sync loop crashed (non-fatal): %s", e)

    # ------------------------------------------------------------------
    # Global Hotkeys
    # ------------------------------------------------------------------
    def register_hotkeys(self, lock_callback, unlock_callback):
        """Register system-wide hotkeys for lock/unlock."""
        try:
            from services.hotkey_service import HotkeyService, MOD_CTRL, MOD_SHIFT, VK_L, VK_U
            self._hotkey_service = HotkeyService()
            self._hotkey_service.register(
                HOTKEY_ID_LOCK, MOD_CTRL | MOD_SHIFT, VK_L,
                callback=lambda: self.root.after(0, lock_callback)
            )
            self._hotkey_service.register(
                HOTKEY_ID_UNLOCK, MOD_CTRL | MOD_SHIFT, VK_U,
                callback=lambda: self.root.after(0, unlock_callback)
            )
            self._hotkey_service.start()
            logger.info("Global hotkeys registered")
        except Exception as e:
            logger.error("Failed to register hotkeys: %s", e)

    # ------------------------------------------------------------------
    # Background Agents
    # ------------------------------------------------------------------
    def start_agents(self):
        """Start all background agents managed by ServiceOrchestrator."""
        if self._service_orchestrator is not None:
            try:
                self._service_orchestrator.start_agents()
            except Exception as e:
                logger.error("Failed to start background agents: %s", e)

    def stop_agents(self):
        """Stop all background agents."""
        if self._service_orchestrator is not None:
            try:
                self._service_orchestrator.stop_agents()
            except Exception as e:
                logger.warning("Error stopping background agents: %s", e)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def shutdown(self):
        """Clean up all managed resources."""
        self._is_running = False

        if self._queue_after_id is not None:
            try:
                self.root.after_cancel(self._queue_after_id)
            except Exception as e:
                logger.debug("Queue callback cancellation skipped: %s", e)
            finally:
                self._queue_after_id = None

        # Stop background agents first
        self.stop_agents()

        # Shut down the crypto task queue
        if self.crypto_queue:
            try:
                self.crypto_queue.drain(timeout=5.0)
                self.crypto_queue.shutdown(wait=False)
            except Exception as e:
                logger.warning("Error shutting down crypto queue: %s", e)

        if self._hotkey_service:
            try:
                self._hotkey_service.stop()
            except Exception as e:
                logger.warning("Error stopping hotkey service: %s", e)

        # Shut down the timeout executor pool
        try:
            from src.timeout import shutdown_timeout_executor
            shutdown_timeout_executor(wait=False)
        except Exception as e:
            logger.warning("Error shutting down timeout executor: %s", e)

        logger.info("ApplicationController shutdown complete")
