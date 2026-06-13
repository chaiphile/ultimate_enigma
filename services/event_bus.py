"""Event bus for cross-component communication.

Implements a thread-safe publish/subscribe pattern to decouple Views from
Controllers. Components publish events without knowing who subscribes,
and subscribers react to events without knowing who published them.

Usage:
    from services.event_bus import event_bus, Events

    # Subscribe
    event_bus.subscribe(Events.UNLOCK_REQUESTED, my_handler)

    # Publish
    event_bus.publish(Events.UNLOCK_REQUESTED, source="lock_screen")

    # Unsubscribe
    event_bus.unsubscribe(Events.UNLOCK_REQUESTED, my_handler)
"""

import logging
import threading
from collections import defaultdict
from typing import Callable, Any

logger = logging.getLogger(__name__)


class Events:
    """Event type constants for the application."""

    # Authentication & Lock events
    UNLOCK_REQUESTED = "unlock_requested"
    EMERGENCY_LOCK = "emergency_lock"
    UNLOCKED = "unlocked"
    LOCKED = "locked"

    # Key & credential events
    KEYS_WIPED = "keys_wiped"
    KEYS_LOADED = "keys_loaded"
    PASSWORD_CHANGED = "password_changed"
    DURESS_MODE_ENTERED = "duress_mode_entered"

    # TOTP events
    TOTP_SETUP_COMPLETE = "totp_setup_complete"
    TOTP_VERIFIED = "totp_verified"
    TOTP_CHANGED = "totp_changed"

    # Service events
    SERVICES_REBUILT = "services_rebuilt"
    NTP_SYNCED = "ntp_synced"
    NTP_SYNC_FAILED = "ntp_sync_failed"

    # Data events
    FRIEND_LIST_CHANGED = "friend_list_changed"
    FRIEND_ADDED = "friend_added"
    FRIEND_REMOVED = "friend_removed"
    RATCHET_INITIALIZED = "ratchet_initialized"
    RATCHET_RESET = "ratchet_reset"

    # Application lifecycle
    APP_STARTING = "app_starting"
    APP_SHUTDOWN = "app_shutdown"

    # Background agent events
    BACKUP_REMINDER = "backup_reminder"
    BACKUP_COMPLETED = "backup_completed"
    RATCHET_LOCKS_CLEANED = "ratchet_locks_cleaned"
    RATCHET_DEADLOCK_DETECTED = "ratchet_deadlock_detected"
    RATCHET_LOCK_STATS = "ratchet_lock_stats"
    SYSTEM_STATUS = "system_status"
    SYSTEM_HEALTH_OK = "system_health_ok"
    SYSTEM_HEALTH_DEGRADED = "system_health_degraded"
    KEY_INFO = "key_info"
    KEY_FINGERPRINT = "key_fingerprint"


class EventBus:
    """Thread-safe publish/subscribe event bus.

    Supports both synchronous and thread-safe (Tkinter mainloop-aware) dispatch.
    Handlers registered with `thread_safe=True` will be dispatched via the
    Tkinter `after()` mechanism when a root widget is configured.
    """

    _instance = None
    _instance_lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern to ensure one global event bus."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._subscribers: dict[str, list[dict]] = defaultdict(list)
        self._lock = threading.RLock()
        self._root = None  # Tkinter root for thread-safe dispatch
        self._initialized = True
        logger.debug("EventBus initialized")

    def set_root(self, root):
        """Configure the Tkinter root for thread-safe event dispatch.

        When set, events published from background threads will be
        dispatched on the main thread via root.after(0, handler).
        """
        self._root = root
        logger.debug("EventBus root widget configured")

    def subscribe(self, event: str, handler: Callable, thread_safe: bool = False):
        """Register a handler for an event type.

        Args:
            event: Event type string (use Events constants).
            handler: Callable to invoke when event is published.
                     Receives keyword arguments from publish().
            thread_safe: If True, handler will be dispatched on the
                        main thread (requires root to be configured).
        """
        with self._lock:
            # Prevent duplicate subscriptions
            for entry in self._subscribers[event]:
                if entry["handler"] is handler:
                    logger.debug("Handler already subscribed to %s", event)
                    return
            self._subscribers[event].append({
                "handler": handler,
                "thread_safe": thread_safe,
            })
            logger.debug("Subscribed to %s: %s", event, handler.__qualname__)

    def unsubscribe(self, event: str, handler: Callable):
        """Remove a handler from an event type.

        Args:
            event: Event type string.
            handler: The handler callable to remove.
        """
        with self._lock:
            self._subscribers[event] = [
                entry for entry in self._subscribers[event]
                if entry["handler"] is not handler
            ]
            logger.debug("Unsubscribed from %s: %s", event, handler.__qualname__)

    def unsubscribe_all(self, handler: Callable):
        """Remove a handler from all event types.

        Useful during component teardown/cleanup.

        Args:
            handler: The handler callable to remove from all events.
        """
        with self._lock:
            for event in list(self._subscribers.keys()):
                self._subscribers[event] = [
                    entry for entry in self._subscribers[event]
                    if entry["handler"] is not handler
                ]

    def publish(self, event: str, **kwargs: Any):
        """Publish an event to all subscribers.

        Args:
            event: Event type string (use Events constants).
            **kwargs: Arbitrary data passed to each handler as keyword args.
        """
        with self._lock:
            entries = list(self._subscribers.get(event, []))

        if not entries:
            logger.debug("Event %s published (no subscribers)", event)
            return

        logger.debug("Event %s published to %d subscriber(s): %s",
                     event, len(entries), kwargs)

        for entry in entries:
            handler = entry["handler"]
            use_thread_safe = entry["thread_safe"]

            try:
                if use_thread_safe and self._root is not None:
                    # Dispatch on main thread via Tkinter event loop
                    self._root.after(0, lambda h=handler, kw=kwargs: h(**kw))
                else:
                    handler(**kwargs)
            except Exception as e:
                logger.error("Error in event handler %s for %s: %s",
                            handler.__qualname__, event, e, exc_info=True)

    def clear(self):
        """Remove all subscriptions. Useful for testing or full reset."""
        with self._lock:
            self._subscribers.clear()
            logger.debug("EventBus cleared")

    def subscriber_count(self, event: str = None) -> int:
        """Return the number of subscribers for an event or all events.

        Args:
            event: If provided, count subscribers for this event only.
                  If None, count total subscribers across all events.
        """
        with self._lock:
            if event:
                return len(self._subscribers.get(event, []))
            return sum(len(v) for v in self._subscribers.values())


# Global singleton instance
event_bus = EventBus()
