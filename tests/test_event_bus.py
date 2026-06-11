"""Tests for the EventBus publish/subscribe system."""

import pytest
from services.event_bus import EventBus, Events


@pytest.fixture
def bus():
    """Fresh EventBus instance for each test."""
    bus = EventBus()
    bus.clear()
    yield bus
    bus.clear()


class TestEventBusBasics:
    """Core pub/sub functionality."""

    def test_subscribe_and_publish(self, bus):
        received = []
        handler = lambda **kw: received.append(kw)

        bus.subscribe("test_event", handler)
        bus.publish("test_event", foo="bar")

        assert len(received) == 1
        assert received[0]["foo"] == "bar"

    def test_multiple_subscribers(self, bus):
        results_a = []
        results_b = []
        bus.subscribe("evt", lambda **kw: results_a.append(kw))
        bus.subscribe("evt", lambda **kw: results_b.append(kw))

        bus.publish("evt", value=42)

        assert len(results_a) == 1
        assert len(results_b) == 1
        assert results_a[0]["value"] == 42

    def test_no_duplicate_subscription(self, bus):
        count = []
        handler = lambda **kw: count.append(1)

        bus.subscribe("evt", handler)
        bus.subscribe("evt", handler)  # duplicate
        bus.publish("evt")

        assert len(count) == 1

    def test_unsubscribe(self, bus):
        received = []
        handler = lambda **kw: received.append(kw)

        bus.subscribe("evt", handler)
        bus.unsubscribe("evt", handler)
        bus.publish("evt")

        assert len(received) == 0

    def test_unsubscribe_all(self, bus):
        received = []
        handler = lambda **kw: received.append(kw)

        bus.subscribe("evt_a", handler)
        bus.subscribe("evt_b", handler)
        bus.unsubscribe_all(handler)

        bus.publish("evt_a")
        bus.publish("evt_b")

        assert len(received) == 0

    def test_publish_no_subscribers(self, bus):
        # Should not raise
        bus.publish("nonexistent_event", foo="bar")

    def test_clear(self, bus):
        handler = lambda **kw: None
        bus.subscribe("evt", handler)
        assert bus.subscriber_count("evt") == 1

        bus.clear()
        assert bus.subscriber_count("evt") == 0
        assert bus.subscriber_count() == 0


class TestEventBusErrorHandling:
    """Handler errors should not crash the bus or prevent other handlers."""

    def test_handler_exception_does_not_stop_others(self, bus):
        results = []

        def bad_handler(**kw):
            raise ValueError("boom")

        def good_handler(**kw):
            results.append(kw)

        bus.subscribe("evt", bad_handler)
        bus.subscribe("evt", good_handler)

        bus.publish("evt", value=1)

        assert len(results) == 1


class TestEventConstants:
    """Events class should define all expected event types."""

    def test_auth_events_exist(self):
        assert Events.UNLOCK_REQUESTED
        assert Events.EMERGENCY_LOCK
        assert Events.UNLOCKED
        assert Events.LOCKED
        assert Events.KEYS_WIPED
        assert Events.KEYS_LOADED
        assert Events.PASSWORD_CHANGED
        assert Events.DURESS_MODE_ENTERED

    def test_totp_events_exist(self):
        assert Events.TOTP_SETUP_COMPLETE
        assert Events.TOTP_VERIFIED
        assert Events.TOTP_CHANGED

    def test_service_events_exist(self):
        assert Events.SERVICES_REBUILT
        assert Events.NTP_SYNCED
        assert Events.NTP_SYNC_FAILED

    def test_data_events_exist(self):
        assert Events.FRIEND_LIST_CHANGED
        assert Events.FRIEND_ADDED
        assert Events.FRIEND_REMOVED
        assert Events.RATCHET_INITIALIZED
        assert Events.RATCHET_RESET

    def test_lifecycle_events_exist(self):
        assert Events.APP_STARTING
        assert Events.APP_SHUTDOWN


class TestEventBusSingleton:
    """Global singleton should return the same instance."""

    def test_singleton_identity(self):
        from services.event_bus import event_bus as global_bus
        bus2 = EventBus()
        assert global_bus is bus2


class TestSubscriberCount:
    """subscriber_count should report accurate counts."""

    def test_count_single_event(self, bus):
        bus.subscribe("evt", lambda **kw: None)
        bus.subscribe("evt", lambda **kw: None)
        assert bus.subscriber_count("evt") == 2

    def test_count_all_events(self, bus):
        bus.subscribe("a", lambda **kw: None)
        bus.subscribe("b", lambda **kw: None)
        bus.subscribe("b", lambda **kw: None)
        assert bus.subscriber_count() == 3
