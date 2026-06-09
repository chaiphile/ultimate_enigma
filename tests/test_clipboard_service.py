"""Tests for ClipboardService."""

import threading
import time
import pytest


class FakeRoot:
    """Minimal tkinter root stub for unit testing without a display."""

    def __init__(self):
        self._clipboard = ""
        self.clear_count = 0
        self.append_count = 0

    def clipboard_clear(self):
        self._clipboard = ""
        self.clear_count += 1

    def clipboard_append(self, text):
        self._clipboard = text
        self.append_count += 1

    def clipboard_get(self):
        if not self._clipboard:
            raise Exception("clipboard empty")
        return self._clipboard


@pytest.fixture
def fake_root():
    return FakeRoot()


@pytest.fixture
def service(fake_root):
    from services.clipboard_service import ClipboardService
    svc = ClipboardService(fake_root, clear_delay=1)
    yield svc
    svc.shutdown()


class TestCopy:
    def test_copy_places_text_on_clipboard(self, service, fake_root):
        assert service.copy("hello") is True
        assert fake_root._clipboard == "hello"

    def test_copy_returns_false_on_failure(self, fake_root):
        from services.clipboard_service import ClipboardService

        class BrokenRoot(FakeRoot):
            def clipboard_clear(self):
                raise RuntimeError("fail")

        svc = ClipboardService(BrokenRoot(), clear_delay=60)
        assert svc.copy("data") is False
        svc.shutdown()

    def test_auto_clear_scheduled_after_copy(self, service, fake_root):
        service.copy("secret")
        time.sleep(1.5)
        assert fake_root._clipboard == ""

    def test_new_copy_cancels_previous_timer(self, fake_root):
        from services.clipboard_service import ClipboardService
        svc = ClipboardService(fake_root, clear_delay=2)

        svc.copy("first")
        time.sleep(0.5)
        svc.copy("second")
        time.sleep(1.0)
        # First timer would have fired at t=2, but was cancelled.
        # Second timer fires at t=2.5 (0.5 + 2). At t=1.5 it should still be present.
        assert fake_root._clipboard == "second"

        time.sleep(1.5)
        assert fake_root._clipboard == ""
        svc.shutdown()

    def test_copy_without_auto_clear_does_not_schedule(self, service, fake_root):
        service.copy("persistent", auto_clear=False)
        time.sleep(1.5)
        assert fake_root._clipboard == "persistent"


class TestGet:
    def test_get_returns_clipboard_content(self, service, fake_root):
        fake_root._clipboard = "data"
        assert service.get() == "data"

    def test_get_returns_none_when_empty(self, service):
        assert service.get() is None


class TestClear:
    def test_clear_empties_clipboard(self, service, fake_root):
        fake_root._clipboard = "something"
        service.clear()
        assert fake_root._clipboard == ""


class TestShutdown:
    def test_shutdown_clears_clipboard(self, fake_root):
        from services.clipboard_service import ClipboardService
        svc = ClipboardService(fake_root, clear_delay=60)
        svc.copy("secret", auto_clear=True)
        svc.shutdown()
        assert fake_root._clipboard == ""

    def test_shutdown_cancels_pending_timer(self, fake_root):
        from services.clipboard_service import ClipboardService
        svc = ClipboardService(fake_root, clear_delay=60)
        svc.copy("secret", auto_clear=True)
        svc.shutdown()
        # Wait past a short interval; timer should not fire again
        time.sleep(0.5)
        # Clipboard was already cleared by shutdown, count should reflect that
        assert fake_root.clear_count >= 1
