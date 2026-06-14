"""Unit tests for controllers/application_controller.py."""

import threading
import time as _real_time_mod
import pytest
from unittest.mock import patch, MagicMock, call
from queue import Queue, Empty

# Save reference to real sleep BEFORE any patching can occur
_real_sleep = _real_time_mod.sleep

from controllers.application_controller import ApplicationController


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_root():
    root = MagicMock()
    root.after = MagicMock(side_effect=lambda ms, cb: cb() if ms == 0 else None)
    return root


@pytest.fixture
def mock_crypto_queue():
    cq = MagicMock()
    cq.start = MagicMock()
    cq.shutdown = MagicMock()
    cq.drain = MagicMock()
    return cq


@pytest.fixture
def controller(mock_root, mock_crypto_queue):
    with patch("controllers.application_controller.CryptoTaskQueue", return_value=mock_crypto_queue):
        ctrl = ApplicationController(mock_root)
        return ctrl


# ---------------------------------------------------------------------------
# Tests: start_queue_processing
# ---------------------------------------------------------------------------

class TestStartQueueProcessing:
    def test_starts_crypto_queue(self, controller, mock_crypto_queue):
        """start_queue_processing calls crypto_queue.start()."""
        controller.start_queue_processing()
        mock_crypto_queue.start.assert_called_once()

    def test_sets_is_running(self, controller):
        """start_queue_processing sets _is_running to True."""
        controller.start_queue_processing()
        assert controller._is_running is True

    def test_calls_process_queue(self, controller, mock_root):
        """start_queue_processing triggers _process_queue."""
        controller._is_running = False
        controller.start_queue_processing()
        mock_root.after.assert_called()


# ---------------------------------------------------------------------------
# Tests: enqueue
# ---------------------------------------------------------------------------

class TestEnqueue:
    def test_puts_task_on_queue(self, controller):
        """enqueue puts a callable on the internal task_queue."""
        task = MagicMock()
        controller.enqueue(task)
        assert not controller.task_queue.empty()

    def test_task_is_callable(self, controller):
        """Enqueued item can be retrieved and called."""
        task = MagicMock()
        controller.enqueue(task)
        retrieved = controller.task_queue.get_nowait()
        retrieved()
        task.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: shutdown
# ---------------------------------------------------------------------------

class TestShutdown:
    def test_shutdown_sets_is_running_false(self, controller, mock_crypto_queue):
        """shutdown sets _is_running to False."""
        controller.start_queue_processing()
        controller.shutdown()
        assert controller._is_running is False

    def test_shutdown_drains_and_shuts_down_crypto_queue(self, controller, mock_crypto_queue):
        """shutdown calls drain and shutdown on crypto_queue."""
        controller.shutdown()
        mock_crypto_queue.drain.assert_called_once_with(timeout=5.0)
        mock_crypto_queue.shutdown.assert_called_once_with(wait=False)

    def test_shutdown_with_no_crypto_queue(self, mock_root):
        """shutdown handles None crypto_queue gracefully."""
        with patch("controllers.application_controller.CryptoTaskQueue", return_value=MagicMock()):
            ctrl = ApplicationController(mock_root)
        ctrl.crypto_queue = None
        ctrl.shutdown()
        assert ctrl._is_running is False

    def test_shutdown_stops_hotkey_service(self, controller, mock_crypto_queue):
        """shutdown calls stop on _hotkey_service if present."""
        controller._hotkey_service = MagicMock()
        controller.shutdown()
        controller._hotkey_service.stop.assert_called_once()

    def test_shutdown_handles_hotkey_error(self, controller, mock_crypto_queue):
        """shutdown does not raise if hotkey service stop throws."""
        controller._hotkey_service = MagicMock()
        controller._hotkey_service.stop.side_effect = RuntimeError("fail")
        controller.shutdown()


# ---------------------------------------------------------------------------
# Tests: NTP sync loop start/stop
# ---------------------------------------------------------------------------

class TestNtpSync:
    def test_start_ntp_sync_schedules_thread(self, controller, mock_root):
        """start_ntp_sync calls root.after with delay."""
        controller.start_ntp_sync(MagicMock())
        mock_root.after.assert_called_once()

    def test_start_ntp_thread_creates_thread(self, controller):
        """_start_ntp_thread creates and starts a daemon thread."""
        enc_service = MagicMock()
        controller._start_ntp_thread(enc_service)

        assert controller._ntp_thread is not None
        assert controller._ntp_thread.daemon is True
        assert "_ntp_sync_loop" in controller._ntp_thread.name

        controller._is_running = False
        controller._ntp_thread.join(timeout=2)

    def test_start_ntp_thread_no_duplicate(self, controller):
        """_start_ntp_thread does nothing if thread already exists."""
        enc_service = MagicMock()
        controller._start_ntp_thread(enc_service)
        first_thread = controller._ntp_thread

        controller._start_ntp_thread(enc_service)
        assert controller._ntp_thread is first_thread

        controller._is_running = False
        first_thread.join(timeout=2)

    def test_ntp_sync_loop_publishes_synced(self, controller):
        """_ntp_sync_loop calls update_ntp_time on success."""
        controller._is_running = True
        enc_service = MagicMock()

        with patch("ntp_client.get_ntp_time", return_value=1700000000), \
             patch("controllers.application_controller.time.sleep", side_effect=lambda s: _real_sleep(0.05)):
            t = threading.Thread(
                target=controller._ntp_sync_loop,
                args=(enc_service,),
            )
            t.start()
            _real_sleep(0.5)
            controller._is_running = False
            t.join(timeout=3)

        enc_service.update_ntp_time.assert_called()

    def test_ntp_sync_loop_publishes_failed_on_none(self, controller):
        """_ntp_sync_loop calls update_ntp_time(None) when get_ntp_time returns None."""
        controller._is_running = True
        enc_service = MagicMock()

        with patch("ntp_client.get_ntp_time", return_value=None), \
             patch("controllers.application_controller.time.sleep", side_effect=lambda s: _real_sleep(0.05)):
            t = threading.Thread(
                target=controller._ntp_sync_loop,
                args=(enc_service,),
            )
            t.start()
            _real_sleep(0.5)
            controller._is_running = False
            t.join(timeout=3)

        enc_service.update_ntp_time.assert_called_with(None)

    def test_ntp_sync_loop_stops_when_is_running_false(self, controller):
        """_ntp_sync_loop exits when _is_running becomes False."""
        controller._is_running = True
        enc_service = MagicMock()

        def run_loop():
            controller._ntp_sync_loop(enc_service)

        with patch("ntp_client.get_ntp_time", return_value=1700000000), \
             patch("controllers.application_controller.time.sleep", side_effect=lambda s: _real_sleep(0.05)):
            t = threading.Thread(target=run_loop, daemon=True)
            t.start()
            _real_sleep(0.2)
            controller._is_running = False
            t.join(timeout=3)

        assert not t.is_alive()


# ---------------------------------------------------------------------------
# Tests: _process_queue
# ---------------------------------------------------------------------------

class TestProcessQueue:
    def test_process_queue_executes_tasks(self, controller, mock_root):
        """_process_queue drains and calls enqueued tasks."""
        task = MagicMock()
        controller.enqueue(task)
        controller._is_running = True

        controller._process_queue()
        task.assert_called_once()

    def test_process_queue_stops_when_not_running(self, controller, mock_root):
        """_process_queue does nothing when _is_running is False."""
        task = MagicMock()
        controller.enqueue(task)
        controller._is_running = False

        controller._process_queue()
        task.assert_not_called()

    def test_process_queue_schedules_next(self, controller, mock_root):
        """_process_queue schedules itself via root.after when running."""
        controller._is_running = True
        controller._process_queue()
        mock_root.after.assert_called_with(100, controller._process_queue)
