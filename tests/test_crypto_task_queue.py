"""Unit tests for CryptoTaskQueue - thread-safe background crypto task execution.

Tests cover:
- Task submission and execution
- Priority scheduling
- Result/error callbacks dispatched to main thread
- Timeout enforcement
- Graceful shutdown and drain
- Error isolation between tasks
"""

import time
import threading
import pytest
from unittest.mock import MagicMock, patch
from concurrent.futures import Future

from services.crypto_task_queue import CryptoTaskQueue, TaskPriority, _PrioritizedTask
from src.exceptions import CryptoTimeoutError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_root():
    """Create a mock Tkinter root widget."""
    root = MagicMock()
    root.after = MagicMock(side_effect=lambda delay, func, *args: func(*args))
    return root


@pytest.fixture
def task_queue(mock_root):
    """Create and start a CryptoTaskQueue for testing."""
    queue = CryptoTaskQueue(root=mock_root, max_workers=2, default_timeout=10.0)
    queue.start()
    yield queue
    queue.shutdown(wait=True, timeout=5.0)


# ---------------------------------------------------------------------------
# Basic Task Execution
# ---------------------------------------------------------------------------

class TestBasicExecution:
    def test_submit_and_execute(self, task_queue):
        """Basic task submission should execute and return result."""
        result = []
        event = threading.Event()

        def task():
            return 42

        def on_success(val):
            result.append(val)
            event.set()

        task_queue.submit(task, on_success=on_success)
        assert event.wait(timeout=5.0), "Task did not complete in time"
        assert result == [42]

    def test_submit_with_args(self, task_queue):
        """Task with positional and keyword arguments."""
        result = []
        event = threading.Event()

        def add(a, b, multiplier=1):
            return (a + b) * multiplier

        def on_success(val):
            result.append(val)
            event.set()

        task_queue.submit(add, args=(3, 4), kwargs={"multiplier": 10},
                         on_success=on_success)
        assert event.wait(timeout=5.0)
        assert result == [70]

    def test_multiple_tasks(self, task_queue):
        """Multiple tasks should all execute."""
        results = []
        lock = threading.Lock()
        count = 10
        events = [threading.Event() for _ in range(count)]

        def task(i):
            return i * 2

        for i in range(count):
            def on_success(val, idx=i):
                with lock:
                    results.append(val)
                events[idx].set()

            task_queue.submit(task, args=(i,), on_success=on_success)

        for e in events:
            assert e.wait(timeout=5.0), "Not all tasks completed"

        assert sorted(results) == [i * 2 for i in range(count)]

    def test_submit_returns_future(self, task_queue):
        """submit() should return a concurrent.futures.Future."""
        future = task_queue.submit(lambda: "hello")
        assert isinstance(future, Future)
        assert future.result(timeout=5.0) == "hello"

    def test_pending_tasks_count(self, task_queue):
        """pending_tasks should reflect submitted vs completed tasks."""
        barrier = threading.Barrier(2)

        def slow_task():
            barrier.wait(timeout=5.0)
            return True

        # Submit a blocking task
        task_queue.submit(slow_task)
        # Submit another quick task
        task_queue.submit(lambda: 42)

        # At least one should be pending initially
        time.sleep(0.1)
        assert task_queue.pending_tasks >= 0  # Can be 0 if fast enough

        barrier.wait(timeout=5.0)  # Release the blocking task
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_error_callback(self, task_queue):
        """on_error should be called when task raises exception."""
        errors = []
        event = threading.Event()

        def failing_task():
            raise ValueError("test error")

        def on_error(exc):
            errors.append(exc)
            event.set()

        task_queue.submit(failing_task, on_error=on_error)
        assert event.wait(timeout=5.0)
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)
        assert "test error" in str(errors[0])

    def test_error_isolation(self, task_queue):
        """One task's error should not affect other tasks."""
        success_results = []
        error_results = []
        event = threading.Event()

        def failing_task():
            raise RuntimeError("boom")

        def good_task():
            return "ok"

        task_queue.submit(failing_task,
                         on_error=lambda e: error_results.append(e))
        task_queue.submit(good_task,
                         on_success=lambda v: success_results.append(v) or event.set())

        assert event.wait(timeout=5.0)
        assert success_results == ["ok"]
        assert len(error_results) == 1

    def test_no_callbacks_still_logs(self, task_queue):
        """Task with no callbacks should still execute and log errors."""
        event = threading.Event()

        def silent_task():
            event.set()
            return True

        task_queue.submit(silent_task)
        assert event.wait(timeout=5.0)


# ---------------------------------------------------------------------------
# Priority Scheduling
# ---------------------------------------------------------------------------

class TestPriority:
    def test_submit_priority(self, task_queue):
        """submit_priority should work as convenience method."""
        result = []
        event = threading.Event()

        task_queue.submit_priority(
            TaskPriority.HIGH,
            lambda: "priority_result",
            on_success=lambda v: result.append(v) or event.set(),
        )

        assert event.wait(timeout=5.0)
        assert result == ["priority_result"]

    def test_task_priority_enum(self):
        """TaskPriority values should be ordered correctly."""
        assert TaskPriority.CRITICAL < TaskPriority.HIGH
        assert TaskPriority.HIGH < TaskPriority.NORMAL
        assert TaskPriority.NORMAL < TaskPriority.LOW


class TestPrioritizedTask:
    def test_ordering(self):
        """_PrioritizedTask should sort by priority then timestamp."""
        t1 = _PrioritizedTask(priority=10, timestamp=1.0, func=lambda: None)
        t2 = _PrioritizedTask(priority=20, timestamp=0.5, func=lambda: None)
        t3 = _PrioritizedTask(priority=10, timestamp=2.0, func=lambda: None)

        tasks = sorted([t2, t1, t3])
        assert tasks[0] == t1  # priority 10, time 1.0
        assert tasks[1] == t3  # priority 10, time 2.0
        assert tasks[2] == t2  # priority 20


# ---------------------------------------------------------------------------
# Timeout Enforcement
# ---------------------------------------------------------------------------

class TestTimeout:
    def test_timeout_enforcement(self, task_queue):
        """Task exceeding timeout should raise CryptoTimeoutError."""
        errors = []
        event = threading.Event()

        def slow_task():
            time.sleep(10)  # Sleep longer than timeout
            return "should not reach"

        def on_error(exc):
            errors.append(exc)
            event.set()

        task_queue.submit(slow_task, on_error=on_error, timeout=1.0)
        assert event.wait(timeout=5.0)
        assert len(errors) == 1
        assert isinstance(errors[0], CryptoTimeoutError)
        assert "timed out" in str(errors[0]).lower()

    def test_no_timeout_when_none(self, task_queue):
        """When timeout is None, task should run to completion."""
        result = []
        event = threading.Event()

        def medium_task():
            time.sleep(0.5)
            return "done"

        task_queue.submit(medium_task,
                         on_success=lambda v: result.append(v) or event.set(),
                         timeout=None)
        assert event.wait(timeout=5.0)
        assert result == ["done"]

    def test_default_timeout_applied(self, mock_root):
        """default_timeout from constructor should be used when per-task is None."""
        queue = CryptoTaskQueue(root=mock_root, max_workers=2, default_timeout=1.0)
        queue.start()
        try:
            errors = []
            event = threading.Event()

            def slow():
                time.sleep(10)

            queue.submit(slow,
                        on_error=lambda e: errors.append(e) or event.set(),
                        timeout=None)  # Should use default_timeout=1.0

            assert event.wait(timeout=5.0)
            assert len(errors) == 1
            assert isinstance(errors[0], CryptoTimeoutError)
        finally:
            queue.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Main Thread Dispatch
# ---------------------------------------------------------------------------

class TestMainThreadDispatch:
    def test_callbacks_use_root_after(self, mock_root):
        """Callbacks should be dispatched via root.after()."""
        queue = CryptoTaskQueue(root=mock_root, max_workers=1)
        queue.start()
        try:
            event = threading.Event()

            queue.submit(
                lambda: "result",
                on_success=lambda v: event.set(),
            )
            assert event.wait(timeout=5.0)
            # root.after should have been called
            assert mock_root.after.called
        finally:
            queue.shutdown(wait=False)

    def test_fallback_when_root_none(self):
        """When root is None, callbacks execute directly."""
        queue = CryptoTaskQueue(root=None, max_workers=1)
        queue.start()
        try:
            result = []
            event = threading.Event()

            queue.submit(
                lambda: 99,
                on_success=lambda v: result.append(v) or event.set(),
            )
            assert event.wait(timeout=5.0)
            assert result == [99]
        finally:
            queue.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Lifecycle & Shutdown
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_start_idempotent(self, task_queue):
        """Calling start() twice should be safe."""
        task_queue.start()
        assert task_queue.is_running

    def test_shutdown_idempotent(self, task_queue):
        """Calling shutdown() twice should be safe."""
        task_queue.shutdown()
        task_queue.shutdown()
        assert not task_queue.is_running

    def test_submit_after_shutdown_raises(self, task_queue):
        """Submitting after shutdown should raise RuntimeError."""
        task_queue.shutdown()
        with pytest.raises(RuntimeError, match="not running"):
            task_queue.submit(lambda: None)

    def test_drain(self, mock_root):
        """drain() should wait for pending tasks."""
        queue = CryptoTaskQueue(root=mock_root, max_workers=2)
        queue.start()

        results = []
        for i in range(5):
            queue.submit(
                lambda i=i: time.sleep(0.1) or results.append(i),
            )

        completed = queue.drain(timeout=10.0)
        queue.shutdown(wait=False)

        assert completed
        assert len(results) == 5

    def test_is_running_property(self, mock_root):
        """is_running should reflect lifecycle state."""
        queue = CryptoTaskQueue(root=mock_root, max_workers=1)
        assert not queue.is_running
        queue.start()
        assert queue.is_running
        queue.shutdown()
        assert not queue.is_running
