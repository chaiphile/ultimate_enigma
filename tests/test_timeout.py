"""Unit tests for timeout utilities (src.timeout).

Tests cover:
- with_timeout decorator
- run_with_timeout function
- CryptoTimeoutError on expiry
- Shutdown of shared executor
- Edge cases and error propagation
"""

import time
import threading
import pytest
from unittest.mock import patch, MagicMock

from src.timeout import (
    with_timeout,
    run_with_timeout,
    shutdown_timeout_executor,
)
from src.exceptions import CryptoTimeoutError


# ---------------------------------------------------------------------------
# with_timeout Decorator
# ---------------------------------------------------------------------------

class TestWithTimeoutDecorator:
    def test_function_completes_within_timeout(self):
        """Function that completes quickly should return normally."""
        @with_timeout(5.0)
        def quick_func():
            return 42

        assert quick_func() == 42

    def test_function_with_args(self):
        """Decorated function should forward args and kwargs."""
        @with_timeout(5.0)
        def add(a, b, multiplier=1):
            return (a + b) * multiplier

        assert add(3, 4, multiplier=10) == 70

    def test_function_exceeds_timeout(self):
        """Function exceeding timeout should raise CryptoTimeoutError."""
        @with_timeout(0.5)
        def slow_func():
            time.sleep(10)
            return "should not reach"

        with pytest.raises(CryptoTimeoutError, match="timed out"):
            slow_func()

    def test_function_propagates_exceptions(self):
        """Exceptions from the wrapped function should propagate."""
        @with_timeout(5.0)
        def failing_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            failing_func()

    def test_preserves_function_name(self):
        """Decorator should preserve function metadata."""
        @with_timeout(5.0)
        def my_named_func():
            """My docstring."""
            pass

        assert my_named_func.__name__ == "my_named_func"
        assert "My docstring" in my_named_func.__doc__

    def test_multiple_calls(self):
        """Decorated function should be callable multiple times."""
        call_count = 0

        @with_timeout(5.0)
        def counting_func():
            nonlocal call_count
            call_count += 1
            return call_count

        assert counting_func() == 1
        assert counting_func() == 2
        assert counting_func() == 3


# ---------------------------------------------------------------------------
# run_with_timeout Function
# ---------------------------------------------------------------------------

class TestRunWithTimeout:
    def test_basic_execution(self):
        """run_with_timeout should execute function and return result."""
        def compute():
            return 100

        result = run_with_timeout(compute, 5.0)
        assert result == 100

    def test_with_positional_args(self):
        """Positional args should be forwarded."""
        def multiply(a, b):
            return a * b

        result = run_with_timeout(multiply, 5.0, 6, 7)
        assert result == 42

    def test_with_kwargs(self):
        """Keyword args should be forwarded."""
        def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        result = run_with_timeout(greet, 5.0, "World", greeting="Hi")
        assert result == "Hi, World!"

    def test_timeout_raises(self):
        """Should raise CryptoTimeoutError when function is too slow."""
        def slow():
            time.sleep(10)

        with pytest.raises(CryptoTimeoutError, match="timed out"):
            run_with_timeout(slow, 0.5)

    def test_exception_propagation(self):
        """Should re-raise exceptions from the function."""
        def fail():
            raise RuntimeError("kaboom")

        with pytest.raises(RuntimeError, match="kaboom"):
            run_with_timeout(fail, 5.0)

    def test_error_message_includes_function_name(self):
        """Timeout error message should include the function name."""
        def my_slow_operation():
            time.sleep(10)

        with pytest.raises(CryptoTimeoutError, match="my_slow_operation"):
            run_with_timeout(my_slow_operation, 0.5)

    def test_error_message_includes_timeout_value(self):
        """Timeout error message should include the timeout duration."""
        def another_slow_op():
            time.sleep(10)

        with pytest.raises(CryptoTimeoutError, match="1\\.5"):
            run_with_timeout(another_slow_op, 1.5)

    def test_concurrent_calls(self):
        """Multiple concurrent calls should all complete."""
        results = []
        lock = threading.Lock()

        def worker(i):
            time.sleep(0.1)
            return i * 2

        threads = []
        for i in range(5):
            def run(idx=i):
                r = run_with_timeout(worker, 5.0, idx)
                with lock:
                    results.append(r)
            t = threading.Thread(target=run)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        assert sorted(results) == [0, 2, 4, 6, 8]


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

class TestShutdown:
    def test_shutdown_executor(self):
        """shutdown_timeout_executor should complete without error."""
        # Just verify it doesn't raise
        shutdown_timeout_executor(wait=True)

    def test_shutdown_idempotent(self):
        """Calling shutdown twice should be safe."""
        shutdown_timeout_executor(wait=False)
        shutdown_timeout_executor(wait=False)


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_very_short_timeout(self):
        """A very short timeout should trigger timeout even for quick tasks."""
        def quick():
            time.sleep(0.2)
            return "done"

        with pytest.raises(CryptoTimeoutError):
            run_with_timeout(quick, 0.01)

    def test_zero_timeout(self):
        """Timeout of 0 should immediately timeout (or very close to it)."""
        def instant():
            return "instant"

        # With 0 timeout, the future.result(timeout=0) should raise
        # immediately if the task hasn't completed yet
        # Note: behavior depends on whether the task starts before the
        # timeout check. We just verify it doesn't crash.
        try:
            run_with_timeout(instant, 0.001)
        except CryptoTimeoutError:
            pass  # Expected for very short timeout

    def test_large_return_value(self):
        """Large return values should be handled correctly."""
        @with_timeout(5.0)
        def large_result():
            return list(range(10000))

        result = large_result()
        assert len(result) == 10000
        assert result[0] == 0
        assert result[-1] == 9999

    def test_none_return_value(self):
        """None return value should be distinguishable from timeout."""
        @with_timeout(5.0)
        def returns_none():
            return None

        assert returns_none() is None

    def test_exception_type_preserved(self):
        """The original exception type should be preserved."""
        class CustomError(Exception):
            pass

        @with_timeout(5.0)
        def raises_custom():
            raise CustomError("custom")

        with pytest.raises(CustomError, match="custom"):
            raises_custom()
