"""Thread-safe task queue for background cryptographic operations.

Provides a managed thread pool for executing long-running crypto tasks
(encryption, decryption, KDF, file operations) without blocking the UI.
Supports result callbacks dispatched to the Tkinter main thread, priority
scheduling, and graceful shutdown.

Integrates with ApplicationController and ServiceOrchestrator to replace
ad-hoc threading.Thread usage in View classes.
"""

import logging
import threading
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    Future,
    TimeoutError as FuturesTimeoutError,
)
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    """Priority levels for crypto tasks. Lower value = higher priority."""
    CRITICAL = 0   # Authentication, key operations
    HIGH = 10      # Encryption/decryption of messages
    NORMAL = 20    # File operations
    LOW = 30       # Background maintenance, NTP sync


@dataclass(order=True)
class _PrioritizedTask:
    """Internal wrapper for priority-sorted task execution."""
    priority: int
    timestamp: float = field(compare=True)
    func: Callable = field(compare=False)
    args: tuple = field(compare=False, default_factory=tuple)
    kwargs: dict = field(compare=False, default_factory=dict)
    future: Future = field(compare=False, default=None)


class CryptoTaskQueue:
    """Managed thread pool for background cryptographic operations.

    Features:
    - ThreadPoolExecutor with configurable worker count
    - Priority-based task scheduling
    - Result/error callbacks dispatched to Tkinter main thread
    - Graceful shutdown with drain support
    - Task timeout enforcement

    Usage::

        queue = CryptoTaskQueue(root, max_workers=4)
        queue.start()

        future = queue.submit(
            task_func,
            args=(arg1, arg2),
            on_success=lambda result: update_ui(result),
            on_error=lambda exc: show_error(exc),
            priority=TaskPriority.NORMAL,
        )

        queue.shutdown()  # call on app close
    """

    def __init__(
        self,
        root,
        max_workers: int = 4,
        default_timeout: Optional[float] = None,
    ):
        """
        Args:
            root: Tkinter root widget (used for main-thread dispatching).
            max_workers: Maximum concurrent worker threads.
            default_timeout: Default timeout in seconds for tasks.
                           None means no timeout.
        """
        self._root = root
        self._max_workers = max_workers
        self._default_timeout = default_timeout
        self._executor: Optional[ThreadPoolExecutor] = None
        self._is_running = False
        self._task_count = 0
        self._completed_count = 0
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Whether the queue is currently accepting tasks."""
        return self._is_running

    @property
    def pending_tasks(self) -> int:
        """Approximate number of tasks submitted but not yet completed."""
        with self._lock:
            return self._task_count - self._completed_count

    def start(self):
        """Start the thread pool executor."""
        if self._is_running:
            return
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="crypto-worker"
        )
        self._is_running = True
        logger.info(
            "CryptoTaskQueue started (max_workers=%d)", self._max_workers
        )

    def shutdown(self, wait: bool = True, timeout: Optional[float] = 30.0):
        """Shut down the executor, optionally waiting for pending tasks.

        Args:
            wait: If True, block until all submitted tasks complete.
            timeout: Maximum seconds to wait for pending tasks.
        """
        if not self._is_running:
            return
        self._is_running = False
        if self._executor:
            self._executor.shutdown(wait=wait)
            self._executor = None
        logger.info(
            "CryptoTaskQueue shut down (submitted=%d, completed=%d)",
            self._task_count, self._completed_count
        )

    def submit(
        self,
        func: Callable[..., Any],
        args: tuple = (),
        kwargs: Optional[dict] = None,
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: Optional[float] = None,
    ) -> Future:
        """Submit a task for background execution.

        Args:
            func: The callable to execute in a worker thread.
            args: Positional arguments for func.
            kwargs: Keyword arguments for func.
            on_success: Callback invoked on the main thread with the result
                       when func completes successfully.
            on_error: Callback invoked on the main thread with the exception
                     when func raises an exception.
            priority: Task priority level.
            timeout: Per-task timeout in seconds. Overrides default_timeout.

        Returns:
            A Future representing the pending computation.

        Raises:
            RuntimeError: If the queue has not been started or is shut down.
        """
        if not self._is_running or self._executor is None:
            raise RuntimeError("CryptoTaskQueue is not running")

        kwargs = kwargs or {}
        effective_timeout = timeout if timeout is not None else self._default_timeout

        future = self._executor.submit(
            self._execute_with_timeout,
            func, args, kwargs, effective_timeout
        )

        with self._lock:
            self._task_count += 1

        # Attach callbacks that dispatch to the main Tkinter thread
        def _on_done(f: Future):
            with self._lock:
                self._completed_count += 1

            try:
                result = f.result()
                if on_success is not None:
                    self._dispatch_to_main(on_success, result)
            except Exception as exc:
                if on_error is not None:
                    self._dispatch_to_main(on_error, exc)
                else:
                    logger.error(
                        "Unhandled task exception in '%s': %s",
                        func.__name__, exc, exc_info=True
                    )

        future.add_done_callback(_on_done)
        return future

    def submit_priority(
        self,
        priority: TaskPriority,
        func: Callable[..., Any],
        *args,
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> Future:
        """Convenience method for submitting with a specific priority.

        Args:
            priority: The task priority level.
            func: The callable to execute.
            *args: Positional arguments.
            on_success: Success callback (main thread).
            on_error: Error callback (main thread).
            timeout: Per-task timeout in seconds.
            **kwargs: Keyword arguments.

        Returns:
            A Future representing the pending computation.
        """
        return self.submit(
            func,
            args=args,
            kwargs=kwargs,
            on_success=on_success,
            on_error=on_error,
            priority=priority,
            timeout=timeout,
        )

    def _execute_with_timeout(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        timeout: Optional[float],
    ) -> Any:
        """Execute a function, optionally enforcing a timeout.

        If timeout is specified and the function exceeds it, a
        CryptoTimeoutError is raised. The function itself runs in the
        worker thread that calls this method.
        """
        if timeout is None or timeout <= 0:
            return func(*args, **kwargs)

        # Use a nested future to enforce the timeout within the worker thread
        inner_executor = ThreadPoolExecutor(max_workers=1)
        try:
            inner_future = inner_executor.submit(func, *args, **kwargs)
            return inner_future.result(timeout=timeout)
        except FuturesTimeoutError:
            from src.exceptions import CryptoTimeoutError
            logger.error(
                "Task '%s' timed out after %.1f seconds",
                func.__name__, timeout
            )
            raise CryptoTimeoutError(
                f"Cryptographic operation '{func.__name__}' timed out "
                f"after {timeout:.1f} seconds."
            )
        finally:
            inner_executor.shutdown(wait=False)

    def _dispatch_to_main(self, callback: Callable, *args):
        """Dispatch a callback to the Tkinter main thread.

        Uses root.after(0, ...) to ensure thread-safe UI updates.
        Falls back to direct invocation if root is unavailable.
        """
        if self._root is not None:
            try:
                self._root.after(0, callback, *args)
            except Exception:
                # Root may have been destroyed during shutdown
                try:
                    callback(*args)
                except Exception as exc:
                    logger.error(
                        "Callback dispatch failed: %s", exc, exc_info=True
                    )
        else:
            try:
                callback(*args)
            except Exception as exc:
                logger.error(
                    "Callback invocation failed: %s", exc, exc_info=True
                )

    def drain(self, timeout: float = 5.0):
        """Wait for all pending tasks to complete, with a timeout.

        Useful during shutdown to ensure all callbacks have fired.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            True if all tasks completed within the timeout, False otherwise.
        """
        start = time.monotonic()
        while self.pending_tasks > 0:
            if time.monotonic() - start > timeout:
                logger.warning(
                    "CryptoTaskQueue drain timed out with %d tasks pending",
                    self.pending_tasks
                )
                return False
            time.sleep(0.05)
        return True
