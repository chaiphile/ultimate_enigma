"""Timeout utilities for cryptographic operations.

Provides decorators and context managers for enforcing time limits on
long-running crypto operations (PQC encapsulation, Argon2id KDF, large
file encryption). Uses concurrent.futures to run operations in a
separate thread and enforce deadlines.
"""

import logging
import functools
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Callable, Optional, TypeVar

from src.exceptions import CryptoTimeoutError

logger = logging.getLogger(__name__)

# Shared executor for timeout-wrapped operations.
# Uses a small pool since crypto ops are CPU-bound and we want to limit
# concurrent heavy operations to avoid resource exhaustion.
_crypto_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.RLock()  # Use RLock to allow reentrant locking
_executor_shutdown = False


def _get_executor() -> ThreadPoolExecutor:
    """Get or create the shared crypto timeout executor.
    
    Lazily creates the executor if it doesn't exist or has been shut down.
    This ensures tests can shutdown and recreate the executor safely.
    
    Note: Does NOT acquire the lock - caller must hold _executor_lock if
    atomic get-and-submit is needed to avoid race conditions with shutdown.
    """
    global _crypto_executor, _executor_shutdown
    if _crypto_executor is None or _executor_shutdown:
        _crypto_executor = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="crypto-timeout"
        )
        _executor_shutdown = False
    return _crypto_executor

T = TypeVar('T')


def with_timeout(timeout_seconds: float):
    """Decorator that enforces a time limit on a function call.

    The decorated function runs in a thread pool. If it does not complete
    within `timeout_seconds`, a CryptoTimeoutError is raised.

    Args:
        timeout_seconds: Maximum seconds the function is allowed to run.

    Returns:
        A decorator that wraps the function with timeout enforcement.

    Example::

        @with_timeout(30.0)
        def heavy_kdf(password: str) -> bytes:
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # Hold lock during get+submit to avoid race with shutdown
            with _executor_lock:
                executor = _get_executor()
                future = executor.submit(func, *args, **kwargs)
            try:
                return future.result(timeout=timeout_seconds)
            except FuturesTimeoutError:
                logger.error(
                    "Operation '%s' timed out after %.1f seconds",
                    func.__name__, timeout_seconds
                )
                raise CryptoTimeoutError(
                    f"Cryptographic operation '{func.__name__}' timed out "
                    f"after {timeout_seconds:.1f} seconds."
                )
        return wrapper
    return decorator


def run_with_timeout(
    func: Callable[..., T],
    timeout_seconds: float,
    *args,
    **kwargs
) -> T:
    """Run a function with a timeout, raising CryptoTimeoutError on expiry.

    This is the imperative (non-decorator) form of `with_timeout`.

    Args:
        func: The callable to execute.
        timeout_seconds: Maximum seconds allowed.
        *args, **kwargs: Arguments forwarded to `func`.

    Returns:
        The return value of `func`.

    Raises:
        CryptoTimeoutError: If the function does not complete in time.
        Exception: Any exception raised by `func` is re-raised.
    """
    # Hold lock during get+submit to avoid race with shutdown
    with _executor_lock:
        executor = _get_executor()
        future = executor.submit(func, *args, **kwargs)
    try:
        return future.result(timeout=timeout_seconds)
    except FuturesTimeoutError:
        logger.error(
            "Operation '%s' timed out after %.1f seconds",
            getattr(func, '__name__', repr(func)), timeout_seconds
        )
        raise CryptoTimeoutError(
            f"Cryptographic operation '{getattr(func, '__name__', repr(func))}' timed out "
            f"after {timeout_seconds:.1f} seconds."
        )


def shutdown_timeout_executor(wait: bool = True):
    """Shut down the shared crypto timeout executor.

    Called during application shutdown to cleanly terminate the thread pool.

    Args:
        wait: If True, block until all pending tasks complete.
    """
    global _crypto_executor, _executor_shutdown
    with _executor_lock:
        if _crypto_executor is not None:
            _crypto_executor.shutdown(wait=wait)
            _crypto_executor = None
            _executor_shutdown = True
    logger.info("Crypto timeout executor shut down")
