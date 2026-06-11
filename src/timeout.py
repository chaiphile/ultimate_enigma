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
_crypto_executor = ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="crypto-timeout"
)

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
            future = _crypto_executor.submit(func, *args, **kwargs)
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
    future = _crypto_executor.submit(func, *args, **kwargs)
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


def shutdown_timeout_executor(wait: bool = True):
    """Shut down the shared crypto timeout executor.

    Called during application shutdown to cleanly terminate the thread pool.

    Args:
        wait: If True, block until all pending tasks complete.
    """
    _crypto_executor.shutdown(wait=wait)
    logger.info("Crypto timeout executor shut down")
