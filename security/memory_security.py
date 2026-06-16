"""
Memory security utilities for locking sensitive data into physical RAM.

Provides functions to lock memory pages to prevent swapping to disk,
and raise process limits for memory locking.
"""

import sys
import ctypes
import ctypes.util
from typing import Optional

if sys.platform == "win32":
    import ctypes.wintypes
    from ctypes import windll
else:
    import resource

PAGE_SIZE = 4096


def _win32_error_str() -> str:
    """Format the last Windows error as a human-readable string."""
    err = windll.kernel32.GetLastError()
    if not err:
        return "Unknown error"
    buf = ctypes.create_string_buffer(256)
    windll.kernel32.FormatMessageA(
        0x00000100 | 0x00000200,  # FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
        None,
        err,
        0,
        buf,
        256,
        None,
    )
    return f"Error {err}: {buf.value.decode('utf-8', errors='replace').strip()}"


def mlock_memory(data: bytearray) -> bool:
    """Lock memory pages containing `data` to prevent swapping to disk.

    The memory region is page-aligned before locking. Returns True on success,
    False on failure (does not raise).
    """
    if not data:
        return False

    # Get stable pointer to the buffer
    c_array = (ctypes.c_char * len(data)).from_buffer(data)
    addr = ctypes.addressof(c_array)

    # Page-align the start address (down)
    start = addr & ~(PAGE_SIZE - 1)
    # Page-align the end address (up)
    end = (addr + len(data) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    size = end - start

    try:
        if sys.platform == "win32":
            result = windll.kernel32.VirtualLock(start, size)
            if not result:
                import logging
                logging.warning("VirtualLock failed: %s", _win32_error_str())
                return False
            return True
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.mlock(start, size)
            if ret != 0:
                errno = ctypes.get_errno()
                import logging
                logging.warning("mlock failed: errno %d", errno)
                return False
            return True
    except Exception as exc:
        import logging
        logging.warning("mlock_memory failed with exception: %s", exc)
        return False


def munlock_memory(data: bytearray) -> None:
    """Unlock previously locked memory pages containing `data`."""
    if not data:
        return

    c_array = (ctypes.c_char * len(data)).from_buffer(data)
    addr = ctypes.addressof(c_array)

    start = addr & ~(PAGE_SIZE - 1)
    end = (addr + len(data) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    size = end - start

    try:
        if sys.platform == "win32":
            windll.kernel32.VirtualUnlock(start, size)
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.munlock(start, size)
    except Exception as exc:
        import logging
        logging.warning("munlock_memory failed with exception: %s", exc)


def raise_mlock_limit(target_bytes: int = 64 * 1024 * 1024) -> None:
    """Raise the process memory lock limit.

    On Linux: increase RLIMIT_MEMLOCK to `target_bytes`.
    On Windows: adjust the process working set size.
    """
    try:
        if sys.platform == "win32":
            min_size = target_bytes
            max_size = target_bytes * 2
            result = windll.kernel32.SetProcessWorkingSetSize(
                windll.kernel32.GetCurrentProcess(),
                min_size,
                max_size,
            )
            if not result:
                import logging
                logging.warning(
                    "SetProcessWorkingSetSize failed: %s", _win32_error_str()
                )
        else:
            # Raise RLIMIT_MEMLOCK
            current = resource.getrlimit(resource.RLIMIT_MEMLOCK)
            new_soft = min(target_bytes, current[1])  # can't exceed hard limit
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (new_soft, current[1]))
    except Exception as exc:
        import logging
        logging.warning("raise_mlock_limit failed with exception: %s", exc)
