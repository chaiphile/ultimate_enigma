"""
Guarded memory buffers with PAGE_NOACCESS guard pages.
Prevents buffer overread/overflow attacks on sensitive data.
"""
from __future__ import annotations

import ctypes
import sys
from typing import Optional

PAGE_SIZE = 0x1000  # 4KB


class GuardedBuffer:
    """Allocate sensitive data between PAGE_NOACCESS guard pages.

    Layout::

        [PAGE_NOACCESS (4KB)] [PAGE_READWRITE (data)] [PAGE_NOACCESS (4KB)]
               guard               payload                  guard
    """

    def __init__(self, size: int, lock: bool = True) -> None:
        self._size = size
        self._base: Optional[int] = None
        self._data_addr: Optional[int] = None
        self._freed = False

        if sys.platform == "win32":
            self._alloc_windows(size)
        else:
            self._alloc_linux(size)

        if lock:
            VirtualLock = ctypes.windll.kernel32.VirtualLock
            VirtualLock.restype = ctypes.c_bool
            VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            VirtualLock(self._data_addr, size)

    # ------------------------------------------------------------------
    # Windows
    # ------------------------------------------------------------------

    def _alloc_windows(self, size: int) -> None:
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_NOACCESS = 0x01
        PAGE_READWRITE = 0x04

        total = PAGE_SIZE + size + PAGE_SIZE

        VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
        VirtualAlloc.restype = ctypes.c_void_p
        VirtualAlloc.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong
        ]
        base = VirtualAlloc(None, total, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS)
        if not base:
            raise OSError("VirtualAlloc failed for guarded region")
        self._base = base

        data_addr = base + PAGE_SIZE

        VirtualProtect = ctypes.windll.kernel32.VirtualProtect
        VirtualProtect.restype = ctypes.c_bool
        VirtualProtect.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong)
        ]
        old_protect = ctypes.c_ulong(0)
        ok = VirtualProtect(data_addr, size, PAGE_READWRITE, ctypes.byref(old_protect))
        if not ok:
            self._release_windows()
            raise OSError("VirtualProtect failed for data region")
        self._data_addr = data_addr

    def _release_windows(self) -> None:
        MEM_RELEASE = 0x8000
        if self._base is not None:
            VirtualFree = ctypes.windll.kernel32.VirtualFree
            VirtualFree.restype = ctypes.c_bool
            VirtualFree.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong
            ]
            VirtualFree(self._base, 0, MEM_RELEASE)
            self._base = None
            self._data_addr = None
            self._freed = True

    # ------------------------------------------------------------------
    # Linux
    # ------------------------------------------------------------------

    def _alloc_linux(self, size: int) -> None:
        PROT_NONE = 0
        PROT_READ = 1
        PROT_WRITE = 2
        MAP_PRIVATE = 0x02
        MAP_ANONYMOUS = 0x20
        MADV_DONTDUMP = 16

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        total = PAGE_SIZE + size + PAGE_SIZE

        mmap = libc.mmap
        mmap.restype = ctypes.c_void_p
        base = mmap(None, total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if base in (None, -1):
            raise OSError("mmap failed for guarded region")
        self._base = base

        data_addr = base + PAGE_SIZE
        mprotect = libc.mprotect
        mprotect.restype = ctypes.c_int
        rc = mprotect(data_addr, size, PROT_READ | PROT_WRITE)
        if rc != 0:
            self._release_linux()
            raise OSError("mprotect failed for data region")

        madvise = libc.madvise
        madvise.restype = ctypes.c_int
        madvise(data_addr, size, MADV_DONTDUMP)

        self._data_addr = data_addr

    def _release_linux(self) -> None:
        if self._base is not None:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.munmap(self._base, PAGE_SIZE + self._size + PAGE_SIZE)
            self._base = None
            self._data_addr = None
            self._freed = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, data: bytes) -> None:
        """Write *data* into the guarded region."""
        if self._freed:
            raise ValueError("buffer already freed")
        if len(data) > self._size:
            raise ValueError(
                f"Data length {len(data)} exceeds buffer size {self._size}"
            )
        ctypes.memmove(self._data_addr, data, len(data))

    def read(self) -> bytearray:
        """Return a copy of the guarded data."""
        if self._freed:
            raise ValueError("buffer already freed")
        buf = (ctypes.c_char * self._size).from_address(self._data_addr)  # type: ignore[arg-type]
        return bytearray(buf)

    def __bytes__(self) -> bytes:
        return bytes(self.read())

    def __len__(self) -> int:
        if self._freed:
            raise ValueError("buffer already freed")
        return self._size

    def __iter__(self):
        return iter(self.read())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GuardedBuffer):
            if self._freed or other._freed:
                return False
            if self._size != other._size:
                return False
            buf1 = (ctypes.c_uint8 * self._size).from_address(self._data_addr)
            buf2 = (ctypes.c_uint8 * other._size).from_address(other._data_addr)
            # Constant-time comparison directly on guarded memory avoids
            # copying data to the Python heap.
            result = 0
            for i in range(self._size):
                result |= buf1[i] ^ buf2[i]
            return result == 0
        return NotImplemented

    def wipe_and_free(self) -> None:
        """Zero the data region, then release the full allocation."""
        if self._freed:
            return
        if self._data_addr is not None:
            buf = (ctypes.c_char * self._size).from_address(self._data_addr)
            for i in range(self._size):
                buf[i] = b'\x00'
        if sys.platform == "win32":
            self._release_windows()
        else:
            self._release_linux()

    # ------------------------------------------------------------------
    # Context manager / destructor
    # ------------------------------------------------------------------

    def __enter__(self) -> GuardedBuffer:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.wipe_and_free()

    def __del__(self) -> None:
        self.wipe_and_free()
