"""
Anti-dump protection: prevent process memory dumping.
Blocks MiniDumpWriteDump (Windows) and core dumps (Linux).
"""

import ctypes
import logging
import sys

logger = logging.getLogger(__name__)


def _patch_minidump_windows() -> None:
    """Patch MiniDumpWriteDump on Windows by replacing the first byte with RET."""
    try:
        dbghelp = ctypes.windll.kernel32.GetModuleHandleW("dbghelp.dll")  # type: ignore[attr-defined]
        if not dbghelp:
            dbghelp = ctypes.windll.kernel32.LoadLibraryW("dbghelp.dll")  # type: ignore[attr-defined]
            if not dbghelp:
                logger.warning("Failed to load dbghelp.dll")
                return

        mini_dump_fn = ctypes.windll.kernel32.GetProcAddress(dbghelp, b"MiniDumpWriteDump")  # type: ignore[attr-defined]
        if not mini_dump_fn:
            logger.warning("Failed to find MiniDumpWriteDump address")
            return

        old_protect = ctypes.c_ulong(0)
        PAGE_EXECUTE_READWRITE = 0x40
        result = ctypes.windll.kernel32.VirtualProtect(  # type: ignore[attr-defined]
            ctypes.c_void_p(mini_dump_fn),
            ctypes.c_size_t(1),
            ctypes.c_ulong(PAGE_EXECUTE_READWRITE),
            ctypes.byref(old_protect),
        )
        if not result:
            logger.warning("VirtualProtect failed to make MiniDumpWriteDump writable")
            return

        ctypes.memmove(mini_dump_fn, b"\xC3", 1)

        ctypes.windll.kernel32.VirtualProtect(  # type: ignore[attr-defined]
            ctypes.c_void_p(mini_dump_fn),
            ctypes.c_size_t(1),
            ctypes.byref(old_protect),
            ctypes.byref(old_protect),
        )

        logger.info("MiniDumpWriteDump patched successfully")
    except Exception as e:
        logger.warning(f"Failed to patch MiniDumpWriteDump: {e}")


def _remove_debug_privilege() -> None:
    """Remove SeDebugPrivilege from the current process token on Windows."""
    try:
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        SE_PRIVILEGE_REMOVED = 0x00000004

        hToken = ctypes.c_void_p()
        result = ctypes.windll.advapi32.OpenProcessToken(  # type: ignore[attr-defined]
            ctypes.windll.kernel32.GetCurrentProcess(),  # type: ignore[attr-defined]
            ctypes.c_ulong(TOKEN_ADJUST_PRIVILEGES),
            ctypes.byref(hToken),
        )
        if not result:
            logger.warning("OpenProcessToken failed")
            return

        luid = ctypes.c_byte * 8
        privilege = luid()
        result = ctypes.windll.advapi32.LookupPrivilegeValueW(  # type: ignore[attr-defined]
            None,
            "SeDebugPrivilege",
            ctypes.byref(privilege),
        )
        if not result:
            logger.warning("LookupPrivilegeValueW failed")
            ctypes.windll.kernel32.CloseHandle(hToken)  # type: ignore[attr-defined]
            return

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Luid", ctypes.c_byte * 8),
                ("Attributes", ctypes.c_ulong),
            ]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.c_ulong),
                ("Privileges", LUID_AND_ATTRIBUTES * 1),
            ]

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = privilege
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED

        result = ctypes.windll.advapi32.AdjustTokenPrivileges(  # type: ignore[attr-defined]
            hToken,
            ctypes.c_int(0),
            ctypes.byref(tp),
            ctypes.c_ulong(0),
            None,
            None,
        )

        ctypes.windll.kernel32.CloseHandle(hToken)  # type: ignore[attr-defined]

        if result:
            logger.info("SeDebugPrivilege removed successfully")
        else:
            logger.warning("AdjustTokenPrivileges failed")
    except Exception as e:
        logger.warning(f"Failed to remove debug privilege: {e}")


def _disable_core_dumps_linux() -> None:
    """Disable core dumps on Linux using setrlimit and prctl."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        logger.info("Core dumps disabled via setrlimit")
    except Exception as e:
        logger.warning(f"Failed to disable core dumps via setrlimit: {e}")

    try:
        PR_SET_DUMPABLE = 4
        libc = ctypes.CDLL("libc.so.6")
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        logger.info("Process made non-dumpable via prctl")
    except Exception as e:
        logger.warning(f"Failed to set dumpable flag via prctl: {e}")


def apply_anti_dump_protections() -> None:
    """Main entry point: apply platform-specific anti-dump protections."""
    if sys.platform == "win32":
        _patch_minidump_windows()
        _remove_debug_privilege()
    elif sys.platform == "linux":
        _disable_core_dumps_linux()
    else:
        logger.warning(f"Anti-dump protections not implemented for platform: {sys.platform}")
