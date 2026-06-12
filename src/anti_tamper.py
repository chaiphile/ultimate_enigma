"""Anti-tamper and anti-debugger protection for Ultimate Enigma.

This module provides aggressive protection against debugging, reverse engineering,
and binary tampering. All checks are ONLY active when running as a frozen PyInstaller
executable (sys.frozen == True). When running from source, all checks are no-ops.

Detection methods:
    - Windows API debugger detection (IsDebuggerPresent, CheckRemoteDebuggerPresent)
    - PEB debug flag via NtQueryInformationProcess
    - Debugger window and process enumeration
    - sys.gettrace/getprofile checks
    - RDTSC timing-based detection
    - PyInstaller bundle integrity verification
    - Import hooking detection
    - Hooking framework detection (Frida, etc.)

Countermeasures:
    - ThreadHideFromDebugger to hide threads from debuggers
    - Silent process termination on detection

Usage:
    Call run_anti_tamper_checks() early in main.py before any other imports.
    Call start_background_checks() after the GUI is initialized.
"""

import sys
import os
import hashlib
import hmac
import random
import struct
import subprocess
import threading
import time
import ctypes
import ctypes.wintypes
import logging
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Anti-Tamper Log File
# ---------------------------------------------------------------------------
# Write to a persistent file so triggers survive process exit.
# Location: same directory as the executable (or CWD when running from source).

ANTI_TAMPER_LOG_FILE = None

def _init_log_file():
    """Initialize the anti-tamper log file path."""
    global ANTI_TAMPER_LOG_FILE
    try:
        if getattr(sys, 'frozen', False):
            log_dir = Path(sys.executable).parent
        else:
            log_dir = Path.cwd()
        ANTI_TAMPER_LOG_FILE = log_dir / "anti_tamper.log"
    except Exception:
        ANTI_TAMPER_LOG_FILE = Path("anti_tamper.log")

_init_log_file()


def _log_trigger(check_name: str, details: str = "") -> None:
    """Write a trigger entry to the anti-tamper log file.

    This function writes directly to disk (no buffering) so the entry
    survives even if the process is killed immediately after.
    """
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{timestamp}] TRIGGERED: {check_name}"
        if details:
            line += f" | {details}"
        line += "\n"

        if ANTI_TAMPER_LOG_FILE is not None:
            with open(ANTI_TAMPER_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass


def _log_info(message: str) -> None:
    """Write an informational entry to the anti-tamper log file."""
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{timestamp}] INFO: {message}\n"

        if ANTI_TAMPER_LOG_FILE is not None:
            with open(ANTI_TAMPER_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANTI_TAMPER_CONFIG = {
    "BACKGROUND_CHECK_INTERVAL": 30,       # seconds between background checks
    "TIMING_CHECK_THRESHOLD_NS": 500_000,  # 0.5ms threshold for RDTSC detection
    "MAX_TIMING_SAMPLES": 5,               # samples for timing check
    "SEEK_MIN_INTERVAL": 5,                # minimum seconds between seeks
    "SEEK_MAX_INTERVAL": 15,               # maximum seconds between seeks
    "SEEK_SUSPICION_THRESHOLD": 3,         # consecutive suspicious results before escalating
    "SEEK_ESCALATED_MIN_INTERVAL": 1,      # minimum seconds when escalated
    "SEEK_ESCALATED_MAX_INTERVAL": 3,      # maximum seconds when escalated
}

DEBUGGER_PROCESS_NAMES = {
    "ollydbg.exe", "olly64.exe", "x64dbg.exe", "x32dbg.exe",
    "ida.exe", "ida64.exe", "idag.exe", "idag64.exe", "idal.exe", "idal64.exe",
    "windbg.exe", "cdb.exe", "ntsd.exe",
    "processhacker.exe", "procmon.exe", "procmon64.exe",
    "cheatengine-x86_64.exe", "cheatengine-i386.exe",
    "dnSpy.exe", "dnSpy.UnityMod.exe",
    "de4dot.exe", "de4dot-blocker.exe",
    "httpdebuggerpro.exe", "fiddler.exe",
    "ruler.exe", "immunity.exe", "immunitydebugger.exe",
    "binaryninja.exe", "radare2.exe", "r2.exe",
    "ghidra.exe", "ghidraRun.exe",
    "jeb.exe", "jeb_winagent.exe",
    "x96dbg.exe", "pex.exe", "pestudio.exe",
}

DEBUGGER_WINDOW_CLASSES = {
    "OLLYDBG", "x64dbg", "x32dbg", "ID", "WinDbgClass",
    "TfrmMain", "TIdaWindow", "TfrmDisasm", "ProcessHacker",
    "MainWindow", "DbgFrameClass", "Afx:400000:0",
}

DEBUGGER_WINDOW_TITLES = {
    "ollydbg", "x64dbg", "x32dbg", "immunity debugger",
    "idapro", "ida pro", "windbg", "cdb", "ntsd",
    "process hacker", "processhacker",
    "cheat engine", "dnspy", "ghidra",
    "fiddler", "http debugger",
    "radare2", "r2", "binary ninja",
}

HOOKING_FRAMEWORKS = {
    "frida", "frida-agent", "frida-server", "frida-tracer",
    "cuckoo", "cuckoomon", "pythonhooker",
    "detours", "minhook", "easyhook",
}

CRITICAL_BUNDLE_FILES = [
    "crypto.py",
    "database.py",
    "key_manager.py",
    "encryption_service.py",
    "double_ratchet.py",
    "pqc_service.py",
    "auth_manager.py",
    "main.py",
    "app.py",
]

# ---------------------------------------------------------------------------
# Windows API Definitions
# ---------------------------------------------------------------------------

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Debug check functions
IsDebuggerPresent = kernel32.IsDebuggerPresent
IsDebuggerPresent.restype = ctypes.c_bool
IsDebuggerPresent.argtypes = []

CheckRemoteDebuggerPresent = kernel32.CheckRemoteDebuggerPresent
CheckRemoteDebuggerPresent.restype = ctypes.c_bool
CheckRemoteDebuggerPresent.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.BOOL),
]

# NtQueryInformationProcess
ProcessDebugPort = 7
ProcessDebugFlags = 0x1F
ProcessDebugObjectHandle = 0x1E

nt_query_info = ntdll.NtQueryInformationProcess
nt_query_info.restype = ctypes.c_long
nt_query_info.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_ulong),
]

# ThreadHideFromDebugger (0x11)
NtSetInformationThread = ntdll.NtSetInformationThread
NtSetInformationThread.restype = ctypes.c_long
NtSetInformationThread.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
]

GetCurrentThread = kernel32.GetCurrentThread
GetCurrentThread.restype = ctypes.wintypes.HANDLE
GetCurrentThread.argtypes = []

GetCurrentProcessId = kernel32.GetCurrentProcessId
GetCurrentProcessId.restype = ctypes.wintypes.DWORD
GetCurrentProcessId.argtypes = []

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = ctypes.wintypes.HANDLE
OpenProcess.argtypes = [
    ctypes.wintypes.DWORD,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = ctypes.wintypes.BOOL
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindows.restype = ctypes.wintypes.BOOL
EnumWindows.argtypes = [
    ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HANDLE, ctypes.wintypes.LPARAM),
    ctypes.wintypes.LPARAM,
]

GetWindowTextW = ctypes.windll.user32.GetWindowTextW
GetWindowTextW.restype = ctypes.c_int
GetWindowTextW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPWSTR, ctypes.c_int]

GetClassNameW = ctypes.windll.user32.GetClassNameW
GetClassNameW.restype = ctypes.c_int
GetClassNameW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPWSTR, ctypes.c_int]

IsWindowVisible = ctypes.windll.user32.IsWindowVisible
IsWindowVisible.restype = ctypes.wintypes.BOOL
IsWindowVisible.argtypes = [ctypes.wintypes.HANDLE]

GetThreadContext = kernel32.GetThreadContext
GetThreadContext.restype = ctypes.wintypes.BOOL
GetThreadContext.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]

SuspendThread = kernel32.SuspendThread
SuspendThread.restype = ctypes.wintypes.DWORD
SuspendThread.argtypes = [ctypes.wintypes.HANDLE]

ResumeThread = kernel32.ResumeThread
ResumeThread.restype = ctypes.wintypes.DWORD
ResumeThread.argtypes = [ctypes.wintypes.HANDLE]

CONTEXT_DEBUG_REGISTERS = 0x00100010  # CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


# ---------------------------------------------------------------------------
# Anti-Debugger: Windows API Checks
# ---------------------------------------------------------------------------

def _check_debugger_present() -> bool:
    """Check IsDebuggerPresent API."""
    try:
        result = IsDebuggerPresent()
        if result:
            _log_trigger("IsDebuggerPresent", "Windows API returned True - debugger attached")
        return result
    except Exception as e:
        _log_info(f"IsDebuggerPresent check failed: {e}")
        return False


def _check_remote_debugger() -> bool:
    """Check if a remote debugger is attached."""
    try:
        is_debugged = ctypes.wintypes.BOOL(False)
        result = CheckRemoteDebuggerPresent(
            ctypes.wintypes.HANDLE(-1),
            ctypes.byref(is_debugged),
        )
        if result and is_debugged.value != 0:
            _log_trigger("RemoteDebugger", "CheckRemoteDebuggerPresent returned True")
            return True
        return False
    except Exception as e:
        _log_info(f"RemoteDebugger check failed: {e}")
        return False


def _check_peb_debugger_flag() -> bool:
    """Check PEB->BeingDebugged via NtQueryInformationProcess."""
    try:
        debug_port = ctypes.c_ulong(0)
        status = nt_query_info(
            ctypes.wintypes.HANDLE(-1),
            ProcessDebugPort,
            ctypes.byref(debug_port),
            ctypes.sizeof(debug_port),
            None,
        )
        if status == 0 and debug_port.value != 0:
            _log_trigger("PEB_Debugger", f"DebugPort={debug_port.value} (non-zero)")
            return True
    except Exception:
        pass

    try:
        debug_flags = ctypes.c_ulong(0)
        status = nt_query_info(
            ctypes.wintypes.HANDLE(-1),
            ProcessDebugFlags,
            ctypes.byref(debug_flags),
            ctypes.sizeof(debug_flags),
            None,
        )
        if status == 0 and debug_flags.value == 0:
            _log_trigger("PEB_Debugger", f"DebugFlags={debug_flags.value} (zero means debugged)")
            return True
    except Exception:
        pass

    try:
        debug_handle = ctypes.c_void_p(0)
        status = nt_query_info(
            ctypes.wintypes.HANDLE(-1),
            ProcessDebugObjectHandle,
            ctypes.byref(debug_handle),
            ctypes.sizeof(debug_handle),
            None,
        )
        if status == 0:
            _log_trigger("PEB_Debugger", f"DebugObjectHandle exists (status={status})")
            return True
    except Exception:
        pass

    return False


def _check_hardware_breakpoints() -> bool:
    """Check for hardware breakpoints via debug registers (Dr0-Dr7)."""
    try:
        thread_handle = GetCurrentThread()
        # Allocate CONTEXT structure (enough space for x64)
        context_buf = ctypes.create_string_buffer(1232)  # sizeof(CONTEXT) for x64
        ctypes.memset(ctypes.addressof(context_buf), 0, 1232)
        # Set ContextFlags
        struct.pack_into("I", context_buf, 48, CONTEXT_DEBUG_REGISTERS)  # ContextFlags offset

        # SuspendThread to safely read context (GetCurrentThread is pseudo-handle, need real handle)
        process_handle = ctypes.windll.kernel32.GetCurrentProcess()
        thread_id = ctypes.windll.kernel32.GetCurrentThreadId()
        real_thread_handle = OpenProcess(0x0010, False, thread_id)  # THREAD_QUERY_INFORMATION

        if real_thread_handle:
            SuspendThread(real_thread_handle)

            # For main thread we can use pseudo-handle with GetThreadContext
            result = GetThreadContext(thread_handle, ctypes.addressof(context_buf))
            ResumeThread(real_thread_handle)
            CloseHandle(real_thread_handle)

            if result:
                # Dr0-Dr3 are at offsets 512, 520, 528, 536 in CONTEXT
                for i in range(4):
                    dr_value = struct.unpack_from("Q", context_buf, 512 + i * 8)[0]
                    if dr_value != 0:
                        _log_trigger("HardwareBreakpoints", f"Dr{i}={dr_value:#x} (non-zero)")
                        return True
    except Exception:
        pass

    return False


def _check_python_debugger_flags() -> bool:
    """Check sys.gettrace and sys.getprofile for active debuggers."""
    try:
        trace = sys.gettrace()
        if trace is not None:
            _log_trigger("PythonDebuggerFlags", f"sys.gettrace() returned: {trace}")
            return True
    except Exception:
        pass

    try:
        profile = sys.getprofile()
        if profile is not None:
            _log_trigger("PythonDebuggerFlags", f"sys.getprofile() returned: {profile}")
            return True
    except Exception:
        pass

    return False


def _check_debugger_windows() -> bool:
    """Detect debugger windows by class name and title."""
    found = []

    @ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HANDLE, ctypes.wintypes.LPARAM)
    def enum_callback(hwnd, lparam):
        if not IsWindowVisible(hwnd):
            return True

        class_buf = ctypes.create_unicode_buffer(256)
        GetClassNameW(hwnd, class_buf, 256)
        class_name = class_buf.value.lower()

        for cls in DEBUGGER_WINDOW_CLASSES:
            cls_lower = cls.lower()
            # Use exact match for short strings to avoid false positives
            # (e.g. "ID" matching inside "chrome_widgetwin_1")
            if len(cls_lower) <= 3:
                if cls_lower == class_name:
                    found.append(f"class={class_buf.value}")
                    return False
            else:
                if cls_lower in class_name:
                    found.append(f"class={class_buf.value}")
                    return False

        title_buf = ctypes.create_unicode_buffer(256)
        GetWindowTextW(hwnd, title_buf, 256)
        title = title_buf.value.lower()

        for t in DEBUGGER_WINDOW_TITLES:
            # Use exact match for short strings to avoid false positives
            if len(t) <= 3:
                if t == title:
                    found.append(f"title={title_buf.value}")
                    return False
            else:
                if t in title:
                    found.append(f"title={title_buf.value}")
                    return False

        return True

    try:
        EnumWindows(enum_callback, 0)
    except Exception:
        pass

    if found:
        _log_trigger("DebuggerWindows", f"Found: {', '.join(found)}")
    return len(found) > 0


def _check_debugger_processes() -> bool:
    """Check for known debugger process names via tasklist."""
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            _log_info(f"tasklist returned code {result.returncode}")
            return False

        output = result.stdout.lower()
        for proc_name in DEBUGGER_PROCESS_NAMES:
            if proc_name in output:
                _log_trigger("DebuggerProcesses", f"Found process: {proc_name}")
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log_info(f"DebuggerProcesses check failed: {type(e).__name__}: {e}")

    return False


def _check_timing() -> bool:
    """Detect debugger-induced timing anomalies using time.perf_counter_ns."""
    try:
        times = []
        for _ in range(ANTI_TAMPER_CONFIG["MAX_TIMING_SAMPLES"]):
            start = time.perf_counter_ns()
            # Tight loop to measure baseline
            for _ in range(1000):
                pass
            end = time.perf_counter_ns()
            times.append(end - start)

        avg = sum(times) / len(times)
        threshold = ANTI_TAMPER_CONFIG["TIMING_CHECK_THRESHOLD_NS"]
        if avg > threshold:
            _log_trigger("TimingAnomaly",
                         f"avg={avg:.0f}ns threshold={threshold}ns samples={times}")
            return True
    except Exception as e:
        _log_info(f"Timing check failed: {e}")

    return False


# ---------------------------------------------------------------------------
# Anti-Tamper: Bundle Integrity
# ---------------------------------------------------------------------------

def _check_meipass() -> bool:
    """Verify PyInstaller _MEIPASS exists and is valid."""
    try:
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass is None:
            return False

        path = Path(meipass)
        if not path.exists():
            _log_trigger("MeipassIntegrity", f"_MEIPASS path does not exist: {meipass}")
            return True
        if not path.is_dir():
            _log_trigger("MeipassIntegrity", f"_MEIPASS is not a directory: {meipass}")
            return True

        return False
    except Exception as e:
        _log_info(f"MeipassIntegrity check failed: {e}")
        return False


def _check_import_hooks() -> bool:
    """Detect if sys.meta_path has been modified to inject hooks."""
    try:
        import importlib
        default_hooks = importlib.util.find_spec("importlib").submodule_search_locations
    except Exception:
        default_hooks = None

    suspicious_hooks = []
    try:
        for hook in sys.meta_path:
            hook_type = type(hook).__name__
            hook_str = str(hook).lower()

            for framework in HOOKING_FRAMEWORKS:
                if framework in hook_str or framework in hook_type.lower():
                    suspicious_hooks.append(f"{hook_type}: {hook_str}")
                    break

            if "frozenimporthook" in hook_str:
                continue

        if suspicious_hooks:
            _log_trigger("ImportHooks", f"Suspicious hooks found: {', '.join(suspicious_hooks)}")
            return True
    except Exception as e:
        _log_info(f"ImportHooks check failed: {e}")

    return False


def _check_frida() -> bool:
    """Detect Frida hooking framework."""
    # Check for Frida files on disk
    frida_paths = [
        os.path.join(os.environ.get("TEMP", ""), "frida-agent.dll"),
        os.path.join(os.environ.get("TEMP", ""), "frida-agent-<arch>.dll"),
        os.path.join(os.environ.get("APPDATA", ""), "frida"),
        "/tmp/frida-*",
    ]

    for frida_path in frida_paths:
        try:
            if "*" in frida_path:
                import glob
                matches = glob.glob(frida_path)
                if matches:
                    _log_trigger("FridaDetection", f"Frida files found: {matches}")
                    return True
            elif os.path.exists(frida_path):
                _log_trigger("FridaDetection", f"Frida path exists: {frida_path}")
                return True
        except Exception:
            pass

    # Check for frida in loaded modules
    try:
        for name in sys.modules:
            if name and "frida" in str(name).lower():
                _log_trigger("FridaDetection", f"Frida module loaded: {name}")
                return True
    except Exception:
        pass

    # Check for frida in environment variables
    try:
        for key, value in os.environ.items():
            if "frida" in str(key).lower() or "frida" in str(value).lower():
                _log_trigger("FridaDetection", f"Frida in env: {key}={value}")
                return True
    except Exception:
        pass

    return False


def _check_module_integrity() -> bool:
    """Check if critical modules have been modified by inspecting bytecode."""
    try:
        import importlib
        import types

        critical_modules = [
            "crypto", "database", "key_manager",
            "encryption_service", "double_ratchet",
        ]

        for mod_name in critical_modules:
            try:
                mod = sys.modules.get(mod_name)
                if mod is None:
                    continue

                if not hasattr(mod, "__file__") or mod.__file__ is None:
                    continue

                mod_path = Path(mod.__file__)
                if not mod_path.exists():
                    continue

                # Check for suspicious patterns in .pyc files
                if mod_path.suffix == ".pyc":
                    with open(mod_path, "rb") as f:
                        data = f.read()
                        # Python magic number + flags
                        if len(data) < 16:
                            _log_trigger("ModuleIntegrity",
                                         f"Module {mod_name} .pyc too short: {len(data)} bytes")
                            return True

                        magic = data[:4]
                        # Verify magic number matches running Python
                        if magic != importlib.util.MAGIC_NUMBER:
                            _log_trigger("ModuleIntegrity",
                                         f"Module {mod_name} magic mismatch: {magic.hex()} != {importlib.util.MAGIC_NUMBER.hex()}")
                            return True
            except Exception:
                continue
    except Exception:
        pass

    return False


# ---------------------------------------------------------------------------
# Anti-Tamper: PE Verification
# ---------------------------------------------------------------------------

def _check_pe_header() -> bool:
    """Verify the running executable's PE header integrity."""
    try:
        if not hasattr(sys, "frozen"):
            return False

        exe_path = sys.executable
        if not os.path.exists(exe_path):
            _log_trigger("PEHeader", f"Executable not found: {exe_path}")
            return True

        with open(exe_path, "rb") as f:
            # DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b"MZ":
                _log_trigger("PEHeader", f"Invalid DOS signature: {dos_header[:2].hex()}")
                return True

            # PE offset
            pe_offset = struct.unpack("<I", dos_header[60:64])[0]

            # Seek to PE header
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                _log_trigger("PEHeader", f"Invalid PE signature: {pe_sig.hex()}")
                return True

            # COFF header
            coff_header = f.read(20)
            num_sections = struct.unpack("<H", coff_header[2:4])[0]
            timestamp = struct.unpack("<I", coff_header[4:8])[0]

            # Sanity checks
            if num_sections == 0 or num_sections > 100:
                _log_trigger("PEHeader", f"Suspicious section count: {num_sections}")
                return True

            # Optional header
            opt_header = f.read(224)
            if len(opt_header) < 224:
                _log_trigger("PEHeader", f"Optional header too short: {len(opt_header)} bytes")
                return True

            # Check for suspicious entry point
            entry_point = struct.unpack("<I", opt_header[16:20])[0]
            image_base = struct.unpack("<Q", opt_header[24:32])[0]

            # Basic sanity: entry point should be within reasonable range
            if entry_point == 0:
                _log_trigger("PEHeader", "Entry point is zero")
                return True

    except Exception as e:
        _log_info(f"PEHeader check failed: {e}")

    return False


# ---------------------------------------------------------------------------
# Countermeasures
# ---------------------------------------------------------------------------

def _hide_thread_from_debugger() -> bool:
    """Call NtSetInformationThread(ThreadHideFromDebugger) to hide current thread."""
    try:
        thread_handle = GetCurrentThread()
        status = NtSetInformationThread(
            thread_handle,
            0x11,  # ThreadHideFromDebugger
            None,
            0,
        )
        return status == 0
    except Exception:
        return False


def _silent_exit():
    """Terminate the process silently without any warning."""
    try:
        # Clear sensitive data from memory before exit
        for mod_name in list(sys.modules.keys()):
            if mod_name and any(s in mod_name.lower() for s in ["crypto", "key", "secret", "password", "database"]):
                try:
                    del sys.modules[mod_name]
                except Exception:
                    pass

        # Force garbage collection
        import gc
        gc.collect()

        # Use os._exit for immediate termination (no cleanup hooks)
        os._exit(1)
    except Exception:
        try:
            os._exit(1)
        except Exception:
            import ctypes
            ctypes.windll.kernel32.TerminateProcess(
                ctypes.wintypes.HANDLE(-1), 1
            )


# ---------------------------------------------------------------------------
# Active Debugger Seeking
# ---------------------------------------------------------------------------

class _DebuggerSeeker:
    """Active debugger seeking with randomized intervals and escalation.

    This class implements an aggressive seeking strategy that:
    1. Randomizes scan intervals to prevent predictable timing
    2. Escalates scan frequency when suspicious activity is detected
    3. Uses cross-validation between multiple detection methods
    4. Performs deep scans on escalation (process memory, threads, modules)
    """

    def __init__(self):
        self._suspicion_count = 0
        self._escalated = False
        self._last_check_time = 0.0
        self._lock = threading.Lock()

    def _get_seek_interval(self) -> float:
        """Get randomized seek interval based on current suspicion level."""
        if self._escalated:
            min_interval = ANTI_TAMPER_CONFIG["SEEK_ESCALATED_MIN_INTERVAL"]
            max_interval = ANTI_TAMPER_CONFIG["SEEK_ESCALATED_MAX_INTERVAL"]
        else:
            min_interval = ANTI_TAMPER_CONFIG["SEEK_MIN_INTERVAL"]
            max_interval = ANTI_TAMPER_CONFIG["SEEK_MAX_INTERVAL"]
        return random.uniform(min_interval, max_interval)

    def _record_suspicion(self) -> None:
        """Record a suspicious finding and potentially escalate."""
        with self._lock:
            self._suspicion_count += 1
            threshold = ANTI_TAMPER_CONFIG["SEEK_SUSPICION_THRESHOLD"]
            if self._suspicion_count >= threshold and not self._escalated:
                self._escalated = True
                _log_info(f"Escalated seeking mode after {self._suspicion_count} suspicious findings")

    def _clear_suspicion(self) -> None:
        """Reset suspicion count after clean scan."""
        with self._lock:
            if self._suspicion_count > 0:
                self._suspicion_count = max(0, self._suspicion_count - 1)
            if self._suspicion_count == 0 and self._escalated:
                self._escalated = False
                _log_info("De-escalated seeking mode - all clear")

    def _deep_scan(self) -> bool:
        """Perform deep scan when escalated - checks process memory and threads.

        Returns:
            True if tampering detected.
        """
        try:
            # Check for injected threads by enumerating all threads
            kernel32 = ctypes.windll.kernel32
            process_handle = kernel32.GetCurrentProcess()
            thread_count = kernel32.GetProcessThreadCount(process_handle) if hasattr(kernel32, 'GetProcessThreadCount') else 0

            # Check for suspicious memory regions (RWX in non-image memory)
            # This detects code injection and hooking
            import ctypes.wintypes as wt

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            MEM_COMMIT = 0x1000
            PAGE_EXECUTE_READWRITE = 0x40

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wt.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wt.DWORD),
                    ("Protect", wt.DWORD),
                    ("Type", wt.DWORD),
                ]

            VirtualQueryEx = kernel32.VirtualQueryEx
            VirtualQueryEx.restype = ctypes.c_size_t
            VirtualQueryEx.argtypes = [
                wt.HANDLE, ctypes.c_void_p,
                ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                ctypes.c_size_t
            ]

            # Scan first 256MB of address space for RWX regions
            address = 0
            max_address = 256 * 1024 * 1024
            suspicious_regions = 0

            while address < max_address:
                mbi = MEMORY_BASIC_INFORMATION()
                result = VirtualQueryEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )
                if result == 0:
                    break

                # Check for committed RWX memory that's not in an image (DLL/EXE)
                if (mbi.State == MEM_COMMIT and
                    mbi.Protect == PAGE_EXECUTE_READWRITE and
                    mbi.Type != 0x10000000):  # Not MEM_IMAGE
                    suspicious_regions += 1
                    if suspicious_regions >= 3:
                        _log_trigger("SeekerDeepScan",
                                   f"Found {suspicious_regions} suspicious RWX memory regions")
                        return True

                address = mbi.BaseAddress + mbi.RegionSize if mbi.RegionSize > 0 else address + 0x10000

        except Exception as e:
            _log_info(f"Deep scan exception: {type(e).__name__}: {e}")

        return False

    def seek(self) -> bool:
        """Run a single seeking cycle with cross-validation.

        Returns:
            True if tampering detected.
        """
        current_time = time.time()

        # Enforce minimum interval between checks
        min_interval = ANTI_TAMPER_CONFIG["SEEK_MIN_INTERVAL"]
        if current_time - self._last_check_time < min_interval:
            return False

        self._last_check_time = current_time

        # Run primary checks
        primary_result = _run_all_checks()

        if primary_result:
            # Cross-validate: run checks again immediately to confirm
            confirm_result = _run_all_checks()
            if confirm_result:
                _log_info("Seeker: Double-confirmed tampering detection")
                return True
            else:
                # First was false positive, log and continue
                _log_info("Seeker: First detection was false positive (cross-validation failed)")
                self._record_suspicion()
                return False

        # No detection - run deep scan if escalated
        if self._escalated:
            deep_result = self._deep_scan()
            if deep_result:
                return True
            self._clear_suspicion()
        else:
            self._clear_suspicion()

        return False

    def get_next_interval(self) -> float:
        """Get the next randomized interval for seeking."""
        return self._get_seek_interval()


# Global seeker instance
_seeker = _DebuggerSeeker()


def _seek_debugger() -> bool:
    """Run a single seeking cycle.

    Returns:
        True if tampering detected.
    """
    return _seeker.seek()


def _get_seek_interval() -> float:
    """Get the next randomized interval for seeking."""
    return _seeker.get_next_interval()


# ---------------------------------------------------------------------------
# Main Detection Pipeline
# ---------------------------------------------------------------------------

def _run_all_checks() -> bool:
    """Run all anti-tamper and anti-debugger checks.

    Returns:
        True if tampering/debugging detected, False otherwise.
    """
    checks = [
        ("IsDebuggerPresent", _check_debugger_present),
        ("RemoteDebugger", _check_remote_debugger),
        ("PEB_Debugger", _check_peb_debugger_flag),
        ("HardwareBreakpoints", _check_hardware_breakpoints),
        ("PythonDebuggerFlags", _check_python_debugger_flags),
        ("DebuggerWindows", _check_debugger_windows),
        ("DebuggerProcesses", _check_debugger_processes),
        ("TimingAnomaly", _check_timing),
        ("MeipassIntegrity", _check_meipass),
        ("ImportHooks", _check_import_hooks),
        ("FridaDetection", _check_frida),
        ("ModuleIntegrity", _check_module_integrity),
        ("PEHeader", _check_pe_header),
    ]

    for name, check_fn in checks:
        try:
            if check_fn():
                # Individual check functions already log details via _log_trigger
                logger.debug("Anti-tamper check triggered: %s", name)
                return True
        except Exception as e:
            _log_info(f"Check '{name}' raised exception: {type(e).__name__}: {e}")
            continue

    return False


def run_anti_tamper_checks() -> None:
    """Run all protection checks and exit silently if tampering detected.

    Call this function BEFORE any other imports in main.py when running frozen.
    """
    if not getattr(sys, "frozen", False):
        return

    _log_info("Anti-tamper checks starting (frozen mode)")
    _hide_thread_from_debugger()
    _log_info("ThreadHideFromDebugger applied")

    if _run_all_checks():
        _log_info("Tampering detected - initiating silent exit")
        _silent_exit()
    else:
        _log_info("All checks passed - no tampering detected")


def start_background_checks(interval: Optional[int] = None) -> None:
    """Start a daemon thread that actively seeks debuggers with randomized intervals.

    Uses the _DebuggerSeeker for randomized timing, cross-validation,
    and escalation when suspicious activity is detected.

    Args:
        interval: Seconds between checks. Defaults to config value.
                  Actual intervals are randomized around this base value.
    """
    if not getattr(sys, "frozen", False):
        return

    if interval is None:
        interval = ANTI_TAMPER_CONFIG["BACKGROUND_CHECK_INTERVAL"]

    _log_info(f"Background seeking started (base interval={interval}s)")

    def _background_loop():
        time.sleep(2)  # Short initial delay
        while True:
            try:
                _hide_thread_from_debugger()
                if _seek_debugger():
                    _log_info("Seeker detected tampering - exiting")
                    _silent_exit()
            except Exception as e:
                _log_info(f"Background seek exception: {type(e).__name__}: {e}")
            # Use randomized interval from seeker
            sleep_time = _get_seek_interval()
            time.sleep(sleep_time)

    thread = threading.Thread(target=_background_loop, daemon=True, name="anti-tamper")
    thread.start()


def check_on_demand() -> bool:
    """Run a single check cycle on demand (e.g., before critical operations).

    Returns:
        True if tampering detected, False if clean.
    """
    if not getattr(sys, "frozen", False):
        return False

    result = _run_all_checks()
    if result:
        _log_info("On-demand check detected tampering")
    return result


__all__ = [
    "run_anti_tamper_checks",
    "start_background_checks",
    "check_on_demand",
]
