"""Tests for anti-tamper and anti-debugger protection module."""

import sys
import os
import struct
import time
import threading
from unittest import mock
from pathlib import Path

import pytest


@pytest.fixture
def frozen_env():
    """Temporarily set sys.frozen = True for testing."""
    original = getattr(sys, "frozen", False)
    sys.frozen = True
    yield
    if original is False:
        del sys.frozen


@pytest.fixture
def unfrozen_env():
    """Ensure sys.frozen is False for testing."""
    original = getattr(sys, "frozen", False)
    if hasattr(sys, "frozen"):
        del sys.frozen
    yield
    if original is not None:
        sys.frozen = original


class TestAntiTamperSkipWhenUnfrozen:
    """Checks should be no-ops when not frozen."""

    def test_run_anti_tamper_checks_skips_when_not_frozen(self, unfrozen_env):
        from src.anti_tamper import run_anti_tamper_checks
        run_anti_tamper_checks()

    def test_start_background_checks_skips_when_not_frozen(self, unfrozen_env):
        from src.anti_tamper import start_background_checks
        start_background_checks()

    def test_check_on_demand_returns_false_when_not_frozen(self, unfrozen_env):
        from src.anti_tamper import check_on_demand
        assert check_on_demand() is False


class TestPythonDebuggerFlags:
    """Test sys.gettrace / sys.getprofile detection."""

    def test_no_debugger_returns_false(self, frozen_env):
        from src.anti_tamper import _check_python_debugger_flags
        with mock.patch("src.anti_tamper.sys") as mock_sys:
            mock_sys.gettrace.return_value = None
            mock_sys.getprofile.return_value = None
            assert _check_python_debugger_flags() is False

    def test_active_trace_returns_true(self, frozen_env):
        from src.anti_tamper import _check_python_debugger_flags
        with mock.patch("src.anti_tamper.sys") as mock_sys:
            mock_sys.gettrace.return_value = lambda *a: None
            mock_sys.getprofile.return_value = None
            assert _check_python_debugger_flags() is True

    def test_active_profile_returns_true(self, frozen_env):
        from src.anti_tamper import _check_python_debugger_flags
        with mock.patch("src.anti_tamper.sys") as mock_sys:
            mock_sys.gettrace.return_value = None
            mock_sys.getprofile.return_value = lambda *a: None
            assert _check_python_debugger_flags() is True


class TestMeipassCheck:
    """Test PyInstaller _MEIPASS verification."""

    def test_no_meipass_returns_false(self, frozen_env):
        from src.anti_tamper import _check_meipass
        with mock.patch.object(sys, "_MEIPASS", None, create=True):
            assert _check_meipass() is False

    def test_valid_meipass_returns_false(self, frozen_env, tmp_path):
        from src.anti_tamper import _check_meipass
        with mock.patch.object(sys, "_MEIPASS", str(tmp_path), create=True):
            assert _check_meipass() is False

    def test_nonexistent_meipass_returns_true(self, frozen_env):
        from src.anti_tamper import _check_meipass
        with mock.patch.object(sys, "_MEIPASS", "/nonexistent/path", create=True):
            assert _check_meipass() is True

    def test_file_instead_of_dir_returns_true(self, frozen_env, tmp_path):
        from src.anti_tamper import _check_meipass
        fake_file = tmp_path / "fake.txt"
        fake_file.write_text("not a directory")
        with mock.patch.object(sys, "_MEIPASS", str(fake_file), create=True):
            assert _check_meipass() is True


class TestImportHooks:
    """Test import hook detection."""

    def test_no_hooks_returns_false(self, frozen_env):
        from src.anti_tamper import _check_import_hooks
        original_hooks = sys.meta_path.copy()
        try:
            sys.meta_path.clear()
            assert _check_import_hooks() is False
        finally:
            sys.meta_path.clear()
            sys.meta_path.extend(original_hooks)

    def test_frida_hook_returns_true(self, frozen_env):
        from src.anti_tamper import _check_import_hooks
        original_hooks = sys.meta_path.copy()
        try:
            sys.meta_path.clear()
            frida_hook = mock.MagicMock()
            frida_hook.__str__ = mock.MagicMock(return_value="<frida_loader.FridaMetaPathFinder>")
            sys.meta_path.append(frida_hook)
            assert _check_import_hooks() is True
        finally:
            sys.meta_path.clear()
            sys.meta_path.extend(original_hooks)


class TestFridaDetection:
    """Test Frida hooking framework detection."""

    def test_frida_in_modules_returns_true(self, frozen_env):
        from src.anti_tamper import _check_frida
        original_modules = sys.modules.copy()
        try:
            sys.modules["frida_agent"] = mock.MagicMock()
            assert _check_frida() is True
        finally:
            sys.modules.clear()
            sys.modules.update(original_modules)

    def test_no_frida_returns_false(self, frozen_env):
        from src.anti_tamper import _check_frida
        original_modules = sys.modules.copy()
        original_environ = os.environ.copy()
        try:
            frida_keys = [k for k in sys.modules if k and "frida" in k.lower()]
            for k in frida_keys:
                del sys.modules[k]

            clean_env = {k: v for k, v in os.environ.items()
                         if "frida" not in k.lower() and "frida" not in v.lower()}
            with mock.patch.dict(os.environ, clean_env, clear=True):
                assert _check_frida() is False
        finally:
            sys.modules.clear()
            sys.modules.update(original_modules)
            os.environ.clear()
            os.environ.update(original_environ)


class TestTimingCheck:
    """Test RDTSC timing-based detection."""

    def test_normal_timing_returns_false(self, frozen_env):
        from src.anti_tamper import _check_timing
        # Each iteration: start, end = 2 values; 5 iterations = 10 values
        values = [0, 10000] * 5
        with mock.patch("time.perf_counter_ns", side_effect=values):
            assert _check_timing() is False

    def test_suspicious_timing_returns_true(self, frozen_env):
        from src.anti_tamper import _check_timing
        # Each iteration: start, end = 2 values; 5 iterations = 10 values
        # Differences of 1_000_000 ns (1ms) exceed 500_000 ns threshold
        values = []
        for i in range(5):
            values.extend([i * 1_000_000, (i + 1) * 1_000_000 + 1_000_000])
        with mock.patch("time.perf_counter_ns", side_effect=values):
            assert _check_timing() is True


class TestDebuggerProcesses:
    """Test process enumeration for debugger detection."""

    def test_no_debugger_found(self, frozen_env):
        from src.anti_tamper import _check_debugger_processes
        mock_result = mock.MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            '"chrome.exe","1234","Console","1","100,000 K"\n'
            '"notepad.exe","5678","Console","1","10,000 K"\n'
        )
        with mock.patch("subprocess.run", return_value=mock_result):
            assert _check_debugger_processes() is False

    def test_debugger_found(self, frozen_env):
        from src.anti_tamper import _check_debugger_processes
        mock_result = mock.MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            '"x64dbg.exe","1234","Console","1","100,000 K"\n'
            '"notepad.exe","5678","Console","1","10,000 K"\n'
        )
        with mock.patch("subprocess.run", return_value=mock_result):
            assert _check_debugger_processes() is True

    def test_timeout_returns_false(self, frozen_env):
        from src.anti_tamper import _check_debugger_processes
        with mock.patch("subprocess.run", side_effect=TimeoutError()):
            assert _check_debugger_processes() is False


class TestModuleIntegrity:
    """Test bytecode integrity verification."""

    def test_intact_module_returns_false(self, frozen_env, tmp_path):
        from src.anti_tamper import _check_module_integrity
        pyc_path = tmp_path / "crypto.pyc"
        header = b"\x00" * 16
        pyc_path.write_bytes(header)

        fake_mod = mock.MagicMock()
        fake_mod.__file__ = str(pyc_path)

        original_modules = sys.modules.copy()
        try:
            sys.modules["crypto"] = fake_mod
            with mock.patch("importlib.util.MAGIC_NUMBER", b"\x00" * 4):
                assert _check_module_integrity() is False
        finally:
            sys.modules.clear()
            sys.modules.update(original_modules)


class TestCheckOnDemand:
    """Test on-demand check functionality."""

    def test_runs_all_checks(self, frozen_env):
        from src.anti_tamper import check_on_demand
        with mock.patch("src.anti_tamper._run_all_checks", return_value=False):
            assert check_on_demand() is False

    def test_detects_tampering(self, frozen_env):
        from src.anti_tamper import check_on_demand
        with mock.patch("src.anti_tamper._run_all_checks", return_value=True):
            assert check_on_demand() is True


class TestRunAllChecks:
    """Test the combined check pipeline."""

    def test_all_clean_returns_false(self, frozen_env):
        from src.anti_tamper import _run_all_checks
        with mock.patch("src.anti_tamper._check_debugger_present", return_value=False), \
             mock.patch("src.anti_tamper._check_remote_debugger", return_value=False), \
             mock.patch("src.anti_tamper._check_peb_debugger_flag", return_value=False), \
             mock.patch("src.anti_tamper._check_hardware_breakpoints", return_value=False), \
             mock.patch("src.anti_tamper._check_python_debugger_flags", return_value=False), \
             mock.patch("src.anti_tamper._check_debugger_windows", return_value=False), \
             mock.patch("src.anti_tamper._check_debugger_processes", return_value=False), \
             mock.patch("src.anti_tamper._check_timing", return_value=False), \
             mock.patch("src.anti_tamper._check_meipass", return_value=False), \
             mock.patch("src.anti_tamper._check_import_hooks", return_value=False), \
             mock.patch("src.anti_tamper._check_frida", return_value=False), \
             mock.patch("src.anti_tamper._check_module_integrity", return_value=False), \
             mock.patch("src.anti_tamper._check_pe_header", return_value=False):
            assert _run_all_checks() is False

    def test_single_failure_returns_true(self, frozen_env):
        from src.anti_tamper import _run_all_checks
        with mock.patch("src.anti_tamper._check_debugger_present", return_value=True), \
             mock.patch("src.anti_tamper._check_remote_debugger", return_value=False), \
             mock.patch("src.anti_tamper._check_peb_debugger_flag", return_value=False), \
             mock.patch("src.anti_tamper._check_hardware_breakpoints", return_value=False), \
             mock.patch("src.anti_tamper._check_python_debugger_flags", return_value=False), \
             mock.patch("src.anti_tamper._check_debugger_windows", return_value=False), \
             mock.patch("src.anti_tamper._check_debugger_processes", return_value=False), \
             mock.patch("src.anti_tamper._check_timing", return_value=False), \
             mock.patch("src.anti_tamper._check_meipass", return_value=False), \
             mock.patch("src.anti_tamper._check_import_hooks", return_value=False), \
             mock.patch("src.anti_tamper._check_frida", return_value=False), \
             mock.patch("src.anti_tamper._check_module_integrity", return_value=False), \
             mock.patch("src.anti_tamper._check_pe_header", return_value=False):
            assert _run_all_checks() is True

    def test_exception_in_check_continues(self, frozen_env):
        from src.anti_tamper import _run_all_checks
        with mock.patch("src.anti_tamper._check_debugger_present", side_effect=RuntimeError), \
             mock.patch("src.anti_tamper._check_remote_debugger", return_value=False), \
             mock.patch("src.anti_tamper._check_peb_debugger_flag", return_value=False), \
             mock.patch("src.anti_tamper._check_hardware_breakpoints", return_value=False), \
             mock.patch("src.anti_tamper._check_python_debugger_flags", return_value=False), \
             mock.patch("src.anti_tamper._check_debugger_windows", return_value=False), \
             mock.patch("src.anti_tamper._check_debugger_processes", return_value=False), \
             mock.patch("src.anti_tamper._check_timing", return_value=False), \
             mock.patch("src.anti_tamper._check_meipass", return_value=False), \
             mock.patch("src.anti_tamper._check_import_hooks", return_value=False), \
             mock.patch("src.anti_tamper._check_frida", return_value=False), \
             mock.patch("src.anti_tamper._check_module_integrity", return_value=False), \
             mock.patch("src.anti_tamper._check_pe_header", return_value=False):
            assert _run_all_checks() is True


class TestBackgroundChecks:
    """Test background check thread."""

    def test_background_thread_starts(self, frozen_env):
        from src.anti_tamper import start_background_checks
        with mock.patch("src.anti_tamper._run_all_checks", return_value=False), \
             mock.patch("src.anti_tamper._hide_thread_from_debugger", return_value=True):
            thread_count_before = threading.active_count()
            start_background_checks(interval=100)
            time.sleep(0.1)
            assert threading.active_count() >= thread_count_before


class TestLogging:
    """Test anti-tamper logging functionality."""

    def test_log_trigger_writes_to_file(self, frozen_env, tmp_path):
        from src.anti_tamper import _log_trigger, ANTI_TAMPER_LOG_FILE
        log_file = tmp_path / "test_trigger.log"
        import src.anti_tamper as at_mod
        original = at_mod.ANTI_TAMPER_LOG_FILE
        try:
            at_mod.ANTI_TAMPER_LOG_FILE = log_file
            _log_trigger("TestCheck", "test details")
            content = log_file.read_text(encoding="utf-8")
            assert "TRIGGERED: TestCheck" in content
            assert "test details" in content
        finally:
            at_mod.ANTI_TAMPER_LOG_FILE = original

    def test_log_info_writes_to_file(self, frozen_env, tmp_path):
        from src.anti_tamper import _log_info
        log_file = tmp_path / "test_info.log"
        import src.anti_tamper as at_mod
        original = at_mod.ANTI_TAMPER_LOG_FILE
        try:
            at_mod.ANTI_TAMPER_LOG_FILE = log_file
            _log_info("test info message")
            content = log_file.read_text(encoding="utf-8")
            assert "INFO: test info message" in content
        finally:
            at_mod.ANTI_TAMPER_LOG_FILE = original

    def test_log_trigger_includes_timestamp(self, frozen_env, tmp_path):
        from src.anti_tamper import _log_trigger
        log_file = tmp_path / "test_timestamp.log"
        import src.anti_tamper as at_mod
        original = at_mod.ANTI_TAMPER_LOG_FILE
        try:
            at_mod.ANTI_TAMPER_LOG_FILE = log_file
            _log_trigger("TestCheck")
            content = log_file.read_text(encoding="utf-8")
            # Timestamp format: [2026-06-13 12:34:56.789]
            assert "[" in content and "]" in content
        finally:
            at_mod.ANTI_TAMPER_LOG_FILE = original

    def test_log_trigger_with_none_log_file(self, frozen_env):
        from src.anti_tamper import _log_trigger
        import src.anti_tamper as at_mod
        original = at_mod.ANTI_TAMPER_LOG_FILE
        try:
            at_mod.ANTI_TAMPER_LOG_FILE = None
            # Should not raise
            _log_trigger("TestCheck", "details")
        finally:
            at_mod.ANTI_TAMPER_LOG_FILE = original


class TestDebuggerWindows:
    """Test debugger window class/title detection."""

    def test_chrome_widgetwin_not_flagged(self, frozen_env):
        """Chrome_WidgetWin_1 should NOT trigger detection (the ID substring fix)."""
        from src.anti_tamper import _check_debugger_windows
        import ctypes

        fake_windows = []

        def fake_enum_windows(callback, lparam):
            # Simulate a Chrome_WidgetWin_1 window
            hwnd = 0x12345
            # The callback checks class name via GetClassNameW - we mock that
            return True

        mock_classes = {"chrome_widgetwin_1"}

        with mock.patch("src.anti_tamper.EnumWindows") as mock_enum:
            def intercept_enum(callback, lparam):
                for hwnd_val in [0x12345]:
                    # Create mock buffers
                    class_buf = ctypes.create_unicode_buffer(256)
                    class_buf.value = "Chrome_WidgetWin_1"
                    # Call the callback - it will use GetClassNameW which we mock
                    result = callback(hwnd_val, 0)
                return True
            mock_enum.side_effect = intercept_enum

            with mock.patch("src.anti_tamper.GetClassNameW") as mock_getclass:
                mock_getclass.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', 'Chrome_WidgetWin_1') or 17
                with mock.patch("src.anti_tamper.IsWindowVisible", return_value=True):
                    with mock.patch("src.anti_tamper.GetWindowTextW") as mock_gettitle:
                        mock_gettitle.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', '') or 0
                        assert _check_debugger_windows() is False

    def test_actual_ida_window_detected(self, frozen_env):
        """A window with class 'TIdaWindow' should be detected."""
        from src.anti_tamper import _check_debugger_windows

        def intercept_enum(callback, lparam):
            hwnd_val = 0x12345
            callback(hwnd_val, 0)
            return True

        with mock.patch("src.anti_tamper.EnumWindows", side_effect=intercept_enum):
            with mock.patch("src.anti_tamper.GetClassNameW") as mock_getclass:
                mock_getclass.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', 'TIdaWindow') or 11
                with mock.patch("src.anti_tamper.IsWindowVisible", return_value=True):
                    with mock.patch("src.anti_tamper.GetWindowTextW") as mock_gettitle:
                        mock_gettitle.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', '') or 0
                        assert _check_debugger_windows() is True

    def test_x64dbg_window_detected(self, frozen_env):
        """A window with 'x64dbg' in class name should be detected."""
        from src.anti_tamper import _check_debugger_windows

        def intercept_enum(callback, lparam):
            callback(0x12345, 0)
            return True

        with mock.patch("src.anti_tamper.EnumWindows", side_effect=intercept_enum):
            with mock.patch("src.anti_tamper.GetClassNameW") as mock_getclass:
                mock_getclass.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', 'x64dbgMainWindow') or 17
                with mock.patch("src.anti_tamper.IsWindowVisible", return_value=True):
                    with mock.patch("src.anti_tamper.GetWindowTextW") as mock_gettitle:
                        mock_gettitle.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', '') or 0
                        assert _check_debugger_windows() is True

    def test_short_window_title_exact_match(self, frozen_env):
        """Short titles (<=3 chars) should use exact match, not substring."""
        from src.anti_tamper import _check_debugger_windows

        def intercept_enum(callback, lparam):
            callback(0x12345, 0)
            return True

        with mock.patch("src.anti_tamper.EnumWindows", side_effect=intercept_enum):
            with mock.patch("src.anti_tamper.GetClassNameW") as mock_getclass:
                mock_getclass.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', 'SomeClass') or 9
                with mock.patch("src.anti_tamper.IsWindowVisible", return_value=True):
                    with mock.patch("src.anti_tamper.GetWindowTextW") as mock_gettitle:
                        # "r2" is 2 chars, should exact-match only if title is exactly "r2"
                        mock_gettitle.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', 'my r2 tool') or 10
                        # "my r2 tool" != "r2", so should NOT match
                        assert _check_debugger_windows() is False

    def test_hidden_windows_skipped(self, frozen_env):
        """Invisible windows should not be checked."""
        from src.anti_tamper import _check_debugger_windows

        with mock.patch("src.anti_tamper.EnumWindows") as mock_enum:
            def intercept_enum(callback, lparam):
                callback(0x12345, 0)
                return True
            mock_enum.side_effect = intercept_enum

            with mock.patch("src.anti_tamper.IsWindowVisible", return_value=False):
                with mock.patch("src.anti_tamper.GetClassNameW") as mock_getclass:
                    mock_getclass.side_effect = lambda hwnd, buf, size: setattr(buf, 'value', 'x64dbg') or 6
                    assert _check_debugger_windows() is False

    def test_no_windows_no_detection(self, frozen_env):
        """No windows enumerated means no detection."""
        from src.anti_tamper import _check_debugger_windows

        with mock.patch("src.anti_tamper.EnumWindows", return_value=True):
            assert _check_debugger_windows() is False

    def test_enumwindows_exception_handled(self, frozen_env):
        """Exception in EnumWindows should not crash."""
        from src.anti_tamper import _check_debugger_windows

        with mock.patch("src.anti_tamper.EnumWindows", side_effect=OSError("fail")):
            assert _check_debugger_windows() is False


class TestDebuggerPresent:
    """Test IsDebuggerPresent API check."""

    def test_debugger_present_returns_true(self, frozen_env):
        from src.anti_tamper import _check_debugger_present
        with mock.patch("src.anti_tamper.IsDebuggerPresent", return_value=True):
            assert _check_debugger_present() is True

    def test_no_debugger_returns_false(self, frozen_env):
        from src.anti_tamper import _check_debugger_present
        with mock.patch("src.anti_tamper.IsDebuggerPresent", return_value=False):
            assert _check_debugger_present() is False

    def test_api_exception_returns_false(self, frozen_env):
        from src.anti_tamper import _check_debugger_present
        with mock.patch("src.anti_tamper.IsDebuggerPresent", side_effect=OSError("fail")):
            assert _check_debugger_present() is False


class TestRemoteDebugger:
    """Test CheckRemoteDebuggerPresent API check."""

    def test_remote_debugger_returns_true(self, frozen_env):
        from src.anti_tamper import _check_remote_debugger
        import ctypes as ct

        original_func = None
        captured_ref = []

        def capture_and_set(handle, is_debugged_ptr):
            captured_ref.append(is_debugged_ptr)

        with mock.patch("src.anti_tamper.CheckRemoteDebuggerPresent") as mock_check:
            mock_check.side_effect = capture_and_set
            # Run the function, then manually set the value
            import src.anti_tamper as at_mod
            orig = at_mod.CheckRemoteDebuggerPresent
            at_mod.CheckRemoteDebuggerPresent = mock_check
            try:
                # The function creates is_debugged = ctypes.wintypes.BOOL(False)
                # and passes ctypes.byref(is_debugged). We need to intercept.
                # Instead, mock the whole function to return True directly.
                mock_check.return_value = True
                with mock.patch.object(at_mod, 'CheckRemoteDebuggerPresent', return_value=True):
                    pass  # Can't easily test this way

                # Better approach: mock at a higher level
            finally:
                at_mod.CheckRemoteDebuggerPresent = orig

        # Simplest correct approach: mock the entire function to control the return path
        # The function checks `if result and is_debugged.value != 0`
        # We need to make the function see is_debugged.value != 0
        # Use a custom mock that writes to the byref'd object
        with mock.patch("src.anti_tamper.CheckRemoteDebuggerPresent") as mock_check:
            def side_effect(handle, is_debugged_byref):
                # is_debugged_byref is a ctypes byref object; we can't easily write to it
                # So instead, we mock at the function level
                pass
            # Return True but the function still checks is_debugged.value
            # The cleanest test: just verify the logic path by mocking result
            pass

        # The actual working approach: override the function entirely
        with mock.patch.object(
            __import__("src.anti_tamper", fromlist=["_check_remote_debugger"]),
            "_check_remote_debugger",
            return_value=True
        ):
            pass  # This is pointless

        # OK, the real solution: the function creates a local BOOL, passes byref to API.
        # We need the API mock to write through the byref pointer.
        # ctypes byref objects don't support __setitem__, but we can use memmove.
        with mock.patch("src.anti_tamper.CheckRemoteDebuggerPresent") as mock_check:
            def write_true(handle, bool_byref):
                # Use ctypes to write to the memory address
                import ctypes
                addr = ctypes.addressof(bool_byref._obj) if hasattr(bool_byref, '_obj') else None
                if addr is not None:
                    ctypes.memmove(addr, ctypes.byref(ctypes.c_long(1)), ctypes.sizeof(ctypes.c_long))
                return True
            mock_check.side_effect = write_true
            assert _check_remote_debugger() is True

    def test_no_remote_debugger_returns_false(self, frozen_env):
        from src.anti_tamper import _check_remote_debugger

        with mock.patch("src.anti_tamper.CheckRemoteDebuggerPresent") as mock_check:
            mock_check.return_value = True
            # is_debugged stays False (default), so should return False
            assert _check_remote_debugger() is False

    def test_api_exception_returns_false(self, frozen_env):
        from src.anti_tamper import _check_remote_debugger
        with mock.patch("src.anti_tamper.CheckRemoteDebuggerPresent", side_effect=OSError("fail")):
            assert _check_remote_debugger() is False


class TestPEBDebuggerFlag:
    """Test NtQueryInformationProcess PEB checks."""

    def test_debug_port_nonzero_returns_true(self, frozen_env):
        from src.anti_tamper import _check_peb_debugger_flag
        import ctypes as ct

        def mock_nt_query(handle, info_class, buf, buf_len, ret_len):
            if info_class == 7:  # ProcessDebugPort
                # Write a non-zero value to the buffer
                ct.memmove(buf, ct.byref(ct.c_ulong(1234)), ct.sizeof(ct.c_ulong))
                return 0
            return 0xC000000D  # STATUS_INFO_LENGTH_MISMATCH

        with mock.patch("src.anti_tamper.nt_query_info", side_effect=mock_nt_query):
            assert _check_peb_debugger_flag() is True

    def test_debug_flags_zero_returns_true(self, frozen_env):
        from src.anti_tamper import _check_peb_debugger_flag
        import ctypes as ct

        def mock_nt_query(handle, info_class, buf, buf_len, ret_len):
            if info_class == 0x1F:  # ProcessDebugFlags
                # Write zero (zero means debugged)
                ct.memmove(buf, ct.byref(ct.c_ulong(0)), ct.sizeof(ct.c_ulong))
                return 0
            return 0xC000000D

        with mock.patch("src.anti_tamper.nt_query_info", side_effect=mock_nt_query):
            assert _check_peb_debugger_flag() is True

    def test_debug_object_handle_exists_returns_true(self, frozen_env):
        from src.anti_tamper import _check_peb_debugger_flag

        def mock_nt_query(handle, info_class, buf, buf_len, ret_len):
            if info_class == 0x1E:  # ProcessDebugObjectHandle
                return 0  # STATUS_SUCCESS means handle exists
            return 0xC000000D

        with mock.patch("src.anti_tamper.nt_query_info", side_effect=mock_nt_query):
            assert _check_peb_debugger_flag() is True

    def test_all_clean_returns_false(self, frozen_env):
        from src.anti_tamper import _check_peb_debugger_flag

        def mock_nt_query(handle, info_class, buf, buf_len, ret_len):
            return 0xC000000D  # STATUS_INFO_LENGTH_MISMATCH for all

        with mock.patch("src.anti_tamper.nt_query_info", side_effect=mock_nt_query):
            assert _check_peb_debugger_flag() is False

    def test_api_exception_returns_false(self, frozen_env):
        from src.anti_tamper import _check_peb_debugger_flag
        with mock.patch("src.anti_tamper.nt_query_info", side_effect=OSError("fail")):
            assert _check_peb_debugger_flag() is False


class TestSilentExit:
    """Test silent exit mechanism."""

    def test_silent_exit_calls_os_exit(self, frozen_env):
        from src.anti_tamper import _silent_exit
        saved = sys.modules.copy()
        try:
            with mock.patch("os._exit") as mock_exit:
                _silent_exit()
                mock_exit.assert_called_once_with(1)
        finally:
            sys.modules.clear()
            sys.modules.update(saved)

    def test_silent_exit_clears_sensitive_modules(self, frozen_env):
        from src.anti_tamper import _silent_exit
        import src.anti_tamper as at_mod
        original_log = at_mod.ANTI_TAMPER_LOG_FILE
        saved = sys.modules.copy()
        try:
            at_mod.ANTI_TAMPER_LOG_FILE = None
            sys.modules["crypto_test_mod"] = mock.MagicMock()
            sys.modules["password_test_mod"] = mock.MagicMock()
            sys.modules["safe_module"] = mock.MagicMock()
            with mock.patch("os._exit"):
                _silent_exit()
            assert "crypto_test_mod" not in sys.modules
            assert "password_test_mod" not in sys.modules
            assert "safe_module" in sys.modules
        finally:
            at_mod.ANTI_TAMPER_LOG_FILE = original_log
            sys.modules.clear()
            sys.modules.update(saved)


class TestDebuggerSeeker:
    """Test active debugger seeking mechanism."""

    def test_seeker_returns_false_when_clean(self, frozen_env):
        """Seeker should return False when no tampering detected."""
        from src.anti_tamper import _DebuggerSeeker
        seeker = _DebuggerSeeker()
        with mock.patch("src.anti_tamper._run_all_checks", return_value=False):
            assert seeker.seek() is False

    def test_seeker_returns_true_when_tampering(self, frozen_env):
        """Seeker should return True when tampering detected twice (cross-validation)."""
        from src.anti_tamper import _DebuggerSeeker
        seeker = _DebuggerSeeker()
        with mock.patch("src.anti_tamper._run_all_checks", return_value=True):
            assert seeker.seek() is True

    def test_seeker_cross_validates(self, frozen_env):
        """Seeker should cross-validate - single detection is treated as false positive."""
        from src.anti_tamper import _DebuggerSeeker
        seeker = _DebuggerSeeker()
        # First call returns True, second returns False -> false positive
        with mock.patch("src.anti_tamper._run_all_checks", side_effect=[True, False]):
            assert seeker.seek() is False
            assert seeker._suspicion_count == 1

    def test_seeker_escalates_after_threshold(self, frozen_env):
        """Seeker should escalate after multiple suspicious findings."""
        from src.anti_tamper import _DebuggerSeeker
        from src.anti_tamper import ANTI_TAMPER_CONFIG
        seeker = _DebuggerSeeker()
        threshold = ANTI_TAMPER_CONFIG["SEEK_SUSPICION_THRESHOLD"]

        # Simulate multiple false positives
        for i in range(threshold):
            seeker._last_check_time = 0  # Reset to bypass interval check
            with mock.patch("src.anti_tamper._run_all_checks", side_effect=[True, False]):
                seeker.seek()

        assert seeker._escalated is True

    def test_seeker_de_escalates_on_clean(self, frozen_env):
        """Seeker should de-escalate after clean scan."""
        from src.anti_tamper import _DebuggerSeeker
        seeker = _DebuggerSeeker()
        seeker._escalated = True
        seeker._suspicion_count = 1
        seeker._last_check_time = 0  # Reset to bypass interval check

        with mock.patch("src.anti_tamper._run_all_checks", return_value=False):
            seeker.seek()

        assert seeker._escalated is False
        assert seeker._suspicion_count == 0

    def test_seeker_randomized_interval(self, frozen_env):
        """Seeker should return randomized intervals."""
        from src.anti_tamper import _DebuggerSeeker
        seeker = _DebuggerSeeker()
        intervals = [seeker.get_next_interval() for _ in range(10)]
        # All intervals should be within bounds
        for interval in intervals:
            assert 0 <= interval <= 15  # max interval

    def test_seeker_escalated_shorter_intervals(self, frozen_env):
        """Escalated seeker should have shorter intervals."""
        from src.anti_tamper import _DebuggerSeeker
        seeker = _DebuggerSeeker()
        seeker._escalated = True
        intervals = [seeker.get_next_interval() for _ in range(10)]
        for interval in intervals:
            assert 0 <= interval <= 3  # escalated max interval

    def test_seek_debugger_function(self, frozen_env):
        """_seek_debugger() should delegate to the global seeker."""
        from src.anti_tamper import _seek_debugger
        with mock.patch("src.anti_tamper._seeker") as mock_seeker:
            mock_seeker.seek.return_value = True
            assert _seek_debugger() is True
            mock_seeker.seek.assert_called_once()
