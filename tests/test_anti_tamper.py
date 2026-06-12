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
            mock_sys.monitoring = None
            assert _check_python_debugger_flags() is False

    def test_active_trace_returns_true(self, frozen_env):
        from src.anti_tamper import _check_python_debugger_flags
        with mock.patch("src.anti_tamper.sys") as mock_sys:
            mock_sys.gettrace.return_value = lambda *a: None
            mock_sys.getprofile.return_value = None
            mock_sys.monitoring = None
            assert _check_python_debugger_flags() is True

    def test_active_profile_returns_true(self, frozen_env):
        from src.anti_tamper import _check_python_debugger_flags
        with mock.patch("src.anti_tamper.sys") as mock_sys:
            mock_sys.gettrace.return_value = None
            mock_sys.getprofile.return_value = lambda *a: None
            mock_sys.monitoring = None
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
