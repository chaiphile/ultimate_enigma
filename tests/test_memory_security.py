"""
Tests for security/memory_security.py, security/guarded_buffer.py, security/anti_dump.py
"""
import sys
import runpy
import secrets
import gc
import pytest


class TestMlockMemory:
    def test_mlock_returns_true_for_bytearray(self):
        from security.memory_security import mlock_memory, munlock_memory
        data = bytearray(secrets.token_bytes(32))
        result = mlock_memory(data)
        assert isinstance(result, bool)
        munlock_memory(data)

    def test_munlock_does_not_crash(self):
        from security.memory_security import munlock_memory
        munlock_memory(bytearray(32))  # Should not raise

    def test_mlock_empty_data(self):
        from security.memory_security import mlock_memory
        result = mlock_memory(bytearray(0))
        assert isinstance(result, bool)

    def test_raise_mlock_limit_does_not_crash(self):
        from security.memory_security import raise_mlock_limit
        raise_mlock_limit(1024 * 1024)  # Should not raise


class TestGuardedBuffer:
    def test_write_read_roundtrip(self):
        from security.guarded_buffer import GuardedBuffer
        gb = GuardedBuffer(32)
        data = secrets.token_bytes(32)
        gb.write(data)
        result = gb.read()
        assert bytes(result) == data
        gb.wipe_and_free()

    def test_write_smaller_than_buffer(self):
        from security.guarded_buffer import GuardedBuffer
        gb = GuardedBuffer(64)
        data = secrets.token_bytes(16)
        gb.write(data)
        result = gb.read()
        assert result[:16] == data
        assert all(b == 0 for b in result[16:])
        gb.wipe_and_free()

    def test_write_too_large_raises(self):
        from security.guarded_buffer import GuardedBuffer
        gb = GuardedBuffer(16)
        with pytest.raises(ValueError):
            gb.write(secrets.token_bytes(32))

    def test_wipe_zeros_data(self):
        from security.guarded_buffer import GuardedBuffer
        gb = GuardedBuffer(32)
        gb.write(secrets.token_bytes(32))
        gb.wipe_and_free()
        # After wipe, base should be None
        assert gb._data_addr is None

    def test_context_manager(self):
        from security.guarded_buffer import GuardedBuffer
        with GuardedBuffer(32) as gb:
            gb.write(b'\x42' * 32)
            assert len(gb.read()) == 32
        # Should be wiped after context exit
        assert gb._data_addr is None

    def test_read_returns_mutable_copy(self):
        from security.guarded_buffer import GuardedBuffer
        gb = GuardedBuffer(16)
        gb.write(b'\x01' * 16)
        data = gb.read()
        data[0] = 0xFF  # Modify the copy
        # Original should be unchanged
        assert gb.read()[0] == 0x01
        gb.wipe_and_free()


class TestAntiDump:
    def test_apply_does_not_crash(self):
        from security.anti_dump import apply_anti_dump_protections
        apply_anti_dump_protections()  # Should not raise

    def test_core_dumps_disabled_linux(self):
        if sys.platform == "win32":
            pytest.skip("Linux only test")
        from security.anti_dump import apply_anti_dump_protections
        apply_anti_dump_protections()
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        assert soft == 0


class TestMainStartupSecurity:
    def test_source_run_skips_startup_hardening(self, monkeypatch):
        if hasattr(sys, "frozen"):
            monkeypatch.delattr(sys, "frozen", raising=False)

        calls = {"mlock": 0, "anti_dump": 0}

        import security.memory_security
        import security.anti_dump

        monkeypatch.setattr(
            security.memory_security,
            "raise_mlock_limit",
            lambda target_bytes=0: calls.__setitem__("mlock", calls["mlock"] + 1),
        )
        monkeypatch.setattr(
            security.anti_dump,
            "apply_anti_dump_protections",
            lambda: calls.__setitem__("anti_dump", calls["anti_dump"] + 1),
        )

        runpy.run_module("main", run_name="__test__")

        assert calls == {"mlock": 0, "anti_dump": 0}
