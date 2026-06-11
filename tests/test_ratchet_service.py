"""Unit tests for RatchetService concurrency mechanisms.

Tests cover:
- Per-friend lock acquisition and release
- Ordered multi-lock acquisition (deadlock prevention)
- Lock timeout behavior
- Lock cleanup
- Concurrency stats and diagnostics
- Deadlock detection utility
"""

import threading
import time
import pytest
from unittest.mock import patch, MagicMock

from services.ratchet_service import RatchetService
from src.exceptions import ConcurrencyError
from src.constants import CONCURRENCY_CONSTANTS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_locks():
    """Reset all friend locks before and after each test."""
    RatchetService._friend_locks.clear()
    RatchetService._friend_lock_timestamps.clear()
    yield
    RatchetService._friend_locks.clear()
    RatchetService._friend_lock_timestamps.clear()


# ---------------------------------------------------------------------------
# Per-Friend Lock Basics
# ---------------------------------------------------------------------------

class TestFriendLockBasics:
    def test_get_friend_lock_creates_new(self):
        """_get_friend_lock should create a new RLock for unknown friends."""
        lock = RatchetService._get_friend_lock("Alice")
        assert lock is not None
        assert "Alice" in RatchetService._friend_locks

    def test_get_friend_lock_returns_same(self):
        """Repeated calls should return the same lock instance."""
        lock1 = RatchetService._get_friend_lock("Bob")
        lock2 = RatchetService._get_friend_lock("Bob")
        assert lock1 is lock2

    def test_different_friends_get_different_locks(self):
        """Each friend should have a unique lock."""
        lock_a = RatchetService._get_friend_lock("Alice")
        lock_b = RatchetService._get_friend_lock("Bob")
        assert lock_a is not lock_b

    def test_lock_timestamps_tracked(self):
        """Lock creation should be timestamped."""
        RatchetService._get_friend_lock("Charlie")
        assert "Charlie" in RatchetService._friend_lock_timestamps
        ts = RatchetService._friend_lock_timestamps["Charlie"]
        assert isinstance(ts, float)
        assert ts > 0


# ---------------------------------------------------------------------------
# Lock Acquisition with Timeout
# ---------------------------------------------------------------------------

class TestLockAcquisition:
    def test_acquire_friend_lock_success(self):
        """_acquire_friend_lock should succeed for uncontested locks."""
        lock = RatchetService._acquire_friend_lock("Dave")
        assert lock is not None
        lock.release()

    def test_acquire_with_custom_timeout(self):
        """Custom timeout should be respected."""
        lock = RatchetService._acquire_friend_lock("Eve", timeout=10.0)
        assert lock is not None
        lock.release()

    def test_acquire_timeout_raises(self):
        """Should raise ConcurrencyError when lock cannot be acquired."""
        # First, hold the lock in the main thread
        lock = RatchetService._get_friend_lock("Frank")
        lock.acquire()  # Held by main thread

        # Try to acquire from another thread with short timeout
        result = []

        def try_acquire():
            try:
                RatchetService._acquire_friend_lock("Frank", timeout=0.5)
                result.append("acquired")
            except ConcurrencyError as e:
                result.append("timeout")

        t = threading.Thread(target=try_acquire)
        t.start()
        t.join(timeout=5.0)

        lock.release()  # Release our hold

        assert result == ["timeout"]

    def test_acquire_timeout_message(self):
        """ConcurrencyError message should include friend name and timeout."""
        lock = RatchetService._get_friend_lock("Grace")
        lock.acquire()

        try:
            RatchetService._acquire_friend_lock("Grace", timeout=0.1)
            pytest.fail("Should have raised ConcurrencyError")
        except ConcurrencyError as e:
            assert "Grace" in str(e)
            assert "0.1" in str(e)
        finally:
            lock.release()

    def test_rlock_allows_recursive_acquisition(self):
        """RLock should allow the same thread to acquire multiple times."""
        lock = RatchetService._acquire_friend_lock("Heidi")
        # Acquire again from same thread - should succeed without blocking
        acquired = lock.acquire(blocking=False)
        assert acquired, "RLock should allow reentrant acquisition"
        lock.release()
        lock.release()


# ---------------------------------------------------------------------------
# Ordered Multi-Lock Acquisition (Deadlock Prevention)
# ---------------------------------------------------------------------------

class TestOrderedLocks:
    def test_acquire_single_lock(self):
        """Ordered acquisition with a single friend should work."""
        locks = RatchetService.acquire_friend_locks_ordered(["Alice"])
        assert len(locks) == 1
        locks[0].release()

    def test_acquire_multiple_in_order(self):
        """Multiple locks should be acquired in alphabetical order."""
        locks = RatchetService.acquire_friend_locks_ordered(
            ["Charlie", "Alice", "Bob"]
        )
        assert len(locks) == 3
        # All should be acquired (order is alphabetical)
        for lock in locks:
            assert lock is not None
        # Release in reverse order
        for lock in reversed(locks):
            lock.release()

    def test_deduplication(self):
        """Duplicate friend names should be deduplicated."""
        locks = RatchetService.acquire_friend_locks_ordered(
            ["Alice", "Bob", "Alice", "Charlie", "Bob"]
        )
        assert len(locks) == 3
        for lock in locks:
            lock.release()

    def test_ordering_is_case_insensitive(self):
        """Ordering should be case-insensitive."""
        locks = RatchetService.acquire_friend_locks_ordered(
            ["charlie", "alice", "Bob"]
        )
        assert len(locks) == 3
        for lock in locks:
            lock.release()

    def test_empty_list(self):
        """Empty friend list should return empty lock list."""
        locks = RatchetService.acquire_friend_locks_ordered([])
        assert locks == []

    def test_ordered_acquire_releases_on_failure(self):
        """If acquisition fails, previously acquired locks should be released."""
        # Pre-acquire Bob's lock to cause failure
        bob_lock = RatchetService._get_friend_lock("Bob")
        bob_lock.acquire()

        try:
            with pytest.raises(ConcurrencyError, match="Bob"):
                RatchetService.acquire_friend_locks_ordered(
                    ["Alice", "Bob", "Charlie"], timeout=0.5
                )

            # Alice's lock should have been released before the exception
            alice_lock = RatchetService._get_friend_lock("Alice")
            # Try non-blocking acquire - should succeed since it was released
            acquired = alice_lock.acquire(blocking=False)
            assert acquired, "Alice's lock should have been released"
            if acquired:
                alice_lock.release()
        finally:
            bob_lock.release()

    def test_no_deadlock_with_crossed_threads(self):
        """Two threads acquiring locks in different orders should not deadlock.

        This is the key deadlock prevention test. Both threads use
        acquire_friend_locks_ordered which guarantees alphabetical ordering.
        """
        results = []
        barrier = threading.Barrier(2, timeout=10.0)
        errors = []

        def thread_a():
            try:
                barrier.wait()
                locks = RatchetService.acquire_friend_locks_ordered(
                    ["Alice", "Bob"], timeout=5.0
                )
                time.sleep(0.1)  # Hold locks briefly
                for lock in reversed(locks):
                    lock.release()
                results.append("A_done")
            except Exception as e:
                errors.append(("A", e))

        def thread_b():
            try:
                barrier.wait()
                # Note: different order in input, but acquire_friend_locks_ordered
                # sorts them, so this is safe!
                locks = RatchetService.acquire_friend_locks_ordered(
                    ["Bob", "Alice"], timeout=5.0
                )
                time.sleep(0.1)
                for lock in reversed(locks):
                    lock.release()
                results.append("B_done")
            except Exception as e:
                errors.append(("B", e))

        t1 = threading.Thread(target=thread_a)
        t2 = threading.Thread(target=thread_b)
        t1.start()
        t2.start()
        t1.join(timeout=15.0)
        t2.join(timeout=15.0)

        assert not errors, f"Errors occurred: {errors}"
        assert "A_done" in results
        assert "B_done" in results


# ---------------------------------------------------------------------------
# Lock Cleanup
# ---------------------------------------------------------------------------

class TestLockCleanup:
    def test_cleanup_with_active_friends(self):
        """cleanup_friend_locks should remove locks for inactive friends."""
        # Create locks for several friends
        RatchetService._get_friend_lock("Alice")
        RatchetService._get_friend_lock("Bob")
        RatchetService._get_friend_lock("Charlie")

        # Cleanup with only Alice active
        removed = RatchetService.cleanup_friend_locks(active_friends=["Alice"])
        assert removed == 2
        assert "Alice" in RatchetService._friend_locks
        assert "Bob" not in RatchetService._friend_locks
        assert "Charlie" not in RatchetService._friend_locks

    def test_cleanup_preserves_held_locks(self):
        """Cleanup should not remove locks that are currently held."""
        lock = RatchetService._get_friend_lock("Held")
        lock.acquire()

        try:
            removed = RatchetService.cleanup_friend_locks(active_friends=[])
            # The held lock should be skipped
            assert removed == 0
            assert "Held" in RatchetService._friend_locks
        finally:
            lock.release()

    def test_cleanup_by_age(self):
        """Cleanup without active_friends should use age-based expiry."""
        # Create a lock and fake an old timestamp
        RatchetService._get_friend_lock("OldFriend")
        RatchetService._friend_lock_timestamps["OldFriend"] = time.monotonic() - 100000

        removed = RatchetService.cleanup_friend_locks()
        assert removed == 1
        assert "OldFriend" not in RatchetService._friend_locks

    def test_cleanup_does_not_remove_fresh_locks(self):
        """Fresh locks should not be removed by age-based cleanup."""
        RatchetService._get_friend_lock("Fresh")

        removed = RatchetService.cleanup_friend_locks()
        assert removed == 0
        assert "Fresh" in RatchetService._friend_locks


# ---------------------------------------------------------------------------
# Stats & Diagnostics
# ---------------------------------------------------------------------------

class TestStatsAndDiagnostics:
    def test_get_lock_stats_empty(self):
        """Stats should show zeros for empty lock dict."""
        stats = RatchetService.get_lock_stats()
        assert stats["total_locks"] == 0
        assert stats["total_timestamps"] == 0

    def test_get_lock_stats_with_locks(self):
        """Stats should reflect actual lock counts."""
        RatchetService._get_friend_lock("A")
        RatchetService._get_friend_lock("B")

        stats = RatchetService.get_lock_stats()
        assert stats["total_locks"] == 2
        assert stats["total_timestamps"] == 2

    def test_detect_potential_deadlock_no_overlap(self):
        """Non-overlapping lock sets should not deadlock."""
        assert not RatchetService.detect_potential_deadlock(
            ["Alice", "Bob"], ["Charlie", "Dave"]
        )

    def test_detect_potential_deadlock_single_overlap(self):
        """Single overlap cannot deadlock (need at least 2 for cycle)."""
        assert not RatchetService.detect_potential_deadlock(
            ["Alice", "Bob"], ["Bob", "Charlie"]
        )

    def test_detect_potential_deadlock_compatible_ordering(self):
        """Compatible orderings should not deadlock."""
        # Both would sort to Alice, Bob - compatible
        assert not RatchetService.detect_potential_deadlock(
            ["Alice", "Bob", "Charlie"], ["Bob", "Alice", "Dave"]
        )

    def test_detect_potential_deadlock_identical_sets(self):
        """Identical lock sets should not deadlock (same ordering)."""
        assert not RatchetService.detect_potential_deadlock(
            ["Alice", "Bob"], ["Alice", "Bob"]
        )


# ---------------------------------------------------------------------------
# Thread Safety Stress Test
# ---------------------------------------------------------------------------

class TestConcurrencyStress:
    def test_concurrent_lock_acquisition(self):
        """Multiple threads acquiring different locks concurrently."""
        results = []
        lock = threading.Lock()
        errors = []

        def worker(name):
            try:
                friend_lock = RatchetService._acquire_friend_lock(name, timeout=5.0)
                time.sleep(0.05)
                with lock:
                    results.append(name)
                friend_lock.release()
            except Exception as e:
                errors.append((name, e))

        threads = []
        names = [f"Friend_{i}" for i in range(10)]
        for name in names:
            t = threading.Thread(target=worker, args=(name,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=15.0)

        assert not errors, f"Errors: {errors}"
        assert sorted(results) == sorted(names)

    def test_same_friend_serial_execution(self):
        """Operations on the same friend should be serialized."""
        order = []
        lock = threading.Lock()
        errors = []

        def worker(i):
            try:
                friend_lock = RatchetService._acquire_friend_lock("Shared", timeout=10.0)
                with lock:
                    order.append(f"start_{i}")
                time.sleep(0.05)
                with lock:
                    order.append(f"end_{i}")
                friend_lock.release()
            except Exception as e:
                errors.append((i, e))

        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=15.0)

        assert not errors, f"Errors: {errors}"

        # Verify serialization: no start_X should appear between
        # start_Y and end_Y for the same friend
        for i in range(5):
            start_idx = order.index(f"start_{i}")
            end_idx = order.index(f"end_{i}")
            # Between start and end, there should be no other start/end
            between = order[start_idx + 1:end_idx]
            assert len(between) == 0, (
                f"Lock for 'Shared' was not serialized: "
                f"between start_{i} and end_{i} found: {between}"
            )
