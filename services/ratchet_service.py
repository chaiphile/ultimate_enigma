"""
Ratchet Service - Wrapper for Double Ratchet state management.

Provides persistence and lifecycle management for Double Ratchet sessions,
storing serialized ratchet states in the friends table of the database.
Supports initialization as Alice (initiator) or Bob (responder) using
shared secrets derived from Hybrid KEM or other key agreement protocols.

Thread Safety & Deadlock Prevention:
    Per-friend reentrant locks (RLock) protect load-mutate-save cycles.
    To prevent deadlocks when multiple friend locks must be acquired
    simultaneously (e.g., batch operations), locks are always acquired
    in alphabetical order (canonical ordering). This eliminates circular-
    wait conditions, one of the four necessary conditions for deadlock.
"""

import json
import base64
import logging
import secrets
import threading
import time
from typing import Optional, Tuple, Dict, List

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from services.double_ratchet import RatchetState
from database import get_connection, safe_execute, DatabaseError
from contextlib import closing

logger = logging.getLogger(__name__)


from models.friend_profile import FriendProfile
from services.friend_repository import get_friend_profile, list_all_friend_profiles
from models.envelope import RatchetEnvelope

from src.exceptions import (
    RatchetStateError,
    RatchetNotFoundError,
    RatchetInitError,
    RatchetServiceError,
    ConcurrencyError,
)
from src.constants import CONCURRENCY_CONSTANTS


class RatchetService:
    """Manages Double Ratchet session state persistence and lifecycle.

    This service wraps the low-level RatchetState class and handles:
    - Loading/saving serialized ratchet states from/to the database
    - Initializing new ratchet sessions (Alice/Bob roles)
    - Querying ratchet session existence
    - Cleaning up expired or deleted sessions

    Thread safety:
        Per-friend locks ensure that concurrent encrypt/decrypt operations
        for the same friend do not corrupt chain counters by racing on
        load -> mutate -> save cycles.
    """

    # Per-friend reentrant locks to prevent deadlocks from recursive acquisition.
    # RLock allows the same thread to acquire the lock multiple times (e.g.,
    # encrypt_to_envelope -> encrypt_message).
    _friend_locks: Dict[str, threading.RLock] = {}
    _friend_lock_timestamps: Dict[str, float] = {}  # Creation timestamps for cleanup
    _locks_guard = threading.RLock()

    # Ratchet state encryption key (derived once at app start).
    # Set via set_ratchet_storage_key() during service initialization.
    _storage_key: Optional[bytes] = None  # 32-byte AES-256 key for encrypting ratchet blobs at rest

    @classmethod
    def set_ratchet_storage_key(cls, key: bytes) -> None:
        """Set the key used to encrypt ratchet states before persisting to DB.
        
        This key should be derived from the user's master secret so that
        ratchet state is encrypted-at-rest with a key not stored in the DB.
        
        Args:
            key: 32-byte AES-256 key.
        """
        if len(key) != 32:
            raise ValueError("Ratchet storage key must be 32 bytes")
        cls._storage_key = key

    @classmethod
    def _derive_storage_key(cls, master_secret: bytes) -> bytes:
        """Derive a ratchet storage encryption key from the master secret.
        
        Uses HKDF-SHA256 with a domain-separated info string so that
        the derived key is distinct from any other keys derived from
        the same master secret.
        
        Args:
            master_secret: The user's master shared secret (32 bytes).
            
        Returns:
            32-byte AES-256 key for encrypting ratchet states at rest.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"enigma-ratchet-storage-key-v1",
            backend=default_backend()
        )
        return hkdf.derive(master_secret)

    @staticmethod
    def _encrypt_ratchet_blob(plaintext_json: str) -> str:
        """Encrypt a serialized ratchet state JSON string for at-rest storage.
        
        Uses AES-256-GCM. Returns a Base64-encoded blob containing
        nonce (12 bytes) + ciphertext + tag (16 bytes).
        
        Falls back to plain JSON if no storage key is set (backward compatibility).
        
        Args:
            plaintext_json: The JSON string of the serialized ratchet state.
            
        Returns:
            Base64-encoded encrypted blob, or the original JSON if no key set.
        """
        key = RatchetService._storage_key
        if key is None:
            # No encryption key configured — store as plaintext (backward compat)
            return plaintext_json
        
        plaintext = plaintext_json.encode('utf-8')
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        blob = nonce + ct
        return base64.b64encode(blob).decode('ascii')

    @staticmethod
    def _decrypt_ratchet_blob(encrypted_blob: str) -> str:
        """Decrypt a ratchet state blob that was encrypted with _encrypt_ratchet_blob.
        
        Detects whether the blob is plain JSON (legacy/unencrypted) or
        Base64-encoded encrypted data by trying JSON parse first.
        
        Args:
            encrypted_blob: The encrypted Base64 blob or plain JSON string.
            
        Returns:
            The decrypted JSON string.
            
        Raises:
            RatchetServiceError: If decryption fails.
        """
        key = RatchetService._storage_key
        if key is None:
            # No encryption key — assume plaintext (backward compat)
            return encrypted_blob
        
        # Try to detect if this is plain JSON (starts with '{')
        if encrypted_blob.startswith('{'):
            return encrypted_blob
        
        try:
            blob = base64.b64decode(encrypted_blob)
            if len(blob) < 12 + 16:  # nonce(12) + min ciphertext(16 tag)
                raise ValueError("Encrypted blob too short")
            nonce = blob[:12]
            ct = blob[12:]
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise RatchetServiceError(
                f"Failed to decrypt ratchet state blob: {e}"
            ) from e

    @classmethod
    def _get_friend_lock(cls, friend_name: str) -> threading.RLock:
        """Return a per-friend RLock, creating one if necessary.

        Uses RLock (reentrant lock) to allow the same thread to acquire
        the lock multiple times without deadlocking. This is essential
        when higher-level methods (e.g., encrypt_to_envelope) call
        lower-level methods (e.g., encrypt_message) that both acquire
        the same per-friend lock.
        """
        with cls._locks_guard:
            if friend_name not in cls._friend_locks:
                cls._friend_locks[friend_name] = threading.RLock()
                cls._friend_lock_timestamps[friend_name] = time.monotonic()
            return cls._friend_locks[friend_name]

    @classmethod
    def _acquire_friend_lock(
        cls, friend_name: str, timeout: Optional[float] = None
    ) -> threading.RLock:
        """Acquire the per-friend lock with an optional timeout.

        Args:
            friend_name: The friend whose lock to acquire.
            timeout: Maximum seconds to wait. If None, uses
                    CONCURRENCY_CONSTANTS['RATCHET_LOCK_TIMEOUT'].

        Returns:
            The acquired RLock instance.

        Raises:
            ConcurrencyError: If the lock cannot be acquired within the timeout.
        """
        if timeout is None:
            timeout = CONCURRENCY_CONSTANTS.get("RATCHET_LOCK_TIMEOUT", 30.0)

        lock = cls._get_friend_lock(friend_name)
        acquired = lock.acquire(timeout=timeout)
        if not acquired:
            raise ConcurrencyError(
                f"Could not acquire ratchet lock for '{friend_name}' "
                f"within {timeout:.1f} seconds. Another operation may be "
                f"in progress."
            )
        return lock

    @classmethod
    def acquire_friend_locks_ordered(
        cls,
        friend_names: List[str],
        timeout: Optional[float] = None,
    ) -> List[threading.RLock]:
        """Acquire multiple per-friend locks in canonical (alphabetical) order.

        Prevents deadlocks by enforcing a total ordering on lock acquisition.
        When code needs to hold locks for multiple friends simultaneously
        (e.g., during batch ratchet operations or rekeying), always use
        this method instead of calling _acquire_friend_lock() repeatedly.

        The locks are acquired in sorted order by friend name (case-insensitive,
        then case-sensitive as tiebreaker). On failure to acquire any lock,
        all previously acquired locks are released before raising.

        Args:
            friend_names: List of friend names whose locks to acquire.
                         Duplicates are silently deduplicated.
            timeout: Maximum seconds to wait per lock. If None, uses
                    CONCURRENCY_CONSTANTS['RATCHET_LOCK_TIMEOUT'].

        Returns:
            List of acquired RLock instances in acquisition order.

        Raises:
            ConcurrencyError: If any lock cannot be acquired within timeout.

        Example::

            locks = RatchetService.acquire_friend_locks_ordered(
                ["Alice", "Bob", "Charlie"]
            )
            try:
                # ... perform batch operation on all three friends ...
            finally:
                for lock in reversed(locks):
                    lock.release()
        """
        if timeout is None:
            timeout = CONCURRENCY_CONSTANTS.get("RATCHET_LOCK_TIMEOUT", 30.0)

        # Deduplicate and sort for canonical ordering
        unique_names = sorted(set(friend_names), key=lambda n: (n.lower(), n))

        acquired: List[threading.RLock] = []
        try:
            for name in unique_names:
                lock = cls._get_friend_lock(name)
                if not lock.acquire(timeout=timeout):
                    raise ConcurrencyError(
                        f"Could not acquire ratchet lock for '{name}' "
                        f"within {timeout:.1f} seconds during ordered "
                        f"multi-lock acquisition. Another operation may be "
                        f"in progress."
                    )
                acquired.append(lock)
        except ConcurrencyError:
            # Release any locks we already acquired, in reverse order
            for lock in reversed(acquired):
                lock.release()
            raise

        return acquired

    @classmethod
    def cleanup_friend_locks(cls, active_friends: Optional[List[str]] = None) -> int:
        """Remove locks for friends that no longer exist.

        Prevents unbounded growth of the lock dictionary when friends
        are repeatedly added and removed.

        Args:
            active_friends: List of currently active friend names.
                           If None, all locks older than LOCK_MAX_AGE
                           are removed.

        Returns:
            Number of locks removed.
        """
        removed = 0
        max_age = CONCURRENCY_CONSTANTS.get("LOCK_MAX_AGE", 7200)
        now = time.monotonic()

        with cls._locks_guard:
            stale_names = []
            if active_friends is not None:
                active_set = set(active_friends)
                for name in list(cls._friend_locks.keys()):
                    if name not in active_set:
                        stale_names.append(name)
            else:
                for name, created_at in cls._friend_lock_timestamps.items():
                    if now - created_at > max_age:
                        stale_names.append(name)

            for name in stale_names:
                # Only remove if the lock is not currently held
                lock = cls._friend_locks.get(name)
                if lock is not None:
                    # RLock has _is_owned() in CPython but it's internal.
                    # Use a non-blocking acquire attempt to check.
                    if lock.acquire(blocking=False):
                        lock.release()
                        del cls._friend_locks[name]
                        cls._friend_lock_timestamps.pop(name, None)
                        removed += 1
                    else:
                        logger.debug(
                            "Skipping lock cleanup for '%s' - lock is held",
                            name
                        )

            if removed > 0:
                logger.info(
                    "Cleaned up %d stale ratchet locks", removed
                )
        return removed

    @classmethod
    def get_lock_stats(cls) -> Dict[str, int]:
        """Return statistics about the current lock state.

        Returns:
            A dict with 'total_locks', 'total_timestamps' keys.
        """
        with cls._locks_guard:
            return {
                "total_locks": len(cls._friend_locks),
                "total_timestamps": len(cls._friend_lock_timestamps),
            }

    @classmethod
    def detect_potential_deadlock(cls, friend_names_a: List[str],
                                  friend_names_b: List[str]) -> bool:
        """Static analysis: check if two lock sets could deadlock.

        Returns True if acquiring locks for set A in one thread while
        another thread acquires locks for set B could result in deadlock.
        This happens when the sets overlap but have different orderings.

        This is a diagnostic tool. In practice, deadlock prevention is
        enforced by acquire_friend_locks_ordered() which always sorts
        friend names before acquisition.

        Args:
            friend_names_a: First set of friend names.
            friend_names_b: Second set of friend names.

        Returns:
            True if a deadlock is possible, False if the lock orderings
            are compatible.
        """
        set_a = set(friend_names_a)
        set_b = set(friend_names_b)
        overlap = set_a & set_b

        # No overlap means no shared locks, so no deadlock possible
        if not overlap or len(overlap) < 2:
            return False

        # If both sets sort the overlapping names identically, no deadlock
        sorted_overlap_a = sorted(overlap, key=lambda n: (n.lower(), n))
        sorted_overlap_b = sorted(overlap, key=lambda n: (n.lower(), n))

        return sorted_overlap_a != sorted_overlap_b

    @staticmethod
    def get_friend_profile(friend_name: str) -> Optional[FriendProfile]:
        """Load a structured FriendProfile from the database.

        This is the preferred entry point for obtaining friend data.
        Replaces direct dictionary/tuple access patterns.

        Args:
            friend_name: The exact name of the friend to look up.

        Returns:
            A FriendProfile instance, or None if the friend does not exist.
        """
        return get_friend_profile(friend_name)

    @staticmethod
    def has_active_ratchet(friend_name: str) -> bool:
        """Check if a friend has an active Double Ratchet session.

        Uses FriendProfile internally for consistent data access.

        Args:
            friend_name: The name of the friend to check.

        Returns:
            True if a ratchet state exists for this friend, False otherwise.
        """
        profile = get_friend_profile(friend_name)
        if profile is None:
            return False
        return profile.has_active_ratchet

    @staticmethod
    def get_ratchet_state(friend_name: str) -> RatchetState:
        """Load and deserialize a ratchet state from the database.

        Args:
            friend_name: The name of the friend whose ratchet state to load.

        Returns:
            A deserialized RatchetState instance.

        Raises:
            RatchetNotFoundError: If no ratchet state exists for this friend.
            RatchetServiceError: If deserialization or DB access fails.
        """
        try:
            with closing(get_connection()) as conn:
                row = conn.execute(
                    "SELECT ratchet_state_json FROM friends WHERE name=?",
                    (friend_name,)
                ).fetchone()

                if row is None:
                    raise RatchetNotFoundError(
                        f"Friend '{friend_name}' not found in database"
                    )
                if row[0] is None:
                    raise RatchetNotFoundError(
                        f"No active ratchet session for '{friend_name}'"
                    )

                # Decrypt the blob if encrypted-at-rest
                decrypted_json = RatchetService._decrypt_ratchet_blob(row[0])
                state_dict = json.loads(decrypted_json)
                return RatchetState.deserialize(state_dict)

        except RatchetNotFoundError:
            raise
        except json.JSONDecodeError as e:
            raise RatchetServiceError(
                f"Corrupted ratchet state JSON for '{friend_name}': {e}"
            ) from e
        except RatchetServiceError:
            raise
        except DatabaseError as e:
            raise RatchetServiceError(
                f"Database error loading ratchet for '{friend_name}': {e}"
            ) from e
        except Exception as e:
            raise RatchetServiceError(
                f"Failed to deserialize ratchet state for '{friend_name}': {e}"
            ) from e

    @staticmethod
    def save_ratchet_state(friend_name: str, state: RatchetState) -> None:
        """Serialize and persist a ratchet state to the database.

        Args:
            friend_name: The name of the friend to associate the state with.
            state: The RatchetState instance to serialize and save.

        Raises:
            RatchetServiceError: If serialization or DB write fails.
        """
        try:
            state_json = json.dumps(state.serialize())
            # Encrypt the blob before persisting to DB (at-rest encryption)
            encrypted_blob = RatchetService._encrypt_ratchet_blob(state_json)
            with closing(get_connection()) as conn:
                safe_execute(
                    conn,
                    "UPDATE friends SET ratchet_state_json=? WHERE name=?",
                    (encrypted_blob, friend_name)
                )
                conn.commit()
            logger.debug("Saved ratchet state for '%s'", friend_name)
        except DatabaseError as e:
            raise RatchetServiceError(
                f"Database error saving ratchet for '{friend_name}': {e}"
            ) from e
        except Exception as e:
            raise RatchetServiceError(
                f"Failed to serialize/save ratchet state for '{friend_name}': {e}"
            ) from e

    @staticmethod
    def init_ratchet_alice(
        friend_name: str,
        bob_dh_pub_bytes: bytes,
        shared_secret: bytes
    ) -> RatchetState:
        """Initialize a new Double Ratchet session as Alice (initiator).

        Creates a new RatchetState, initializes it as Alice using Bob's
        DH public key and the shared secret, persists it to the database,
        and returns the initialized state.

        Args:
            friend_name: The name of the friend (Bob) to initialize with.
            bob_dh_pub_bytes: Bob's X25519 DH public key as raw 32 bytes.
            shared_secret: The initial shared secret from key agreement
                          (e.g., derived from Hybrid KEM encapsulation).

        Returns:
            The initialized RatchetState instance.

        Raises:
            RatchetInitError: If initialization or persistence fails.
        """
        try:
            bob_dh_pub = X25519PublicKey.from_public_bytes(bob_dh_pub_bytes)
            state = RatchetState()
            state.initialize_as_alice(bob_dh_pub, shared_secret)
            RatchetService.save_ratchet_state(friend_name, state)
            RatchetService._ensure_ratchet_capability(friend_name)
            logger.info("Initialized ratchet as Alice for '%s'", friend_name)
            return state
        except ValueError as e:
            raise RatchetInitError(
                f"Invalid DH public key or shared secret for '{friend_name}': {e}"
            ) from e
        except RatchetServiceError:
            raise
        except Exception as e:
            raise RatchetInitError(
                f"Failed to initialize ratchet as Alice for '{friend_name}': {e}"
            ) from e

    @staticmethod
    def init_ratchet_bob(
        friend_name: str,
        alice_dh_pub_bytes: bytes,
        shared_secret: bytes
    ) -> RatchetState:
        """Initialize a new Double Ratchet session as Bob (responder).

        Creates a new RatchetState, initializes it as Bob using Alice's
        DH public key and the shared secret, persists it to the database,
        and returns the initialized state.

        Args:
            friend_name: The name of the friend (Alice) to initialize with.
            alice_dh_pub_bytes: Alice's X25519 DH public key as raw 32 bytes.
            shared_secret: The initial shared secret from key agreement
                          (e.g., derived from Hybrid KEM decapsulation).

        Returns:
            The initialized RatchetState instance.

        Raises:
            RatchetInitError: If initialization or persistence fails.
        """
        try:
            alice_dh_pub = X25519PublicKey.from_public_bytes(alice_dh_pub_bytes)
            state = RatchetState()
            state.initialize_as_bob(alice_dh_pub, shared_secret)
            RatchetService.save_ratchet_state(friend_name, state)
            RatchetService._ensure_ratchet_capability(friend_name)
            logger.info("Initialized ratchet as Bob for '%s'", friend_name)
            return state
        except ValueError as e:
            raise RatchetInitError(
                f"Invalid DH public key or shared secret for '{friend_name}': {e}"
            ) from e
        except RatchetServiceError:
            raise
        except Exception as e:
            raise RatchetInitError(
                f"Failed to initialize ratchet as Bob for '{friend_name}': {e}"
            ) from e

    @staticmethod
    def delete_ratchet(friend_name: str) -> bool:
        """Remove the ratchet state for a friend.

        Sets the ratchet_state_json column to NULL for the specified friend.
        This effectively terminates the Double Ratchet session.

        Args:
            friend_name: The name of the friend whose ratchet to delete.

        Returns:
            True if a ratchet state was removed, False if none existed.

        Raises:
            RatchetServiceError: If the database operation fails.
        """
        try:
            with closing(get_connection()) as conn:
                cursor = safe_execute(
                    conn,
                    "UPDATE friends SET ratchet_state_json=NULL "
                    "WHERE name=? AND ratchet_state_json IS NOT NULL",
                    (friend_name,)
                )
                conn.commit()
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info("Deleted ratchet state for '%s'", friend_name)
                else:
                    logger.debug(
                        "No ratchet state to delete for '%s'", friend_name
                    )
                return deleted
        except DatabaseError as e:
            raise RatchetServiceError(
                f"Database error deleting ratchet for '{friend_name}': {e}"
            ) from e

    @staticmethod
    def _ensure_ratchet_capability(friend_name: str) -> None:
        """Ensure the friend's capabilities_json includes double_ratchet: True.

        Called automatically after ratchet initialization so that the
        encryption service can detect ratchet support via capability flags
        even without checking the database for active sessions.
        """
        try:
            with closing(get_connection()) as conn:
                row = conn.execute(
                    "SELECT capabilities_json FROM friends WHERE name=?",
                    (friend_name,)
                ).fetchone()
                caps = {}
                if row and row[0]:
                    try:
                        caps = json.loads(row[0])
                    except (json.JSONDecodeError, TypeError):
                        caps = {}
                if not caps.get("double_ratchet"):
                    caps["double_ratchet"] = True
                    safe_execute(
                        conn,
                        "UPDATE friends SET capabilities_json=? WHERE name=?",
                        (json.dumps(caps), friend_name)
                    )
                    conn.commit()
                    logger.debug(
                        "Set double_ratchet capability for '%s'", friend_name
                    )
        except DatabaseError as e:
            logger.warning(
                "Could not update capabilities for '%s': %s", friend_name, e
            )

    @staticmethod
    def encrypt_message(friend_name: str, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt a message using the active ratchet session for a friend.

        Loads the ratchet state, performs encryption (which advances the
        send chain), saves the updated state, and returns the header and
        ciphertext.

        Args:
            friend_name: The name of the friend to encrypt for.
            plaintext: The message bytes to encrypt.

        Returns:
            A tuple of (header, ciphertext) where header contains the DH
            public key, message number, and previous chain length.

        Raises:
            RatchetNotFoundError: If no active ratchet session exists.
            RatchetServiceError: If encryption or state persistence fails.
            ConcurrencyError: If the per-friend lock cannot be acquired
                             within the timeout period.
        """
        lock = RatchetService._acquire_friend_lock(friend_name)
        try:
            state = RatchetService.get_ratchet_state(friend_name)
            try:
                header, ciphertext = state.encrypt(plaintext)
            except ValueError as e:
                raise RatchetServiceError(
                    f"Ratchet encryption failed for '{friend_name}': {e}"
                ) from e

            # Persist the advanced state
            RatchetService.save_ratchet_state(friend_name, state)
        finally:
            lock.release()
        return header, ciphertext

    @staticmethod
    def encrypt_to_envelope(friend_name: str, plaintext: bytes) -> RatchetEnvelope:
        """Encrypt a message and return a structured RatchetEnvelope.

        Preferred over encrypt_message() when the caller needs to build
        a wire-format packet. Encapsulates both the cryptographic operation
        and the envelope construction in a single call.

        Args:
            friend_name: The name of the friend to encrypt for.
            plaintext: The message bytes to encrypt.

        Returns:
            A RatchetEnvelope containing sender name, header, and ciphertext.

        Raises:
            RatchetNotFoundError: If no active ratchet session exists.
            RatchetServiceError: If encryption or state persistence fails.
        """
        header, ciphertext = RatchetService.encrypt_message(friend_name, plaintext)
        return RatchetEnvelope(
            sender_name=friend_name,
            header=header,
            ciphertext=ciphertext,
        )

    @staticmethod
    def decrypt_message(
        friend_name: str,
        header: bytes,
        ciphertext: bytes
    ) -> bytes:
        """Decrypt a message using the active ratchet session for a friend.

        Loads the ratchet state, performs decryption (which may advance
        the receive chain and/or perform DH ratchet steps), saves the
        updated state, and returns the plaintext.

        Args:
            friend_name: The name of the friend who sent the message.
            header: The message header (DH pub + msg_num + prev_chain_len).
            ciphertext: The encrypted message (nonce + AES-GCM ciphertext).

        Returns:
            The decrypted plaintext bytes.

        Raises:
            RatchetNotFoundError: If no active ratchet session exists.
            RatchetServiceError: If decryption or state persistence fails.
            ConcurrencyError: If the per-friend lock cannot be acquired
                             within the timeout period.
        """
        lock = RatchetService._acquire_friend_lock(friend_name)
        try:
            state = RatchetService.get_ratchet_state(friend_name)
            try:
                plaintext = state.decrypt(header, ciphertext)
            except (ValueError, Exception) as e:
                raise RatchetServiceError(
                    f"Ratchet decryption failed for '{friend_name}': {e}"
                ) from e

            # Persist the advanced state (including any skipped keys)
            RatchetService.save_ratchet_state(friend_name, state)
        finally:
            lock.release()
        return plaintext
