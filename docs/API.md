# API Reference

## Controllers

### ApplicationController

Application lifecycle management.

```python
class ApplicationController:
    def __init__(self, root: tk.Tk)
    
    def start_queue_processing(self) -> None
        """Start the crypto task queue worker threads."""
    
    def start_ntp_sync(self, encryption_service, service_lock) -> None
        """Schedule deferred NTP synchronization."""
    
    def register_hotkeys(self, lock_callback, unlock_callback) -> None
        """Register global hotkeys for emergency lock/unlock."""
    
    def shutdown(self) -> None
        """Clean up resources on application exit."""
    
    @property
    def crypto_queue(self) -> CryptoTaskQueue
        """Access the crypto task queue instance."""
    
    @property
    def task_queue(self) -> CryptoTaskQueue
        """Alias for crypto_queue (backward compatibility)."""
```

### AuthController

Authentication and key management.

```python
class AuthController:
    def __init__(self, root: tk.Tk, key_store: KeyStore, ui=None, totp_persistence=None)
    
    def load_keys(self, first_run: bool) -> bool
        """Load or generate keys. Returns False if user cancels."""
    
    def enforce_mandatory_totp_setup(self) -> bool
        """Ensure TOTP is configured. Returns False if user declines."""
    
    def verify_startup_totp(self) -> bool
        """Verify TOTP at startup. Returns False if verification fails."""
    
    def request_unlock(self, current_ks: KeyStore) -> tuple[bool, KeyStore, TOTPService]
        """Handle unlock flow. Returns (success, new_keystore, totp_service)."""
    
    def wipe_sensitive_data(self) -> None
        """Zero all sensitive data from memory."""
    
    def show_totp_setup(self) -> None
        """Display TOTP setup dialog."""
    
    def load_totp_secret(self, totp_service, password, ks) -> bool
        """Load and decrypt the persisted TOTP secret."""
    
    def persist_totp_secret(self, secret_bytes: bytes, password: str) -> None
        """Encrypt and persist the TOTP secret."""
    
    def init_totp(self, password: str) -> None
        """Initialize TOTP for first-time setup or re-init."""
    
    def generate_new_totp(self, password: str) -> None
        """Generate a fresh TOTP secret and persist it."""
    
    def regenerate_totp(self) -> None
        """Regenerate TOTP secret and show new QR code."""
    
    def is_totp_enabled(self) -> bool
        """Check if TOTP is currently enabled."""
    
    def set_totp_enabled(self, value: bool) -> None
        """Enable or disable TOTP verification."""
```

### ServiceOrchestrator

Service dependency injection container.

```python
class ServiceOrchestrator:
    def __init__(self, root, key_store: KeyStore, crypto_queue=None)
    
    def rebuild_services(self, new_key_store: KeyStore, tab_references: dict = None) -> None
        """Rebuild all services with new keys after unlock."""
    
    def shutdown(self) -> None
        """Clean up services requiring explicit shutdown."""
    
    @property
    def encryption_service(self) -> EncryptionService
    @property
    def file_service(self) -> FileService
    @property
    def friends_service(self) -> FriendsService
    @property
    def clipboard_service(self) -> ClipboardService
    @property
    def global_secret_service(self) -> GlobalSecretService
    @property
    def service_lock(self) -> threading.RLock
```

---

## Services

### EncryptionService

Core cryptographic operations. Decomposed into three strategy classes behind a facade.

```python
class EncryptionService:
    def __init__(self, key_store: KeyStore)
    
    def encrypt(self, plaintext: str, friend_name: str = None,
                mode: str = 'shared', sign: bool = True,
                self_destruct_seconds: int = None) -> tuple[bytes, int]
        """Encrypt a message. Returns (raw_packet_bytes, timestamp)."""
    
    def encrypt_base64(self, **kwargs) -> str
        """Convenience: encrypt and return Base64-encoded string."""
    
    def decrypt(self, b64_text: str) -> str
        """Decrypt a Base64-encoded message. Auto-detects envelope type."""
    
    def update_ntp_time(self, timestamp: float) -> None
        """Set NTP-corrected timestamp for time-based key derivation."""
    
    @property
    def last_encrypt_mode(self) -> str | None
        """Mode used by most recent encrypt(): 'ratchet', 'pqc', 'legacy', or None."""
    
    @property
    def last_decrypt_mode(self) -> str | None
        """Mode used by most recent decrypt(): 'ratchet', 'pqc', 'legacy', or None."""
```

### FileService

File encryption operations.

```python
class FileService:
    def __init__(self, key_store: KeyStore)
    
    def encrypt_file(self, input_path: str, output_path: str,
                    password: str = None, friend_name: str = None) -> bool
        """Encrypt a file. Uses password or friend's key."""
    
    def decrypt_file(self, input_path: str, output_path: str,
                    password: str = None) -> bool
        """Decrypt a file."""
```

### FriendsService

Contact management.

```python
class FriendsService:
    def __init__(self, key_store: KeyStore)
    
    def add_friend(self, name: str, public_key_pem: str,
                  shared_secret_b64: str = None) -> bool
        """Add a new friend/contact."""
    
    def remove_friend(self, name: str) -> bool
        """Remove a friend by name."""
    
    def get_friend(self, name: str) -> FriendProfile | None
        """Retrieve a friend's profile."""
    
    def list_friends(self) -> list[str]
        """Get list of all friend names."""
    
    def update_shared_secret(self, name: str, secret_b64: str) -> bool
        """Update ECDH-derived shared secret for a friend."""
```

### ClipboardService

Secure clipboard handling.

```python
class ClipboardService:
    def __init__(self, root: tk.Tk)
    
    def copy(self, text: str, auto_clear: bool = True) -> None
        """Copy text to clipboard with optional auto-clear."""
    
    def get(self) -> str
        """Get current clipboard contents."""
    
    def clear(self) -> None
        """Clear the clipboard immediately."""
    
    def shutdown(self) -> None
        """Cancel pending auto-clear timers."""
```

### GlobalSecretService

Shared secret management.

```python
class GlobalSecretService:
    def __init__(self, key_store: KeyStore)
    
    def get_fingerprint(self) -> str
        """Get fingerprint of current global secret."""
    
    def export_secret(self) -> str
        """Export global secret as Base64."""
    
    def import_secret(self, secret_b64: str) -> bool
        """Import a new global secret."""
    
    def perform_ecdh(self, peer_public_key: bytes) -> str
        """Perform ECDH key exchange. Returns derived secret as Base64."""
```

### TOTPService

Time-based one-time password.

```python
class TOTPService:
    def __init__(self, secret: bytes = None)
    
    def generate_totp_uri(self, account_name: str, issuer: str = "UltimateEnigma") -> str
        """Generate otpauth:// URI for QR code."""
    
    def verify(self, code: str) -> bool
        """Verify a TOTP code."""
    
    def get_current_code(self) -> str
        """Get current TOTP code (for testing)."""
```

### BackupService

Encrypted backup and restore operations.

```python
class BackupService:
    def __init__(self, key_store: KeyStore, backup_dir=None, max_backups=10, reminder_days=7)
    
    def export_backup(self, password: str) -> dict
        """Export all key material as an encrypted backup dict."""
    
    def import_backup(self, data: dict, password: str) -> None
        """Import and decrypt a backup dict, restoring keys."""
    
    def export_backup_to_file(self, password: str, backup_dir=None) -> Path
        """Export backup to an encrypted JSON file. Returns file path."""
    
    def import_backup_from_file(self, filepath: Path, password: str) -> None
        """Import backup from an encrypted JSON file."""
    
    def list_backups(self, backup_dir=None) -> List[Path]
        """List all backup files in the backup directory."""
    
    def get_last_backup_timestamp(self) -> Optional[float]
        """Get timestamp of most recent backup, or None if no backups."""
    
    def should_remind_backup(self) -> tuple[bool, Optional[int]]
        """Check if user should be reminded to back up.
        Returns (should_remind, days_since_last_backup)."""
```

### TotpPersistence

Encrypted TOTP secret storage.

```python
class TotpPersistence:
    def __init__(self, key_store: KeyStore)
    
    def load_totp_secret(self, totp_service, password, ks) -> bool
        """Load and decrypt the persisted TOTP secret into totp_service."""
    
    def persist_totp_secret(self, secret_bytes: bytes, password: str) -> None
        """Encrypt and persist the TOTP secret."""
    
    def is_totp_setup_complete(self) -> bool
        """Check if TOTP has been set up at least once."""
    
    def set_totp_setup_complete(self, value: bool) -> None
        """Mark TOTP setup as complete or incomplete."""
    
    def is_totp_enabled(self) -> bool
        """Check if TOTP verification is currently enabled."""
    
    def set_totp_enabled(self, value: bool) -> None
        """Enable or disable TOTP verification."""
```

### FriendRepository

Low-level friend data access.

```python
def get_friend_profile(name: str) -> Optional[FriendProfile]
    """Retrieve a single friend profile by name."""

def list_all_friend_profiles() -> List[FriendProfile]
    """List all stored friend profiles."""
```

### XChaCha20Poly1305

XChaCha20-Poly1305 AEAD encryption.

```python
class XChaCha20Poly1305:
    def __init__(self, key: bytes)
    
    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes
        """Encrypt plaintext with associated data. Returns ciphertext + tag."""
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes
        """Decrypt ciphertext with associated data. Returns plaintext."""
```

### HotkeyService

Global hotkey registration for emergency lock/unlock.

```python
class HotkeyService:
    def __init__(self)
    
    def register(self, hotkey_id: int, modifiers: int, vk: int, callback: Callable) -> None
        """Register a global hotkey with Windows virtual key code and modifiers."""
    
    def start(self) -> None
        """Start listening for registered hotkeys."""
    
    def stop(self) -> None
        """Stop listening and unregister all hotkeys."""
```

### EventBus

Publish/subscribe event system.

```python
class EventBus:
    def subscribe(self, event: str, handler: Callable, thread_safe: bool = False) -> None
        """Register an event handler."""
    
    def unsubscribe(self, event: str, handler: Callable) -> None
        """Remove an event handler."""
    
    def unsubscribe_all(self, handler: Callable) -> None
        """Remove handler from all events."""
    
    def publish(self, event: str, **kwargs) -> None
        """Publish an event to all subscribers."""
    
    def clear(self) -> None
        """Remove all subscriptions."""
    
    def subscriber_count(self, event: str = None) -> int
        """Count subscribers for an event or all events."""

# Global singleton
event_bus = EventBus()
```

### Events Constants

```python
class Events:
    # Authentication
    UNLOCK_REQUESTED = "unlock_requested"
    EMERGENCY_LOCK = "emergency_lock"
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    DURESS_MODE_ENTERED = "duress_mode_entered"
    
    # Keys
    KEYS_WIPED = "keys_wiped"
    KEYS_LOADED = "keys_loaded"
    PASSWORD_CHANGED = "password_changed"
    
    # TOTP
    TOTP_SETUP_COMPLETE = "totp_setup_complete"
    TOTP_VERIFIED = "totp_verified"
    TOTP_CHANGED = "totp_changed"
    
    # Ratchet
    RATCHET_INITIALIZED = "ratchet_initialized"
    RATCHET_RESET = "ratchet_reset"
    
    # Services
    SERVICES_REBUILT = "services_rebuilt"
    NTP_SYNCED = "ntp_synced"
    NTP_SYNC_FAILED = "ntp_sync_failed"
    
    # Data
    FRIEND_LIST_CHANGED = "friend_list_changed"
    FRIEND_ADDED = "friend_added"
    FRIEND_REMOVED = "friend_removed"
    
    # Lifecycle
    APP_STARTING = "app_starting"
    APP_SHUTDOWN = "app_shutdown"
```

---

## Models

### KeyStore

Key storage abstraction with delegated lockout management.

```python
class KeyStore:
    def load(self, master_password: str) -> bool
        """Load and decrypt keys from database."""
    
    def save(self) -> None
        """Persist encrypted keys to database."""
    
    def wipe(self) -> None
        """Zero all keys from memory."""
    
    def get_decryption_snapshot(self) -> tuple
        """Returns thread-safe snapshot for decryption operations.
        Returns (my_priv, friends_for_crypto, secrets_to_try, legacy_priv)
        where:
        - my_priv: Current RSA private key or None
        - friends_for_crypto: List of (name, pub, secret) tuples
        - secrets_to_try: List of shared secrets including global + friend secrets
        - legacy_priv: Legacy RSA private key or None
        """
    
    @property
    def private_key(self) -> rsa.RSAPrivateKey
    @property
    def public_key(self) -> rsa.RSAPublicKey
    @property
    def global_secret(self) -> bytes
    @property
    def failed_attempts(self) -> int
        """Number of consecutive failed authentication attempts (delegates to LockoutManager)."""
    @property
    def locked_until(self) -> float
        """Epoch timestamp until which the account is locked (delegates to LockoutManager)."""
    @property
    def my_name(self) -> str
        """Display name for ratchet envelope sender identification.
        Falls back to 'user-<8-char-hash>' if not configured."""
    
    def set_my_name(self, name: str) -> None
        """Persist display name to settings table."""
```

### FriendProfile

Friend/contact data model.

```python
@dataclass
class FriendProfile:
    name: str
    public_key_pem: str
    shared_secret: bytes | None
    created_at: datetime
    fingerprint: str
```

### Envelope

Message envelope structure.

```python
@dataclass
class Envelope:
    version: int
    flags: int
    timestamp: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    signature: bytes | None
    self_destruct: int | None
```

---

## Utilities

### SecureString

Memory-safe string handling with 3-pass secure wipe.

```python
class SecureString:
    def __init__(self, data)  # str, bytes, or bytearray
    
    def wipe(self) -> None
        """3-pass secure wipe: zero → random → zero."""
    
    def to_str(self) -> str
        """Convert to Python str (immutable — use immediately)."""
    
    def to_bytes(self) -> bytes
        """Convert to bytes (immutable — use immediately)."""
    
    def to_bytearray(self) -> bytearray
        """Return mutable copy (caller must wipe)."""
    
    def lock(self) -> None:
        """Lock the underlying bytearray in RAM (VirtualLock/mlock).
        
        Prevents the sensitive data from being paged to disk.
        Call on long-lived secrets (master password, DB encryption key).
        Automatically unlocked by wipe().
        """
    
    def append(self, data) -> None
        """Append str, bytes, or SecureString."""
    
    def copy(self) -> SecureString
        """Create deep copy."""
    
    @property
    def is_wiped(self) -> bool
    
    # Context manager (recommended)
    def __enter__(self)
    def __exit__(self, *args)
        # Auto-wipes on exit

# Factory methods
SecureString.from_str(data) -> SecureString
SecureString.from_bytes(data) -> SecureString

# Standalone utilities
secure_compare(a, b) -> bool  # Constant-time comparison
wipe_bytes(data: bytearray) -> None  # Wipe mutable buffer
```

### GuardedBuffer (`security/guarded_buffer.py`)

Memory buffers protected by PAGE_NOACCESS guard pages. Prevents buffer overread/overflow attacks on sensitive key material.

```python
class GuardedBuffer:
    def __init__(self, size: int, lock: bool = True)
        """Allocate a guarded buffer with guard pages before and after.
        
        Args:
            size: Number of bytes for the data region.
            lock: If True, immediately mlock the entire allocation.
        """
    
    def write(self, data: bytes) -> None:
        """Write data into the guarded region.
        
        Raises ValueError if len(data) > buffer size.
        """
    
    def read(self) -> bytearray:
        """Return a mutable copy of the guarded data."""
    
    def wipe_and_free(self) -> None:
        """Zero the data region, then release the entire allocation."""
    
    def __eq__(self, other: object) -> bool:
        """Constant-time comparison using hmac.compare_digest.
        
        Prevents timing side-channels when comparing secret material.
        """
    
    # Context manager (recommended)
    def __enter__(self) -> GuardedBuffer
    def __exit__(self, *args) -> None
        # Calls wipe_and_free()
```

### Anti-Tamper (src/anti_tamper.py)

Anti-debugger and anti-tamper protections for the frozen .exe. All functions are no-ops when `sys.frozen` is not set. The check pipeline is **fail-closed**: any unexpected exception in a check function is treated as tamper detected.

```python
def run_anti_tamper_checks() -> None:
    """Run all protection checks and exit silently if tampering detected.
    
    Call this function BEFORE any other imports in main.py when running frozen.
    Handles: debugger detection, PE verification, import hooks, timing anomalies.
    Fail-closed: exceptions in checks are treated as tamper.
    """

def start_background_checks(interval: int = None) -> None:
    """Start a daemon thread that periodically runs anti-tamper checks.
    
    Args:
        interval: Seconds between checks. Defaults to 30.
    """

def check_on_demand() -> bool:
    """Run a single check cycle on demand (e.g., before critical operations).
    
    Returns:
        True if tampering detected, False if clean.
    """
```

### Memory Security (`security/memory_security.py`)

Platform-native memory locking and working set management.

```python
def mlock_memory(data: bytearray) -> bool:
    """Lock memory pages containing data to prevent swapping to disk.
    
    Uses VirtualLock on Windows, mlock on Linux.
    Operates on page-aligned regions spanning the bytearray.
    Returns True on success, False on failure (app continues).
    """

def munlock_memory(data: bytearray) -> None:
    """Unlock previously locked memory pages."""

def raise_mlock_limit(target_bytes: int = 64 * 1024 * 1024) -> None:
    """Raise the memory locking quota.
    
    On Linux: raises RLIMIT_MEMLOCK.
    On Windows: adjusts process working set size.
    Call once at startup before any mlock operations.
    """
```

### Anti-Dump (`security/anti_dump.py`)

Process memory dump prevention.

```python
def apply_anti_dump_protections() -> None:
    """Apply all platform-specific anti-dump protections.
    
    Windows: Patches MiniDumpWriteDump with RET instruction,
             removes SeDebugPrivilege from process token.
    Linux: Disables core dumps via setrlimit and prctl.
    """
```

### Timeout Decorator

```python
def timeout(seconds: float, error_message: str = "Operation timed out"):
    """Decorator to enforce operation timeout."""
```

### Constants Access

```python
from src.constants import get_magic_byte, get_kdf_param, KDF_PARAMS, CRYPTO_CONSTANTS

magic = get_magic_byte("RATCHET_ENVELOPE")  # 0xD0
time_cost = get_kdf_param("ARGON2_TIME_COST")  # 3
```

### AppBuilder (`builders/app_builder.py`)

Step-by-step composition root for `EnigmaApp`. Each step is independently testable with mocked dependencies.

```python
class AppBuilder:
    def __init__(self, root: tk.Tk)
    
    def step1_init_window(self) -> bool
        """Configure root window, style, and event bus."""
    
    def step2_init_database(self) -> bool
        """Detect first-run and ensure DB schema exists."""
    
    def step3_init_keystore(self) -> bool
        """Create the KeyStore instance."""
    
    def step4_init_controllers(self) -> bool
        """Create ApplicationController, TotpPersistence, AuthController."""
    
    def step5_authenticate(self) -> bool
        """Load keys, enforce mandatory TOTP, verify startup TOTP."""
    
    def step6_init_services(self) -> bool
        """Create ServiceOrchestrator, TrustChainService, wire them together."""
    
    def build(self) -> dict | None
        """Run all steps in order. Returns component dict or None on failure."""
```

### Crypto Helpers (`crypto.py`)

```python
def extract_key_hint(packet: bytes) -> bytes | None
    """Extract the 2-byte SHA-256 key hint from a legacy packet.
    
    Returns the hint bytes if KEY_HINT_FLAG is set, otherwise None.
    Used by LegacyEncryptionStrategy to skip non-matching shared secrets
    before attempting full AES-GCM decryption (O(1) filter vs O(N) brute-force).
    """
```

---

## Error Handling

Custom exceptions are defined in `src/exceptions.py`:

```python
class EnigmaError(Exception):
    """Base exception for Ultimate Enigma."""

class KeyStoreError(EnigmaError):
    """Key loading, saving, or password verification failed."""

class EncryptionError(EnigmaError):
    """Encryption cannot proceed."""

class DecryptionError(EnigmaError):
    """Decryption fails."""

class RatchetStateError(EnigmaError):
    """Double Ratchet state error."""

class RatchetNotFoundError(RatchetStateError):
    """No active ratchet session for a friend."""

class RatchetInitError(RatchetStateError):
    """Ratchet initialization fails."""

class RatchetServiceError(RatchetStateError):
    """General ratchet service failure."""

class TOTPValidationError(EnigmaError):
    """TOTP verification or secret failure."""

class CryptoTimeoutError(EnigmaError):
    """Crypto operation exceeds time limit."""

class ConcurrencyError(EnigmaError):
    """Lock acquisition or concurrency failure."""
```

Database-specific exceptions are in `database.py`:

```python
class DatabaseError(Exception):
    """Base database exception."""

class DatabaseCorruptedError(DatabaseError):
    """DB file corrupted — restore from backup."""

class DatabaseLockedError(DatabaseError):
    """DB locked by another process — retry."""

class DatabaseIntegrityError(DatabaseError):
    """Constraint violation (UNIQUE, FK)."""

class DatabaseConnectionError(DatabaseError):
    """Cannot establish connection."""
```
