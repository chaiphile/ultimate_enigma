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
    def __init__(self, root: tk.Tk, key_store: KeyStore)
    
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

Core cryptographic operations.

```python
class EncryptionService:
    def __init__(self, key_store: KeyStore)
    
    def encrypt_message(self, plaintext: str, friend_name: str = None,
                       sign: bool = True, self_destruct: int = None) -> str
        """Encrypt a message. Returns Base64-encoded ciphertext."""
    
    def decrypt_message(self, ciphertext_b64: str) -> dict
        """Decrypt a message. Returns {'plaintext', 'verified', 'expired'}."""
    
    def get_time_offset(self) -> float
        """Get current NTP time offset in seconds."""
    
    def set_time_offset(self, offset: float) -> None
        """Update NTP time offset."""
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
    
    # Keys
    KEYS_WIPED = "keys_wiped"
    KEYS_LOADED = "keys_loaded"
    PASSWORD_CHANGED = "password_changed"
    
    # TOTP
    TOTP_SETUP_COMPLETE = "totp_setup_complete"
    TOTP_VERIFIED = "totp_verified"
    
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

Key storage abstraction.

```python
class KeyStore:
    def load(self, master_password: str) -> bool
        """Load and decrypt keys from database."""
    
    def save(self) -> None
        """Persist encrypted keys to database."""
    
    def wipe(self) -> None
        """Zero all keys from memory."""
    
    @property
    def private_key(self) -> rsa.RSAPrivateKey
    @property
    def public_key(self) -> rsa.RSAPublicKey
    @property
    def global_secret(self) -> bytes
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

Memory-safe string handling.

```python
class SecureString:
    def __init__(self, value: str)
    
    def get(self) -> str
        """Retrieve the string value."""
    
    def wipe(self) -> None
        """Zero the underlying memory."""
    
    def __enter__(self)
    def __exit__(self)
        # Context manager for automatic wiping
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

---

## Error Handling

Custom exceptions are defined in `src/exceptions.py`:

```python
class EnigmaError(Exception):
    """Base exception for Ultimate Enigma."""

class AuthenticationError(EnigmaError):
    """Authentication failed."""

class DecryptionError(EnigmaError):
    """Decryption failed."""

class KeyNotFoundError(EnigmaError):
    """Required key not found."""

class TimeoutError(EnigmaError):
    """Operation timed out."""
```
