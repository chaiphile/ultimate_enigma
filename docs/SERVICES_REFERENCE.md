# Services Reference

Comprehensive documentation for every service in the `services/` directory.

---

## Table of Contents

- [EncryptionService](#encryptionservice)
- [FileService](#fileservice)
- [FriendsService](#friendsservice)
- [GlobalSecretService](#globalsecretservice)
- [ClipboardService](#clipboardservice)
- [EventBus](#eventbus)
- [CryptoTaskQueue](#cryptotaskqueue)
- [ECDHService](#ecdhservice)
- [TOTPService](#totpservice)
- [AuthManager](#authmanager)
- [BackupService](#backupservice)
- [HotkeyService](#hotkeyservice)
- [RatchetService](#ratchetservice)
- [DoubleRatchet (RatchetState)](#doubleratchet-ratchetstate)
- [PQCService (HybridKEM)](#pqcservice-hybridkem)
- [PQCSignatures (HybridSigner)](#pqcsignatures-hybridsigner)

---

## EncryptionService

**File:** `services/encryption_service.py`

Thin wrapper around the `crypto` module that holds a reference to the KeyStore. Supports three encryption modes: Legacy (AES-GCM + RSA), Double Ratchet, and Post-Quantum Hybrid KEM.

### Constructor

```python
EncryptionService(key_store)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key_store` | KeyStore or KeyStoreModel | Must expose `global_secret`, `my_priv`, `friends`, and `get_decryption_snapshot()` method |

**Note:** The service now uses `get_decryption_snapshot()` for thread-safe decryption operations, which returns a tuple of `(my_priv, friends_for_crypto, secrets_to_try, legacy_priv)`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `last_encrypt_mode` | `Optional[str]` | `'ratchet'`, `'pqc'`, `'legacy'`, or `None` |
| `last_decrypt_mode` | `Optional[str]` | `'ratchet'`, `'pqc'`, `'legacy'`, or `None` |

### Methods

#### `update_ntp_time(timestamp: Optional[float])`
Sets the NTP-corrected timestamp used for time-based key derivation.

#### `encrypt(plaintext, friend_name=None, mode='shared', sign=True, self_destruct_seconds=None) -> Tuple[bytes, int]`
Encrypts plaintext according to the chosen mode. Automatically selects Double Ratchet if an active session exists for the friend, or PQC if mode is `'pqc'`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | `str` | Message text to encrypt |
| `friend_name` | `Optional[str]` | Target friend name |
| `mode` | `str` | `'shared'`, `'rsa'`, or `'pqc'` |
| `sign` | `bool` | Whether to sign with private key |
| `self_destruct_seconds` | `Optional[int]` | Self-destruct timer |

**Returns:** `(raw_packet_bytes, timestamp)`

**Raises:** `EncryptionError`

#### `encrypt_base64(**kwargs) -> str`
Convenience method: encrypts and returns Base64-encoded string. Accepts same kwargs as `encrypt()`.

#### `decrypt(b64_text: str) -> str`
Decrypts a Base64-encoded message. Auto-detects envelope type (Ratchet `0xD0`, PQC `0x50`, or Legacy) and routes accordingly.

**Raises:** `DecryptionError`

### Internal Methods

| Method | Description |
|--------|-------------|
| `_resolve_encryption_key(friend_name, mode)` | Determines symmetric key and optional RSA pub key |
| `_get_friend_keys(name)` | Returns `(public_key, shared_secret)` for a friend |
| `_decode_base64_packet(b64_text)` | Decodes Base64, raises `DecryptionError` on failure |
| `_peek_flags(packet)` | Reads flags byte from packet |
| `_get_friends_hybrid_list()` | Builds list of hybrid signing public keys for verification |
| `_decrypt_with_rsa(packet, my_priv, friends, legacy_priv)` | Tries current then legacy RSA key |
| `_decrypt_with_shared_secrets(packet, secrets, friends)` | Tries each shared secret |
| `_friend_supports_ratchet(friend_name)` | Checks active session or capability flag |
| `_get_my_name()` | Returns `KeyStore.my_name` for ratchet envelope sender identification |
| `_encrypt_with_ratchet(plaintext, friend_name)` | Encrypts via Double Ratchet, wraps in `RatchetEnvelope` with `sender_name` set to `KeyStore.my_name` (not the recipient) |
| `_decrypt_with_ratchet(packet)` | Parses `RatchetEnvelope`, decrypts via Double Ratchet |
| `_encrypt_with_pqc(plaintext, friend_name)` | Encrypts via Hybrid KEM, wraps in `PQCEncvelope` |
| `_decrypt_with_pqc(packet)` | Parses `PQCEncvelope`, decapsulates and decrypts |
| `_build_decryption_error(flags)` | Creates user-friendly error message |

---

## FileService

**File:** `services/file_service.py`

Service layer for file encryption/decryption. Handles password-based (Argon2id + AES-GCM) and shared-secret-based file operations.

### Exceptions

| Exception | Description |
|-----------|-------------|
| `FileServiceError` | Base exception for file service errors |
| `SharedSecretDetected` | Raised when a shared-secret file is detected; contains `owner` and `fingerprint` attributes |

### Standalone Functions

#### `file_encrypt(input_path, output_path, password)`
Encrypts a file using AES-GCM with Argon2id-derived key. Format: `A2ID(4) + salt(16) + nonce(12) + ciphertext`. KDF wrapped in timeout.

#### `file_decrypt(input_path, output_path, password)`
Decrypts with automatic KDF detection (Argon2id or legacy PBKDF2).

#### `file_encrypt_shared(input_path, output_path, shared_secret, sign=False, my_priv=None)`
Encrypts using shared secret with HKDF-derived key and optional RSA signature.

#### `file_decrypt_shared(input_path, output_path, secrets_dict, friends_for_sig=None)`
Decrypts shared-secret file. Returns signature verification message.

### FileService Class

#### Constructor
```python
FileService(key_store)
```

#### Methods

| Method | Description |
|--------|-------------|
| `encrypt_file(input_path, output_path, method, password=None, friend_name=None, sign=False)` | Encrypts a file. `method`: `'password'`, `'global'`, or `'friend'` |
| `decrypt_file(input_path, output_path, password=None) -> str` | Auto-detects encryption method. Returns signature message. May raise `SharedSecretDetected` |
| `decrypt_with_shared_secret(input_path, output_path, fingerprint) -> str` | Decrypts after user confirms detected fingerprint |

---

## FriendsService

**File:** `services/friends_service.py`

High-level API for managing friends, shared secrets, ECDH keys, PQC keys, and Double Ratchet sessions.

### Exception

| Exception | Description |
|-----------|-------------|
| `FriendsServiceError` | Raised when a friend operation fails |

### Constructor
```python
FriendsService(key_store: KeyStore)
```

### Query Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_all_friends()` | `List[Dict]` | List of friend summaries with name, fingerprints, capabilities |
| `get_friend_details(name)` | `Optional[Dict]` | Detailed view of one friend |
| `get_friend_secret(name)` | `Optional[bytes]` | Shared secret for a friend |
| `friend_exists(name)` | `bool` | Check if friend exists |
| `get_friend_names()` | `List[str]` | All friend names |
| `friend_has_secret(name)` | `bool` | Check if friend has shared secret |
| `get_friend_x25519_key(name)` | `Optional[str]` | X25519 public key Base64 |
| `get_friend_capabilities(name)` | `Dict` | Capabilities dict |
| `friend_has_pqc_key(name)` | `bool` | Check if friend has PQC key |
| `friend_has_hybrid_sig_key(name)` | `bool` | Check if friend has hybrid signing key |
| `get_my_public_info()` | `Dict` | Own RSA public key fingerprint and PEM |
| `get_my_pqc_combined_pub()` | `Optional[str]` | Own PQC combined public key Base64 |
| `get_my_hybrid_sig_combined_pub()` | `Optional[str]` | Own hybrid signing combined public key Base64 |
| `verify_password(password)` | `bool` | Verify master password |

### Mutation Methods

| Method | Description |
|--------|-------------|
| `add_friend(name, public_key_pem, shared_secret=None, master_password='', x25519_pub_b64=None, capabilities=None, pqc_combined_pub_b64=None, hybrid_sig_pub_b64=None)` | Add or update a friend |
| `remove_friend(name)` | Remove a friend entirely |
| `update_shared_secret(name, new_secret, master_password, x25519_pub_b64=None)` | Replace shared secret for existing friend |

### Double Ratchet Methods

| Method | Description |
|--------|-------------|
| `has_active_ratchet(name)` | Check if friend has active ratchet session |
| `init_ratchet(name, role, master_password)` | Initialize ratchet as `'alice'` or `'bob'` |
| `reset_ratchet(name)` | Delete ratchet session and disable capability |

### PQC Methods

| Method | Description |
|--------|-------------|
| `generate_pqc_keys(master_password) -> str` | Generate hybrid PQC keys, return combined pub Base64 |
| `pqc_encapsulate(friend_name, master_password) -> Tuple[str, bytes]` | Encapsulate: returns `(ciphertext_b64, shared_secret)` |
| `pqc_decapsulate(ciphertext_b64, master_password) -> bytes` | Decapsulate: returns 32-byte shared secret |

---

## GlobalSecretService

**File:** `services/global_secret_service.py`

Manages the global shared secret used for group communication.

### Exception

| Exception | Description |
|-----------|-------------|
| `GlobalSecretServiceError` | Raised when a global secret operation fails |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_fingerprint()` | `Optional[str]` | SHA-256 fingerprint of current secret |
| `has_secret()` | `bool` | Whether a global secret is loaded |
| `export_secret_b64()` | `str` | Base64-encoded secret |
| `validate_secret_b64(b64_str)` | `bytes` | Validate and decode Base64 secret (must be 32 bytes) |
| `update_secret(new_secret, master_password)` | `str` | Update secret, returns new fingerprint |
| `verify_password(password)` | `bool` | Verify master password |

---

## ClipboardService

**File:** `services/clipboard_service.py`

Manages clipboard operations with automatic clearing for sensitive data.

### Constructor
```python
ClipboardService(root, clear_delay=30)
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `copy(text, auto_clear=True)` | `bool` | Copy to clipboard, optionally schedule auto-clear |
| `get()` | `Optional[str]` | Read clipboard content |
| `clear()` | `None` | Immediately clear clipboard |
| `shutdown()` | `None` | Cancel timers and clear on exit |

---

## EventBus

**File:** `services/event_bus.py`

Thread-safe publish/subscribe singleton for decoupled cross-component communication.

### Events Constants

| Event | Description |
|-------|-------------|
| `UNLOCK_REQUESTED` | User clicked unlock |
| `EMERGENCY_LOCK` | Emergency lock triggered |
| `UNLOCKED` / `LOCKED` | Lock state changed |
| `KEYS_WIPED` / `KEYS_LOADED` | Key lifecycle events |
| `PASSWORD_CHANGED` | Master password changed |
| `DURESS_MODE_ENTERED` | Duress mode activated |
| `TOTP_SETUP_COMPLETE` / `TOTP_VERIFIED` / `TOTP_CHANGED` | TOTP events |
| `SERVICES_REBUILT` | Services rebuilt after unlock |
| `NTP_SYNCED` / `NTP_SYNC_FAILED` | NTP sync results |
| `FRIEND_LIST_CHANGED` / `FRIEND_ADDED` / `FRIEND_REMOVED` | Friend data events |
| `RATCHET_INITIALIZED` / `RATCHET_RESET` | Ratchet lifecycle |
| `APP_STARTING` / `APP_SHUTDOWN` | Application lifecycle |

### Methods

| Method | Description |
|--------|-------------|
| `set_root(root)` | Configure Tkinter root for thread-safe dispatch |
| `subscribe(event, handler, thread_safe=False)` | Register handler for event |
| `unsubscribe(event, handler)` | Remove handler |
| `unsubscribe_all(handler)` | Remove handler from all events |
| `publish(event, **kwargs)` | Publish event to all subscribers |
| `clear()` | Remove all subscriptions |
| `subscriber_count(event=None)` | Count subscribers |

---

## CryptoTaskQueue

**File:** `services/crypto_task_queue.py`

Managed thread pool for background cryptographic operations with priority scheduling and timeout enforcement.

### TaskPriority Enum

| Value | Name | Use Case |
|-------|------|----------|
| 0 | `CRITICAL` | Authentication, key operations |
| 10 | `HIGH` | Message encryption/decryption |
| 20 | `NORMAL` | File operations |
| 30 | `LOW` | Background maintenance |

### Constructor
```python
CryptoTaskQueue(root, max_workers=4, default_timeout=None)
```

### Methods

| Method | Description |
|--------|-------------|
| `start()` | Start the thread pool |
| `shutdown(wait=True, timeout=30.0)` | Shut down executor |
| `submit(func, args=(), kwargs=None, on_success=None, on_error=None, priority=NORMAL, timeout=None) -> Future` | Submit task with callbacks dispatched to main thread |
| `submit_priority(priority, func, *args, ...)` | Convenience for priority submission |
| `drain(timeout=5.0) -> bool` | Wait for pending tasks |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `is_running` | `bool` | Whether queue accepts tasks |
| `pending_tasks` | `int` | Approximate pending count |

---

## ECDHService

**File:** `services/ecdh_service.py`

Pure X25519 key agreement operations with no UI dependency.

### Static Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `generate_private_key()` | `X25519PrivateKey` | Generate ephemeral private key |
| `private_to_public_bytes(priv)` | `bytes` | Extract raw 32-byte public key |
| `public_bytes_to_key(pub_bytes)` | `X25519PublicKey` | Convert raw bytes to key object |
| `compute_shared_secret(priv, peer_pub_bytes)` | `bytes` | Perform X25519 DH exchange |
| `derive_key(shared_secret)` | `bytes` | HKDF-derived 32-byte symmetric key |
| `encode_public_key(pub_bytes)` | `str` | Base64-encode public key |
| `decode_public_key(b64)` | `bytes` | Decode Base64 public key |
| `fingerprint(pub_bytes)` | `str` | SHA-256 fingerprint (16 hex chars) |
| `generate_keypair()` | `(priv, pub_bytes)` | Generate key pair |
| `perform_exchange(peer_pub, own_private=None)` | `(derived_key, our_pub)` | High-level ECDH exchange |

---

## TOTPService

**File:** `services/totp_service.py`

RFC 6238 compliant TOTP with HMAC-SHA1, 30-second intervals, 6-digit codes, ±1 step drift tolerance.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `TOTP_DIGITS` | 6 | Code length |
| `TOTP_INTERVAL` | 30 | Seconds per step |
| `TOTP_DRIFT` | 1 | ±1 step tolerance |

### Methods

| Method | Description |
|--------|-------------|
| `set_secret(secret)` | Set TOTP secret (≥20 bytes, uses first 20) |
| `set_raw_secret(secret)` | Set exact 20-byte secret |
| `clear_secret()` | Wipe secret from memory |
| `has_secret()` | Check if secret is set |
| `get_b32_secret()` | Base32-encoded secret for display |
| `get_raw_secret()` | Raw 20-byte secret for persistence |
| `generate(timestamp=None)` | Generate current 6-digit code |
| `verify(code, timestamp=None)` | Verify code with drift tolerance |
| `time_remaining()` | Seconds until current code expires |
| `provisioning_uri(account, issuer)` | `otpauth://` URI for authenticator apps |
| `generate_random_secret(length=32)` | Static: generate random secret |

---

## AuthManager

**File:** `services/auth_manager.py`

Authentication business logic: password verification, changes, duress passwords, lockout.

### Methods

| Method | Description |
|--------|-------------|
| `load_lockout_state()` | Load persistent lockout from DB |
| `save_lockout_state()` | Persist lockout to DB |
| `get_lockout_delay()` | Seconds to wait before next attempt |
| `verify_password(password) -> (bool, bool)` | Returns `(is_valid, is_duress)` |
| `change_password(old, new)` | Re-encrypt all secrets with new password |
| `set_duress_password(duress_password)` | Configure duress password |
| `load_duress_decoy()` | Load fake decoy state |

---

## BackupService

**File:** `services/backup_service.py`

Export/import database + keys with HMAC-SHA256 integrity verification.

### Constructor
```python
BackupService(key_store, backup_dir=None, max_backups=10, reminder_days=7)
```

### Methods

| Method | Description |
|--------|-------------|
| `export_backup(password) -> dict` | Package encrypted blobs into export dict |
| `import_backup(data, password)` | Validate HMAC, wipe current, restore, reload |
| `export_backup_to_file(password, backup_dir=None) -> Path` | Timestamped file export with pruning |
| `import_backup_from_file(filepath, password)` | Load and restore from file |
| `list_backups(backup_dir=None) -> List[Path]` | Sorted list of backup files |
| `get_last_backup_timestamp()` | Unix timestamp of last backup |
| `should_remind_backup() -> (bool, Optional[int])` | Check if reminder is warranted |

---

## HotkeyService

**File:** `services/hotkey_service.py`

Windows-only global hotkey registration via Win32 API (`RegisterHotKey`).

### Constants

| Constant | Value |
|----------|-------|
| `MOD_CTRL` | `0x0002` |
| `MOD_SHIFT` | `0x0004` |
| `VK_L` | `0x4C` |
| `VK_U` | `0x55` |

### Methods

| Method | Description |
|--------|-------------|
| `register(hotkey_id, modifiers, vk, callback)` | Store hotkey definition |
| `start()` | Start listener thread, register hotkeys |
| `stop()` | Unregister hotkeys, stop listener |

---

## RatchetService

**File:** `services/ratchet_service.py`

Persistence and lifecycle management for Double Ratchet sessions. Thread-safe with per-friend reentrant locks and deadlock prevention via canonical ordering.

### Static Methods

| Method | Description |
|--------|-------------|
| `get_friend_profile(name) -> Optional[FriendProfile]` | Load structured profile |
| `has_active_ratchet(name) -> bool` | Check for active session |
| `get_ratchet_state(name) -> RatchetState` | Load and deserialize state |
| `save_ratchet_state(name, state)` | Serialize and persist state |
| `init_ratchet_alice(name, bob_dh_pub_bytes, shared_secret)` | Initialize as Alice |
| `init_ratchet_bob(name, alice_dh_pub_bytes, shared_secret)` | Initialize as Bob |
| `delete_ratchet(name) -> bool` | Remove ratchet state |
| `encrypt_message(name, plaintext) -> (header, ciphertext)` | Encrypt with ratchet |
| `encrypt_to_envelope(name, plaintext) -> RatchetEnvelope` | Encrypt + wrap in envelope |
| `decrypt_message(name, header, ciphertext) -> bytes` | Decrypt with ratchet |

### Lock Management

| Method | Description |
|--------|-------------|
| `_get_friend_lock(name)` | Get/create per-friend RLock |
| `_acquire_friend_lock(name, timeout)` | Acquire with timeout |
| `acquire_friend_locks_ordered(names, timeout)` | Acquire multiple in sorted order (deadlock prevention) |
| `cleanup_friend_locks(active_friends)` | Remove stale locks |
| `get_lock_stats()` | Lock statistics |
| `detect_potential_deadlock(names_a, names_b)` | Static deadlock analysis |

---

## DoubleRatchet (RatchetState)

**File:** `services/double_ratchet.py`

Signal Protocol Double Ratchet implementation providing forward secrecy and post-compromise security.

### RatchetState Class

#### Initialization

| Method | Description |
|--------|-------------|
| `initialize_as_alice(bob_dh_pub, shared_secret)` | Init as initiator |
| `initialize_as_bob(alice_dh_pub, shared_secret, local_dh_priv=None)` | Init as responder |

#### Core Operations

| Method | Returns | Description |
|--------|---------|-------------|
| `encrypt(plaintext) -> (header, ciphertext)` | Encrypt message, advance send chain |
| `decrypt(header, ciphertext) -> bytes` | Decrypt, handle out-of-order, DH ratchet steps |
| `dh_ratchet_step(remote_pub)` | Perform DH ratchet step |
| `get_local_dh_public_key() -> bytes` | Current DH public key |

#### Serialization

| Method | Description |
|--------|-------------|
| `serialize() -> dict` | Serialize state for storage |
| `deserialize(data) -> RatchetState` | Class method: restore from dict |

#### Internal KDF Methods

| Method | Description |
|--------|-------------|
| `_hkdf_rk(rk, dh_out)` | Root key KDF: derives new root + chain key |
| `_hkdf_ck(ck)` | Chain key KDF: HMAC-based stepping (new_ck, message_key) |
| `_decrypt_with_key(key, data)` | AES-GCM decrypt with message key |

---

## PQCService (HybridKEM)

**File:** `services/pqc_service.py`

Hybrid classical + post-quantum key encapsulation combining X25519 ECDH with CRYSTALS-Kyber-768.

### Functions

| Function | Description |
|----------|-------------|
| `is_pqc_available() -> bool` | Check if liboqs + Kyber768 available |

### HybridKEM Static Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `generate_keys()` | `dict` | Generate X25519 + Kyber768 key pair |
| `encapsulate(remote_combined_pub)` | `dict` | Generate shared secret + ciphertext |
| `decapsulate(keys, ciphertext)` | `bytes` | Recover 32-byte shared secret |

### Key Format

Combined public key: `[len_x(2) | x25519(32) | len_ky(2) | kyber_pub]`

Ciphertext: `[x_pub(32) | kyber_ct]`

---

## PQCSignatures (HybridSigner)

**File:** `services/pqc_signatures.py`

Hybrid digital signatures combining Ed25519 with CRYSTALS-Dilithium3 (or ML-DSA-65).

### HybridSigner Static Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `generate_keys()` | `dict` | Generate Ed25519 + Dilithium3 key pair |
| `sign(message, ed_priv, dil_priv)` | `bytes` | Create hybrid signature |
| `verify(message, signature, ed_pub, dil_pub)` | `bool` | Verify BOTH signatures must pass |
| `parse_combined_pub(combined_pub)` | `(ed_pub, dil_pub)` | Parse combined public key |
| `load_ed_public_key(ed_pub_bytes)` | `Ed25519PublicKey` | Load Ed25519 public key |

### Signature Format

`[ed_sig_len(2) | ed_sig(64) | dil_sig(variable)]`

---

## Controllers

### ServiceOrchestrator

**File:** `controllers/service_orchestrator.py`

Centralized manager for all business service instances. Handles creation, rebuilding, dependency injection, and PQC model wiring.

#### Constructor
```python
ServiceOrchestrator(root, key_store, crypto_queue=None)
```

Creates: `EncryptionService`, `FileService`, `FriendsService`, `ClipboardService`, `GlobalSecretService`

Also calls `configure_pqc_support()` to inject PQC dependencies into the model layer, avoiding upward model → service imports.

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `encryption_service` | EncryptionService | Current instance |
| `file_service` | FileService | Current instance |
| `friends_service` | FriendsService | Current instance |
| `clipboard_service` | ClipboardService | Current instance |
| `global_secret_service` | GlobalSecretService | Current instance |
| `service_lock` | RLock | Thread-safe service access |

#### Methods

| Method | Description |
|--------|-------------|
| `rebuild_services(new_key_store, tab_references)` | Rebuild all services, update tab refs, publish event |
| `shutdown()` | Clean up clipboard service |

#### Events Published
- `SERVICES_REBUILT`

### PQC Model Wiring

The `ServiceOrchestrator` is responsible for wiring PQC dependencies into the model layer at startup and after service rebuilds:

```python
from models.key_store import configure_pqc_support

# In __init__ and rebuild_services:
try:
    from services.pqc_service import is_pqc_available
    from services.pqc_signatures import HybridSigner
    configure_pqc_support(is_pqc_available, HybridSigner)
except (ImportError, RuntimeError, OSError):
    configure_pqc_support(lambda: False)
```

This ensures `models/key_store.py` can check PQC availability without importing from `services/`.

---
