# Services Reference

Comprehensive documentation for every service in the `services/` directory. Covers 23 service modules (25 directory entries minus `__init__.py` and `__pycache__/`).

---

## Table of Contents

- [EncryptionService](#encryptionservice)
- [AnomalyDetectionService](#anomalydetectionservice)
- [FileService](#fileservice)
- [FriendsService](#friendsservice)
- [GlobalSecretService](#globalsecretservice)
- [ClipboardService](#clipboardservice)
- [EventBus](#eventbus)
- [CryptoTaskQueue](#cryptotaskqueue)
- [ECDHService](#ecdhservice)
- [TOTPService](#totpservice)
- [TotpPersistence](#totppersistence)
- [AuthManager](#authmanager)
- [BackupService](#backupservice)
- [HotkeyService](#hotkeyservice)
- [XChaCha20Poly1305](#xchacha20poly1305)
- [RatchetService](#ratchetservice)
- [DoubleRatchet (RatchetState)](#doubleratchet-ratchetstate)
- [PQCService (HybridKEM)](#pqcservice-hybridkem)
- [PQCSignatures (HybridSigner)](#pqcsignatures-hybridsigner)
- [TrustChainService](#trustchainservice)
- [ShamirService](#shamirservice)
- [BackgroundAgents](#backgroundagents)
- [FriendRepository](#friendrepository)
- [AuthController](#authcontroller)

---

## EncryptionService

**File:** `services/encryption/` package

Facade over three focused encryption strategies. The public API is preserved via a thin facade that delegates to the appropriate strategy based on mode and envelope type.

### Package Structure

```
services/encryption/
├── __init__.py              # Re-exports EncryptionService, EncryptionStrategy, EncryptionError, DecryptionError
├── encryption_facade.py     # EncryptionService facade + EncryptionStrategy Protocol
├── legacy_strategy.py       # LegacyEncryptionStrategy (shared-secret + RSA hybrid)
├── ratchet_strategy.py      # RatchetEncryptionStrategy (Double Ratchet)
└── pqc_strategy.py          # PqcEncryptionStrategy (Post-Quantum Hybrid KEM)
```

### Constructor

```python
EncryptionService(key_store, anomaly_service=None)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key_store` | KeyStore | Must expose `global_secret`, `my_priv`, `friends`, `get_decryption_snapshot()`, and optionally `friends_capabilities`, `friends_pqc_combined_pub`, `pqc_decryption_bundle`, `my_name` |
| `anomaly_service` | `Optional[AnomalyDetectionService]` | If provided, each decrypted message is scored for anomalous metadata |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `last_encrypt_mode` | `Optional[str]` | `'ratchet'`, `'pqc'`, `'legacy'`, or `None` |
| `last_decrypt_mode` | `Optional[str]` | `'ratchet'`, `'pqc'`, `'legacy'`, or `None` |

### Methods

#### `update_ntp_time(timestamp: Optional[float])`
Sets the NTP-corrected timestamp used for time-based key derivation.

#### `encrypt(plaintext, friend_name=None, mode='shared', sign=True, self_destruct_seconds=None) -> Tuple[bytes, int]`
Encrypts plaintext. Automatically selects strategy based on mode and friend capabilities.

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
Convenience: encrypts and returns Base64-encoded string.

#### `decrypt(b64_text: str) -> str`
Decrypts a Base64-encoded message. Auto-detects envelope type and routes to the correct strategy.

**Raises:** `DecryptionError`

### Sub-Services

#### LegacyEncryptionStrategy
**File:** `services/encryption/legacy_strategy.py`

Handles shared-secret and RSA hybrid encryption. Contains all legacy key resolution, RSA decryption with fallback to legacy keys, and shared-secret iteration logic.

#### RatchetEncryptionStrategy
**File:** `services/encryption/ratchet_strategy.py`

Handles Double Ratchet encryption/decryption. Wraps `RatchetService` and builds `RatchetEnvelope` structures.

#### PqcEncryptionStrategy
**File:** `services/encryption/pqc_strategy.py`

Handles Post-Quantum Hybrid KEM encryption/decryption. Wraps `HybridKEM` with timeout protection and builds `PQCEncvelope` structures.

---

## AnomalyDetectionService

**File:** `services/anomaly_detection_service.py`

Isolation Forest-based anomaly detector that scores incoming messages using metadata only (no plaintext access). Zero-knowledge design.

### Constructor

```python
AnomalyDetectionService(model_path: Optional[str] = None)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `model_path` | `Optional[str]` | Path to pre-trained `.pkl` model. Defaults to `anomaly_model.pkl` in project root. |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `enabled` | `bool` | Whether scoring is active (read/write) |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `is_available()` | `bool` | `True` if the model loaded successfully |
| `score_message(friend_name, packet)` | `Optional[MessageScore]` | Score a message packet. Returns `MessageScore` if model is available, else `None`. Publishes `ANOMALY_DETECTED` event when anomaly is detected. |

### Feature Extraction

The service extracts a 7-element feature vector from raw packet metadata:

| Index | Feature | Description |
|-------|---------|-------------|
| 0 | `packet_size` | Total packet size in bytes |
| 1 | `name_length` | Length of the sender name string |
| 2 | `env_type_code` | Envelope type: 0=ratchet, 1=pqc, 2=legacy, -1=unknown |
| 3 | `header_len` | Parsed header/KEM ciphertext length |
| 4 | `ct_len` | Parsed ciphertext length |
| 5 | `hour_of_day` | Local hour (0–23) |
| 6 | `day_of_week` | Local weekday (0=Monday, 6=Sunday) |

### Integration

`AnomalyDetectionService` is created by `ServiceOrchestrator` and injected into `EncryptionService`. After each successful decryption, the facade calls `score_message()` with the sender name and raw packet. If the score falls below the model's threshold, an `ANOMALY_DETECTED` event is published to the `EventBus`, which triggers a toast notification and red banner in the main UI.

---

## FileService

**Files:** `services/file_ops.py` (standalone functions) + `services/file_service.py` (service class)

Service layer for file encryption/decryption. The standalone crypto functions are in `file_ops.py`; the `FileService` class in `file_service.py` is a thin facade over them.

### Exceptions

| Exception | Description |
|-----------|-------------|
| `FileServiceError` | Base exception for file service errors |
| `SharedSecretDetected` | Raised when a shared-secret file is detected; contains `owner` and `fingerprint` attributes |

### Standalone Functions (`services/file_ops.py`)

#### `file_encrypt(input_path, output_path, password)`
Encrypts a file using AES-GCM with Argon2id-derived key. Format: `A2ID(4) + salt(16) + nonce(12) + ciphertext`. KDF wrapped in timeout.

#### `file_decrypt(input_path, output_path, password)`
Decrypts with automatic KDF detection (Argon2id or legacy PBKDF2).

#### `file_encrypt_shared(input_path, output_path, shared_secret, sign=False, my_priv=None, hybrid_ed_priv=None, hybrid_dil_priv=None)`
Encrypts using shared secret with HKDF-derived key and optional RSA or hybrid (Ed25519 + Dilithium3) signature.

#### `file_decrypt_shared(input_path, output_path, secrets_dict, friends_for_sig=None, friends_hybrid=None)`
Decrypts shared-secret file with multi-layer signature verification. Returns signature verification message.

### FileService Class (`services/file_service.py`)

#### Constructor
```python
FileService(key_store)
```

The constructor initializes a fingerprint cache for `_build_secrets_dict()`. SHA-256 fingerprints are computed once and reused across calls. Call `invalidate_fingerprint_cache()` after key store modifications.

#### Methods

| Method | Description |
|--------|-------------|
| `encrypt_file(input_path, output_path, method, password=None, friend_name=None, sign=False)` | Encrypts a file. `method`: `'password'`, `'global'`, or `'friend'` |
| `decrypt_file(input_path, output_path, password=None) -> str` | Auto-detects encryption method. Returns signature message. May raise `SharedSecretDetected` |
| `decrypt_with_shared_secret(input_path, output_path, fingerprint) -> str` | Decrypts after user confirms detected fingerprint |
| `invalidate_fingerprint_cache()` | Invalidate cached fingerprints after key store changes |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `FILE_MAGIC` | `b'ENIGMA\x01'` | 7-byte magic for shared-secret encrypted files |

---

## FriendsService

**File:** `services/friends/` package

High-level API for managing friends, shared secrets, ECDH keys, PQC keys, and Double Ratchet sessions. Decomposed into four focused sub-services behind a facade.

### Package Structure

```
services/friends/
├── __init__.py              # Re-exports FriendsService, FriendsServiceError
├── friends_facade.py        # FriendsService facade (delegates all methods)
├── crud.py                  # FriendCrudService (CRUD, queries, auth)
├── ratchet_mgmt.py          # FriendRatchetManager (Double Ratchet lifecycle)
├── pqc_keys.py              # FriendPqcKeyService (PQC key exchange)
└── hybrid_sig_keys.py       # FriendHybridSigKeyService (hybrid signing keys)
```

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

### Sub-Services

#### FriendCrudService (`services/friends/crud.py`)
CRUD operations, queries, and auth for friends. Contains 14 methods for friend management, all delegating to `KeyStore`.

#### FriendRatchetManager (`services/friends/ratchet_mgmt.py`)
Manages Double Ratchet sessions for friends. Orchestrates `RatchetService` and updates capability flags.

#### FriendPqcKeyService (`services/friends/pqc_keys.py`)
PQC key generation, encapsulation, and decapsulation. Wraps `HybridKEM` operations.

#### FriendHybridSigKeyService (`services/friends/hybrid_sig_keys.py`)
Hybrid signing key generation and import. Handles Ed25519 + Dilithium3 key lifecycle.

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

### Events Constants (38 total, `services/event_bus.py:28-83`)

| Category | Constants |
|----------|-----------|
| Authentication & Lock | `UNLOCK_REQUESTED`, `EMERGENCY_LOCK`, `UNLOCKED`, `LOCKED` |
| Key & credential | `KEYS_WIPED`, `KEYS_LOADED`, `PASSWORD_CHANGED`, `DURESS_MODE_ENTERED` |
| TOTP | `TOTP_SETUP_COMPLETE`, `TOTP_VERIFIED`, `TOTP_CHANGED` |
| Service | `SERVICES_REBUILT`, `NTP_SYNCED`, `NTP_SYNC_FAILED` |
| Data / Friend | `FRIEND_LIST_CHANGED`, `FRIEND_ADDED`, `FRIEND_REMOVED`, `RATCHET_INITIALIZED`, `RATCHET_RESET` |
| Trust chain | `CERTIFICATE_ISSUED`, `CERTIFICATE_RECEIVED`, `CERTIFICATE_REVOKED`, `TRUST_LEVEL_CHANGED`, `RECOVERY_SHARE_CREATED`, `RECOVERY_KEY_RECONSTRUCTED` |
| Security | `ANOMALY_DETECTED` |
| Application lifecycle | `APP_STARTING`, `APP_SHUTDOWN` |
| Background agent | `BACKUP_REMINDER`, `BACKUP_COMPLETED`, `RATCHET_LOCKS_CLEANED`, `RATCHET_DEADLOCK_DETECTED`, `RATCHET_LOCK_STATS`, `SYSTEM_STATUS`, `SYSTEM_HEALTH_OK`, `SYSTEM_HEALTH_DEGRADED`, `KEY_INFO`, `KEY_FINGERPRINT` |

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
| `verify(code, timestamp=None, track_replay=True)` | Verify code with drift tolerance. `track_replay=False` skips replay counter advancement (used for self-tests) |
| `set_counter_persistence(save_callback, initial_counter=-1)` | Wire durable replay-counter storage. `save_callback` is invoked with the newest accepted counter whenever it advances. `initial_counter` raises the in-memory counter so previously consumed codes stay rejected across restarts |
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

### TrustChainService

**File:** `services/trust_chain_service.py` (1000+ lines)

Decentralized trust chain management for certificate-based identity verification. Certificates are cryptographically verified against pinned issuer keys before being trusted.

```python
class TrustChainService:
    def __init__(self, key_store: KeyStore)
```

| Method | Returns | Description |
|--------|---------|-------------|
| `issue_certificate(subject_name, subject_pub_b64, cert_type, validity_days=365)` | `TrustCertificate` | Create, sign, and persist a new certificate |
| `receive_certificate(cert_data, received_from=None)` | `bool` | Import and verify a certificate from a peer |
| `revoke_certificate(cert_id, reason=None)` | `bool` | Mark a certificate as revoked |
| `get_certificate(cert_id)` | `Optional[TrustCertificate]` | Retrieve certificate by ID |
| `get_certificates_for_subject(name)` | `List[TrustCertificate]` | All certificates for a subject |
| `get_certificates_by_type(cert_type)` | `List[TrustCertificate]` | Filter by certificate type |
| `get_all_certificates()` | `List[TrustCertificate]` | All stored certificates |
| `get_trust_level(subject_name)` | `TrustLevel` | Compute aggregate trust level (only verified certs count) |
| `verify_certificate(cert_id)` | `bool` | Verify a certificate's full validity chain including issuer identity and hybrid signature |
| `import_received_certs(cert_dicts)` | `int` | Import certificates from a peer; cryptographically verifies each before trusting. Returns count of imported certs (rejected certs have invalid signatures or unknown issuers) |
| `export_certificate(cert_id)` | `Optional[str]` | Export as Base64 string |
| `import_certificate(b64_data)` | `Optional[TrustCertificate]` | Import from Base64 string |
| `clean_expired()` | `int` | Remove expired certificates |

**Internal verification methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `_expected_issuer_pub(issuer_name)` | `Optional[bytes]` | Return the pinned hybrid signing public key for an issuer (self or known friend) |
| `_verify_cert_object(cert)` | `None` | Verify a certificate's hybrid signature against the issuer's pinned key. Raises `CertificateSignatureError` if issuer is unknown, key mismatches, or signature is invalid |

Trust levels: NONE (0), BASIC (1), VERIFIED (2), TRUSTED (3+).

---

### ShamirService

**File:** `services/shamir_service.py` (223 lines)

Shamir's Secret Sharing over GF(256) for threshold-based key recovery.

```python
class ShamirService:
    @staticmethod
    def split_secret(secret: bytes, total_shares: int, threshold: int) -> List[Tuple[int, bytes]]
        """Split a secret into N shares, requiring T for reconstruction.
        Returns list of (share_index, share_data) tuples."""
    
    @staticmethod
    def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes
        """Reconstruct the original secret from T or more shares.
        Uses Lagrange interpolation over GF(256)."""
    
    @staticmethod
    def generate_recovery_share(owner_name, holder_name, holder_pub, secret, threshold, total_shares, password) -> List[dict]
        """Generate and persist encrypted recovery shares across holders."""
    
    @staticmethod
    def recover_secret(shares_data, password) -> Optional[bytes]
        """Reconstruct secret from collected shares and decrypt."""
```

Parameters: irreducible polynomial 0x11D over GF(256). Pre-computed exp/log tables for fast field arithmetic. Max 10 shares, min threshold 2.

---

### Background Agents

**File:** `services/background_agents.py` (536 lines)

Background agent framework for periodic maintenance and monitoring tasks. Each agent runs in its own daemon thread.

**Base class:** `BackgroundAgent` — common lifecycle (start, stop, loop interval, threading.Event for shutdown signaling).

**Agent classes:**

| Agent | Interval | Description |
|-------|----------|-------------|
| `BackupReminderAgent` | 3600s (1h) | Checks last backup timestamp and publishes BACKUP_REMINDER if overdue |
| `RatchetMaintenanceAgent` | 3600s (1h) | Cleans stale ratchet locks, detects deadlocks, publishes lock statistics |
| `SystemMonitorAgent` | 300s (5m) | Monitors memory usage, key integrity, and publishes SYSTEM_HEALTH events |
| `KeyInspectorAgent` | 3600s (1h) | Checks key expiry, rotation needs, publishes KEY_INFO and KEY_FINGERPRINT |

**Lifecycle:**
```python
# Start all agents
agent_manager.start_agents()

# Stop all agents (called during shutdown)
agent_manager.stop_agents()
```

Agents are managed by ServiceOrchestrator (`controllers/service_orchestrator.py:56-134`), which provides `start_agents()` and `stop_agents()` methods. Tab references can subscribe to agent-published events for UI updates.

---

## FriendRepository

**File:** `services/friend_repository.py`

Data access layer for `FriendProfile` persistence. Centralises all database queries for friend data.

### Standalone Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `get_friend_profile(name)` | `Optional[FriendProfile]` | Load a single profile from DB |
| `list_all_friend_profiles()` | `List[FriendProfile]` | Load all profiles from DB |

---

## TotpPersistence

**File:** `services/totp_persistence.py`

Handles persistence of TOTP secrets, setup status, enabled state, and replay counter to/from the database. Uses multiple decryption strategies for backward compatibility.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `TOTP_SECRET_KEY` | `'totp_secret_encrypted'` | DB key for encrypted TOTP secret |
| `TOTP_SETUP_KEY` | `'totp_setup_complete'` | DB key for setup flag |
| `TOTP_ENABLED_KEY` | `'totp_enabled'` | DB key for enabled flag |
| `TOTP_LAST_COUNTER_KEY` | `'totp_last_counter'` | DB key for highest accepted TOTP counter (cross-restart replay protection) |

### Methods

| Method | Description |
|--------|-------------|
| `load_totp_secret(totp_service, password, ks)` | Load with multiple decryption strategies; wires replay counter after secret is installed |
| `persist_totp_secret(secret_bytes, password)` | Encrypt and store TOTP secret; resets replay counter to -1 |
| `load_last_counter()` | Return the highest TOTP time-step counter accepted so far, or -1 |
| `save_last_counter(counter)` | Persist the highest accepted TOTP counter for cross-restart replay protection |
| `is_totp_setup_complete()` | Check DB flag |
| `set_totp_setup_complete(value)` | Set DB flag |
| `is_totp_enabled()` | Check DB flag (falls back to setup status) |
| `set_totp_enabled(value)` | Set DB flag |

---

## XChaCha20Poly1305

**File:** `services/xchacha20_poly1305.py`

XChaCha20-Poly1305 AEAD cipher providing nonce-misuse-resistant encryption with a 192-bit nonce space. Implements HChaCha20 subkey derivation in pure Python. Used by the Double Ratchet protocol.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `XCHACHA20_KEY_SIZE` | 32 | Key length in bytes |
| `XCHACHA20_NONCE_SIZE` | 24 | Nonce length in bytes |
| `XCHACHA20_TAG_SIZE` | 16 | Authentication tag length |

### Standalone Functions

| Function | Description |
|----------|-------------|
| `generate_nonce()` | Generate cryptographically random 24-byte nonce |
| `run_self_test()` | Run KAT self-test against known vectors |

### Class: XChaCha20Poly1305

| Method | Description |
|--------|-------------|
| `__init__(key)` | Validate 32-byte key, store raw key |
| `encrypt(nonce, plaintext, associated_data)` | Encrypt with HChaCha20 subkey derivation + IETF ChaCha20-Poly1305 |
| `decrypt(nonce, ciphertext, associated_data)` | Verify and decrypt ciphertext |

---

## Controllers

### ServiceOrchestrator

**File:** `controllers/service_orchestrator.py`

Centralized manager for all business service instances. Handles creation, rebuilding, dependency injection, and PQC model wiring.

#### Constructor
```python
ServiceOrchestrator(root, key_store, crypto_queue=None)
```

Creates: `EncryptionService` (with `AnomalyDetectionService`), `FileService`, `FriendsService`, `ClipboardService`, `GlobalSecretService`

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

### AuthController

**File:** `controllers/auth_controller.py`

Manages authentication UI flow: unlock screen, password verification, TOTP integration, and session lifecycle.

#### Constructor
```python
class AuthController:
    def __init__(self, root: tk.Tk, key_store: KeyStore, ui=None, totp_persistence=None)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `root` | `tk.Tk` | Tkinter root window |
| `key_store` | `KeyStore` | Key store instance |
| `ui` | `Optional` | UI reference |
| `totp_persistence` | `Optional[TotpPersistence]` | TOTP persistence handler |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `load_totp_secret(totp_service, password, ks)` | `bool` | Load with multiple decryption strategies |
| `persist_totp_secret(secret_bytes, password)` | `None` | Encrypt and store TOTP secret |
| `init_totp(password)` | `None` | Load existing or generate new |
| `generate_new_totp(password)` | `None` | Generate and persist new secret |
| `regenerate_totp()` | `None` | Regenerate from setup dialog |
| `is_totp_enabled()` | `bool` | Check DB flag |
| `set_totp_enabled(value)` | `None` | Set DB flag |

---
