# Models Reference

Comprehensive documentation for all data models in the `models/` directory and core data structures.

---

## Table of Contents

- [RatchetEnvelope](#ratchetenvelope)
- [PQCEncvelope](#pqcencvelope)
- [FriendProfile](#friendprofile)
- [KeyStoreModel](#keystoremodel)
- [KeyStore (Runtime)](#keystore-runtime)
- [Database Schema](#database-schema)
- [SecureString](#securestring)
- [Exception Hierarchy](#exception-hierarchy)
- [Constants](#constants)

---

## RatchetEnvelope

**File:** `models/envelope.py`

Structured representation of a Double Ratchet message envelope. Immutable dataclass.

### Wire Format
```
0xD0 | name_len(1B) | name(UTF-8) | hdr_len(2B BE) | header | ciphertext
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `sender_name` | `str` | UTF-8 encoded sender display name (set via `KeyStore.my_name`) |
| `header` | `bytes` | Raw Double Ratchet header (DH pub + msg_num + prev_chain_len) |
| `ciphertext` | `bytes` | AES-GCM encrypted payload including nonce and tag |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `build()` | `bytes` | Serialize to binary wire format |
| `parse(packet)` | `RatchetEnvelope` | Class method: deserialize from bytes |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `RATCHET_ENVELOPE_MAGIC` | `0xD0` | Magic byte identifier |

---

## PQCEncvelope

**File:** `models/envelope.py`

Structured representation of a Post-Quantum Hybrid KEM message envelope. Immutable dataclass.

### Wire Format
```
0x50 | kem_ct_len(2B BE) | kem_ciphertext | nonce(12B) | aes_gcm_ciphertext+tag
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `kem_ciphertext` | `bytes` | KEM encapsulation output (Kyber768 + X25519) |
| `nonce` | `bytes` | 12-byte AES-GCM nonce |
| `aes_ciphertext` | `bytes` | AES-256-GCM encrypted payload with auth tag |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `build()` | `bytes` | Serialize to binary wire format |
| `parse(packet)` | `PQCEncvelope` | Class method: deserialize from bytes |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PQC_ENVELOPE_MAGIC` | `0x50` | Magic byte identifier |
| `NONCE_LENGTH` | `12` | Required nonce length |

---

## Envelope Identification

**File:** `models/envelope.py`

### `identify_envelope_type(packet: bytes) -> Optional[str]`

Identifies envelope type from first byte. Returns `'ratchet'`, `'pqc'`, or `None`.

---

## FriendProfile

**File:** `models/friend_profile.py`

Immutable representation of a friend's profile and session state. Replaces scattered dictionary/tuple representations.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Unique friend identifier |
| `public_key` | `Optional[bytes]` | RSA or X25519 public key bytes |
| `shared_secret` | `Optional[bytes]` | Pre-shared symmetric key |
| `capabilities` | `Dict[str, Any]` | Capability flags (e.g., `{"double_ratchet": True}`) |
| `has_active_ratchet` | `bool` | Whether ratchet session exists |
| `pqc_combined_pub` | `Optional[bytes]` | PQC combined public key |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `supports_double_ratchet` | `bool` | Checks capabilities dict |
| `supports_pqc` | `bool` | Checks capabilities dict |

### Class Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `from_database(friend_name)` | `Optional[FriendProfile]` | Load from DB by name |
| `list_all()` | `list[FriendProfile]` | Load all profiles |

---

## KeyStoreModel

**File:** `models/key_store.py`

Pure data model and persistence manager for cryptographic keys. Strictly a data/persistence layer — no business logic.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `my_pub` | RSA public key | Own RSA public key |
| `my_priv` | RSA private key | Own RSA private key |
| `legacy_priv` | RSA private key | Previous RSA key (30-day retention) |
| `global_secret` | `Optional[bytearray]` | Global shared secret (mutable for wiping) |
| `friends` | `List[Tuple]` | `(name, pub, shared_secret)` tuples |
| `friends_x25519` | `Dict[str, str]` | Name → Base64 X25519 public key |
| `friends_capabilities` | `Dict[str, dict]` | Name → capabilities dict |
| `friends_pqc_combined_pub` | `Dict[str, bytes]` | Name → raw PQC combined pub |
| `my_kyber_priv` | `Optional[bytes]` | Local Kyber secret key |
| `my_pqc_combined_pub` | `Optional[bytes]` | Local hybrid combined pub |
| `my_ed_priv` | Ed25519PrivateKey | Hybrid signing Ed25519 key |
| `my_dil_priv` | `Optional[bytes]` | Hybrid signing Dilithium3 key |
| `my_hybrid_sig_combined_pub` | `Optional[bytes]` | Hybrid signing combined pub |
| `friends_hybrid_sig_pubs` | `Dict[str, tuple]` | Name → `(ed_pub, dil_pub)` |
| `my_name` (property) | `str` | Display name for ratchet envelope sender identification; falls back to `user-<8-char-hash>` if unset |

### Methods

| Method | Description |
|--------|-------------|
| `to_dict() -> dict` | Serialize non-sensitive metadata |
| `from_dict(data) -> KeyStoreModel` | Restore metadata (no key material) |
| `load(password)` | Load all keys from database |
| `save_friend(name, pem, ...)` | Save friend to DB and memory |
| `remove_friend(name)` | Remove from DB and memory |
| `get_friend_secret(name)` | Retrieve friend's shared secret |
| `get_decryption_snapshot()` | Returns tuple of `(my_priv, friends_for_crypto, secrets_to_try, legacy_priv)` for thread-safe decryption operations. `friends_for_crypto` is list of `(name, pub, secret)` tuples. `secrets_to_try` includes global secret and all friend shared secrets. Returns `None` for missing keys. |
| `wipe()` | Securely erase all sensitive keys |

---

## KeyStore (Runtime)

**File:** `key_manager.py`

Full runtime key store with authentication, lockout, PQC key management, and password change workflows. Extends the data model with business logic.

### Additional Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `failed_attempts` | `int` | Brute-force counter |
| `locked_until` | `float` | Epoch timestamp for lockout |
| `_duress_mode` | `bool` | Whether duress password was used |
| `_needs_rotation` | `bool` | RSA key below CNSA 2.0 minimum |

### Key Methods

| Method | Description |
|--------|-------------|
| `load(password) -> bool` | Load all keys from DB |
| `verify_password(password) -> bool` | Check master or duress password with backoff |
| `set_duress_password(duress_password)` | Configure duress password |
| `update_global_secret(new_secret, password)` | Update global secret |
| `ensure_pqc_keys(password)` | Generate PQC keys if missing |
| `ensure_pqc_keys_full(password) -> Optional[dict]` | Full PQC bundle with X25519 priv |
| `load_pqc_bundle(password) -> Optional[dict]` | Load existing PQC bundle |
| `rotate_rsa_key(password)` | Generate new 4096-bit RSA, retire old |
| `change_password(old, new)` | Re-encrypt all secrets |
| `get_decryption_snapshot()` | Thread-safe snapshot for background decryption |
| `load_duress_decoy() -> bool` | Load fake decoy state |
| `set_my_name(name)` | Persist display name to `settings` table for ratchet sender identity |
| `wipe()` | Securely erase all keys |

### File Encryption Functions (in key_manager.py)

| Function | Description |
|----------|-------------|
| `file_encrypt(input_path, output_path, password)` | Password-based file encryption (Argon2id) |
| `file_decrypt(input_path, output_path, password)` | Auto-detect KDF, decrypt file |
| `file_encrypt_shared(input_path, output_path, shared_secret, sign, my_priv)` | Shared-secret file encryption |
| `file_decrypt_shared(input_path, output_path, secrets_dict, friends_for_sig)` | Shared-secret file decryption |

---

## Database Schema

**File:** `database.py`

SQLite database at `~/.ultimate_enigma/enigma.db` with WAL mode and foreign keys enabled.

### Tables

#### `settings`
| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT PK | Setting name |
| `value` | TEXT NOT NULL | Setting value (JSON for encrypted data) |

Known keys: `public_key`, `private_key_encrypted`, `global_secret`, `legacy_private_key_encrypted`, `legacy_key_expiry`, `kyber_priv_encrypted`, `pqc_combined_pub_b64`, `pqc_x25519_priv_encrypted`, `ed25519_priv_encrypted`, `dilithium_priv_encrypted`, `hybrid_sig_combined_pub_b64`, `totp_secret_encrypted`, `totp_setup_complete`, `totp_enabled`, `lockout_data`, `duress_verifier`, `last_backup_ts`, `my_name`

#### `friends`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK AUTO | Auto-increment ID |
| `name` | TEXT NOT NULL UNIQUE | Friend name |
| `public_key_pem` | TEXT NOT NULL | RSA public key PEM |
| `has_shared_secret` | INTEGER NOT NULL | 0 or 1 |
| `shared_secret_encrypted` | TEXT | JSON: `{kdf, salt, nonce, ct}` |
| `x25519_public_key_b64` | TEXT | Raw X25519 pub key Base64 |
| `ratchet_state_json` | TEXT | Serialized RatchetState |
| `capabilities_json` | TEXT | JSON capabilities dict |
| `pqc_combined_pub_b64` | TEXT | PQC combined pub Base64 |
| `hybrid_sig_pub_b64` | TEXT | Hybrid signing combined pub Base64 |

### Key Functions

| Function | Description |
|----------|-------------|
| `get_connection()` | Get DB connection with WAL + FK pragmas |
| `check_integrity()` | Run SQLite integrity_check |
| `safe_execute(conn, sql, params)` | Execute with granular error classification |
| `init_db()` | Create schema, add migration columns |
| `encrypt_secret(plain_bytes, password)` | AES-GCM encrypt with Argon2id KDF |
| `decrypt_secret(enc_dict, password)` | Auto-detect KDF (Argon2id or legacy PBKDF2) |
| `migrate_secrets_to_argon2id(password)` | Re-encrypt legacy secrets |

### Exception Hierarchy

| Exception | Description |
|-----------|-------------|
| `DatabaseError` | Base exception |
| `DatabaseCorruptedError` | DB file corrupted |
| `DatabaseLockedError` | DB locked by another process |
| `DatabaseIntegrityError` | Constraint violation |
| `DatabaseConnectionError` | Cannot establish connection |

---

## SecureString

**File:** `src/secure_string.py`

Wrapper for sensitive string data that can be securely wiped from memory. Uses bytearray internally.

### Usage Patterns

```python
# Context manager (recommended)
with SecureString("password") as pw:
    use(pw.to_str())
# Auto-wiped

# Manual
pw = SecureString("password")
try:
    use(pw.to_str())
finally:
    pw.wipe()
```

### Methods

| Method | Description |
|--------|-------------|
| `wipe()` | Zero out + random overwrite + zero out |
| `to_str()` | Convert to Python str (cannot be wiped) |
| `to_bytes()` | Convert to bytes (cannot be wiped) |
| `to_bytearray()` | Mutable copy (caller must wipe) |
| `encode(encoding)` | Encode with specified encoding |
| `append(data)` | Append str/bytes/SecureString |
| `copy()` | Deep copy |
| `is_wiped` | Property: whether wiped |

### Security Features

- Constant-time `__eq__` via `hmac.compare_digest`
- Unhashable (prevents use as dict keys)
- Auto-wipe on `__del__`
- Safe `__repr__` (never exposes data)

### Utility Functions

| Function | Description |
|----------|-------------|
| `secure_compare(a, b)` | Constant-time comparison |
| `wipe_bytes(data)` | Wipe bytearray (bytes are immutable) |
| `wipe_str(data)` | Document intent (strings cannot be wiped) |

---

## Exception Hierarchy

**File:** `src/exceptions.py`

```
EnigmaError (base)
├── KeyStoreError
├── EncryptionError
├── DecryptionError
├── RatchetStateError
│   ├── RatchetNotFoundError
│   ├── RatchetInitError
│   └── RatchetServiceError
├── TOTPValidationError
├── CryptoTimeoutError
└── ConcurrencyError
```

---

## Constants

**File:** `src/constants.py`

### Protocol Magic Bytes

| Key | Value | Description |
|-----|-------|-------------|
| `RATCHET_ENVELOPE` | `0xD0` | Double Ratchet envelope |
| `PQC_ENVELOPE` | `0x50` | PQC Hybrid KEM envelope |
| `FILE_SHARED_SECRET` | `b'ENIGMA\x01'` | Shared-secret file header |
| `FILE_KDF_ARGON2ID` | `b'A2ID'` | Argon2id file KDF tag |

### KDF Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `ARGON2_TIME_COST` | 3 | Iterations |
| `ARGON2_MEMORY_COST` | 65536 | 64 MB memory |
| `ARGON2_PARALLELISM` | 4 | Parallel threads |
| `ARGON2_HASH_LEN` | 32 | Output length |
| `ARGON2_SALT_LEN` | 16 | Salt length |
| `PBKDF2_LEGACY_ITERATIONS` | 300,000 | Legacy iteration count |

### Concurrency Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `CRYPTO_QUEUE_MAX_WORKERS` | 4 | Max concurrent workers |
| `CRYPTO_QUEUE_DEFAULT_TIMEOUT` | 120s | Default task timeout |
| `RATCHET_LOCK_TIMEOUT` | 30s | Per-friend lock timeout |
| `PQC_OPERATION_TIMEOUT` | 60s | PQC encaps/decaps |
| `ARGON2ID_TIMEOUT` | 90s | KDF timeout |
| `FILE_OPERATION_TIMEOUT` | 300s | Large file ops |
| `RSA_OPERATION_TIMEOUT` | 30s | RSA operations |

### Anti-Tamper Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `BACKGROUND_CHECK_INTERVAL` | 30 | Seconds between background checks |
| `TIMING_CHECK_THRESHOLD_NS` | 500,000 | Timing anomaly threshold (0.5ms) |
| `TIMING_SAMPLES` | 5 | Timing samples per check |
| `CRITICAL_MODULES` | list | Modules to verify bytecode integrity |
| `DEBUGGER_PROCESSES` | list | Known debugger process names |
| `HOOKING_FRAMEWORKS` | list | Known hooking framework indicators |
| `SILENT_EXIT` | True | Exit without warning message |
| `EXIT_CODE` | 1 | Process exit code |
| `HIDE_THREADS` | True | Hide threads from debugger |

### Helper Functions

| Function | Description |
|----------|-------------|
| `get_magic_byte(envelope_type)` | Retrieve magic byte by name |
| `get_kdf_param(param_name)` | Retrieve KDF parameter by name |
