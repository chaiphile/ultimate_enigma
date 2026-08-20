# Models Reference

Comprehensive documentation for all data models in the `models/` directory and core data structures.

---

## Table of Contents

- [RatchetEnvelope](#ratchetenvelope)
- [PQCEncvelope](#pqcencvelope)
- [FriendProfile](#friendprofile)
- [MessageScore](#messagescore)
- [KeyStore (Runtime)](#keystore-runtime)
- [TrustChain](#trustchain)
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

## MessageScore

**File:** `models/message_score.py`

Immutable dataclass holding the anomaly score and classification for a scored message. Produced by `AnomalyDetectionService` after each message is decrypted.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `friend_name` | `str` | Sender/recipient of the scored message |
| `score` | `float` | Raw Isolation Forest score (negative = anomalous, positive = normal) |
| `is_anomaly` | `bool` | `True` if score falls below the threshold |
| `threshold` | `float` | Cutoff value used for classification |
| `envelope_type` | `str` | Type of envelope (`'ratchet'`, `'pqc'`, `'legacy'`, or `'unknown'`) |
| `packet_size` | `int` | Size of the raw packet in bytes |
| `timestamp` | `datetime` | When the scoring occurred (UTC) |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `confidence` | `float` | Normalized confidence (0–1). Lower scores (more anomalous) produce lower confidence. Computed as `(score - (-1.0)) / 2.0`, clamped to [0, 1]. |

---

## KeyStore (Runtime)

> **Note:** There is no `models/key_store.py` file. All key store logic is in `key_manager.py` at the project root. The `KeyStore` class in `key_manager.py` is the single source of truth for in-memory key management.

## KeyStore (Runtime)

**File:** `key_manager.py`

Full runtime key store with authentication, lockout, PQC key management, and password change workflows. Thin orchestrator that delegates lockout to `security/lockout.py` (`LockoutManager`) and key generation to `src/key_generation.py`. The KeyStore is the single in-memory container that holds all cryptographic keys and friend data.

### In-Memory Key Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `my_pub` / `my_priv` | RSA public/private key | Own RSA 4096-bit key pair |
| `legacy_priv` | RSA private key | Previous RSA key (30-day retention) |
| `global_secret` | `GuardedBuffer` | 256-bit global shared secret in guarded memory |
| `friends` | `List[Tuple]` | `(name, pub, shared_secret)` where secrets are `GuardedBuffer` |
| `friends_x25519` | `Dict[str, str]` | Name → Base64 X25519 public key |
| `friends_capabilities` | `Dict[str, dict]` | Name → capabilities dict |
| `friends_pqc_combined_pub` | `Dict[str, bytes]` | Name → raw PQC combined pub bytes |
| `friends_hybrid_sig_pubs` | `Dict[str, tuple]` | Name → `(ed_pub, dil_pub)` |
| `my_kyber_priv` | `Optional[GuardedBuffer]` | Own Kyber768 secret key (guarded memory for wipe-on-lock) |
| `my_pqc_combined_pub` | `Optional[bytes]` | Own hybrid combined PQC public key |
| `my_ed_priv` | `Ed25519PrivateKey` | Own hybrid signing Ed25519 key |
| `my_dil_priv` | `Optional[GuardedBuffer]` | Own hybrid signing Dilithium3 secret key (guarded memory for wipe-on-lock) |
| `my_hybrid_sig_combined_pub` | `Optional[bytes]` | Own hybrid signing combined public key |
| `my_name` (property) | `str` | Display name for ratchet envelope sender |
| `_lockout` | `LockoutManager` | Delegated lockout state machine |
| `_duress_mode` | `bool` | Whether duress password was used |
| `_needs_rotation` | `bool` | RSA key below CNSA 2.0 minimum |
| `_ratchet_storage_key` | `bytearray` | AES-256 key for encrypted ratchet persistence |
| `_cached_pqc_bundle` | `Optional[dict]` | Cached full PQC bundle (X25519 + Kyber) for decapsulation |
| `_rsa_key_bytes` | `Optional[GuardedBuffer]` | RSA private key bytes in guarded memory |

### Key Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `load(password)` | `bool` | Load all keys from DB, decrypt with password |
| `verify_password(password)` | `(bool, bool)` | Check master or duress password; returns `(is_valid, is_duress)` |
| `set_duress_password(duress_password)` | — | Configure duress password |
| `update_global_secret(new_secret, password)` | — | Update global secret |
| `ensure_pqc_keys(password)` | — | Generate PQC keys if missing |
| `ensure_pqc_keys_full(password)` | `Optional[dict]` | Full PQC bundle with X25519 priv |
| `load_pqc_bundle(password)` | `Optional[dict]` | Load existing PQC bundle |
| `rotate_rsa_key(password)` | — | Generate new 4096-bit RSA, retire old |
| `change_password(old, new)` | — | Re-encrypt all secrets |
| `get_decryption_snapshot()` | `tuple` | Thread-safe snapshot for background decryption |
| `load_duress_decoy()` | `bool` | Load fake decoy state |
| `save_friend(name, pem, …)` | — | Save friend to DB and memory |
| `remove_friend(name)` | — | Remove from DB and memory |
| `set_my_name(name)` | — | Persist display name to settings |
| `wipe()` | — | Securely erase all keys from memory |
| `reset_with_recovery_key(new_password)` | `bool` | Reset all crypto material using new password (recovery flow) |
| `get_friend_secret(name)` | `Optional[bytes]` | Get friend's shared secret by name |
| `pqc_decryption_bundle` (property) | `Optional[dict]` | Return cached PQC key bundle for decapsulation |
| `needs_key_rotation` (property) | `bool` | True if RSA key is below CNSA 2.0 minimum |
| `is_duress_mode` (property) | `bool` | True if last auth used duress password |
| `failed_attempts` (property) | `int` | Number of consecutive failed auth attempts |
| `locked_until` (property) | `float` | Epoch timestamp until account is locked |

> Note: File encryption functions (`file_encrypt`, `file_encrypt_shared`, etc.) are defined in `services/file_ops.py`, not in `key_manager.py`. The `key_manager.py` may import them but does not define them.

---

## TrustChain

**File:** `models/trust_chain.py`

Trust certificate system for decentralized identity verification. Defines certificate types, trust levels, and revocation status.

### Enums

```python
class CertificateType(Enum):
    IDENTITY = "identity"        # Binds name to public key
    RECOVERY = "recovery"        # Recovery authority certificate
    DELEGATION = "delegation"    # Delegated signing authority

class TrustLevel(IntEnum):
    NONE = 0         # No certificates
    BASIC = 1        # One or more certs (basic verification)
    VERIFIED = 2     # Multiple confirming certs
    TRUSTED = 3      # Mutually attested (highest level)

class RevocationStatus(Enum):
    VALID = "valid"              # Certificate is valid
    REVOKED = "revoked"          # Certificate was revoked
    EXPIRED = "expired"          # Past expiration date
```

### TrustCertificate

Immutable dataclass for certificate data:

| Attribute | Type | Description |
|-----------|------|-------------|
| `cert_id` | `str` | UUID4 unique identifier |
| `subject_name` | `str` | Certificate subject display name |
| `subject_pub_b64` | `str` | Subject's public key (Base64) |
| `issuer_name` | `str` | Issuer's display name |
| `issuer_pub_b64` | `str` | Issuer's public key (Base64) |
| `cert_type` | `CertificateType` | Identity, recovery, or delegation |
| `not_before` | `float` | Validity start (epoch) |
| `not_after` | `float` | Validity end (epoch) |
| `signature_b64` | `str` | Hybrid signature (Ed25519 + Dilithium3) |
| `revoked` | `bool` | Whether certificate has been revoked |
| `revocation_reason` | `Optional[str]` | Reason for revocation |
| `received_from` | `Optional[str]` | Who forwarded this certificate |
| `created_at` | `float` | Creation timestamp |

Certificate operations are managed by `services/trust_chain_service.py`.

---

## Database Schema

**File:** `database.py`

SQLite database at `~/.ultimate_enigma/enigma.db` with WAL mode and foreign keys enabled. When SQLCipher3 is available, the database is encrypted at rest using AES-256-CBC with a per-machine key derived via Argon2id. Falls back to unencrypted SQLite if SQLCipher3 is not installed.

### Tables

#### `settings`
| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT PK | Setting name |
| `value` | TEXT NOT NULL | Setting value (JSON for encrypted data) |

Known keys: `public_key`, `private_key_encrypted`, `global_secret`, `legacy_private_key_encrypted`, `legacy_key_expiry`, `kyber_priv_encrypted`, `pqc_combined_pub_b64`, `pqc_x25519_priv_encrypted`, `ed25519_priv_encrypted`, `dilithium_priv_encrypted`, `hybrid_sig_combined_pub_b64`, `totp_secret_encrypted`, `totp_setup_complete`, `totp_enabled`, `lockout_data`, `duress_verifier`, `last_backup_ts`, `my_name`, `sqlcipher_db_key`, `ratchet_storage_key`

#### `trust_certificates`
| Column | Type | Description |
|--------|------|-------------|
| `cert_id` | TEXT PK | UUID4 certificate ID |
| `subject_name` | TEXT NOT NULL | Certificate subject |
| `subject_pub_b64` | TEXT NOT NULL | Subject public key (Base64) |
| `issuer_name` | TEXT NOT NULL | Certificate issuer |
| `issuer_pub_b64` | TEXT NOT NULL | Issuer public key (Base64) |
| `cert_type` | TEXT NOT NULL | Certificate type enum value |
| `not_before` | REAL NOT NULL | Validity start timestamp |
| `not_after` | REAL NOT NULL | Validity end timestamp |
| `signature_b64` | TEXT NOT NULL | Hybrid signature (Base64) |
| `revoked` | INTEGER NOT NULL | Revocation flag |
| `revocation_reason` | TEXT | Reason if revoked |
| `received_from` | TEXT | Forwarding source |
| `created_at` | REAL NOT NULL | Creation timestamp |

#### `recovery_shares`
| Column | Type | Description |
|--------|------|-------------|
| `share_id` | TEXT PK | Unique share identifier |
| `owner_name` | TEXT NOT NULL | Secret owner |
| `share_index` | INTEGER NOT NULL | Share number |
| `total_shares` | INTEGER NOT NULL | Total shares in scheme |
| `threshold` | INTEGER NOT NULL | Minimum shares needed |
| `encrypted_share_b64` | TEXT NOT NULL | Encrypted share data |
| `holder_name` | TEXT NOT NULL | Share holder identity |
| `holder_pub_b64` | TEXT NOT NULL | Holder's public key |
| `created_at` | REAL NOT NULL | Creation timestamp |

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

```
DatabaseError
├── DatabaseCorruptedError
├── DatabaseLockedError
├── DatabaseIntegrityError
└── DatabaseConnectionError
```

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
EnigmaError
├── KeyStoreError
├── EncryptionError
├── DecryptionError
├── RatchetStateError
│   ├── RatchetNotFoundError
│   ├── RatchetInitError
│   └── RatchetServiceError
├── TOTPValidationError
├── CryptoTimeoutError
├── ConcurrencyError
├── TrustChainError
│   ├── CertificateError
│   │   ├── CertificateExpiredError
│   │   ├── CertificateRevokedError
│   │   └── CertificateSignatureError
│   └── ShamirError
│       ├── InsufficientSharesError
│       └── InvalidShareError
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
| `TRUST_CERT_BUNDLE` | `0x74` | Trust certificate bundle envelope |

### KDF Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `ARGON2_TIME_COST` | 3 | Iterations |
| `ARGON2_MEMORY_COST` | 65536 | 64 MB memory |
| `ARGON2_PARALLELISM` | 4 | Parallel threads |
| `ARGON2_HASH_LEN` | 32 | Output length |
| `ARGON2_SALT_LEN` | 16 | Salt length |
| `PBKDF2_LEGACY_ITERATIONS` | 300,000 | Legacy iteration count |

### Crypto Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `AES_KEY_SIZE` | 32 | AES-256 key size |
| `RSA_MIN_KEY_SIZE` | 4096 | Minimum RSA key size (CNSA 2.0) |
| `LEGACY_KEY_RETENTION_DAYS` | 30 | Days to retain old RSA key |
| `AES_GCM_NONCE_SIZE` | 12 | AES-GCM nonce length |
| `AES_GCM_TAG_SIZE` | 16 | AES-GCM authentication tag length |
| `WINDOW_SIZE` | 2 | TOTP window size |
| `SELF_DESTRUCT_FLAG` | 4 | Self-destruct message flag bit |
| `HYBRID_SIG_FLAG` | 8 | Hybrid signature flag bit |
| `KEY_HINT_FLAG` | 16 | Key hint flag bit |

### Security & Lockout Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `BACKOFF_TABLE` | `[0,0,0,0,0,5,10,30,60,120,300,600,1800,3600]` | 14-entry exponential backoff (seconds) |
| `HARD_LOCKOUT_THRESHOLD` | 15 | Consecutive failures before hard lockout |
| `HARD_LOCKOUT_DURATION` | 3600 | Hard lockout duration (1 hour) |
| `MAX_TOTP_ATTEMPTS` | 5 | Maximum TOTP attempts before lockout |
| `SESSION_TIMEOUT` | 900 | Session timeout (15 minutes) |

### Database Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `SQLCIPHER_PAGE_SIZE` | 4096 | SQLCipher page size |
| `SQLCIPHER_KDF_ITER` | 256000 | SQLCipher KDF iterations |

### Trust Chain Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `TRUST_LEVEL_BASIC` | 1 | One or more certs (basic verification) |
| `TRUST_LEVEL_VERIFIED` | 2 | Multiple confirming certs |
| `TRUST_LEVEL_TRUSTED` | 3 | Mutually attested (highest level) |
| `CERT_TYPE_IDENTITY` | `"identity"` | Binds name to public key |
| `CERT_TYPE_RECOVERY` | `"recovery"` | Recovery authority certificate |
| `CERT_TYPE_DELEGATION` | `"delegation"` | Delegated signing authority |
| `RECOVERY_SHARE_EXPIRY_DAYS` | 365 | Recovery share validity period |

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
| `HARDWARE_BREAKPOINT_CHECK` | True | Enable detection of hardware breakpoints via debug registers |
| `SEEK_MIN_INTERVAL` | 5 | Minimum seconds between seeking scans (normal mode) |
| `SEEK_MAX_INTERVAL` | 15 | Maximum seconds between seeking scans (normal mode) |
| `SEEK_SUSPICION_THRESHOLD` | 3 | Consecutive suspicious findings before escalation |
| `SEEK_ESCALATED_MIN_INTERVAL` | 1 | Minimum seconds between escalated scans |
| `SEEK_ESCALATED_MAX_INTERVAL` | 3 | Maximum seconds between escalated scans |

### Helper Functions

| Function | Description |
|----------|-------------|
| `get_magic_byte(envelope_type)` | Retrieve magic byte by name |
| `get_kdf_param(param_name)` | Retrieve KDF parameter by name |

---

## Crypto Utilities

**File:** `src/crypto_utils.py`

Shared PEM and password helpers, consolidating duplicated code from `key_manager.py`, `models/key_store.py`, and `crypto.py`.

| Function | Description |
|----------|-------------|
| `password_to_bytes(password)` | Convert `str`, `bytes`, or `SecureString` to raw bytes |
| `pem_to_pubkey(pem)` | Load PEM-encoded public key |
| `pem_to_privkey(pem, password)` | Load and decrypt PEM-encoded private key |
| `privkey_to_encrypted_pem(priv, password)` | Encrypt private key to PEM format |
| `pubkey_to_pem(pub)` | Encode public key to PEM string |
