# Database Structure

## Overview

Ultimate Enigma Messenger uses **SQLite** as its persistent storage backend. The database file is located at `~/.ultimate_enigma/enigma.db` (platform-dependent via `pathlib.Path.home()`).

The database module (`database.py`) provides:

- **Connection management** with WAL journal mode and foreign keys enabled
- **Granular exception hierarchy** covering corruption, locking, integrity, and connection errors
- **Secret encryption** using Argon2id KDF + AES-GCM (with legacy PBKDF2-HMAC-SHA256 backward compatibility)
- **Schema migration** via idempotent `ALTER TABLE ADD COLUMN` statements
- **Encryption at rest** via `sqlcipher3` (transparent AES-256-CBC encryption of the entire database file)

---

## Table of Contents

- [Connection & Configuration](#connection--configuration)
- [Exception Hierarchy](#exception-hierarchy)
- [Key Derivation](#key-derivation)
- [Tables](#tables)
  - [settings](#settings-table)
  - [friends](#friends-table)
- [Models Layer](#models-layer)
- [Secret Encryption Format](#secret-encryption-format)
- [Usage Patterns](#usage-patterns)

---

## Connection & Configuration

**Source:** `database.py` — `get_connection()`

```python
DB_PATH = Path.home() / ".ultimate_enigma" / "enigma.db"
```

### Pragma Settings

| Pragma | Value | Purpose |
|--------|-------|---------|
| `journal_mode` | `WAL` | Write-Ahead Logging for concurrent read/write performance |
| `foreign_keys` | `ON` | Enforce referential integrity |

### Encryption at Rest (sqlcipher3)

When `sqlcipher3` is installed and a per-machine DB encryption key has been derived, the entire database file is transparently encrypted using **AES-256-CBC** via SQLCipher with the following parameters:

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-CBC |
| Page size | 4096 |
| KDF iterations | 256,000 |
| HMAC algorithm | HMAC_SHA512 |
| KDF algorithm | PBKDF2_HMAC_SHA512 |

On first run, a random 32-byte DB key is generated, encrypted with the user's master password via Argon2id + AES-GCM, and stored in the `settings` table under the key `sqlcipher_db_key`. On subsequent opens, the encrypted key is decrypted and used to unlock the database.

If `sqlcipher3` is not available, the database falls back to plain SQLite (unencrypted) with a warning log.

### Connection Function

```python
def get_connection() -> sqlite3.Connection:
```

Always call this function wrapped in `contextlib.closing()` or a `with` statement to ensure proper cleanup.

### Integrity Check

```python
def check_integrity() -> Tuple[bool, str]:
```

Runs `PRAGMA integrity_check` on the database. Returns `(True, "ok")` on success or `(False, <details>)` on corruption.

### Safe Execution

```python
def safe_execute(conn, sql: str, params: tuple = ()):
```

Wraps `conn.execute()` and classifies any `sqlite3.Error` into the granular exception hierarchy.

---

## Exception Hierarchy

**Source:** `database.py`

All database exceptions inherit from `DatabaseError` and provide detailed, user-actionable error messages.

```
DatabaseError (base)
├── DatabaseCorruptedError     # DB file corrupt – restore from backup
├── DatabaseLockedError        # Temporarily locked – retry
├── DatabaseIntegrityError     # Constraint violation (UNIQUE, FK, etc.)
└── DatabaseConnectionError    # Cannot open or create DB file
```

### Error Classification Logic

Errors are classified in `_classify_sqlite_error()` by:
1. **Exception type** (e.g., `sqlite3.IntegrityError` → `DatabaseIntegrityError`)
2. **Message keywords** (e.g., `"locked"`/`"busy"` → `DatabaseLockedError`; `"corrupt"`/`"malformed"` → `DatabaseCorruptedError`)
3. **Fallback** to generic `DatabaseError`

---

## Key Derivation

### Argon2id (Primary)

Used for all new secret encryption. Parameters defined as module-level constants in `database.py`:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `ARGON2_TIME_COST` | `3` | Iterations |
| `ARGON2_MEMORY_COST` | `65536` | 64 MB memory |
| `ARGON2_PARALLELISM` | `4` | Parallel threads |
| `ARGON2_HASH_LEN` | `32` | 256-bit output |
| `ARGON2_SALT_LEN` | `16` | Salt length |
| `ARGON2_TYPE` | `Type.ID` | Argon2id variant |

### PBKDF2-HMAC-SHA256 (Legacy)

Retained for backward-compatible decryption of existing databases.

| Parameter | Value |
|-----------|-------|
| `SECRET_KDF_ITERATIONS` | `300,000` |

### Automatic Migration

`migrate_secrets_to_argon2id(password)` re-encrypts all legacy PBKDF2 secrets with Argon2id. Should be called after first successful login post-upgrade. Returns the number of secrets migrated.

---

## Tables

### `settings` Table

Key-value store for application configuration and encrypted key material.

#### Schema

```sql
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

#### All Known Keys

| Key | Type | Description | Set By |
|-----|------|-------------|--------|
| `public_key` | PEM text | RSA public key (4096-bit recommended) | `init_db()` |
| `private_key_encrypted` | PEM text | RSA private key, encrypted with master password | `init_db()` |
| `global_secret` | JSON | 256-bit global shared secret, encrypted as `{kdf,salt,nonce,ct}` | `init_db()` |
| `legacy_private_key_encrypted` | PEM text | Previous RSA private key (30-day retention) | `rotate_rsa_key()` |
| `legacy_key_expiry` | text | Unix timestamp when legacy key expires | `rotate_rsa_key()` |
| `kyber_priv_encrypted` | JSON | CRYSTALS-Kyber private key (encrypted) | `ensure_pqc_keys()` / `ensure_pqc_keys_full()` |
| `pqc_x25519_priv_encrypted` | JSON | X25519 private key for PQC bundle (encrypted) | `ensure_pqc_keys_full()` |
| `pqc_combined_pub_b64` | Base64 text | Combined PQC public key (X25519 + Kyber768) | `ensure_pqc_keys()` / `ensure_pqc_keys_full()` |
| `ed25519_priv_encrypted` | JSON | Ed25519 private key (encrypted raw 32 bytes) | `init_db()` (hybrid sig path) |
| `dilithium_priv_encrypted` | JSON | CRYSTALS-Dilithium3 private key (encrypted) | `init_db()` (hybrid sig path) |
| `hybrid_sig_combined_pub_b64` | Base64 text | Combined hybrid signing public key (Ed25519 + Dilithium3) | `init_db()` (hybrid sig path) |
| `totp_secret_encrypted` | JSON | TOTP secret (encrypted 20-byte key) | Auth setup |
| `totp_setup_complete` | text | Flag indicating TOTP setup completion | Auth setup |
| `totp_enabled` | text | Flag indicating TOTP is enabled | Auth setup |
| `lockout_data` | JSON | `{"failures": int, "locked_until": float}` | `KeyStore._save_lockout_state()` |
| `duress_verifier` | JSON | Encrypted dummy secret for duress detection | `set_duress_password()` |
| `last_backup_ts` | text | Unix timestamp of last versioned backup | `BackupService._record_backup_timestamp()` |
| `my_name` | text | User's display name for ratchet envelope sender identity | `set_my_name()` |

#### Key Lifecycle

```
First Run (init_db):
  → Generate RSA-4096 key pair
  → Generate 256-bit global_secret
  → Generate hybrid signing keys (if liboqs available)

Key Rotation (rotate_rsa_key):
  → Current private_key_encrypted → legacy_private_key_encrypted
  → Set legacy_key_expiry = now + 30 days
  → Generate new RSA-4096 pair → private_key_encrypted
  → On load: expired legacy keys are automatically deleted

Migration (migrate_secrets_to_argon2id):
  → Reads all encrypted secrets
  → Re-encrypts using Argon2id if currently PBKDF2
```

---

### `friends` Table

Stores information about known contacts including cryptographic keys and session state.

#### Schema

```sql
CREATE TABLE IF NOT EXISTS friends (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    name                    TEXT    NOT NULL UNIQUE,
    public_key_pem          TEXT    NOT NULL,
    has_shared_secret       INTEGER NOT NULL DEFAULT 0,
    shared_secret_encrypted TEXT,       -- JSON: {kdf, salt, nonce, ct}
    x25519_public_key_b64   TEXT,       -- ADDED via ALTER TABLE
    ratchet_state_json      TEXT,       -- ADDED via ALTER TABLE (may be encrypted)
    capabilities_json       TEXT,       -- ADDED via ALTER TABLE
    pqc_combined_pub_b64    TEXT,       -- ADDED via ALTER TABLE
    hybrid_sig_pub_b64      TEXT        -- ADDED via ALTER TABLE
);
```

#### Column Details

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | INTEGER PK | No | Auto-increment row identifier |
| `name` | TEXT UNIQUE | No | Friend's unique display name |
| `public_key_pem` | TEXT | No | Friend's RSA public key in PEM format |
| `has_shared_secret` | INTEGER | No | Boolean flag: 1 if shared secret exists |
| `shared_secret_encrypted` | TEXT | Yes | Encrypted shared secret JSON (`{kdf, salt, nonce, ct}`) |
| `x25519_public_key_b64` | TEXT | Yes | Raw 32-byte X25519 public key, Base64 encoded |
| `ratchet_state_json` | TEXT | Yes | Serialized Double Ratchet session state (plain JSON or AES-256-GCM encrypted blob) |
| `capabilities_json` | TEXT | Yes | JSON dictionary of capability flags (e.g., `{"double_ratchet": true, "pqc": false}`) |
| `pqc_combined_pub_b64` | TEXT | Yes | Friend's combined PQC public key (X25519 + Kyber768), Base64 encoded |
| `hybrid_sig_pub_b64` | TEXT | Yes | Friend's combined hybrid signing public key (Ed25519 + Dilithium3), Base64 encoded |

#### Indexes

- Primary key on `id`
- Unique index on `name`

#### Column Migration History

The core schema was created in `init_db()`. Additional columns were added via `ALTER TABLE` statements executed at various points:

```python
# Migration order (idempotent — ignores OperationalError if column exists)
ALTER TABLE friends ADD COLUMN x25519_public_key_b64 TEXT;
ALTER TABLE friends ADD COLUMN ratchet_state_json TEXT;
ALTER TABLE friends ADD COLUMN capabilities_json TEXT;
ALTER TABLE friends ADD COLUMN pqc_combined_pub_b64 TEXT;
ALTER TABLE friends ADD COLUMN hybrid_sig_pub_b64 TEXT;
```

Migration logic exists in:
- `database.init_db()` — adds all columns on schema init
- `key_manager.KeyStore.load()` — adds `x25519_public_key_b64` and `hybrid_sig_pub_b64` as a safety net
- `models/key_store.py.KeyStoreModel.load()` — depends on columns already existing

---

## Models Layer

The `models/` package provides structured data objects that replace raw dictionary and tuple access patterns.

### `FriendProfile` (`models/friend_profile.py`)

Immutable dataclass for friend data. Provides `from_database()` and `list_all()` class methods that query the `friends` table and return typed objects.

```python
@dataclass(frozen=True)
class FriendProfile:
    name: str
    public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    capabilities: Dict[str, Any] = field(default_factory=dict)
    has_active_ratchet: bool = False
    pqc_combined_pub: Optional[bytes] = None
```

### `KeyStoreModel` (`models/key_store.py`)

Pure data model and persistence manager for cryptographic keys. Provides:
- `load(password)` — loads all keys from DB
- `save_friend(name, pem, ...)` — persists friend data
- `remove_friend(name)` — deletes friend from DB
- `get_decryption_snapshot()` — thread-safe snapshot for decryption workers
- `wipe()` — secure memory erasure

### `KeyStore` (`key_manager.py`)

Full runtime key store extending the data model with business logic:
- Password verification with exponential backoff and hard lockout
- PQC key generation and management
- RSA key rotation with 30-day legacy retention
- Duress password mode
- Password change (re-encrypt all secrets)

### Envelope Models (`models/envelope.py`)

Defines the binary wire formats for message envelopes:

| Model | Magic Byte | Purpose |
|-------|-----------|---------|
| `RatchetEnvelope` | `0xD0` | Double Ratchet message format |
| `PQCEncvelope` | `0x50` | Post-Quantum Hybrid KEM message format |

---

## Secret Encryption Format

All sensitive values stored in the database are encrypted at rest. The encryption uses **AES-256-GCM** with a key derived via **Argon2id** (or legacy **PBKDF2-HMAC-SHA256**).

### Encrypted Value JSON Structure

```json
{
    "kdf": "argon2id",          // optional; "pbkdf2" implied if absent
    "salt": "<base64-salt>",    // 16 bytes for Argon2id
    "nonce": "<base64-nonce>",  // 12 bytes
    "ct": "<base64-ciphertext>" // AES-GCM ciphertext + 16-byte tag
}
```

### Encryption/Decryption Functions

```python
def encrypt_secret(plain_bytes: bytes, password) -> dict:
    """Encrypt bytes using AES-GCM with Argon2id-derived key.
    Returns JSON-serializable dict tagged with kdf='argon2id'.
    """

def decrypt_secret(enc_dict: dict, password) -> bytes:
    """Decrypt with auto-detection of Argon2id vs PBKDF2.
    Legacy entries (no 'kdf' tag) are decrypted with PBKDF2.
    """
```

### What Gets Encrypted

| Data | Table.Column | Encryption |
|------|-------------|------------|
| RSA private key | `settings.private_key_encrypted` | PEM-level (BestAvailableEncryption) |
| Global secret | `settings.global_secret` | AES-GCM + Argon2id |
| Legacy RSA private key | `settings.legacy_private_key_encrypted` | PEM-level |
| Kyber private key | `settings.kyber_priv_encrypted` | AES-GCM + Argon2id |
| PQC X25519 private key | `settings.pqc_x25519_priv_encrypted` | AES-GCM + Argon2id |
| Ed25519 private key | `settings.ed25519_priv_encrypted` | AES-GCM + Argon2id |
| Dilithium3 private key | `settings.dilithium_priv_encrypted` | AES-GCM + Argon2id |
| TOTP secret | `settings.totp_secret_encrypted` | AES-GCM + Argon2id |
| Duress verifier | `settings.duress_verifier` | AES-GCM + Argon2id |
| Friend shared secrets | `friends.shared_secret_encrypted` | AES-GCM + Argon2id |
| Ratchet state (optional) | `friends.ratchet_state_json` | AES-GCM + HKDF-derived storage key |

---

## Usage Patterns

### Querying Settings

```python
from contextlib import closing
import database

with closing(database.get_connection()) as conn:
    row = conn.execute(
        "SELECT value FROM settings WHERE key=?", ("my_name",)
    ).fetchone()
    if row:
        value = row[0]
```

### Updating Settings

```python
with closing(database.get_connection()) as conn:
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("my_name", "Alice")
    )
    conn.commit()
```

### Loading a Friend Profile

```python
from models.friend_profile import FriendProfile

profile = FriendProfile.from_database("Bob")
if profile:
    print(f"Name: {profile.name}")
    print(f"Supports DR: {profile.supports_double_ratchet}")
    print(f"Has ratchet: {profile.has_active_ratchet}")
```

### Loading All Friends

```python
for profile in FriendProfile.list_all():
    print(profile.name, profile.capabilities)
```

### Saving a Friend

```python
key_store.save_friend(
    name="Bob",
    pem=bob_public_key_pem,
    shared_secret=shared_secret_bytes,
    password=master_password,
    x25519_pub_b64=base64_x25519_pub,
    capabilities={"double_ratchet": True, "pqc": True},
    pqc_combined_pub_b64=base64_pqc_pub,
    hybrid_sig_pub_b64=base64_hybrid_pub,
)
```

### Ratchet State Persistence

Ratchet states are serialized, optionally encrypted with a HKDF-derived storage key, and stored in `friends.ratchet_state_json`:

```python
from services.ratchet_service import RatchetService

# Load state
state = RatchetService.get_ratchet_state(friend_name)

# Save state
RatchetService.save_ratchet_state(friend_name, updated_state)

# Delete state
RatchetService.delete_ratchet(friend_name)
```

### Full Schema Initialization

```python
import database

# Create tables and apply migrations
database.init_db()

# Verify integrity
ok, detail = database.check_integrity()