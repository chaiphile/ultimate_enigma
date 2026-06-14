# Architecture Documentation

## Overview

Ultimate Enigma Messenger follows a **Model-View-Controller (MVC)** architecture with an event-driven service layer. The application is designed for security, modularity, and maintainability.

```
┌─────────────────────────────────────────────────────────────────┐
│                         EnigmaApp (main)                        │
│  ┌─────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │ApplicationCtrl│  │  AuthController  │  │ServiceOrchestrator│  │
│  └──────┬──────┘  └────────┬─────────┘  └────────┬──────────┘  │
│         │                  │                      │             │
│         ▼                  ▼                      ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │ CryptoQueue │    │  KeyStore   │    │     Services        │ │
│  │  Hotkeys    │    │  TOTP       │    │  ├─ EncryptionSvc   │ │
│  │  NTP Sync   │    │  TotpPersist│    │  ├─ FileService     │ │
│  └─────────────┘    │  LockScreen │    │  ├─ FriendsService  │ │
│                     └─────────────┘    │  ├─ BackupService   │ │
│                                        │  ├─ ClipboardSvc    │ │
│  ┌─────────────────────────────────┐   │  ├─ GlobalSecretSvc │ │
│  │           Views (Tabs)          │   │  └─ ...             │ │
│  │  EncryptTab | DecryptTab | ...  │   └─────────────────────┘ │
│  └─────────────────────────────────┘                           │
│                              ▲                                  │
│                              │                                  │
│                    ┌─────────┴─────────┐                       │
│                    │      EventBus     │                       │
│                    │  (Pub/Sub System) │                       │
│                    └───────────────────┘                       │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              SQLCipher3 Encryption Layer                │   │
│  │     (AES-256 encrypted SQLite database)                 │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
ultimate_enigma/
├── main.py                 # Application entry point, logging setup
├── app.py                  # EnigmaApp - main window orchestration (delegates to AppBuilder)
├── builders/               # Composition root
│   └── app_builder.py      # AppBuilder - step-by-step app construction
├── controllers/            # MVC Controllers
│   ├── application_controller.py  # App lifecycle, hotkeys, queues
│   ├── auth_controller.py         # Authentication, TOTP, lock/unlock
│   └── service_orchestrator.py    # Service creation and DI
├── models/                 # Data Models
│   ├── envelope.py         # Message envelope structures
│   ├── friend_profile.py   # Friend/contact data model
│   └── key_store.py        # Key storage abstraction (pure data + persistence)
├── services/               # Business Logic Services
│   ├── encryption/                 # EncryptionService package (decomposed)
│   │   ├── __init__.py             # Re-exports
│   │   ├── encryption_facade.py    # Strategy dispatcher facade
│   │   ├── legacy_strategy.py      # Shared-secret + RSA hybrid
│   │   ├── ratchet_strategy.py     # Double Ratchet
│   │   └── pqc_strategy.py         # Post-Quantum Hybrid KEM
│   ├── friends/                    # FriendsService package (decomposed)
│   │   ├── __init__.py             # Re-exports
│   │   ├── friends_facade.py       # Delegating facade
│   │   ├── crud.py                 # Friend CRUD + queries + auth
│   │   ├── ratchet_mgmt.py         # Double Ratchet lifecycle
│   │   ├── pqc_keys.py             # PQC key exchange
│   │   └── hybrid_sig_keys.py      # Hybrid signing keys
│   ├── file_service.py             # FileService class (thin facade)
│   ├── file_ops.py                 # Standalone file crypto functions
│   ├── clipboard_service.py       # Secure clipboard handling
│   ├── global_secret_service.py   # Shared secret management
│   ├── auth_manager.py            # Authentication logic
│   ├── totp_service.py            # TOTP generation/verification
│   ├── double_ratchet.py          # Signal Protocol ratchet
│   ├── ratchet_service.py         # Ratchet state management
│   ├── ecdh_service.py            # ECDH key exchange
│   ├── pqc_service.py             # Post-quantum cryptography
│   ├── pqc_signatures.py          # PQC digital signatures
│   ├── backup_service.py          # Encrypted backups
│   ├── totp_persistence.py        # Encrypted TOTP secret storage
│   ├── friend_repository.py       # Low-level friend data access
│   ├── xchacha20_poly1305.py      # XChaCha20-Poly1305 AEAD encryption
│   ├── hotkey_service.py          # Global hotkey registration
│   ├── crypto_task_queue.py       # Async crypto operations
│   └── event_bus.py               # Pub/sub event system
├── views/                  # View Layer (Tkinter UI)
│   ├── __init__.py
│   ├── encrypt_tab.py      # Message encryption UI
│   ├── decrypt_tab.py      # Message decryption UI
│   ├── file_tab.py         # File encryption UI
│   ├── friends_tab.py      # Friend management UI
│   ├── about_tab.py        # Settings/about UI
│   ├── ntp_tab.py          # NTP sync UI
│   ├── secret_tab.py       # Shared secret UI
│   ├── lock_screen.py      # Lock screen overlay
│   ├── visual_enigma.py    # Rotor animation widget
│   ├── ecdh.py             # ECDH key exchange dialog
│   ├── auth_ui_callbacks.py # UI callback injection for AuthController
│   └── utils.py            # Password dialog and validation
├── components/             # Reusable UI Components
│   └── totp_dialogs.py           # TOTP setup/verify dialogs
├── src/                    # Core Utilities
│   ├── constants.py              # Centralized constants
│   ├── exceptions.py             # Custom exception classes
│   ├── secure_string.py          # Memory-safe string handling
│   ├── timeout.py                # Timeout decorators/utilities
│   ├── crypto_utils.py           # Shared PEM/password helpers (DRY)
│   ├── crypto_task_helper.py     # Shared crypto task submission helper
│   ├── key_generation.py         # RSA/PQC/hybrid key generation and DB init
│   └── anti_tamper.py            # Anti-debugger & anti-tamper protections (frozen .exe only)
├── security/               # Security Hardening
│   ├── __init__.py               # Package init
│   ├── memory_security.py        # VirtualLock/mlock page locking
│   ├── guarded_buffer.py         # PAGE_NOACCESS guard page buffers
│   ├── lockout.py                # Exponential backoff lockout state machine
│   └── anti_dump.py              # Anti-dump protections
├── crypto.py               # Low-level crypto primitives
├── database.py             # SQLite schema and operations
├── key_manager.py          # KeyStore thin orchestrator (lockout → security/lockout.py, keygen → src/key_generation.py)
└── tests/                  # Test suite
```

### View Layer Organization

All View components (Tkinter UI tabs, dialogs, and widgets) are organized under the `views/` package. This enforces a clean separation between the UI layer and business logic. Views receive dependencies via constructor injection and communicate with controllers/services through the EventBus or direct method calls — never by reaching into internal state.

## Controllers

### ApplicationController
Manages application-wide concerns:
- Crypto task queue initialization and processing
- Global hotkey registration (emergency lock/unlock)
- NTP synchronization scheduling
- Graceful shutdown coordination

### AuthController
Handles all authentication flows:
- Master password verification and key loading
- First-run key generation
- TOTP setup enforcement and verification
- Emergency lock and unlock coordination
- Sensitive data wiping
- UI decoupled via injectable `_ui` callbacks (no direct tkinter dependency)

### ServiceOrchestrator
Central dependency injection container:
- Creates and manages all service instances
- Handles service rebuilding after unlock
- Updates tab references when services change
- Coordinates service shutdown
- Wires PQC dependencies into model layer via `configure_pqc_support()`

## Services

### EncryptionService
Core cryptographic operations, decomposed into three strategy classes behind a facade:

- **LegacyEncryptionStrategy**: AES-256-GCM symmetric encryption, RSA-OAEP key wrapping, time-based key derivation, digital signatures (RSA-PSS + hybrid), self-destruct support
- **RatchetEncryptionStrategy**: Double Ratchet per-message forward-secret encryption via `RatchetService`
- **PqcEncryptionStrategy**: Post-Quantum Hybrid KEM (X25519 + Kyber768) with timeout protection
- Thread-safe decryption via `KeyStore.get_decryption_snapshot()`

### FileService
File encryption operations, with standalone crypto functions in `file_ops.py`:

- Password-based file encryption (AES-GCM + Argon2id)
- Shared-secret file encryption with RSA/hybrid signature verification
- Fingerprint-based auto-detection for shared-secret files

### FriendsService
Contact management, decomposed into four sub-services behind a facade:

- **FriendCrudService**: Friend CRUD, queries, X25519 accessors, auth
- **FriendRatchetManager**: Double Ratchet session lifecycle
- **FriendPqcKeyService**: PQC key generation, encapsulate/decapsulate
- **FriendHybridSigKeyService**: Hybrid signing key generation and import

### ClipboardService
Secure clipboard handling:
- Copy sensitive data with auto-clear timer
- Configurable clear delay (default 30 seconds)
- Automatic cleanup on app exit

### DoubleRatchet / RatchetService
Signal Protocol implementation:
- Per-conversation ratchet state
- Forward secrecy and break-in recovery
- Thread-safe per-friend locking
- Sender identity via `KeyStore.my_name` in ratchet envelopes

### PQCService
Post-quantum cryptography:
- CRYSTALS-Kyber KEM integration via liboqs
- Hybrid classical + PQC encryption
- Future-proof key encapsulation

### EventBus
Decoupled communication system:
- Thread-safe publish/subscribe pattern
- Tkinter-aware main thread dispatch
- Event types defined in `Events` class

## Event Flow

The EventBus enables loose coupling between components:

```
[FriendsTab] --FRIEND_LIST_CHANGED--> [EventBus] --> [EncryptTab]
                                                  --> [FileTab]

[LockScreen] --EMERGENCY_LOCK-------> [EventBus] --> [App]
                                                  --> [Services]

[AuthController] --SERVICES_REBUILT-> [EventBus] --> [All Tabs]
```

### Available Events

| Event | Description |
|-------|-------------|
| `UNLOCK_REQUESTED` | User initiated unlock |
| `EMERGENCY_LOCK` | Emergency lock triggered |
| `UNLOCKED` | App successfully unlocked |
| `LOCKED` | App locked |
| `DURESS_MODE_ENTERED` | Duress mode activated (coerced unlock) |
| `KEYS_WIPED` | Keys cleared from memory |
| `KEYS_LOADED` | Keys loaded from database |
| `TOTP_SETUP_COMPLETE` | TOTP configured |
| `TOTP_VERIFIED` | TOTP code validated |
| `TOTP_CHANGED` | TOTP secret updated |
| `RATCHET_INITIALIZED` | New ratchet session established |
| `RATCHET_RESET` | Ratchet session reset |
| `SERVICES_REBUILT` | Services recreated |
| `NTP_SYNCED` | Time synchronized |
| `FRIEND_LIST_CHANGED` | Contacts modified |
| `APP_SHUTDOWN` | Application closing |

## Threading Model

- **Main Thread**: Tkinter GUI event loop
- **Crypto Workers**: ThreadPoolExecutor for async crypto operations
- **Background Tasks**: NTP sync (lock-free timestamp assignment), clipboard auto-clear timers
- **Thread Safety**: EventBus dispatches to main thread via `root.after()`
- **Decryption Snapshots**: `KeyStore.get_decryption_snapshot()` provides thread-safe key material snapshots for background decryption tasks
- **Deadlock Prevention**: `acquire_friend_locks_ordered()` acquires per-friend ratchet locks in a consistent global order to prevent deadlocks when multiple threads interact with the same friends

## Data Flow

1. User interacts with View (Tab)
2. View calls Service method or publishes Event
3. Service performs business logic, may use CryptoQueue for heavy ops
4. Service updates Model (KeyStore/Database)
5. Service publishes Event or returns result
6. View updates UI based on result or event

## Security Boundaries

- All secrets encrypted at rest (Argon2id + AES-GCM)
- Keys zeroed from memory on lock/close via `GuardedBuffer.wipe_and_free()`
- Sensitive pages pinned in RAM (VirtualLock/mlock) to prevent swap leakage
- Guard pages detect buffer overread/overflow attacks
- Anti-dump: MiniDumpWriteDump patched, core dumps disabled, SeDebugPrivilege removed
- Clipboard auto-clear prevents leakage
- Per-friend ratchet locks prevent race conditions
- TOTP required for unlock after emergency lock
- Anti-tamper protections active in frozen .exe (debugger + binary integrity checks, fail-closed on errors)
