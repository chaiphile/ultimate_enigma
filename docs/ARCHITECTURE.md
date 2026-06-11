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
│  │  NTP Sync   │    │  LockScreen │    │  ├─ FileService     │ │
│  └─────────────┘    └─────────────┘    │  ├─ FriendsService  │ │
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
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
ultimate_enigma/
├── main.py                 # Application entry point, logging setup
├── app.py                  # EnigmaApp - main window orchestration
├── controllers/            # MVC Controllers
│   ├── application_controller.py  # App lifecycle, hotkeys, queues
│   ├── auth_controller.py         # Authentication, TOTP, lock/unlock
│   └── service_orchestrator.py    # Service creation and DI
├── models/                 # Data Models
│   ├── envelope.py         # Message envelope structures
│   ├── friend_profile.py   # Friend/contact data model
│   └── key_store.py        # Key storage abstraction
├── services/               # Business Logic Services
│   ├── encryption_service.py      # Core encryption/decryption
│   ├── file_service.py            # File encryption operations
│   ├── friends_service.py         # Contact management
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
│   ├── hotkey_service.py          # Global hotkey registration
│   ├── crypto_task_queue.py       # Async crypto operations
│   └── event_bus.py               # Pub/sub event system
├── components/             # Reusable UI Components
│   └── totp_dialogs.py           # TOTP setup/verify dialogs
├── src/                    # Core Utilities
│   ├── constants.py              # Centralized constants
│   ├── exceptions.py             # Custom exception classes
│   ├── secure_string.py          # Memory-safe string handling
│   └── timeout.py                # Timeout decorators/utilities
├── *_tab.py                # View layer (Tkinter tabs)
├── crypto.py               # Low-level crypto primitives
├── database.py             # SQLite schema and operations
├── key_manager.py          # KeyStore implementation
└── tests/                  # Test suite
```

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

### ServiceOrchestrator
Central dependency injection container:
- Creates and manages all service instances
- Handles service rebuilding after unlock
- Updates tab references when services change
- Coordinates service shutdown

## Services

### EncryptionService
Core cryptographic operations:
- AES-256-GCM symmetric encryption
- RSA-OAEP key wrapping
- Time-based key derivation with sliding window
- Digital signatures (RSA-PSS)
- Self-destruct message support

### FileService
File encryption operations:
- Password-based file encryption (AES-GCM + Argon2id)
- Friend-specific file encryption
- Chunked processing for large files

### FriendsService
Contact management:
- Add/remove/update friend profiles
- Public key storage and retrieval
- ECDH shared secret management
- Friend list change notifications

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
| `KEYS_WIPED` | Keys cleared from memory |
| `KEYS_LOADED` | Keys loaded from database |
| `TOTP_SETUP_COMPLETE` | TOTP configured |
| `TOTP_VERIFIED` | TOTP code validated |
| `SERVICES_REBUILT` | Services recreated |
| `NTP_SYNCED` | Time synchronized |
| `FRIEND_LIST_CHANGED` | Contacts modified |
| `APP_SHUTDOWN` | Application closing |

## Threading Model

- **Main Thread**: Tkinter GUI event loop
- **Crypto Workers**: ThreadPoolExecutor for async crypto operations
- **Background Tasks**: NTP sync, clipboard auto-clear timers
- **Thread Safety**: EventBus dispatches to main thread via `root.after()`

## Data Flow

1. User interacts with View (Tab)
2. View calls Service method or publishes Event
3. Service performs business logic, may use CryptoQueue for heavy ops
4. Service updates Model (KeyStore/Database)
5. Service publishes Event or returns result
6. View updates UI based on result or event

## Security Boundaries

- All secrets encrypted at rest (Argon2id + AES-GCM)
- Keys zeroed from memory on lock/close
- Clipboard auto-clear prevents leakage
- Per-friend ratchet locks prevent race conditions
- TOTP required for unlock after emergency lock
