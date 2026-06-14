# Ultimate Enigma Messenger

A desktop application for secure hybrid encryption, digital signatures, and file encryption — inspired by the Enigma machine but built with modern cryptography.

**Author:** Chaiphile  
**Version:** 2.2  
**License:** Polyform Noncommercial License 1.0.0

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-Polyform%20NC-orange.svg)

---

## Overview

Ultimate Enigma Messenger is a **local cryptographic tool** that encrypts messages and files using a combination of:

- **AES‑256‑GCM** for symmetric encryption
- **RSA‑OAEP (4096-bit)** for key wrapping and friend‑specific encryption
- **Argon2id** for memory-hard key derivation
- **Double Ratchet Protocol** for forward secrecy and break-in recovery
- **Post-Quantum Cryptography** (X25519 + Kyber768 hybrid KEM) for quantum-safe encryption
- **TOTP Authentication** for secure unlock verification
- **Hybrid Digital signatures** (Ed25519 + Dilithium3) for authenticity and non‑repudiation
- **Time‑based symmetric keys** with NTP-synchronized sliding window (WINDOW_SIZE=2, ±60s)
- **Self‑destruct messages** with configurable expiration

All sensitive keys are encrypted at rest and stored in a SQLCipher-encrypted SQLite database (via `sqlcipher3`). When `sqlcipher3` is unavailable, the app falls back to plain SQLite with a warning. The app provides an intuitive dark-themed GUI built with ttkbootstrap for encryption, decryption, contact management, and key exchange.

**Detailed Documentation:** See the [`docs/`](docs/) directory for comprehensive guides:
- [Setup Guide (Windows/macOS/Linux)](docs/SETUP.md) – Multi-OS installation and configuration
- [Services Reference](docs/SERVICES_REFERENCE.md) – Every service, method, and parameter documented
- [Models Reference](docs/MODELS_REFERENCE.md) – Data models, database schema, SecureString, constants
- [Views & Controllers Reference](docs/VIEWS_AND_CONTROLLERS.md) – All UI tabs, controllers, dialogs
- [Architecture](docs/ARCHITECTURE.md) – System design and component interaction
- [Security Model](docs/SECURITY.md) – Threat model and security properties
- [API Reference](docs/API.md) – API documentation
- [Contributing Guidelines](docs/CONTRIBUTING.md) – Development guidelines and workflows
- [Database Reference](docs/DATABASE.md) – Database schema and operations
- [Hybrid Signature Implementation](docs/HYBRID_SIGNATURE_IMPLEMENTATION.md) – Hybrid signature details
- [Scientific Report](docs/SCIENTIFIC_REPORT.md) – Cryptographic architecture and scientific foundations

---

## Features

### Core Encryption
- **Hybrid Encryption** – AES-GCM for speed, RSA-OAEP for friend-only confidentiality
- **Time‑Based Keys** – Every message encrypted with a key derived from shared secret + timestamp; valid within ±60-second window (WINDOW_SIZE=2)
- **Hybrid Digital Signatures** – Ed25519 + Dilithium3 for authenticity and non‑repudiation
- **Self‑Destruct** – Set messages to expire after configurable duration

### Key Management
- **Friend Management** – Store friends' public keys and ECDH-derived shared secrets
- **ECDH Key Exchange** – X25519 key exchange for unique per-friend secrets
- **Global Shared Secret** – Fallback symmetric key for group communication
- **Double Ratchet** – Signal Protocol implementation with XChaCha20-Poly1305 for forward secrecy

### Post-Quantum Security
- **Hybrid KEM** – X25519 + Kyber768 for quantum-safe key encapsulation
- **Hybrid Signatures** – Ed25519 + Dilithium3 for quantum-safe authentication
- **Hybrid Envelopes** – Classical + PQC encryption for transition safety
- **Future-Proof** – Protects against quantum computer threats

### Authentication & Protection
- **Master Password** – Argon2id-derived key protects all secrets at rest (PBKDF2-to-Argon2id migration supported)
- **TOTP Verification** – RFC 6238 time-based one-time password for unlock
- **Duress Password** – Alternate password that triggers duress mode
- **Emergency Lock** – Instant key wipe with hotkey support (Ctrl+Shift+L)
- **Lockout Protection** – Exponential backoff on failed attempts
- **Anti-Tamper** – Debugger detection, binary integrity checks, hooking framework detection, and hardware breakpoint detection in compiled .exe

### File Operations
- **File Encryption** – Encrypt/decrypt any file with password (AES-GCM + Argon2id)
- **Friend-Specific Files** – Encrypt files for specific recipients
- **Signature Verification** – Verify file signatures on decrypt
- **Chunked Processing** – Handle large files efficiently

### User Experience
- **Dark Theme** – Modern ttkbootstrap "darkly" theme
- **Clipboard Auto-Clear** – Sensitive data cleared after configurable timeout
- **NTP Synchronization** – Multi-server NTP consensus with outlier rejection for accurate time-based key derivation
- **Event-Driven UI** – Decoupled components via EventBus with 22 event types
- **Rotor Animation** – Visual Enigma machine header animation
- **SecureString** – Memory-safe string handling with 3-pass wipe

---

## Installation

### Quick Start

For detailed OS-specific instructions (Windows, macOS, Linux), see the **[Setup Guide](docs/SETUP.md)**.

```bash
# Clone
git clone https://github.com/yourusername/ultimate-enigma.git
cd ultimate-enigma

# Virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

# Install & run
pip install -r requirements.txt
python main.py
```

#### Windows Prerequisites (C++ Build Tools)

On Windows, native Python extensions (like `cryptography`, `argon2-cffi`) and the Post-Quantum Cryptography library (`liboqs`) require a C/C++ compiler to build. 

**Required Components:**
- **Visual Studio Build Tools** (or full Visual Studio 2022)
- **MSVC v143 C++ Build Tools** (x86/x64)
- **Windows 11 SDK**

We provide an **automated PowerShell script** to install all required C++ development components silently:

```powershell
# Open PowerShell as Administrator, navigate to the project folder, and run:
.\setup_dev_env.ps1
```

For manual installation instructions, see the [Windows Setup Guide](docs/SETUP.md#windows-setup).

### Platform-Specific Notes

| Platform | Key Notes |
|----------|----------|
| **Windows** | Full support including global hotkeys (Ctrl+Shift+L/U). Use `build_app.bat` for executable. **Requires C++ Build Tools** (see Windows Prerequisites above). |
| **macOS** | Install via Homebrew (`brew install python@3.12`). No global hotkeys (use lock button). Apple Silicon supported. |
| **Linux** | Requires `python3-tk` package. No global hotkeys. X11 or Wayland with XWayland required. |

See [docs/SETUP.md](docs/SETUP.md) for complete installation steps, liboqs/PQC setup, troubleshooting, and building executables on each platform.

---

## Usage

### First Launch

1. You will be prompted to set a **master password** (minimum 16 characters required)
2. The app generates a 4096-bit RSA key pair, PQC keys, hybrid signing keys, and 256-bit global shared secret
3. TOTP setup is required for secure unlock capability
4. All keys are encrypted with your master password and stored securely
5. **Set your display name** (required for Double Ratchet): In the Friends tab, click **"Set My Name"** and enter the exact name your contacts use for you — this is embedded in ratchet envelopes so recipients can identify your session

### Main Interface

The application is organized into tabs:

#### Encrypt & Send
- Type your message, optionally sign it with your private key
- Choose from 4 encryption modes: **Ratchet**, **Shared Secret**, **RSA**, **PQC**
- Enable **self‑destruct** and select expiration time
- Click **Encrypt & Send** – Base64 ciphertext is displayed and copied

#### Decrypt & Receive
- Paste received Base64 message into input field
- Click **Decrypt Message** – plaintext and signature verification appear
- Mode indicator shows encryption type used
- Expired self-destruct messages show appropriate error

#### File Encryption
- Encrypt any file with 3 methods: **password**, **global secret**, **friend secret**
- Decrypt encrypted files with same method
- Support for friend-specific file encryption
- Signature verification on decrypt

#### Friends
- Add friends with name, public key (PEM), and optional shared secret
- Perform **ECDH key exchange** with selected friend
- Initialize **Double Ratchet** sessions
- Remove friends, view public key details and fingerprints
- Treeview-based friend management

#### Shared Secret
- View fingerprint of current global shared secret
- Export/import global secret (Base64)
- Start **ECDH key exchange** for secure secret establishment

#### NTP
- View local system time and NTP server time
- Multi-server NTP consensus with outlier rejection
- Auto-refresh capability
- Choose from preset servers or enter custom hostname
- Displays time offset and last sync timestamp

#### About
- App version, author, and privacy statement
- Backup and restore functionality
- Security actions (key wipe, etc.)

### Emergency Lock

- Click **EMERGENCY LOCK** button or use hotkey (Ctrl+Shift+L)
- Immediately wipes all keys from memory
- Requires master password + TOTP to unlock
- All services are rebuilt with restored keys

---

## Testing

The project includes a comprehensive test suite using `pytest` with **550+ tests** covering all modules.

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/test_encryption_service.py -v
```

### Run with Coverage
```bash
pytest tests/ --cov=. --cov-report=html
```

### Test Coverage

The test suite covers:
- Cryptographic primitives (AES, RSA, ECDH, Argon2id, PQC)
- Double Ratchet protocol operations
- Time‑based key sliding window
- Self‑destruct logic
- Database encryption/decryption
- KeyStore operations (load, save, wipe)
- File encryption/decryption
- TOTP generation and verification
- EventBus publish/subscribe
- Clipboard service (copy, clear, auto-clear timer)
- NTP client (query, timeout, error handling, consensus)
- Anti-tamper and anti-debugger detection logic
- Concurrent operations and thread safety
- Edge cases (corrupt data, wrong passwords, timeouts)
- SecureString memory safety
- Constant-time decryption

### Test Utilities

Batch files are provided for common test scenarios:
- `run_tests.py` – Main test runner
- `run_specific_tests.bat` – Run targeted tests
- `run_timeout_tests.bat` – Test timeout handling
- `run_concurrent_test.bat` – Test concurrent operations

---

## Architecture

The project follows an **MVC (Model-View-Controller)** architecture with an event-driven service layer:

```
┌─────────────────────────────────────────────────────────────┐
│                      EnigmaApp (main)                       │
│  ┌────────────────┐ ┌──────────────┐ ┌───────────────────┐  │
│  │ApplicationCtrl │ │AuthController│ │ServiceOrchestrator│  │
│  └────────────────┘ └──────────────┘ └───────────────────┘  │
│                              │                              │
│                    ┌─────────┴─────────┐                    │
│                    │      EventBus     │                    │
│                    │   (22 event types)│                    │
│                    └───────────────────┘                    │
│                              │                              │
│  ┌───────────────────────────┼───────────────────────────┐  │
│  │          Services         │          Views            │  │
│  │  EncryptionSvc            │  EncryptTab               │  │
│  │  FileService              │  DecryptTab               │  │
│  │  FriendsService           │  FriendsTab               │  │
│  │  ClipboardService         │  FileTab                  │  │
│  │  DoubleRatchet            │  SecretTab                │  │
│  │  PQCService               │  NtpTab                   │  │
│  │  TOTPService              │  AboutTab                 │  │
│  │  HotkeyService            │  LockScreen               │  │
│  │  ... (19 services)        │  VisualEnigma             │  │
│  └───────────────────────────┴───────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

| Directory/File | Purpose |
|----------------|---------|
| `main.py` | Entry point (48 lines) - logging, anti-tamper, ttkbootstrap darkly theme |
| `app.py` | EnigmaApp class (373 lines) - composition root, 7 tabs, emergency lock/unlock, event subscriptions, rotor animation |
| `crypto.py` | Crypto operations (465 lines) - AES-256-GCM + RSA-OAEP, time-based keys, constant-time decryption, hybrid signing, self-destruct |
| `database.py` | Database layer (500 lines) - SQLite/SQLCipher, Argon2id KDF, schema init, integrity check, error classification, PBKDF2-to-Argon2id migration |
| `key_manager.py` | Key management (1182 lines) - RSA 4096-bit, PQC keys, hybrid sig keys, exponential backoff lockout, duress mode, password change |
| `ntp_client.py` | NTP client (145 lines) - Multi-server NTP consensus with outlier rejection |
| `controllers/` | MVC controllers (3 files) - lifecycle, auth, service DI |
| `models/` | Data models (3 files) - envelope (RatchetEnvelope, PQCEncvelope), friend profile, re-exports |
| `services/` | Business logic (19 files, ~5214 lines) - encryption, files, friends, ratchet, PQC, TOTP, etc. |
| `views/` | View layer (12 files, ~2747 lines) - tabs, dialogs, lock screen, utilities |
| `components/` | Reusable UI components (5 files) - add friend, hybrid sig exchange, PQC exchange, TOTP dialogs |
| `src/` | Core utilities (8 files, ~2014 lines) - constants, exceptions, secure string, crypto helpers, anti-tamper, timeout |
| `tests/` | Test suite (23 files, 550+ tests) |
| `docs/` | Documentation (11 reference files) |

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Security Considerations

- **Master Password** – Never stored; used only to derive encryption key via Argon2id. If lost, data cannot be recovered.
- **Memory Safety** – Keys are zeroed from memory on lock/close using `SecureString` with 3-pass wipe.
- **Time‑Based Keys** – Offers ±60-second replay protection window (WINDOW_SIZE=2); not a substitute for network security.
- **Constant-Time Decryption** – Decryption timing is constant regardless of failure mode to prevent timing attacks.
- **Self‑Destruct** – Client‑side feature only; does **not** guarantee deletion on recipient's machine.
- **Key Storage** – All secrets encrypted at rest (Argon2id + AES-GCM) in SQLite database.
- **ECDH** – Performed locally; users must verify fingerprints through secure channel to prevent MITM.
- **TOTP** – Required for unlock after emergency lock; prevents unauthorized access.
- **Lockout** – Exponential backoff and hard lockout protect against brute force.
- **Duress Mode** – Alternate password triggers duress mode for coercion scenarios.
- **Post-Quantum** – Hybrid KEM (X25519 + Kyber768) and hybrid signatures (Ed25519 + Dilithium3) for quantum-safe security.
- **Anti-Tamper** – Compiled .exe includes debugger detection, binary integrity checks, hooking framework detection, and hardware breakpoint detection. Process exits silently if tampering is detected.
- **Hybrid Signatures** – Combines classical (Ed25519) and post-quantum (Dilithium3) signatures for transition safety.
- **Thread Safety** – Per-friend RLock prevents deadlocks in concurrent ratchet operations.
- **EventBus** – Thread-safe singleton event system with 22 event types for decoupled communication.

For the complete security model, see [docs/SECURITY.md](docs/SECURITY.md).

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| ttkbootstrap | ≥1.10.0 | Modern themed Tkinter widgets |
| cryptography | ≥41.0.0 | Core cryptographic operations |
| argon2-cffi | ≥23.1.0 | Memory-hard key derivation |
| qrcode[pil] | ≥7.4 | QR code generation for TOTP |
| liboqs-python | ≥0.9.0 | Post-quantum cryptography (Kyber, Dilithium) |
| sqlcipher3 | ≥1.2.0 | Encrypted SQLite database |
| pytest | ≥7.0.0 | Testing framework (optional) |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/SETUP.md) | Multi-OS installation (Windows/macOS/Linux), PQC setup, troubleshooting |
| [Services Reference](docs/SERVICES_REFERENCE.md) | All 19 services with every method, parameter, and return type |
| [Models Reference](docs/MODELS_REFERENCE.md) | Envelopes (RatchetEnvelope, PQCEncvelope), FriendProfile, DB schema, SecureString, constants |
| [Views & Controllers](docs/VIEWS_AND_CONTROLLERS.md) | All 12 view files, 3 controllers, 5 component dialogs, lock screen, utilities |
| [Architecture](docs/ARCHITECTURE.md) | MVC design, event flow, threading model |
| [Security Model](docs/SECURITY.md) | Cryptographic primitives, threat model, known limitations |
| [API Reference](docs/API.md) | API documentation |
| [Contributing](docs/CONTRIBUTING.md) | Code style, testing, PR process |
| [Database Reference](docs/DATABASE.md) | Database schema and operations |
| [Hybrid Signature Implementation](docs/HYBRID_SIGNATURE_IMPLEMENTATION.md) | Hybrid signature implementation details |
| [Scientific Report](docs/SCIENTIFIC_REPORT.md) | Cryptographic architecture and scientific foundations |

---

## License

This project is licensed under the **Polyform Noncommercial License 1.0.0**. See the [`LICENSE.txt`](LICENSE.txt) file for details.

---

## Acknowledgements

- [Python Cryptography library](https://cryptography.io/) for all cryptographic operations
- [liboqs](https://openquantumsafe.org/) for post-quantum algorithms
- [ttkbootstrap](https://ttkbootstrap.readthedocs.io/) for modern UI theming
- Tkinter for the GUI framework
- The Enigma machine for historical inspiration
- Signal Protocol for Double Ratchet design

---

*Privacy is a right, not a privilege.*