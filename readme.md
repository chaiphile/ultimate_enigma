# Ultimate Enigma Messenger

A desktop application for secure hybrid encryption, digital signatures, and file encryption — inspired by the Enigma machine but built with modern cryptography.

**Author:** Chaiphile  
**Version:** 2.2  
**License:** Polyform Noncommercial License 1.0.0

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-Polyform%20NC-orange.svg)

---

## 🔐 Overview

Ultimate Enigma Messenger is a **local cryptographic tool** that encrypts messages and files using a combination of:

- **AES‑256‑GCM** for symmetric encryption
- **RSA‑OAEP (4096-bit)** for key wrapping and friend‑specific encryption
- **Argon2id** for memory-hard key derivation
- **Double Ratchet Protocol** for forward secrecy and break-in recovery
- **Post-Quantum Cryptography** (CRYSTALS-Kyber) for quantum-safe encryption
- **TOTP Authentication** for secure unlock verification
- **Digital signatures** (RSA‑PSS) for authenticity and non‑repudiation
- **Time‑based symmetric keys** with NTP-synchronized sliding window
- **Self‑destruct messages** with configurable expiration

All sensitive keys are encrypted at rest and stored in a SQLCipher-encrypted SQLite database (via `sqlcipher3`). When `sqlcipher3` is unavailable, the app falls back to plain SQLite with a warning. The app provides an intuitive dark-themed GUI built with ttkbootstrap for encryption, decryption, contact management, and key exchange.

📚 **Detailed Documentation:** See the [`docs/`](docs/) directory for comprehensive guides:
- [Setup Guide (Windows/macOS/Linux)](docs/SETUP.md) – Multi-OS installation and configuration
- [Services Reference](docs/SERVICES_REFERENCE.md) – Every service, method, and parameter documented
- [Models Reference](docs/MODELS_REFERENCE.md) – Data models, database schema, SecureString, constants
- [Views & Controllers Reference](docs/VIEWS_AND_CONTROLLERS.md) – All UI tabs, controllers, dialogs
- [Architecture](docs/ARCHITECTURE.md) – System design and component interaction
- [Security Model](docs/SECURITY.md) – Threat model and security properties
- [Contributing Guidelines](docs/CONTRIBUTING.md) – Development guidelines and workflows

---

## ✨ Features

### Core Encryption
- **Hybrid Encryption** – AES-GCM for speed, RSA-OAEP for friend-only confidentiality
- **Time‑Based Keys** – Every message encrypted with a key derived from shared secret + timestamp; valid within ±90-second window
- **Digital Signatures** – Sign messages with your private key; verify sender identity
- **Self‑Destruct** – Set messages to expire after configurable duration

### Key Management
- **Friend Management** – Store friends' public keys and ECDH-derived shared secrets
- **ECDH Key Exchange** – X25519 key exchange for unique per-friend secrets
- **Global Shared Secret** – Fallback symmetric key for group communication
- **Double Ratchet** – Signal Protocol implementation for forward secrecy

### Post-Quantum Security
- **CRYSTALS-Kyber KEM** – NIST-standardized post-quantum key encapsulation
- **Hybrid Envelopes** – Classical + PQC encryption for transition safety
- **Future-Proof** – Protects against quantum computer threats

### Authentication & Protection
- **Master Password** – Argon2id-derived key protects all secrets at rest
- **TOTP Verification** – Time-based one-time password for unlock
- **Emergency Lock** – Instant key wipe with hotkey support
- **Lockout Protection** – Exponential backoff on failed attempts
- **Anti-Tamper** – Debugger detection, binary integrity checks, and hardware breakpoint detection in compiled .exe

### File Operations
- **File Encryption** – Encrypt/decrypt any file with password (AES-GCM + Argon2id)
- **Friend-Specific Files** – Encrypt files for specific recipients
- **Chunked Processing** – Handle large files efficiently

### User Experience
- **Dark Theme** – Modern ttkbootstrap "darkly" theme
- **Clipboard Auto-Clear** – Sensitive data cleared after 30 seconds
- **NTP Synchronization** – Accurate time for time-based key derivation
- **Event-Driven UI** – Decoupled components via EventBus
- **Rotor Animation** – Visual Enigma machine header animation

---

## 🖥️ Screenshots

*(Add screenshots here of the main window, encryption tab, friends list, etc.)*

---

## 🚀 Installation

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

#### ⚠️ Windows Prerequisites (C++ Build Tools)

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

## 📖 Usage

### First Launch

1. You will be prompted to set a **master password** (minimum 12 characters recommended)
2. The app generates a 4096-bit RSA key pair and 256-bit global shared secret
3. TOTP setup is required for secure unlock capability
4. All keys are encrypted with your master password and stored securely
5. **Set your display name** (required for Double Ratchet): In the Friends tab, click **"✏️ Set My Name"** and enter the exact name your contacts use for you — this is embedded in ratchet envelopes so recipients can identify your session

### Main Interface

The application is organized into tabs:

#### ✉️ Encrypt & Send
- Type your message, optionally sign it with your private key
- Choose a **friend** for recipient-specific encryption
- Enable **self‑destruct** and select expiration time
- Click **Encrypt & Send** – Base64 ciphertext is displayed and copied

#### 📥 Decrypt & Receive
- Paste received Base64 message into input field
- Click **Decrypt Message** – plaintext and signature verification appear
- Expired self-destruct messages show appropriate error

#### 🔗 Shared Secret
- View fingerprint of current global shared secret
- Export/import global secret (Base64)
- Start **ECDH key exchange** for secure secret establishment

#### 🔐 File Encryption
- Encrypt any file with password using AES-GCM + Argon2id
- Decrypt encrypted files with same password
- Support for friend-specific file encryption

#### 👥 Friends
- Add friends with name, public key (PEM), and optional shared secret
- Perform **ECDH key exchange** with selected friend
- Remove friends, view public key details and fingerprints

#### 🕐 NTP
- View local system time and NTP server time
- Manually synchronize with NTP server
- Choose from preset servers or enter custom hostname
- Displays time offset and last sync timestamp

#### ℹ️ About
- App version, author, and privacy statement
- TOTP setup access

### Emergency Lock

- Click **🔒 EMERGENCY LOCK** button or use registered hotkey
- Immediately wipes all keys from memory
- Requires master password + TOTP to unlock
- All services are rebuilt with restored keys

---

## 🧪 Testing

The project includes a comprehensive test suite using `pytest`.

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
- NTP client (query, timeout, error handling)
- Anti-tamper and anti-debugger detection logic
- Concurrent operations and thread safety
- Edge cases (corrupt data, wrong passwords, timeouts)

### Test Utilities

Batch files are provided for common test scenarios:
- `run_tests.py` – Main test runner
- `run_specific_tests.bat` – Run targeted tests
- `run_timeout_tests.bat` – Test timeout handling
- `run_concurrent_test.bat` – Test concurrent operations

---

## 🏛️ Architecture

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
│  └───────────────────────────┴───────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

| Directory/File | Purpose |
|----------------|---------|
| `controllers/` | MVC controllers (lifecycle, auth, service DI) |
| `models/` | Data models (envelope, friend profile, key store) |
| `services/` | Business logic services (encryption, files, friends, etc.) |
| `views/` | View layer (Tkinter tabs, dialogs, lock screen, utilities) |
| `components/` | Reusable UI components (TOTP dialogs) |
| `src/` | Core utilities (constants, exceptions, secure string, crypto helpers, anti-tamper) |
| `tests/` | Comprehensive test suite |
| `app.py` | Main window orchestration |
| `main.py` | Application entry point |

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🔒 Security Considerations

- **Master Password** – Never stored; used only to derive encryption key via Argon2id. If lost, data cannot be recovered.
- **Memory Safety** – Keys are zeroed from memory on lock/close using `SecureString`.
- **Time‑Based Keys** – Offers ±90-second replay protection window; not a substitute for network security.
- **Self‑Destruct** – Client‑side feature only; does **not** guarantee deletion on recipient's machine.
- **Key Storage** – All secrets encrypted at rest (Argon2id + AES-GCM) in SQLite database.
- **ECDH** – Performed locally; users must verify fingerprints through secure channel to prevent MITM.
- **TOTP** – Required for unlock after emergency lock; prevents unauthorized access.
- **Lockout** – Exponential backoff and hard lockout protect against brute force.
- **Post-Quantum** – CRYSTALS-Kyber provides quantum-safe key encapsulation.
- **Anti-Tamper** – Compiled .exe includes debugger detection, binary integrity checks, hooking framework detection, and hardware breakpoint detection. Process exits silently if tampering is detected.

For the complete security model, see [docs/SECURITY.md](docs/SECURITY.md).

---

## 🤖 Model Context Protocol (MCP)

Ultimate Enigma supports the **Model Context Protocol (MCP)**, an open standard for connecting AI applications to external systems. This allows LLMs to securely interact with the application's cryptographic functions.

### Features
- **Secure Context**: Provides LLMs with secure access to encryption/decryption tools without exposing raw keys
- **Automated Workflows**: Enables AI agents to perform batch file encryption or key management
- **Standardized Integration**: Follows MCP specification for compatibility with AI assistants

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| ttkbootstrap | ≥1.10.0 | Modern themed Tkinter widgets |
| cryptography | ≥41.0.0 | Core cryptographic operations |
| argon2-cffi | ≥23.1.0 | Memory-hard key derivation |
| qrcode[pil] | ≥7.4 | QR code generation for TOTP |
| liboqs-python | ≥0.9.0 | Post-quantum cryptography (Kyber) |
| pytest | ≥7.0.0 | Testing framework (optional) |

---

## 📄 License

This project is licensed under the **Polyform Noncommercial License 1.0.0**. See the [`LICENSE.txt`](LICENSE.txt) file for details.

---

## 🙏 Acknowledgements

- [Python Cryptography library](https://cryptography.io/) for all cryptographic operations
- [liboqs](https://openquantumsafe.org/) for post-quantum algorithms
- [ttkbootstrap](https://ttkbootstrap.readthedocs.io/) for modern UI theming
- Tkinter for the GUI framework
- The Enigma machine for historical inspiration
- Signal Protocol for Double Ratchet design

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/SETUP.md) | Multi-OS installation (Windows/macOS/Linux), PQC setup, troubleshooting |
| [Services Reference](docs/SERVICES_REFERENCE.md) | All 16 services with every method, parameter, and return type |
| [Models Reference](docs/MODELS_REFERENCE.md) | Envelopes, FriendProfile, KeyStore, DB schema, SecureString, constants |
| [Views & Controllers](docs/VIEWS_AND_CONTROLLERS.md) | All 7 tabs, 3 controllers, dialogs, lock screen, utilities |
| [Architecture](docs/ARCHITECTURE.md) | MVC design, event flow, threading model |
| [Security Model](docs/SECURITY.md) | Cryptographic primitives, threat model, known limitations |
| [Contributing](docs/CONTRIBUTING.md) | Code style, testing, PR process |

---

*Privacy is a right, not a privilege.*
