
A desktop application for secure hybrid encryption, digital signatures, and file encryption — inspired by the Enigma machine but built with modern cryptography.

**Author:** Chaiphile
**Version:** 2.2

![Python|98](https://img.shields.io/badge/python-3.8+-blue.svg)

---

## 🔐 Overview

Ultimate Enigma Messenger is a **local cryptographic tool** that encrypts messages and files using a combination of:

- **AES‑256‑GCM** for symmetric encryption
- **RSA‑OAEP** for key wrapping and friend‑specific encryption
- **Time‑based symmetric keys** with a sliding window (±3 steps of 30 seconds)
- **Digital signatures** (RSA‑PSS) for authenticity and non‑repudiation
- **Self‑destruct messages** (optional expiration)

All sensitive keys (private RSA key, global shared secret, friends’ shared secrets) are encrypted with a master password and stored in a SQLite database.  
The app provides an intuitive dark-themed GUI for encryption, decryption, contact management, and key exchange.

---

## ✨ Features

- **Hybrid Encryption** – AES‑GCM for speed, RSA‑OAEP for friend‑only confidentiality.
- **Time‑Based Keys** – Every message is encrypted with a key derived from a shared secret and the current time; valid only within a ±90‑second window.
- **Digital Signatures** – Sign messages with your private key; verify sender identity inside the app.
- **Self‑Destruct** – Set a message to expire after 5 min, 10 min, 1 hour, etc.
- **Friend Management** – Store friends’ public keys and optionally ECDH‑derived shared secrets.
- **ECDH Key Exchange** – Perform X25519 key exchange to establish a unique shared secret with a friend.
- **File Encryption** – Encrypt/decrypt any file with a password using AES‑GCM + PBKDF2.
- **Global Shared Secret** – A fallback symmetric key usable with all users who know it.
- **Secure Memory Wipe** – Keys are zeroed from memory on app close.
- **Master Password Protection** – All long‑term secrets are encrypted at rest (PBKDF2‑HMAC‑SHA256 + AES‑GCM).

---

## 🖥️ Screenshots

*(Add screenshots here of the main window, encryption tab, friends list, etc.)*

---

## 🚀 Installation

### Prerequisites

- Python **3.8 or higher**
- `pip` (Python package manager)
- Tkinter (usually bundled with Python; on Linux you may need `python3-tk`)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ultimate-enigma.git
   cd ultimate-enigma
   ```

2. **(Optional) Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

   If no `requirements.txt` exists, you can create one with:
   ```text
   cryptography
   pytest
   ```
   Then run `pip install cryptography pytest` manually.

4. **Run the application**
   ```bash
   python main.py
   ```

---

## 📖 Usage

### First Launch

- You will be prompted to set a **master password** (minimum 4 characters).  
- The app generates a 3072‑bit RSA key pair and a 256‑bit global shared secret, all encrypted with your master password.

### Main Interface

The application is organized into tabs:

#### ✉️ Encrypt & Send
- Type your message, optionally sign it with your private key.
- Choose a **friend** to encrypt the message specifically for them (using their public RSA key).  
  If the friend has a shared secret from ECDH, that secret will be used instead of the global one.
- Enable **self‑destruct** and select an expiration time.
- Click **Encrypt & Send** – the Base64‑encoded ciphertext is displayed and can be copied.

#### 📥 Decrypt & Receive
- Paste a received Base64 message into the input field.
- Click **Decrypt Message**; the plaintext (and signature verification result) appears in the output area.
- Messages that have self‑destructed will show an appropriate error.

#### 🔗 Shared Secret
- View the fingerprint of the current global shared secret.
- Export the global secret (Base64) to share manually.
- Import a new global secret (replaces the current one).
- Start an **ECDH key exchange** to update the global secret securely with a peer.

#### 🔐 File Encryption
- Encrypt any file with a password using AES‑GCM + PBKDF2 (300,000 iterations).
- Decrypt an encrypted file by providing the same password.

#### 👥 Friends
- Add friends by entering their name, public key (PEM format), and optionally a shared secret (Base64).
- Perform **ECDH key exchange** with a selected friend to derive a shared secret directly inside the app.
- Remove friends, view public key details, and fingerprints.

#### ℹ️ About
- Displays app version, author, and a brief privacy statement.

---

## 🧪 Testing

The project includes a comprehensive test suite using `pytest`.

Run all tests:
```bash
pytest test.py test_crypto.py -v
```

The tests cover:
- Cryptographic primitives (AES, RSA, ECDH, key derivation)
- Time‑based key sliding window
- Self‑destruct logic
- Database encryption/decryption
- KeyStore operations (load, save, wipe)
- File encryption/decryption
- Packet format and flag parsing
- Edge cases (corrupt data, wrong passwords, non‑UTF‑8 plaintext)

---

## 🏛️ Architecture

The project is structured as follows:

| File               | Purpose                                      |
|--------------------|----------------------------------------------|
| `main.py`          | Application entry point, logging setup       |
| `app.py`           | Main window, tab setup, key loading, rotor animation |
| `crypto.py`        | Core encryption/decryption and signature functions |
| `key_manager.py`   | KeyStore class, database read/write, file crypto  |
| `database.py`      | SQLite schema, PBKDF2+AES secret encryption  |
| `encrypt_tab.py`   | UI for message encryption                    |
| `decrypt_tab.py`   | UI for message decryption                    |
| `friends_tab.py`   | Friend list management and ECDH              |
| `secret_tab.py`    | Global secret management and ECDH            |
| `file_tab.py`      | File encryption/decryption UI                |
| `about_tab.py`     | About window                                 |
| `ecdh.py`          | X25519 key exchange dialog                   |
| `visual_enigma.py` | Rotor animation in the header                |
| `styles.py`        | Modern dark theme for ttk widgets            |
| `utils.py`         | Password dialog helper                       |
| `test.py`          | Main test suite                              |
| `test_crypto.py`   | Additional crypto unit tests                 |

---

## 🤖 Model Context Protocol (MCP)

Ultimate Enigma supports the **Model Context Protocol (MCP)**, an open standard for connecting AI applications to external systems [[1]]. This allows Large Language Models (LLMs) to securely interact with the application's cryptographic functions and data sources.

### Features
- **Secure Context**: Provides LLMs with secure access to encryption/decryption tools without exposing raw keys.
- **Automated Workflows**: Enables AI agents to perform complex cryptographic tasks like batch file encryption or key management.
- **Standardized Integration**: Follows the MCP specification for seamless compatibility with various AI assistants and development environments [[5]].

---

## 🔒 Security Considerations

- **Master Password** – The master password is never stored; it is used only to derive an encryption key for the private key and shared secrets. If lost, data cannot be recovered.
- **Time‑Based Keys** – Offers a small window of replay protection (90 seconds), but is not a substitute for proper network security if used over the internet.
- **Self‑Destruct** – This is a **client‑side feature**; it relies on the recipient’s app honouring the expiry. It does **not** guarantee deletion on the recipient’s machine.
- **Key Management** – All secrets are encrypted with AES‑GCM using PBKDF2‑derived keys. The database file (`enigma.db`) should be kept private.
- **ECDH** – X25519 key exchange is performed locally; users must manually verify the fingerprint through a secure channel to prevent MITM attacks.
- **Memory Cleanup** – Keys are zeroed and garbage collected when the app closes.

---

## 📄 License

This project is licensed under the Polyform Noncommercial License 1.0.0. See the `LICENSE.txt` file for details.

---

## 🙏 Acknowledgements

- [Python Cryptography library](https://cryptography.io/) for all cryptographic operations.
- Tkinter for the GUI framework.
- The Enigma machine for inspiration.

---

*Privacy is a right, not a privilege.*