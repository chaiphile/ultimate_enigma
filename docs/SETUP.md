# Ultimate Enigma Messenger – Setup Guide

Comprehensive installation and setup instructions for **Windows**, **macOS**, and **Linux**.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Windows Setup](#windows-setup)
- [macOS Setup](#macos-setup)
- [Linux Setup](#linux-setup)
- [Post-Quantum Cryptography (liboqs)](#post-quantum-cryptography-liboqs)
- [Virtual Environment (Recommended)](#virtual-environment-recommended)
- [Building Standalone Executable](#building-standalone-executable)
- [First Launch Walkthrough](#first-launch-walkthrough)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Python | 3.8+ | 3.10+ recommended |
| pip | Latest | Comes with Python |
| Tkinter | Bundled | May need separate install on Linux |
| Git | Any | For cloning the repository |
| C/C++ Compiler (Windows) | Required | Visual Studio Build Tools with MSVC (needed for `cryptography`, `argon2-cffi`, and building `liboqs`)
| Windows 11 SDK | Required | Required for MSVC compilation on Windows 11
| CMake | Optional | Only needed if building liboqs from source |

---

## Windows Setup

### Step 1: Install Python

1. Download Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. During installation, **check "Add Python to PATH"**
3. Verify installation:
   ```powershell
   python --version
   pip --version
   ```

### Step 2: Install C++ Build Tools (Required for Native Extensions & PQC)

Many Python dependencies used by Ultimate Enigma (such as `cryptography`, `argon2-cffi`, and `liboqs-python`) require a C/C++ compiler to build native extensions on Windows. Additionally, if you want to compile the Post-Quantum Cryptography library (`liboqs`) from source, you will need a full C++ development environment.

**Required Components:**
- **Visual Studio Build Tools** (or full Visual Studio 2022)
- **MSVC v143 C++ Build Tools** (x86/x64)
- **Windows 11 SDK** (10.0.22621.0 or later)
- **C++ CMake tools for Windows** (optional, for building liboqs)

#### Automated Installation (Recommended)

We provide a PowerShell script that automatically downloads and installs all required components silently.

1. Open **PowerShell as Administrator**.
2. Navigate to the project directory:
   ```powershell
   cd C:\path\to\ultimate-enigma
   ```
3. Run the setup script:
   ```powershell
   .\setup_dev_env.ps1
   ```
   *Note: If you get an execution policy error, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` first.*

#### Manual Installation

If you prefer to install manually or need to customize the components:

1. Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).
2. Run the installer and select the **"Desktop development with C++"** workload.
3. Ensure the following individual components are checked in the right-hand panel:
   - **MSVC v143 - VS 2022 C++ x64/x86 build tools**
   - **Windows 11 SDK** (e.g., 10.0.22621.0)
   - **C++ CMake tools for Windows** (optional)
4. Click **Install** and wait for the process to complete (this may take 10–20 minutes).

After installation, **restart your terminal** or computer to ensure the `cl.exe` compiler and environment variables are correctly loaded into your PATH.

---

### Step 3: Clone the Repository

```powershell
git clone https://github.com/yourusername/ultimate-enigma.git
cd ultimate-enigma
```

### Step 4: Create Virtual Environment (Recommended)

```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

> **Note:** On Windows, `liboqs-python` requires the `liboqs.dll` native library. See [Post-Quantum Cryptography](#post-quantum-cryptography-liboqs) below.

### Step 6: Run the Application

```powershell
python main.py
```

### Optional: Build Executable

```powershell
# Using the provided batch file
build_app.bat

# Or manually with PyInstaller
pip install pyinstaller
pyinstaller UltimateEnigma.spec
```

The executable will be created at `dist/UltimateEnigma.exe`.

---

## macOS Setup

### Step 1: Install Python

**Option A: Homebrew (Recommended)**
```bash
brew install python@3.12
```

**Option B: Official Installer**
Download from [python.org](https://www.python.org/downloads/macos/)

Verify:
```bash
python3 --version
pip3 --version
```

### Step 2: Install System Dependencies

```bash
# Xcode Command Line Tools (required for compiling native extensions)
xcode-select --install

# Tkinter is included with Python on macOS via Homebrew
# If using system Python, you may need:
brew install python-tk
```

### Step 3: Clone and Set Up

```bash
git clone https://github.com/yourusername/ultimate-enigma.git
cd ultimate-enigma

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 4: Run

```bash
python main.py
```

### macOS-Specific Notes

- **Gatekeeper**: If macOS blocks the app, go to System Preferences → Security & Privacy → Allow
- **Clipboard**: macOS clipboard auto-clear works via Tkinter's clipboard API
- **Global Hotkeys**: Not supported on macOS (Windows-only feature via Win32 API). Use the Emergency Lock button instead.
- **liboqs on Apple Silicon**: Use `brew install liboqs` or build from source for ARM64 support

---

## Linux Setup

### Step 1: Install System Packages

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv python3-tk git build-essential cmake
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip python3-tkinter git gcc gcc-c++ cmake make
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip tk git base-devel cmake
```

### Step 2: Clone and Set Up

```bash
git clone https://github.com/yourusername/ultimate-enigma.git
cd ultimate-enigma

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Run

```bash
python main.py
```

### Linux-Specific Notes

- **Tkinter**: Must be installed separately (`python3-tk` on Debian/Ubuntu). Without it, the app will fail to start with `ModuleNotFoundError: No module named 'tkinter'`.
- **Display Server**: Requires X11 or Wayland with XWayland. Pure Wayland may have clipboard issues.
- **Global Hotkeys**: Not supported on Linux (Windows-only feature). Use the Emergency Lock button.
- **Permissions**: The database is stored in `~/.ultimate_enigma/enigma.db`. Ensure your home directory is writable.
- **liboqs**: Install via package manager or build from source:
  ```bash
  sudo apt install liboqs-dev   # Debian/Ubuntu (if available)
  # Or build from source (see PQC section below)
  ```

---

## Post-Quantum Cryptography (liboqs)

The Post-Quantum Cryptography features (CRYSTALS-Kyber KEM, Dilithium3 signatures) require the **liboqs** native library. The app works without it but PQC features will be disabled.

### Windows

```powershell
# Option 1: Pre-built wheel (easiest)
pip install liboqs-python

# Option 2: If the wheel doesn't include the DLL, download liboqs.dll
# from https://github.com/open-quantum-safe/liboqs/releases
# and place it in your Python directory or project root
```

### macOS

```bash
# Option 1: Homebrew
brew install liboqs
pip install liboqs-python

# Option 2: Build from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=ON
make -j$(sysctl -n hw.ncpu)
sudo make install
pip install liboqs-python
```

### Linux

```bash
# Option 1: Package manager (Debian/Ubuntu)
sudo apt install liboqs-dev
pip install liboqs-python

# Option 2: Build from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig
pip install liboqs-python
```

### Verifying PQC Installation

After installation, verify that liboqs is working:
```python
python -c "import oqs; print('Kyber768' in oqs.get_enabled_kem_mechanisms())"
```
Should print `True`.

---

## Virtual Environment (Recommended)

Using a virtual environment isolates dependencies and prevents conflicts:

```bash
# Create
python -m venv venv        # Windows/Linux/macOS

# Activate
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows (CMD)
venv\Scripts\Activate.ps1  # Windows (PowerShell)

# Deactivate when done
deactivate
```

---

## Building Standalone Executable

### Windows

```powershell
pip install pyinstaller
pyinstaller UltimateEnigma.spec
```

Or use the provided batch file:
```powershell
build_app.bat
```

### macOS / Linux

```bash
pip install pyinstaller
pyinstaller UltimateEnigma.spec
```

> **Note:** Executables are platform-specific. You must build on each target OS separately.

### Spec File Details

The `UltimateEnigma.spec` file configures PyInstaller to:
- Bundle all Python dependencies
- Include the `liboqs` native library (if present)
- Include the `src.anti_tamper` module for anti-debugger/anti-tamper protections
- Set the application icon (`enigma.ico`)
- Create a single-file executable

### Anti-Tamper Protections

The compiled executable includes aggressive anti-tamper and anti-debugger protections that are **only active when running as a frozen .exe**. When running from source (`python main.py`), all protections are disabled for development convenience.

Protections include:
- Windows API debugger detection (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`)
- PEB debug flag verification via `NtQueryInformationProcess`
- Debugger window and process enumeration
- `sys.gettrace()` / `sys.getprofile()` checks
- Timing-based anomaly detection
- PyInstaller bundle integrity verification
- Import hook and Frida detection
- PE header validation

**If tampering or debugging is detected, the process exits silently with no warning.**

See `docs/SECURITY.md` for full details.

---

## First Launch Walkthrough

1. **Set Master Password**
   - Minimum 16 characters recommended
   - Must include uppercase, lowercase, digit, and special character
   - This password encrypts ALL keys at rest — **never lose it**

2. **Key Generation**
   - 4096-bit RSA key pair generated automatically
   - 256-bit global shared secret generated
   - Hybrid signing keys (Ed25519 + Dilithium3) generated if liboqs is available
   - All keys encrypted with master password via Argon2id

3. **TOTP Setup (Mandatory)**
   - Scan QR code with Google Authenticator, Authy, or Microsoft Authenticator
   - Or manually enter the Base32 secret
   - TOTP is required for unlock after emergency lock

4. **Set Your Display Name** (required for Double Ratchet)
   - In the Friends tab, click **"✏️ Set My Name"**
   - Enter the exact name your contacts use for you in their friend list
   - This name is embedded in ratchet envelopes so recipients can look up the correct session
   - If not set, a fallback identifier (`user-<8-char-hash>`) is derived from your public key

5. **Ready to Use**
   - Add friends via the Friends tab
   - Perform ECDH key exchange for per-friend secrets
   - Encrypt/decrypt messages and files

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'tkinter'` | Install `python3-tk` (Linux) or reinstall Python with Tcl/Tk (Windows) |
| `liboqs not available` | Install liboqs native library + `pip install liboqs-python`. App works without PQC. |
| `Permission denied` on database | Check write permissions on `~/.ultimate_enigma/` |
| Clipboard not clearing | Ensure no other app is monitoring clipboard; Tkinter limitation on some platforms |
| Hotkeys not working | Global hotkeys are Windows-only. Use the Emergency Lock button on macOS/Linux |
| NTP sync fails | Check firewall; app falls back to system time automatically |
| `cryptography` build errors | Install build tools: `build-essential` (Linux), Xcode CLT (macOS), or run `setup_dev_env.ps1` to install Visual C++ Build Tools & Windows 11 SDK (Windows) |
| `sqlcipher3` import fails | Install SQLCipher dev libraries: `libsqlcipher-dev` (Linux), `brew install sqlcipher` (macOS), or download `sqlcipher.dll` (Windows). See [SQLCipher docs](https://www.zetetic.net/sqlcipher/) |
| App crashes on startup | Check `enigma.log` in the project directory for detailed error messages |

### Log Files

- **Application log**: `enigma.log` (in project directory or alongside executable)
- **Database location**: `~/.ultimate_enigma/enigma.db`
- **Backup location**: `~/.ultimate_enigma/backups/`

### Getting Help

1. Check the log file for error details
2. Verify Python version: `python --version` (must be 3.8+)
3. Verify all dependencies: `pip list | grep -E "ttkbootstrap|cryptography|argon2|qrcode|liboqs"`
4. Try deleting `~/.ultimate_enigma/enigma.db` and restarting (fresh setup)

---

## Quick Reference Commands

```bash
# Install
pip install -r requirements.txt

# Run
python main.py

# Test
pytest tests/ -v

# Build
pyinstaller UltimateEnigma.spec

# Clean
rm -rf build/ dist/ *.spec.bak __pycache__ .pytest_cache
```
