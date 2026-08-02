# Contributing to Ultimate Enigma

Thank you for your interest in contributing to Ultimate Enigma Messenger! This document provides guidelines for development, testing, and code style.

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Git
- **Windows Users Only:** Visual Studio Build Tools with MSVC and Windows 11 SDK (required for native Python extensions like `cryptography` and `argon2-cffi`). Install them via winget (`winget install Microsoft.VisualStudio.2022.BuildTools`) or the manual steps in `docs/SETUP.md`.

### Environment Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ultimate-enigma.git
   cd ultimate-enigma
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

## Project Structure

The application follows an MVC architecture with approximately **9 tabs**, **22 service modules**, and **8 reusable components**.

```
main.py              Entry point, logging, anti-tamper, theme init
app.py               EnigmaApp composition root (9 tabs, event wiring, emergency lock)
crypto.py            AES-GCM + RSA-OAEP, time-based keys, constant-time decrypt
database.py          SQLCipher/SQLite layer, Argon2id KDF, PBKDF2→Argon2id migration
key_manager.py       KeyStore: RSA 4096, PQC keys, duress mode, password change

builders/
  app_builder.py     Application composition root builder

models/              Data structures (envelope, friend_profile)
views/               UI files (tabs, lock_screen, utils)
  ecdh.py            ECDH key exchange view
controllers/         Business logic coordination (3 controllers)
services/            22 service modules (plus encryption/ and friends/ subpackages)
  ecdh_service.py    ECDH key exchange service
  file_ops.py        File operation utilities
  encryption/        Subpackage: encryption strategies (facade, legacy, pqc, ratchet)
  friends/           Subpackage: friends management (crud, facade, keys)
components/          8 reusable dialogs
  recovery_unlock_dialog.py
  update_friend_keys_dialog.py
src/                 Constants, exceptions, helpers
  crypto_task_helper.py  Async crypto task helpers
security/            Memory security, anti-dump, guarded buffers, lockout
tests/               38 test files, 1035 tests
  encryption/        (empty) – future grouped tests
  friends/           (empty) – future grouped tests
```

## Code Style

### General Guidelines

- Use type hints for all function signatures
- Write docstrings for all public classes and methods
- Follow PEP 8 naming conventions
- Keep functions focused and single-purpose
- Use logging instead of print statements

### Security Considerations

- Never log sensitive data (keys, passwords, plaintext)
- Use `SecureString` for sensitive string handling
- Always wipe sensitive data when no longer needed
- Use constants from `src/constants.py` instead of magic numbers
- Apply timeout decorators to potentially blocking operations
- Anti-tamper protections (`src/anti_tamper.py`) only activate in frozen .exe; do not test debugger detection from source
- Use `GuardedBuffer` (`security/guarded_buffer.py`) for in-memory secrets (e.g. chain keys, global secret). GuardedBuffer supports `bytes()`, `len()`, iteration, and `==` comparison for seamless interop with bytes-based code. Always wrap values via `_update_chain_key()` or `GuardedBuffer.write()` — never store raw `bytes` for sensitive data.

### UI / UX Guidelines (Tkinter + ttkbootstrap)

Use the shared helpers in `views/utils.py` instead of ad-hoc implementations so behavior stays consistent (see `docs/VIEWS_AND_CONTROLLERS.md` → *Shared UI Helpers*).

- **Never show raw exceptions to users.** Wrap user-facing errors with `friendly_error(exc)` in `messagebox.showerror`, and log the raw detail with `logger.exception(...)`.
- **Don't block the UI thread.** Run blocking crypto/network/file work off-thread via `run_busy(...)` (or the existing `submit_crypto_task`). Show a busy cursor and disable the trigger button while in flight. **Tkinter is not thread-safe** — the `work()` callable must do no UI calls; perform all widget updates in `on_done`/`on_error`.
- **Modal dialogs:** call `init_modal(dlg, parent, focus_widget=...)` once after creating/sizing a `Toplevel` — it centers over the parent, makes it modal (`grab_set`), binds `<Escape>` and the window-close (X) button, and sets initial focus.
- **Feedback:** prefer inline feedback (`flash_widget_text` on a copy button) over modal "done" dialogs for frequent actions. Confirm destructive actions with `askyesno`, and act on the current selection rather than asking the user to retype identifiers.
- **Theme over hardcoded styling:** use ttkbootstrap `bootstyle` and `ttk.Style().colors`; avoid hardcoded hex colors and Windows-only fonts so light/dark themes and non-Windows platforms render correctly. Don't rely on color alone to convey state — pair it with a text label.
- **Read-only displays:** keep ciphertext/plaintext output widgets `state='disabled'` (toggle only while inserting) so users can't corrupt them.

### Example: Service Method

```python
def encrypt(self, plaintext: str, friend_name: str = None, mode: str = 'shared', sign: bool = True) -> bytes:
    """Encrypt a message for optional specific recipient.

    Args:
        plaintext: The message text to encrypt.
        friend_name: Optional friend name for recipient-specific encryption.

    Returns:
        Base64-encoded ciphertext string.

    Raises:
        KeyNotFoundError: If friend's key is not found.
        EncryptionError: If encryption fails.
    """
    # Implementation...
```

## Testing

### Running Tests

Run all tests:
```bash
pytest tests/ -v
```

Run specific test file:
```bash
pytest tests/test_encryption_service.py -v
```

Run with coverage:
```bash
pytest tests/ --cov=. --cov-report=html
```

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_<module>.py`
- Name test functions `test_<feature>_<scenario>`
- Use fixtures from `conftest.py` for common setup
- Test both success and failure cases

The test directory contains **38 test files** with **1035 tests**. It includes subdirectories for future grouped tests:
```
tests/
├── encryption/          # (empty) – future encryption service tests
├── friends/             # (empty) – future friends service tests
├── test_*.py            # Individual module tests (38 files, 1035 tests)
└── conftest.py          # Shared fixtures
```

### Example Test

```python
import pytest
from services.encryption import EncryptionService

class TestEncryptionService:
    def test_encrypt_decrypt_roundtrip(self, key_store):
        """Test that encrypted messages can be decrypted."""
        service = EncryptionService(key_store)
        plaintext = "Hello, World!"
        
        ciphertext, timestamp = service.encrypt(plaintext)
        result = service.decrypt(ciphertext)
        
        assert plaintext in result
    
    def test_decrypt_invalid_ciphertext_raises(self, key_store):
        """Test that invalid ciphertext raises DecryptionError."""
        service = EncryptionService(key_store)
        
        with pytest.raises(DecryptionError):
            service.decrypt_message("invalid_base64!!!")
```

## Adding New Features

### Adding a New Service

1. Create `services/new_service.py` (or use the sub-package pattern: `services/new_service/__init__.py` with separate modules)
2. Define the service class with `__init__(self, key_store: KeyStore)`
3. Add to `ServiceOrchestrator.__init__()` and `rebuild_services()`
4. Update tab references if needed
5. If the service needs periodic background work, create an agent class in `services/background_agents.py`
6. Write comprehensive tests

### Adding a New Tab

1. Create `new_tab.py` with a class inheriting from or containing a Frame
2. Accept required services in `__init__`
3. Add to `_setup_tabs()` in `app.py`
4. Subscribe to relevant events if needed
5. Update `ServiceOrchestrator._update_tab_references()` if service-dependent

### Adding a New Event

1. Add constant to `Events` class in `services/event_bus.py`
2. Publish event where appropriate: `event_bus.publish(Events.NEW_EVENT, ...)`
3. Subscribe in components that need to react
4. Document the event in this file and ARCHITECTURE.md

## Pull Request Process

1. Create a feature branch from `master`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes with clear, atomic commits

3. Ensure all tests pass:
   ```bash
   pytest tests/ -v
   ```

4. Update documentation if applicable:
   - `docs/ARCHITECTURE.md` for structural changes
   - `docs/API.md` for new public APIs
    - `docs/SECURITY.md` for security-relevant changes
    - `docs/SCIENTIFIC_REPORT.md` for cryptographic research and standards updates
    - `readme.md` for user-facing changes

5. Submit a pull request with:
   - Clear description of changes
   - Reference to any related issues
   - Summary of testing performed

## Security Reporting

**Do not open public issues for security vulnerabilities.**

Please report security issues privately to the maintainer. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## License

By contributing, you agree that your contributions will be licensed under the Polyform Noncommercial License 1.0.0.

## Questions?

Open an issue for questions about development, architecture, or features.
