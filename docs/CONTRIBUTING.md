# Contributing to Ultimate Enigma

Thank you for your interest in contributing to Ultimate Enigma Messenger! This document provides guidelines for development, testing, and code style.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git
- **Windows Users Only:** Visual Studio Build Tools with MSVC and Windows 11 SDK (required for native Python extensions like `cryptography` and `argon2-cffi`). Run the provided `setup_dev_env.ps1` script as Administrator to install these automatically.

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

Follow the MVC architecture:

- **Models** (`models/`): Data structures and storage abstractions
- **Views** (`*_tab.py`): Tkinter UI components
- **Controllers** (`controllers/`): Business logic coordination
- **Services** (`services/`): Reusable business logic
- **Utilities** (`src/`): Constants, exceptions, helpers

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

### Example: Service Method

```python
def encrypt_message(self, plaintext: str, friend_name: str = None) -> str:
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

The test directory structure includes subdirectories for feature areas:
```
tests/
├── encryption/          # Encryption service tests
├── friends/             # Friends service tests
├── test_*.py            # Individual module tests
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
        
        ciphertext = service.encrypt_message(plaintext)
        result = service.decrypt_message(ciphertext)
        
        assert result["plaintext"] == plaintext
        assert result["verified"] is True
    
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
5. Write comprehensive tests

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
