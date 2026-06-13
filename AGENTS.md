# AGENTS.md — Ultimate Enigma Messenger

## What This Is

Python desktop cryptographic messenger (Tkinter/ttkbootstrap). Windows-first. MVC with 7 layers: models, views, controllers, services, src, components, security.

## Commands

```bash
# Run app
python main.py

# Run all tests
pytest tests/ -v

# Run single test file
pytest tests/test_encryption_service.py -v

# Run single test
pytest tests/test_crypto.py::TestClass::test_method -v

# Build Windows .exe (requires Visual Studio Build Tools + liboqs)
build_app.bat
```

No lint/typecheck commands are configured. No pyproject.toml, tox.ini, or Makefile exists.

## Architecture

```
main.py          → Entry point, logging, anti-tamper, theme init
app.py           → EnigmaApp composition root (7 tabs, event wiring, emergency lock)
crypto.py        → AES-GCM + RSA-OAEP, time-based keys, constant-time decrypt
database.py      → SQLCipher/SQLite layer, Argon2id KDF, PBKDF2→Argon2id migration
key_manager.py   → KeyStore: RSA 4096, PQC keys, lockout, duress mode, password change

controllers/     → application_controller, auth_controller, service_orchestrator
models/          → envelope.py (RatchetEnvelope, PQCEncvelope), friend_profile.py
services/        → 19 services: encryption, double_ratchet, pqc, totp, event_bus, etc.
views/           → 12 UI files: tabs, lock_screen, visual_enigma, utils
components/      → Reusable dialogs: add_friend, hybrid_sig_exchange, pqc_exchange, totp
src/             → constants.py, exceptions.py, secure_string.py, anti_tamper.py, timeout.py
security/        → memory_security, anti_dump, guarded_buffer
tests/           → 36 test files, 550+ tests, conftest.py with isolated DB fixture
```

## Key Gotchas

- **Database path**: `~/.ultimate_enigma/enigma.db`. Tests monkeypatch this to a tmp_path via `conftest.py:isolated_db` fixture (autouse). If you add DB operations, they'll get an isolated DB automatically in tests.
- **Anti-tamper**: Only activates when `sys.frozen == True` (PyInstaller exe). Never triggers from source. Don't test debugger detection from `python main.py`.
- **SQLCipher fallback**: App falls back to plain SQLite if `sqlcipher3` is unavailable. All DB access goes through `database.get_connection()`.
- **SecureString**: Sensitive strings must use `SecureString` (bytearray with 3-pass wipe). Never store passwords/plaintext in regular strings if they'll persist in memory.
- **EventBus**: Thread-safe singleton. Views publish events; app.py subscribes for cross-component coordination. 22 event types in `services/event_bus.py`.
- **Per-friend RLock**: Double ratchet uses per-friend locks with ordered acquisition to prevent deadlocks. See `services/ratchet_service.py`.
- **Constants**: All magic numbers live in `src/constants.py`. Never hardcode crypto params, timeouts, or UI defaults.
- **Post-quantum**: Depends on `liboqs` (CRYSTALS-Kyber + Dilithium3). Build requires `oqs.dll` bundled via PyInstaller.
- **Build**: `build_app.bat` and `UltimateEnigma.spec` hardcode `OQS_PATH` and `OQS_DLL` paths. Update these if your Python/liboqs install paths differ.
- **NTP sync**: Deferred until after GUI renders. Uses multi-server consensus with outlier rejection (min 3 servers agree).
- **KeyStore.verify_password()**: Returns `(is_valid, is_duress)` tuple. Duress password triggers decoy mode.
- **Emergency lock**: Wipes keys immediately. Requires master password + TOTP to unlock. Services rebuilt on unlock.
- **GuardedBuffer**: `security/guarded_buffer.py` — wraps secrets in PAGE_NOACCESS-guarded virtual memory. Supports `bytes()`, `len()`, iteration, and `==`. Always store chain keys and global_secret as `GuardedBuffer`, never raw `bytes`. Use `_update_chain_key()` in double_ratchet.py for automatic wrapping.

## Testing Notes

- `conftest.py` adds project root to `sys.path` and creates isolated DB per test.
- `run_tests.py` is a hardcoded script that runs a specific subset of tests — use `pytest` directly instead.
- Test subdirectories: `tests/encryption/`, `tests/friends/` for grouped tests.
- `tests/test_anti_tamper.py` mocks ctypes calls for cross-platform testing.

## Code Style

- Type hints on all function signatures (per `docs/CONTRIBUTING.md`).
- Use `logging` not `print`.
- Never log sensitive data (keys, passwords, plaintext).
- Use constants from `src/constants.py`, not magic numbers.
- Apply timeout decorators to potentially blocking operations.
