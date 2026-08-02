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
app.py           → EnigmaApp composition root (9 tabs, event wiring, emergency lock)
crypto.py        → AES-GCM + RSA-OAEP, time-based keys, constant-time decrypt
database.py      → SQLCipher/SQLite layer, Argon2id KDF, PBKDF2→Argon2id migration
key_manager.py   → KeyStore: RSA 4096, PQC keys, duress mode, password change (thin orchestrator)

controllers/     → application_controller, auth_controller, service_orchestrator
models/          → envelope.py (RatchetEnvelope, PQCEnvelope), friend_profile.py
services/        → 22 services (top-level) + encryption/, friends/, and code_analysis/ subpackages: encryption, double_ratchet, pqc, totp, event_bus, etc.
views/           → 13 UI files: tabs, lock_screen, help_tab, utils
components/      → Reusable dialogs: add_friend, hybrid_sig_exchange, pqc_exchange, totp
src/             → constants.py, exceptions.py, secure_string.py, anti_tamper.py, timeout.py, crypto_utils.py, key_generation.py
security/        → memory_security, anti_dump, guarded_buffer, lockout
tests/           → 38 test files, 1035 tests, conftest.py with isolated DB fixture
tools/devtools/  → Optional external code-analysis toolchain config + setup_devtools.ps1 (see below)
```

## Key Gotchas

- **Database path**: `~/.ultimate_enigma/enigma.db`. Tests monkeypatch this to a tmp_path via `conftest.py:isolated_db` fixture (autouse). If you add DB operations, they'll get an isolated DB automatically in tests.
- **Anti-tamper**: Only activates when `sys.frozen == True` (PyInstaller exe). Never triggers from source. Don't test debugger detection from `python main.py`. Pipeline is **fail-closed**: exceptions in checks are treated as tamper.
- **SQLCipher fallback**: App falls back to plain SQLite if `sqlcipher3` is unavailable. All DB access goes through `database.get_connection()`.
- **SecureString**: Sensitive strings must use `SecureString` (bytearray with 3-pass wipe). Never store passwords/plaintext in regular strings if they'll persist in memory.
- **EventBus**: Thread-safe singleton. Views publish events; app.py subscribes for cross-component coordination. 38 event types in `services/event_bus.py`.
- **Per-friend RLock**: Double ratchet uses per-friend locks with ordered acquisition to prevent deadlocks. See `services/ratchet_service.py`.
- **Constants**: All magic numbers live in `src/constants.py`. Never hardcode crypto params, timeouts, or UI defaults.
- **Post-quantum**: Depends on `liboqs` (CRYSTALS-Kyber + Dilithium3). Build requires `oqs.dll` bundled via PyInstaller.
- **Build**: `build_app.bat` and `UltimateEnigma.spec` hardcode `OQS_PATH` and `OQS_DLL` paths. Update these if your Python/liboqs install paths differ.
- **NTP sync**: Deferred until after GUI renders. Uses multi-server consensus with outlier rejection (min 3 servers agree).
- **Emergency lock**: Wipes keys immediately. Requires master password + TOTP to unlock. Services rebuilt on unlock.
- **GuardedBuffer**: `security/guarded_buffer.py` — wraps secrets in PAGE_NOACCESS-guarded virtual memory. Supports `bytes()`, `len()`, iteration, and `==`. Always store chain keys and global_secret as `GuardedBuffer`, never raw `bytes`. Use `_update_chain_key()` in double_ratchet.py for automatic wrapping.
- **KeyStore.verify_password()**: Returns `(is_valid, is_duress)` tuple. Duress password triggers decoy mode. Lockout state delegated to `LockoutManager` in `security/lockout.py`.
- **Code analysis tools are optional**: `services/code_analysis/` wraps external dev tools (ripgrep, universal-ctags, tree-sitter, semgrep, CodeQL, clangd, rust-analyzer) with timeouts. Always degrade gracefully — never assume a tool is installed; use `CodeAnalysisService.all_tool_statuses()` or catch `CodeAnalysisToolNotFoundError`.
- **Windows .cmd shims**: npm-installed CLIs (e.g. `tree-sitter`) are `.cmd` shims that `subprocess` can't execute directly. `CodeAnalysisService._run()` routes `.cmd`/`.bat` through `cmd.exe /c` — keep that behavior if you add tool calls.

## Testing Notes

- `conftest.py` adds project root to `sys.path` and creates isolated DB per test.
- There is no `run_tests.py` or batch test runners in the repo — run tests directly with `pytest`.
- Test subdirectories: `tests/encryption/`, `tests/friends/` exist as empty placeholders — no test files created yet.
- `tests/test_anti_tamper.py` mocks ctypes calls for cross-platform testing.
- `tests/test_code_analysis_service.py` mocks all subprocess calls — it never requires the external tools to be installed.

## Code Analysis Toolchain (optional, dev-only)

`services/code_analysis/` exposes `CodeAnalysisService`, which wraps seven
optional external dev tools behind a timeout-protected, gracefully-degrading
Python API. These are developer utilities, NOT part of the runtime security
path — the app never assumes they exist.

| Tool | Executable | Purpose |
|---|---|---|
| ripgrep | `rg` | regex search (`svc.search(...)`) |
| universal-ctags | `ctags` | tag index (`svc.generate_tags(...)`) |
| tree-sitter | `tree-sitter` | parse files (`svc.parse_file(...)`) |
| semgrep | `semgrep` | SAST (`svc.semgrep_scan(...)`) |
| CodeQL | `codeql` | semantic analysis (`svc.codeql_version()`, `svc.codeql_resolve_languages()`) |
| clangd | `clangd` | C/C++ LSP (`svc.tool_status("clangd")`) |
| rust-analyzer | `rust-analyzer` | Rust LSP (`svc.tool_status("rust_analyzer")`) |

- Install/repair all tools idempotently: `powershell -ExecutionPolicy Bypass -File tools\devtools\setup_devtools.ps1`
- Repo configs live in `tools/devtools/` (`ctags.cnf`, `semgrep.rules.yaml`) plus root `.clangd` and `.rgignore`.
- Probe everything with `svc.all_tool_statuses()` before invoking a specific tool; a missing tool raises `CodeAnalysisToolNotFoundError` from `src/exceptions.py`.
- Add new tool wrappers to `services/code_analysis/code_analysis_service.py` and keep `TOOL_SPECS` in `services/code_analysis/tools.py` in sync.

## Code Style

- Type hints on all function signatures (per `docs/CONTRIBUTING.md`).
- Use `logging` not `print`.
- Never log sensitive data (keys, passwords, plaintext).
- Use constants from `src/constants.py`, not magic numbers.
- Apply timeout decorators to potentially blocking operations.
