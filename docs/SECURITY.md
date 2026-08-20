# Security Model

## Overview

Ultimate Enigma Messenger implements defense-in-depth security with multiple layers of protection for cryptographic keys, messages, and user data.

## Cryptographic Primitives

### Symmetric Encryption
- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes), randomly generated per operation
- **Authentication Tag**: 128 bits (16 bytes)
- **Use Cases**: Message encryption, file encryption, database secret storage

### Asymmetric Encryption
- **Algorithm**: RSA-OAEP with SHA-256
- **Key Size**: 4096 bits minimum (CNSA 2.0 compliant)
- **Use Cases**: Key wrapping, friend-specific message encryption

### Key Exchange
- **Classical**: X25519 ECDH
- **Post-Quantum**: CRYSTALS-Kyber (via liboqs-python)
- **Hybrid Mode**: Combines classical + PQC for transition safety

### Digital Signatures
- **Algorithm**: RSA-PSS with SHA-256
- **Purpose**: Message authenticity and non-repudiation

### Key Derivation
- **Primary**: Argon2id (memory-hard, GPU-resistant)
  - Time Cost: 3 iterations
  - Memory Cost: 64 MB
  - Parallelism: 4 threads
  - Output: 256 bits
- **Legacy**: PBKDF2-HMAC-SHA256 (300,000 iterations)

### Post-Quantum Cryptography
- **KEM**: CRYSTALS-Kyber for quantum-safe key encapsulation
- **Signatures**: PQC signature schemes for future-proofing
- **Integration**: Hybrid envelopes support both classical and PQC

## Key Management

### Master Password
- Never stored; used only to derive encryption keys
- Minimum length: 16 characters
- Used with Argon2id to derive database encryption key
- Loss is unrecoverable - no password reset mechanism

### Key Storage
- All secrets encrypted at rest in SQLite database
- Database location: `~/.ultimate_enigma/enigma.db`
- Encryption: AES-256-GCM with Argon2id-derived key
- Write-Ahead Logging enabled for crash safety

### Database Encryption at Rest (SQLCipher3)

When `sqlcipher3` is installed and a per-machine DB encryption key has been derived, the entire database file is transparently encrypted using **AES-256-CBC** via SQLCipher:

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-CBC |
| Page size | 4096 |
| KDF iterations | 256,000 |
| HMAC algorithm | HMAC_SHA512 |
| KDF algorithm | PBKDF2_HMAC_SHA512 |

On first run, a random 32-byte DB key is generated, encrypted with the user's master password via Argon2id + AES-GCM, and stored in the `settings` table under the key `sqlcipher_db_key`. On subsequent opens, the encrypted key is decrypted and used to unlock the database.

If `sqlcipher3` is not available, the database falls back to plain SQLite (unencrypted) with a warning log.

### Key Lifecycle
1. **Generation**: Keys generated locally on first run
2. **Storage**: Encrypted with master password-derived key
3. **Loading**: Decrypted into memory after authentication
4. **Usage**: Held in memory during active session
5. **Wiping**: Zeroed from memory on lock/close via `secure_string`

### Memory Security (Section 4.3 — Military-Grade)

The application implements defense-in-depth memory protection to prevent key material from leaking through swap, hibernation, or memory dumps.

#### Page Locking (`security/memory_security.py`)
- **Windows**: `VirtualLock` / `VirtualUnlock` pin sensitive pages in physical RAM, preventing paging to `pagefile.sys`
- **Linux**: `mlock` / `munlock` achieve the same effect; `RLIMIT_MEMLOCK` raised at startup via `raise_mlock_limit(64MB)`
- Applied to all `GuardedBuffer` instances and locked `SecureString` objects

#### Guard Pages (`security/guarded_buffer.py`)
- Sensitive buffers allocated between `PAGE_NOACCESS` guard pages (4 KB each)
- Any buffer overread/overflow triggers an immediate access violation (SIGSEGV/SEH)
- Layout: `[PAGE_NOACCESS][sensitive data][PAGE_NOACCESS]`
- `GuardedBuffer.write()` uses `ctypes.memmove()` for efficient bulk copy
- `GuardedBuffer.read()`, `wipe_and_free()` with context manager support
- Equality comparison uses `hmac.compare_digest` for constant-time semantics (prevents timing side-channels on secret comparison)
- On Linux: `madvise(MADV_DONTDUMP)` excludes guard-protected regions from core dumps

#### Anti-Dump Protection (`security/anti_dump.py`)
- **Windows**: Patches `MiniDumpWriteDump` entry point with `RET` instruction (0xC3) to block minidumps, correctly restoring original page protections after patching
- **Windows**: Removes `SeDebugPrivilege` from process token to limit cross-process memory access
- **Linux**: Disables core dumps via `setrlimit(RLIMIT_CORE, 0)` and `prctl(PR_SET_DUMPABLE, 0)`

#### SecureString Locking (`src/secure_string.py`)
- New `lock()` method calls `mlock_memory()` on the internal bytearray
- `wipe()` calls `munlock_memory()` before zeroing
- Long-lived secrets (master password, DB key) use `.lock()` after creation
- `database.set_master_password()` accepts `str` or `SecureString` directly (avoids creating plaintext copies)
- `append()` rejects `str` input with `TypeError` to prevent non-wipeable copies in Python's internal `PyUnicodeObject`; use `bytes` or `bytearray` instead

#### Key Storage Conversion
All previously immutable `bytes` secrets now stored in `GuardedBuffer`:
- `KeyStore.global_secret` → `GuardedBuffer`
- `KeyStore.friends[...].shared_secret` → `GuardedBuffer`
- `KeyStore.my_kyber_priv` → `GuardedBuffer`
- `KeyStore.my_dil_priv` → `GuardedBuffer`
- `RatchetState.root_key`, `send_chain_key`, `recv_chain_key` → `GuardedBuffer(32)`
- `XChaCha20Poly1305._key` → `GuardedBuffer`
- `database._MASTER_PASSWORD` → `SecureString` with `.lock()`
- `RatchetService._storage_key` → derived from master password via HKDF (not from `global_secret`)

#### Ratchet Storage Key (SEC-06)
- Ratchet states are encrypted at rest with AES-256-GCM before DB storage
- The storage key is a **random 32-byte** value, wrapped with the master password via Argon2id (`database.encrypt_secret`) and persisted under the `ratchet_storage_key` setting
- Because the key itself does not depend on the password, persisted ratchet blobs survive restarts **and** master-password changes (`change_password()` re-wraps the wrapper; `reset_with_recovery_key()` generates a fresh key and clears stale blobs)
- Security rests on master-password strength: an attacker with DB access alone cannot unwrap the key

#### Startup Initialization (`main.py`)
- `raise_mlock_limit(64MB)` called before any other imports
- `apply_anti_dump_protections()` patches minidump and removes debug privilege

#### Limitations
| Limitation | Reason |
|-----------|--------|
| Cold boot attack | DRAM retains data after power loss; triple wipe reduces window |
| Kernel debugger | WinDbg/JTAG can read any memory; anti-tamper detects some |
| Python GC copies | CPython GC may leave stale copies; GuardedBuffer is outside GC heap |
| Hypervisor | VM introspection reads guest RAM; requires TPM/sealed enclave |

## Authentication

### Startup Flow
1. Check if database exists (first run detection)
2. Prompt for master password
3. Derive decryption key via Argon2id
4. Attempt to decrypt and load keys
5. Verify TOTP if configured
6. Initialize services

### TOTP (Time-based One-Time Password)
- Required for unlock after emergency lock
- Algorithm: HMAC-SHA1, 6-digit code, 30-second interval
- Drift tolerance: ±1 step
- Replay protection: each TOTP value accepted at most once per interval; highest accepted counter is persisted to the database so replay protection survives application restarts
- Self-test verification uses `track_replay=False` to avoid consuming codes during startup
- RFC 6238 compliant implementation
- QR code generation for authenticator app setup
- Maximum TOTP attempts: 5

### Lock Screen
- Lock screen timeout: 300 seconds (5 minutes)

### Lockout Protection
- Exponential backoff on failed attempts via `LockoutManager` (`security/lockout.py`)
- Backoff table: [0, 0, 0, 0, 0, 5, 10, 30, 60, 120, 300, 600, 1800, 3600] seconds (14 entries)
- Hard lockout after 15 failures (3600 second / 1 hour duration)
- Maximum TOTP attempts: 5
- Session timeout: 900 seconds (15 minutes)
- Persistent attempt tracking across restarts via database

## Message Security

### Hybrid Encryption Scheme
```
Message → AES-GCM encrypt → Ciphertext
                ↑
         Session Key ← RSA-OAEP unwrap OR ECDH derived
```

### Time-Based Keys
- Keys derived from shared secret + timestamp
- Sliding window: ±2 steps of 30 seconds (±60 second validity)
- Provides replay protection within window
- NTP sync ensures clock accuracy
- **Key hint**: Shared-secret packets embed a 2-byte SHA-256 fingerprint of the key (flag bit 4). On decryption, non-matching candidates are skipped before attempting AES-GCM, reducing brute-force from O(N) to O(1) per candidate (constant-time hash comparison)

### Self-Destruct Messages
- Expiration timestamp embedded in envelope
- Client-side enforcement only
- **Warning**: Does not guarantee deletion on recipient's machine
- Available durations: 5 min, 10 min, 1 hour, custom

### Double Ratchet Protocol
- Per-conversation state machine
- Forward secrecy: past messages secure if current key compromised
- Break-in recovery: future messages secure after compromise healed
- Thread-safe per-friend locking prevents race conditions
- Sender identity: each ratchet envelope embeds the sender's display name (`KeyStore.my_name`) so recipients can look up the correct session; must match the name the recipient has saved as their friend entry

## File Encryption

### Password-Based
- KDF: Argon2id with military-grade parameters
- Encryption: AES-256-GCM
- Header magic bytes identify file type
- Supports arbitrary file sizes via chunked processing

### Friend-Specific
- Uses friend's public key or shared secret
- Same security properties as message encryption

## Trust Chain

### Certificate Verification on Import
- `import_received_certs()` cryptographically verifies each certificate's hybrid signature (Ed25519 + Dilithium3) before importing
- The issuer's embedded public key must match the locally pinned key for that issuer (defeats forged-issuer attacks)
- Certificates with invalid signatures or unknown issuers are rejected and counted separately in the UI
- `get_trust_level()` only counts certificates that have been verified against pinned issuer keys

## Network Security

### NTP Synchronization
- UDP queries to public NTP servers (up to 5 servers, 2s timeout each)
- Clock offset calculation for time-based keys
- NTP queries run entirely outside the service lock — the lock is only held for the brief timestamp assignment (atomic under CPython GIL), eliminating lock contention with encrypt/decrypt operations
- Multiple server options for redundancy
- Timeout handling prevents blocking

### No Network Communication
- Application is fully local/offline capable
- No telemetry or phone-home functionality
- Users control all data transmission

## Anomaly Detection

### Overview
The `AnomalyDetectionService` provides zero-knowledge anomaly scoring on incoming message metadata. It uses a pre-trained **Isolation Forest** model (scikit-learn) to detect statistically anomalous messages without ever accessing plaintext content.

### Design Principles
- **Zero-knowledge**: Only raw packet metadata is used (sizes, envelope type, timestamps). No decrypted content is accessed.
- **Offline**: The model runs entirely locally. No network calls, no telemetry.
- **Fail-open**: If the model fails to load or scoring raises an exception, the message is still delivered (no denial of service).
- **Non-blocking**: Scoring runs after decryption completes and does not delay message delivery.

### Feature Vector (7 elements)

| Index | Feature | Source |
|-------|---------|--------|
| 0 | `packet_size` | Total packet bytes |
| 1 | `name_length` | Sender name string length |
| 2 | `env_type_code` | 0=ratchet, 1=pqc, 2=legacy, -1=unknown |
| 3 | `header_len` | Parsed header/KEM ciphertext length |
| 4 | `ct_len` | Parsed ciphertext length |
| 5 | `hour_of_day` | Local hour (0–23) |
| 6 | `day_of_week` | Local weekday (0=Monday, 6=Sunday) |

### Integration
1. `ServiceOrchestrator` creates `AnomalyDetectionService` and injects it into `EncryptionService`
2. After each successful decryption, `EncryptionService` calls `score_message(sender_name, raw_packet)`
3. If the Isolation Forest score falls below the model threshold, a `MessageScore` with `is_anomaly=True` is returned
4. `AnomalyDetectionService` publishes an `ANOMALY_DETECTED` event to the `EventBus`
5. `EnigmaApp` receives the event and displays:
   - A toast notification (auto-dismiss after 8 seconds)
   - A persistent red banner (auto-dismiss after 10 seconds)
   - A status bar flash (auto-dismiss after 10 seconds)

### Model
- **File**: `anomaly_model.pkl` (pre-trained Isolation Forest, shipped with the application)
- **Training**: Offline on synthetic metadata mimicking normal chat patterns
- **Threshold**: Stored as `model.threshold_` attribute (default: -0.5)
- **Thread-safe**: Model is read-only after load; concurrent scoring is safe

## Threat Model

### Protected Against
| Threat | Mitigation |
|--------|------------|
| Disk theft | All secrets encrypted at rest |
| Memory dumping | GuardedBuffer + VirtualLock + MiniDump patch |
| Clipboard snooping | Auto-clear after 30 seconds |
| Brute force | Argon2id + lockout protection |
| Replay attacks | Time-based key window |
| MITM (key exchange) | Fingerprint verification required |
| Quantum computers | PQC hybrid encryption support |
| Debugging / reverse engineering | Anti-debugger + anti-tamper protections |
| Binary tampering | PE header + bytecode integrity checks |
| Code injection / hooking | Import hook + Frida detection |
| Swap file leakage | VirtualLock/mlock pins pages in RAM |
| Core dumps | MADV_DONTDUMP + RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 |
| Anomalous message patterns | Isolation Forest metadata scoring |
### Known Limitations
| Limitation | Notes |
|------------|-------|
| Self-destruct | Client-side only, not guaranteed |
| Time window | 60-second replay window exists |
| Physical access | Attacker with runtime access can extract keys |
| Side channels | No specific side-channel mitigations |
| Metadata | Message timing/patterns may leak information |
| Source mode | Anti-tamper protections only active in frozen .exe |

## Secure Development Practices

### Code Organization
- Constants centralized in `src/constants.py` as frozen dataclasses with backward-compatible dict aliases
- Custom exceptions in `src/exceptions.py`
- Secure string handling in `src/secure_string.py`
- Timeout decorators prevent hanging operations

### Testing
- Comprehensive test suite in `tests/`
- Coverage of crypto primitives, edge cases, error handling
- Concurrent operation testing
- Timeout scenario testing

### Dependencies
- `cryptography`: Well-audited crypto library
- `liboqs-python`: NIST-standardized PQC algorithms
- `argon2-cffi`: Reference Argon2 implementation
- Minimal dependency footprint

## Compliance Notes

- **CNSA 2.0**: RSA-4096+ meets Commercial National Security Algorithm requirements
- **NIST PQC**: CRYSTALS-Kyber is NIST-standardized post-quantum KEM
- **RFC 6238**: TOTP implementation follows standard
- **Signal Protocol**: Double Ratchet provides proven security properties

## Recommendations for Users

1. Use a strong, unique master password (16+ characters recommended)
2. Enable TOTP for additional unlock protection
3. Verify ECDH fingerprints through a secure out-of-band channel
4. Keep the application updated for security patches
5. Store backups securely (they contain encrypted secrets)
6. Be aware that self-destruct is a convenience feature, not a guarantee
7. Use NTP sync to ensure accurate time-based key derivation

## Anti-Tamper & Anti-Debugger Protections

### Overview

Ultimate Enigma includes aggressive anti-tamper and anti-debugger protections for the compiled Windows executable. These protections are **only active when running as a frozen PyInstaller .exe** (`sys.frozen == True`). When running from source (`python main.py`), all checks are no-ops to allow normal development.

Source: `src/anti_tamper.py`

### Detection Methods

#### Anti-Debugger (9 methods)
| Method | Technique | Details |
|--------|-----------|---------|
| `IsDebuggerPresent()` | Windows API | Detects local user-mode debugger |
| `CheckRemoteDebuggerPresent()` | Windows API | Detects kernel/debugger connections |
| `NtQueryInformationProcess` | NT Kernel API | Checks `DebugPort`, `DebugFlags`, `DebugObjectHandle` via PEB |
| `sys.gettrace()` | Python runtime | Detects active trace hooks (pydevd, pdb, etc.) |
| `sys.getprofile()` | Python runtime | Detects active profiling hooks |
| Window enumeration | Win32 API | Scans for debugger window classes (exact match for short names ≤3 chars to avoid false positives); detects OllyDbg, x64dbg, IDA, WinDbg, Ghidra, etc. |
| Process enumeration | `tasklist` | Checks running processes against 22 known debugger names |
| Timing analysis | `time.perf_counter_ns()` | Detects debugger stepping via RDTSC timing anomalies (threshold: 500_000ns, 5 samples) |
| Hardware breakpoint detection | Windows API | Reads Dr0-Dr3 debug registers via `GetThreadContext` |

#### Anti-Tamper (6 methods)
| Method | Technique | Details |
|--------|-----------|---------|
| `_MEIPASS` verification | PyInstaller | Verifies bundle temp directory exists, is valid, and critical file SHA-256 hashes match expected values (when populated by build script) |
| Import hook detection | `sys.meta_path` | Detects injected import finders (e.g., Frida loaders) |
| Frida detection | File + env + modules | Checks for Frida files on disk, environment variables, and loaded modules |
| Module integrity checks | `.pyc` + 7 critical modules | Validates Python magic numbers for 7 critical modules match running interpreter |
| PE header validation | Binary analysis | Verifies DOS/PE signatures, section count, entry point sanity |
| Hooking framework detection | Loaded module scan | Checks for 7 known hooking frameworks (Frida, Detours, MinHook, etc.) |

#### Countermeasures
| Countermeasure | Technique | Details |
|----------------|-----------|---------|
| `ThreadHideFromDebugger` | NT Kernel API | Hides all threads from debugger via `NtSetInformationThread(0x11)` |
| Silent exit | `os._exit(1)` | Immediate termination with memory cleanup (no warning message) |
| Memory wipe | GC + module cleanup | Clears sensitive module references before termination |

### Configuration

All configuration is centralized in `src/constants.py` under `ANTI_TAMPER_CONSTANTS`:

```python
ANTI_TAMPER_CONSTANTS = {
    "BACKGROUND_CHECK_INTERVAL": 30,         # seconds between background checks
    "TIMING_CHECK_THRESHOLD_NS": 500_000,     # 0.5ms timing anomaly threshold
    "TIMING_SAMPLES": 5,                      # timing samples per check
    "CRITICAL_MODULES": 7,                    # number of critical modules integrity-checked
    "DEBUGGER_PROCESSES": 22,                 # known debugger process names monitored
    "HOOKING_FRAMEWORKS": 7,                  # known hooking frameworks detected
    "SILENT_EXIT": True,                      # exit without warning
    "EXIT_CODE": 1,                           # process exit code
    "HIDE_THREADS": True,                     # hide threads from debugger
}
```

### Behavior

1. **Startup**: `run_anti_tamper_checks()` runs immediately after PyInstaller path setup, before any other imports
2. **Background**: A daemon thread runs active seeking checks with randomized intervals (5-15 seconds normal, 1-3 seconds escalated)
3. **Cross-validation**: Detections are double-checked before confirming to prevent false positives
4. **Escalation**: When suspicious activity is detected (3+ consecutive findings), scan frequency increases and deep scans (memory region analysis) are performed
5. **On-demand**: `check_on_demand()` can be called before critical operations
6. **Detection**: Any confirmed check triggers immediate silent exit
7. **Fail-closed**: Exceptions in individual checks are treated as tamper (fail closed, not open) — prevents attackers from bypassing checks by triggering errors

### Testing

58 unit tests in `tests/test_anti_tamper.py` cover:
- All detection methods in isolation
- Skipped behavior when not frozen
- Fail-closed exception handling in the check pipeline
- Background thread startup
- Mocked Windows API calls for cross-platform testing
- Test classes: TestDebuggerWindows, TestDebuggerPresent, TestRemoteDebugger, TestPEBDebuggerFlag, TestSilentExit

### Build Integration

- `UltimateEnigma.spec`: `src.anti_tamper` added to `hiddenimports`
- `build_app.bat`: `--hidden-import=src.anti_tamper` flag added
- No new dependencies (stdlib only: `ctypes`, `os`, `sys`, `subprocess`, `hashlib`)
