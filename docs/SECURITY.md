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
- Minimum length: 12 characters
- Used with Argon2id to derive database encryption key
- Loss is unrecoverable - no password reset mechanism

### Key Storage
- All secrets encrypted at rest in SQLite database
- Database location: `~/.ultimate_enigma/enigma.db`
- Encryption: AES-256-GCM with Argon2id-derived key
- Write-Ahead Logging enabled for crash safety

### Key Lifecycle
1. **Generation**: Keys generated locally on first run
2. **Storage**: Encrypted with master password-derived key
3. **Loading**: Decrypted into memory after authentication
4. **Usage**: Held in memory during active session
5. **Wiping**: Zeroed from memory on lock/close via `secure_string`

### Memory Safety
- `SecureString` class for sensitive data
- Explicit zeroing before garbage collection
- Keys wiped on:
  - Emergency lock
  - Application close
  - Failed authentication
  - Service rebuild
- Thread-safe key snapshots via `KeyStore.get_decryption_snapshot()` prevent race conditions during background decryption

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
- RFC 6238 compliant implementation
- QR code generation for authenticator app setup
- Rate limiting on verification attempts

### Lockout Protection
- Exponential backoff on failed attempts
- Backoff table: [0, 0, 0, 0, 0, 5, 10, 30, 60, 120, 300, 600, 1800, 3600] seconds
- Hard lockout after 15 failures (1 hour duration)
- Per-session attempt tracking

## Message Security

### Hybrid Encryption Scheme
```
Message → AES-GCM encrypt → Ciphertext
                ↑
         Session Key ← RSA-OAEP unwrap OR ECDH derived
```

### Time-Based Keys
- Keys derived from shared secret + timestamp
- Sliding window: ±3 steps of 30 seconds (±90 second validity)
- Provides replay protection within window
- NTP sync ensures clock accuracy

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

## Network Security

### NTP Synchronization
- UDP queries to public NTP servers
- Clock offset calculation for time-based keys
- Multiple server options for redundancy
- Timeout handling prevents blocking

### No Network Communication
- Application is fully local/offline capable
- No telemetry or phone-home functionality
- Users control all data transmission

## Threat Model

### Protected Against
| Threat | Mitigation |
|--------|------------|
| Disk theft | All secrets encrypted at rest |
| Memory dumping | Keys zeroed on lock/close |
| Clipboard snooping | Auto-clear after 30 seconds |
| Brute force | Argon2id + lockout protection |
| Replay attacks | Time-based key window |
| MITM (key exchange) | Fingerprint verification required |
| Quantum computers | PQC hybrid encryption support |
| Debugging / reverse engineering | Anti-debugger + anti-tamper protections |
| Binary tampering | PE header + bytecode integrity checks |
| Code injection / hooking | Import hook + Frida detection |

### Known Limitations
| Limitation | Notes |
|------------|-------|
| Self-destruct | Client-side only, not guaranteed |
| Time window | 90-second replay window exists |
| Physical access | Attacker with runtime access can extract keys |
| Side channels | No specific side-channel mitigations |
| Metadata | Message timing/patterns may leak information |
| Source mode | Anti-tamper protections only active in frozen .exe |

## Secure Development Practices

### Code Organization
- Constants centralized in `src/constants.py`
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
| Process enumeration | `tasklist` | Checks running processes against 30+ known debugger names |
| Timing analysis | `time.perf_counter_ns()` | Detects debugger stepping via RDTSC timing anomalies (threshold: 0.5ms) |
| Hardware breakpoint detection | Windows API | Reads Dr0-Dr3 debug registers via `GetThreadContext` |

#### Anti-Tamper (5 methods)
| Method | Technique | Details |
|--------|-----------|---------|
| `_MEIPASS` verification | PyInstaller | Verifies bundle temp directory exists and is a valid directory |
| Import hook detection | `sys.meta_path` | Detects injected import finders (e.g., Frida loaders) |
| Frida detection | File + env + modules | Checks for Frida files on disk, environment variables, and loaded modules |
| Module bytecode integrity | `.pyc` verification | Validates Python magic numbers match running interpreter |
| PE header validation | Binary analysis | Verifies DOS/PE signatures, section count, entry point sanity |

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
    "BACKGROUND_CHECK_INTERVAL": 30,     # seconds between background checks
    "TIMING_CHECK_THRESHOLD_NS": 500_000, # 0.5ms timing anomaly threshold
    "TIMING_SAMPLES": 5,                  # timing samples per check
    "SILENT_EXIT": True,                  # exit without warning
    "EXIT_CODE": 1,                       # process exit code
    "HIDE_THREADS": True,                 # hide threads from debugger
    "SEEK_MIN_INTERVAL": 5,              # min seconds between seeking scans
    "SEEK_MAX_INTERVAL": 15,             # max seconds between seeking scans
    "SEEK_SUSPICION_THRESHOLD": 3,        # consecutive suspicious findings before escalation
    "SEEK_ESCALATED_MIN_INTERVAL": 1,    # min seconds between escalated scans
    "SEEK_ESCALATED_MAX_INTERVAL": 3,    # max seconds between escalated scans
}
```

### Behavior

1. **Startup**: `run_anti_tamper_checks()` runs immediately after PyInstaller path setup, before any other imports
2. **Background**: A daemon thread runs active seeking checks with randomized intervals (5-15 seconds normal, 1-3 seconds escalated)
3. **Cross-validation**: Detections are double-checked before confirming to prevent false positives
4. **Escalation**: When suspicious activity is detected (3+ consecutive findings), scan frequency increases and deep scans (memory region analysis) are performed
5. **On-demand**: `check_on_demand()` can be called before critical operations
6. **Detection**: Any confirmed check triggers immediate silent exit
7. **Errors**: Individual check failures are caught and skipped (resilient pipeline)

### Testing

58 unit tests in `tests/test_anti_tamper.py` cover:
- All detection methods in isolation
- Skipped behavior when not frozen
- Exception resilience in the check pipeline
- Background thread startup
- Mocked Windows API calls for cross-platform testing
- Test classes: TestDebuggerWindows, TestDebuggerPresent, TestRemoteDebugger, TestPEBDebuggerFlag, TestSilentExit

### Build Integration

- `UltimateEnigma.spec`: `src.anti_tamper` added to `hiddenimports`
- `build_app.bat`: `--hidden-import=src.anti_tamper` flag added
- No new dependencies (stdlib only: `ctypes`, `os`, `sys`, `subprocess`, `hashlib`)
