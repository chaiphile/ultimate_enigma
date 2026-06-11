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

### Known Limitations
| Limitation | Notes |
|------------|-------|
| Self-destruct | Client-side only, not guaranteed |
| Time window | 90-second replay window exists |
| Physical access | Attacker with runtime access can extract keys |
| Side channels | No specific side-channel mitigations |
| Metadata | Message timing/patterns may leak information |

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
