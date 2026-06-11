# Hybrid Signature Implementation Summary

## Overview

This document describes the complete implementation of **Hybrid Digital Signatures** (Ed25519 + CRYSTALS-Dilithium3/ML-DSA-65) in Ultimate Enigma Messenger.

Hybrid signatures combine classical Ed25519 signatures with post-quantum Dilithium3 signatures. Both must verify successfully for a signature to be considered valid, providing security against both classical and quantum computer attacks.

## Architecture

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| `HybridSigner` | `services/pqc_signatures.py` | Core hybrid signature operations (key gen, sign, verify) |
| `hybrid_sign()` / `hybrid_verify()` | `crypto.py` | Wrapper functions for message signing |
| `HYBRID_SIG_FLAG` | `crypto.py` | Bit flag (value 8) for hybrid signatures in message packets |
| `FriendsService` | `services/friends_service.py` | Key generation, import, and management |
| `FriendsTab` | `friends_tab.py` | UI dialog for hybrid signature key exchange |
| `FileService` | `services/file_service.py` | Hybrid signature support for file operations |
| `KeyStore` | `key_manager.py` | Persistent storage and loading of hybrid signing keys |

### Signature Format

**Combined Signature:** `[ed_sig_len(2 bytes BE) | ed_sig(64 bytes) | dil_sig(variable)]`

**Combined Public Key:** `[ed_pub_len(2 bytes BE) | ed_pub(32 bytes) | dil_pub_len(2 bytes BE) | dil_pub(variable)]`

## Implementation Details

### 1. Key Generation (`HybridSigner.generate_keys()`)

Generates both Ed25519 and Dilithium3/ML-DSA-65 key pairs:
- Ed25519: 32-byte public key, fast classical signatures
- Dilithium3: ~1952-byte public key, quantum-resistant signatures
- Returns combined public key for exchange/storage

### 2. Signing (`HybridSigner.sign()`)

Signs a message with both algorithms:
1. Ed25519 signs the message (always 64 bytes)
2. Dilithium3 signs the same message (variable length)
3. Combines into `[ed_len(2) | ed_sig | dil_sig]`

### 3. Verification (`HybridSigner.verify()`)

Verifies both signatures:
1. Parse combined signature format
2. Verify Ed25519 signature
3. Verify Dilithium3 signature
4. Return `True` only if **BOTH** succeed

### 4. Message Encryption Integration

In `crypto.py`, the `encrypt_message()` function:
- Accepts `hybrid_ed_priv` and `hybrid_dil_priv` kwargs
- Sets `HYBRID_SIG_FLAG` (bit 3) in the flags byte
- Hybrid signatures take priority over RSA when available
- The signature is included in the AES-GCM AAD for authentication

In `decrypt_message()`:
- Checks `HYBRID_SIG_FLAG` in flags
- Iterates through `friends_hybrid` list to find matching signer
- Reports "✅ Hybrid Signature Verified (Ed25519 + Dilithium3) from {name}"

### 5. File Operations Integration

In `file_service.py` and `key_manager.py`:
- New flag bit `_FILE_FLAG_HYBRID_SIGN = 2` for file-level hybrid signatures
- `file_encrypt_shared()` accepts `hybrid_ed_priv` and `hybrid_dil_priv` params
- `file_decrypt_shared()` accepts `friends_hybrid` list for verification
- Hybrid signatures take priority over RSA when both are available

### 6. Key Management

In `key_manager.py` (`KeyStore`):
- Hybrid signing keys generated during `init_db()` if liboqs available
- Ed25519 private key encrypted and stored as `ed25519_priv_encrypted`
- Dilithium3 private key encrypted and stored as `dilithium_priv_encrypted`
- Combined public key stored as `hybrid_sig_combined_pub_b64`
- Friend hybrid public keys stored in `friends` table as `hybrid_sig_pub_b64`

In `FriendsService`:
- `generate_hybrid_sig_keys(password)` - Generate and store new keys
- `import_friend_hybrid_sig_pub(name, b64, password)` - Import friend's key
- `get_my_hybrid_sig_combined_pub()` - Export my public key as Base64
- `get_hybrid_sig_key_fingerprint(b64)` - Get SHA-256 fingerprint

### 7. UI Integration

In `friends_tab.py`:
- New "✍️ Hybrid Sig Exchange" button in top action bar
- `hybrid_sig_exchange_dialog()` with 3 tabs:
  1. **My Signing Keys** - Generate, view, copy public key, see fingerprint
  2. **Import Friend Key** - Import friend's public key with validation
  3. **Status** - Overview of all friends with hybrid signing keys

- Friend list table shows "✍️ Yes" in "Hybrid Sig" column when key is stored
- Detail panel shows "✍️ Stored" or "❌ Not configured" for hybrid sig key

## Usage Workflow

### Setting Up Hybrid Signatures

1. **Generate your hybrid signing keys:**
   - Open Friends tab
   - Click "✍️ Hybrid Sig Exchange"
   - Enter master password
   - Click "🔑 Generate New Signing Keys"
   - Copy your combined public key

2. **Exchange public keys with friends:**
   - Share your combined public key with your friend (via secure channel)
   - Receive their combined public key
   - In "Import Friend Key" tab, select the friend and paste their key
   - Click "💾 Import & Save Signing Key"

3. **Verify fingerprints out-of-band:**
   - Compare fingerprints via phone, video call, or other secure channel
   - This prevents man-in-the-middle attacks

### Using Hybrid Signatures

**For messages:**
- Hybrid signatures are automatically used when signing messages (if keys are available)
- The "Sign with my private key" checkbox enables signing
- Recipients with your hybrid public key will see "✅ Hybrid Signature Verified"

**For files:**
- Check "Sign with my private key" in the File tab
- Hybrid signatures are automatically used when available
- Recipients will see signature verification status when decrypting

## Security Properties

1. **Dual Algorithm Security:** Both Ed25519 and Dilithium3 must be broken simultaneously to forge a signature
2. **Post-Quantum Resistance:** Dilithium3 (ML-DSA-65) is NIST FIPS 204 standardized and resistant to quantum computers
3. **Classical Fallback:** If Dilithium3 is ever broken, Ed25519 still provides classical security
4. **Quantum Fallback:** If Ed25519 is broken by quantum computers, Dilithium3 still provides security
5. **Strict Verification:** Both signatures must pass — no fallback to single-algorithm verification
6. **Authenticated Packaging:** Signatures are included in AES-GCM AAD, preventing tampering

## Dependencies

- `liboqs-python >= 0.9.0` - Python bindings for liboqs
- `liboqs` native library (liboqs.dll on Windows, liboqs.so on Linux)
- `cryptography >= 41.0.0` - For Ed25519 operations

## Algorithm Details

| Property | Ed25519 | Dilithium3 (ML-DSA-65) |
|----------|---------|------------------------|
| Type | Classical (Elliptic Curve) | Post-Quantum (Lattice-based) |
| Public Key Size | 32 bytes | ~1,952 bytes |
| Signature Size | 64 bytes | ~3,293 bytes |
| NIST Level | N/A | Level 3 (equivalent to AES-192) |
| Standard | RFC 8032 | FIPS 204 |
| Quantum Resistance | ❌ No | ✅ Yes |

## Testing

Comprehensive tests in `tests/test_pqc_signatures.py`:
- Key generation tests (sizes, uniqueness, format)
- Signing tests (format, determinism, edge cases)
- Verification tests (valid, wrong message, wrong key, tampered, truncated)
- Combined public key parsing roundtrip tests
- Integration tests with `crypto.py` wrappers
- File operation integration tests

Tests are automatically skipped if liboqs is not available.

## File Changes Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `services/friends_service.py` | Added methods | `generate_hybrid_sig_keys()`, `import_friend_hybrid_sig_pub()`, `get_hybrid_sig_key_fingerprint()` |
| `friends_tab.py` | Added button + dialog | "✍️ Hybrid Sig Exchange" button and `hybrid_sig_exchange_dialog()` |
| `services/file_service.py` | Extended functions | Added hybrid sig support to `file_encrypt_shared()` and `file_decrypt_shared()` |
| `key_manager.py` | Extended functions | Added hybrid sig support to `file_encrypt_shared()` and `file_decrypt_shared()` |
| `tests/test_pqc_signatures.py` | New file | Comprehensive test suite for hybrid signatures |

## Backward Compatibility

- All changes are backward compatible
- RSA-PSS signatures continue to work as before
- Hybrid signatures are used automatically when available
- Old packets without hybrid signatures are verified with RSA as fallback
- Files encrypted with the old format (flag bit 0 = RSA) still decrypt correctly
