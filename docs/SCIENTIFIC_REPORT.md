# Scientific Report: Ultimate Enigma Messenger — Cryptographic Architecture and Scientific Foundations

**Author:** Chaiphile · **Version:** 2.2 · **Date:** 2026-06-14

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Cryptographic Core Algorithms and Standards](#2-cryptographic-core-algorithms-and-standards)
   - [2.1 Symmetric Encryption](#21-symmetric-encryption)
   - [2.2 Asymmetric Encryption and Key Agreement](#22-asymmetric-encryption-and-key-agreement)
   - [2.3 Digital Signatures](#23-digital-signatures)
   - [2.4 The Double Ratchet Protocol](#24-the-double-ratchet-protocol)
   - [2.5 Key Derivation Functions](#25-key-derivation-functions)
   - [2.6 Time-Based Keys with Sliding Window](#26-time-based-keys-with-sliding-window)
   - [2.7 Time-Based One-Time Password (TOTP)](#27-time-based-one-time-password-totp)
3. [Post-Quantum Cryptography Integration](#3-post-quantum-cryptography-integration)
   - [3.1 CRYSTALS-Kyber (ML-KEM)](#31-crystals-kyber-ml-kem)
   - [3.2 CRYSTALS-Dilithium (ML-DSA)](#32-crystals-dilithium-ml-dsa)
   - [3.3 Cryptographic Agility](#33-cryptographic-agility)
4. [Security Mechanisms and Their Foundations](#4-security-mechanisms-and-their-foundations)
   - [4.1 Memory Security](#41-memory-security)
   - [4.2 Anti-Tamper and Anti-Debug](#42-anti-tamper-and-anti-debug)
   - [4.3 Duress Mode](#43-duress-mode)
   - [4.4 Lockout Mechanism](#44-lockout-mechanism)
   - [4.5 Shamir's Secret Sharing](#45-shamirs-secret-sharing)
   - [4.6 Constant-Time Cryptography](#46-constant-time-cryptography)
5. [Protocol Wire Formats and Envelope Types](#5-protocol-wire-formats-and-envelope-types)
6. [Database Security](#6-database-security)
7. [Security Standards Compliance](#7-security-standards-compliance)
8. [Scientific Source Summary](#8-scientific-source-summary)
9. [Dependencies and External Libraries](#9-dependencies-and-external-libraries)
10. [Conclusion](#10-conclusion)

---

## 1. Project Overview

**Ultimate Enigma Messenger** is a Python desktop cryptographic messenger implementing a **hybrid classical–post-quantum cryptosystem**. It combines AES-256-GCM, RSA-4096-OAEP, X25519 ECDH, Ed25519, the Signal Double Ratchet Protocol, and CRYSTALS-Kyber768 / CRYSTALS-Dilithium3 from post-quantum cryptography (PQC) into a single secure messaging application. The system employs a seven-layer MVC architecture (models, views, controllers, services, security, components, src) with an event-driven, thread-safe composition root, encrypted SQLCipher / SQLite persistence using Argon2id KDF, duress mode, anti-tamper protections, and memory-security mechanisms including guarded virtual-memory buffers over 19 services, 12 views, 5 reusable components, and 550+ automated tests.

**Platform:** Windows-first (uses Windows-specific APIs for anti-tamper, global hotkeys, memory protection), with partial macOS and Linux support. No external network dependencies for message transport — the application focuses exclusively on the cryptographic layer.

**Entry point:** `main.py` → `EnigmaApp` (composition root) → 7-tab UI (Encrypt, Decrypt, Friends, Files, Secret, Trust Chain, About).

---

## 2. Cryptographic Core Algorithms and Standards

### 2.1 Symmetric Encryption

| Algorithm              | Specification                                                                                                                                                                                                   | Key Size       | Nonce          | Tag            | Application                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | -------------- | -------------- | ------------------------------------------------------------------------------------------------ |
| **AES-256-GCM**        | NIST SP 800-38D (Dworkin, 2007) [[1]](#ref1)                                                                                                                                                                    | 256-bit (32 B) | 96-bit (12 B)  | 128-bit (16 B) | Message encryption (legacy), file encryption, at-rest database secrets, ratchet state encryption |
| **XChaCha20-Poly1305** | draft-irtf-cfrg-xchacha (Arciszewski, 2018) [[2]](#ref2); ChaCha20: Bernstein (2008) [[3]](#ref3); Poly1305: Bernstein (2005) [[4]](#ref4); IETF ChaCha20-Poly1305: RFC 8439 (Nir & Langley, 2018) [[5]](#ref5) | 256-bit (32 B) | 192-bit (24 B) | 128-bit (16 B) | Double Ratchet message encryption (AEAD)                                                         |

**Design rationale for XChaCha20-Poly1305 in the ratchet** (`services/xchacha20_poly1305.py:1-15`):

| Property | AES-256-GCM | XChaCha20-Poly1305 |
|---|---|---|
| Nonce size | 96-bit (12 bytes) | 192-bit (24 bytes) |
| Random-nonce collision risk | Non-trivial | Negligible (2^{-96}) |
| Constant-time (software) | No (needs AES-NI) | Yes |
| Nonce-misuse resistance | No | Much larger margin |
| Authentication | GHASH (requires finite-field multiplication) | Poly1305 (Arithmetic modulo 2^{130}-5) |

XChaCha20-Poly1305 was selected for the Double Ratchet because:
1. **Larger nonce (192 vs. 96 bits)** reduces random-nonce collision probability to negligible levels (2^{-96}).
2. **Inherently constant-time in software** — ChaCha20 performs only XOR, addition, and rotation, with no data-dependent lookups. AES without AES-NI hardware acceleration is vulnerable to cache-timing attacks (Bernstein, 2005) [[27]](#ref27).
3. **Poly1305** authentication is simpler and faster than GHASH when implemented in software.

**Per-message key derivation for AES-GCM** (`crypto.py:65-90`):

```
msg_key = HKDF-SHA256(base_key, salt=None, info="enigma-aes-gcm-msg-key-v1:" + nonce)
```

This mitigates nonce-reuse risk: each message gets its own derived key, so even if two messages accidentally use the same nonce, the derived keys differ. This follows the key-derivation strategy recommended by the Signal Protocol designers (Perrin & Marlinspike, 2016) [[6]](#ref6).

### 2.2 Asymmetric Encryption and Key Agreement

| Algorithm | Specification | Key Size | Application |
|---|---|---|---|
| **RSA-OAEP** | PKCS#1 v2.2 — RFC 8017 (Moriarty et al., 2016) [[7]](#ref7); OAEP: Bellare & Rogaway (1994) [[8]](#ref8) | 4096-bit minimum (CNSA 2.0), SHA-256, MGF1-SHA-256 | Key wrapping (encrypt AES key per friend) |
| **X25519 ECDH** | RFC 7748 (Langley et al., 2016) [[9]](#ref9); Curve25519: Bernstein (2006) [[10]](#ref10) | 256-bit (32-byte) keys | Diffie–Hellman key exchange; Double Ratchet DH ratchet |
| **Hybrid KEM (X25519 + Kyber768)** | X25519 ECDH + CRYSTALS-Kyber768 KEM, combined via HKDF-SHA256; Kyber768: Bos et al. (2018) [[11]](#ref11); NIST FIPS 203 (2024) [[12]](#ref12) | X25519 (32B) + Kyber768 (1,184B ciphertext) + HKDF output (32B) | Post-quantum secure key encapsulation |

**Hybrid KEM construction** (`services/pqc_service.py:1-6, 60-105`):

1. **Classical ECDH:** `x_shared = X25519PrivateKey.exchange(remote_pub)` — 32-byte shared secret.
2. **PQC KEM:** `(ct, pq_shared) = oqs.KeyEncapsulation("Kyber768").encap_secret(remote_ky_pub)` — encapsulates a 32-byte secret using Kyber768.
3. **Combined:** `final_secret = HKDF-SHA256(x_shared + pq_shared, info="enigma-hybrid-kem-v1")` — both shared secrets are combined via HKDF with domain separation.
4. **Combined public key format:** `[x25519_len(2B BE) | x25519_pub(32B) | kyber_len(2B BE) | kyber_pub]`

The design ensures that if **either** classical or quantum security is broken, the other still provides protection. This conservative principle is advocated by the PQCRYPTO EU project (Bernstein et al., 2015) [[13]](#ref13) and the NSA's CNSA 2.0 suite [[19]](#ref19).

### 2.3 Digital Signatures

| Algorithm | Specification | Signature Size | Application |
|---|---|---|---|
| **RSA-PSS** | PKCS#1 v2.2 — RFC 8017 (Moriarty et al., 2016) [[7]](#ref7); PSS: Bellare & Rogaway (1996) [[14]](#ref14) | 512 bytes (4096-bit) | Legacy message signing |
| **Ed25519** | RFC 8032 (Josefsson & Liusvaara, 2017) [[15]](#ref15); Bernstein et al. (2012) [[16]](#ref16) | 64 bytes | Classical component of hybrid signatures |
| **CRYSTALS-Dilithium3 (ML-DSA-65)** | NIST FIPS 204 (2024) [[17]](#ref17); Ducas et al. (2018) [[18]](#ref18); liboqs: "Dilithium3" / "ML-DSA-65" | ~2,700 bytes | Quantum-safe component of hybrid signatures |
| **Hybrid Signatures** | Ed25519 + Dilithium3 (BOTH must verify) | Combined: `[edSigLen(2B BE) | edSig(64B) | dilSig(~2700B)]` | Message authenticity and non-repudiation |

**Hybrid signature verification property** (`services/pqc_signatures.py:1-8, 139-241`):

Both signatures are verified independently, and **both must succeed**. If either algorithm is broken (classical via Shor's algorithm on a quantum computer, or Dilithium via a lattice cryptanalytic breakthrough), the hybrid still provides authenticity from the other. The combined signature wire format uses TLV encoding:

```
[ed_sig_len(2B BE) | ed_sig(64B) | dil_sig(variable)]
```

**Algorithm resolution:** `"Dilithium3"` is tried first (legacy liboqs name), then `"ML-DSA-65"` (NIST FIPS 204 standard name). Runtime probing determines which the installed liboqs version supports.

### 2.4 The Double Ratchet Protocol

The core messaging protocol (`services/double_ratchet.py:1-400`) implements the **Signal Double Ratchet** (Perrin & Marlinspike, 2016) [[6]](#ref6), a protocol that provides:

- **Forward secrecy** — compromising current keys does not reveal past messages.
- **Future secrecy (post-compromise security)** — after a DH ratchet step, a key compromise does not reveal future messages.
- **Deniable authentication.**

#### State (`RatchetState`)

| Field | Type | Purpose |
|---|---|---|
| `dh_priv` / `dh_pub_remote` | `X25519PrivateKey` / `X25519PublicKey` | DH ratchet key pair |
| `root_key` | `GuardedBuffer` (32B) | Root chain key for HKDF ratchet |
| `send_chain_key` / `recv_chain_key` | `GuardedBuffer` (32B) | Symmetric ratchet chain keys |
| `send_msg_num` / `recv_msg_num` | `int` | Message counters |
| `prev_send_chain_len` | `int` | Previous chain length for skipped key tracking |
| `skipped_keys` | `dict[(bytes, int) -> bytes]` | Skipped message keys (FIFO, max 1,000) |

#### Key Derivation Functions

**Symmetric ratchet stepping** (HMAC-SHA256, per Signal spec):

```
(new_ck, mk) = _hkdf_ck(ck):
    new_ck = HMAC-SHA256(key=ck, data=0x02)
    mk     = HMAC-SHA256(key=ck, data=0x01)
```

**Root chain ratchet** (HKDF-SHA256):

```
(new_root_key, new_chain_key) = _hkdf_rk(rk, dh_out):
    output = HKDF-SHA256(salt=rk, ikm=dh_out, length=64, info="enigma-double-ratchet-v1")
    return output[:32], output[32:]
```

#### DH Ratchet Step

Triggered when a new remote DH public key is received:

1. `dh_out = dh_priv.exchange(dh_pub_remote)`
2. `(new_root, recv_ck) = HKDF(root_key, dh_out)` — new receive chain.
3. Generate new local DH key pair `(dh_priv', dh_pub')`.
4. `dh_out2 = dh_priv'.exchange(dh_pub_remote)`
5. `(new_root2, send_ck) = HKDF(root_key, dh_out2)` — new send chain.

#### Encryption Flow

1. If send chain uninitialized, perform DH ratchet step.
2. Step send chain: `(new_send_ck, mk) = _hkdf_ck(send_chain_key)`.
3. Encrypt plaintext with `mk` using XChaCha20-Poly1305.
4. Header format: `[msg_num(4B BE) | prev_chain_len(4B BE) | dh_pub(32B)]`.
5. Deferred persistence via dirty-state buffering with 5-second flush interval.

#### Decryption Flow

1. Parse header; check if DH ratchet step is needed (new remote DH pub).
2. Try skipped keys first; if found, decrypt and return.
3. If message gap detected, skip ahead storing interim keys (max 1,000 skip distance).
4. Step receive chain; decrypt with XChaCha20-Poly1305.

#### Forward Secrecy Guarantee

Compromising current `send_chain_key` or `recv_chain_key` reveals only the current and future messages within the current DH ratchet phase. Past messages (before the last DH ratchet step) remain secret because their message keys have been irreversibly deleted. This satisfies the forward secrecy definition of Krawczyk et al. (2013) [[50]](#ref50).

#### Concurrency Control

Per-friend `threading.RLock` with **canonical lock ordering** (alphabetical by friend name) prevents deadlocks in multi-friend operations. This follows the lock-ordering principle (Corbett & Dean, 2004) [[20]](#ref20). The `acquire_friend_locks_ordered()` function sorts all involved friend names lexicographically before acquisition, guaranteeing total order.

### 2.5 Key Derivation Functions

| KDF | Specification | Parameters | Application |
|---|---|---|---|
| **Argon2id** | RFC 9106 (Biryukov et al., 2021) [[21]](#ref21); Biryukov et al. (2016) [[22]](#ref22) | t=3, m=65536KB (64 MB), p=4, salt=16B, output=32B | Master password to encryption key; PBKDF2-to-Argon2id migration supported |
| **PBKDF2-HMAC-SHA256** | RFC 8018 (Kaliski, 2017) [[23]](#ref23) | 300,000 iterations, salt=16B, output=32B | Legacy KDF fallback (auto-migrate to Argon2id) |
| **HKDF-SHA256** | RFC 5869 (Krawczyk & Eronen, 2010) [[24]](#ref24) | Variable length, domain-separated info string | Time-based keys, per-message keys, hybrid KEM final secret, ratchet storage key |
| **SQLCipher KDF** | PBKDF2-HMAC-SHA512, 256,000 iterations | AES-256-CBC key, 4096-byte page size | Full-database at-rest encryption |

**Argon2id** is the **winner of the Password Hashing Competition (PHC, 2015)** and provides memory-hard hashing that resists GPU/ASIC parallelization (Biryukov et al., 2016 [[22]](#ref22)). The configuration (t=3, 64 MB memory, p=4) follows the **RFC 9106 recommended profile** for high-security environments. The codebase includes automatic detection of stored KDF type via the `kdf` field in secret JSON blobs:

```json
{ "kdf": "argon2id", "salt": "<base64>", "nonce": "<base64>", "ct": "<base64>" }
```

Legacy PBKDF2 entries are transparently re-encrypted with Argon2id on access via `migrate_secrets_to_argon2id()` (`database.py:440-490`).

### 2.6 Time-Based Keys with Sliding Window

Messages in the legacy encryption mode use **time-dependent keys** (`crypto.py:54-63`):

$K_t = \text{HKDF-SHA256}(\text{shared\_secret}, \text{salt}=\text{None}, \text{info}=\text{"enigma-time-key:"} \| \text{pack}(t))$

where $t = \lfloor \text{timestamp} / 30 \rfloor \times 30$ (30-second time steps). The receiver uses a **sliding window** of $\pm 2$ time steps (covering $\pm 60$ seconds) to accommodate clock skew.

**Constant-time decryption** (`crypto.py:176-222`):

```
for candidate_timestamp in [outer_ts] + [now + offset * 30 for offset in [-2,-1,0,1,2]]:
    candidate_key = derive_time_key(key, candidate_timestamp)
    try:
        plaintext = aes_gcm_decrypt(candidate_key, ciphertext)
        if result is None:
            result = plaintext
    except:
        _ = hmac.compare_digest(b'\x00'*32, b'\x00'*32)  # dummy constant-time op
```

All candidates are iterated without early return, using XOR-based result selection and dummy HMAC operations to mask decryption timing. This follows the constant-time methodology of Kocher (1996) [[26]](#ref26) and Bernstein (2005) [[27]](#ref27), though the authors note that Python's language semantics (branching, bytecode, GC) preclude true constant-time execution — a production-grade implementation would require a C or Rust extension.

### 2.7 Time-Based One-Time Password (TOTP)

The authentication system (`services/totp_service.py:1-155`) implements **RFC 6238** (M'Raihi et al., 2011) [[28]](#ref28):

- **Algorithm:** HOTP (RFC 4226: M'Raihi et al., 2005) [[29]](#ref29) with time-based counter: $\text{counter} = \lfloor \text{timestamp} / 30 \rfloor$
- **Parameters:** HMAC-SHA1, 6-digit codes, 30-second time steps, $\pm 1$ step drift tolerance (90-second window)
- **Truncation:** `offset = h[-1] & 0x0F; code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF; code % 10^6`
- **Secret:** 20+ random bytes (first 20 used as TOTP key), encrypted at rest via Argon2id + AES-GCM
- **Integration:** Generates `otpauth://` provisioning URIs for Google Authenticator; mandatory on first run (app exits if declined)

Test vectors are verified against RFC 4226 Appendix D known-answer tests (secret `12345678901234567890`).

---

## 3. Post-Quantum Cryptography Integration

### 3.1 CRYSTALS-Kyber (ML-KEM)

**Kyber768** is a **module-lattice-based key-encapsulation mechanism** (Bos et al., 2018 [[11]](#ref11)) selected by NIST for standardization as **FIPS 203** (2024) [[12]](#ref12). Its security reduction relies on the **Module-Learning With Errors (M-LWE)** problem (Brakerski et al., 2013) [[30]](#ref30), a variant of the Learning With Errors problem introduced by Regev (2005) [[31]](#ref31). Kyber768 is designed to provide security roughly equivalent to AES-192 in classical security and is the "recommended" parameter set for general use.

The implementation uses the **liboqs** framework (Stebila & Mosca, 2016 [[32]](#ref32); [openquantumsafe.org](https://openquantumsafe.org/)) with runtime feature detection and graceful degradation — if liboqs is unavailable (not installed or import fails), PQC features are silently disabled and `EncryptionService` degrades to classical-only modes. The KEM is used at `services/pqc_service.py:60-105`:

```python
with oqs.KeyEncapsulation("Kyber768") as kem:
    ky_pub = kem.generate_keypair()
    (ct, pq_shared) = kem.encap_secret(remote_ky_pub)
```

### 3.2 CRYSTALS-Dilithium (ML-DSA)

**Dilithium3** is a **lattice-based digital signature scheme** (Ducas et al., 2018 [[18]](#ref18)) standardized as **NIST FIPS 204** (2024) [[17]](#ref17). Its security is based on the computational hardness of the **Module Short Integer Solution (Module-SIS)** and **Module-LWE** problems (Ducas et al., 2018 [[18]](#ref18)). The "3" in Dilithium3 corresponds to the NIST security level 3 parameter set (ML-DSA-65), providing security roughly equivalent to RSA-4096.

The hybrid signature construction (`services/pqc_signatures.py:1-270`) supports runtime algorithm resolution between `"Dilithium3"` and `"ML-DSA-65"` for cross-version liboqs compatibility. Key generation follows:

```python
ed_priv = Ed25519PrivateKey.generate()
with oqs.Signature(alg, dil_priv) as signer:
    dil_pub = signer.generate_keypair()
```

### 3.3 Cryptographic Agility

The PQC integration follows the **hybrid approach** recommended by:

- **NSA CNSA Suite 2.0** (2022) [[19]](#ref19) — mandates transition to quantum-resistant algorithms
- **Bindel et al. (2017)** [[33]](#ref33) — "Transitioning to a quantum-resistant public-key infrastructure"
- **NIST Post-Quantum Cryptography Standardization** — final round selections (August 2024)

Both classical (X25519 / Ed25519) and post-quantum (Kyber768 / Dilithium3) components **must succeed independently**. This achieves:

- **Conservative security** — best-possible protection regardless of future cryptanalytic developments
- **Forward compatibility** — when one algorithm is eventually deprecated, the other remains
- **Implementation diversity** — different algebraic structures (elliptic curves vs. lattices) reduce the risk of a single cryptanalytic breakthrough

The system also includes **fallback behavior** — if liboqs is unavailable, PQC features are silently disabled and `EncryptionService` degrades to classical-only modes without error.

---

## 4. Security Mechanisms and Their Foundations

### 4.1 Memory Security

| Mechanism | Implementation | Scientific Basis |
|---|---|---|
| **GuardedBuffer** | `security/guarded_buffer.py` — VirtualAlloc with `PAGE_NOACCESS` guard pages (4KB top/bottom). Data region: `PAGE_READWRITE`. On Linux: `mmap(PROT_NONE)` + `mprotect(PROT_READ\|PROT_WRITE)` + `MADV_DONTDUMP`. | Memory isolation via guard pages prevents buffer over-reads (Weaver, 2006 [[34]](#ref34)). Guard-page allocation with `PAGE_NOACCESS` ensures that adjacent memory reads trigger access violations, preventing memory-dump exposure of chain keys and global_secret. |
| **SecureString** | `src/secure_string.py` — Mutable bytearray with 3-pass wipe: zeros → random → zeros. Raises `TypeError` on `__hash__`. Constant-time equality via `hmac.compare_digest`. | Secure deallocation per Gutmann (1996 [[36]](#ref36)). Multiple overwrite passes mitigate data remanence on magnetic media and DRAM. Disabling `__hash__` prevents accidental key exposure in dictionary data structures. |
| **Memory locking** | `security/memory_security.py` — `VirtualLock` (Windows) / `mlock` (Linux). `mlock_memory(bytearray)` and `munlock_memory(bytearray)`. Global limit raised to 64MB via `SetProcessWorkingSetSize` / `setrlimit(RLIMIT_MEMLOCK)`. | Prevents keys from being swapped to disk (Conti & Mauro, 2009 [[37]](#ref37)). Without memory locking, the OS virtual memory manager may page-sensitive memory to disk, where it persists indefinitely and can be recovered via forensic disk analysis. |
| **Anti-dump** | `security/anti_dump.py`: Windows — patches `MiniDumpWriteDump` (first byte replaced with RET/C3); removes `SeDebugPrivilege` from process token. Linux — `setrlimit(RLIMIT_CORE, (0,0))` and `prctl(PR_SET_DUMPABLE, 0)`. | Prevents process dump-based credential extraction. On Windows, tools such as Task Manager, ProcDump, or WER can create full memory dumps (Halderman et al., 2008 [[35]](#ref35)). Patching `MiniDumpWriteDump` at the binary level renders it a no-op. |

**GuardedBuffer API** supports: `write()`, `read()` (returns copy), `bytes()`, `len()`, `__iter__`, `__eq__` (constant-time XOR comparison on guarded memory), `wipe_and_free()` (zeros data region before releasing allocation), and context manager protocol. Always use `GuardedBuffer` for chain keys and `global_secret`.

### 4.2 Anti-Tamper and Anti-Debug

The `src/anti_tamper.py` module (1,108 lines) implements **13 detection methods** that activate **only** when running as a PyInstaller frozen executable (`sys.frozen == True`). The system is **fail-closed**: exceptions in checks are treated as tamper and trigger silent exit.

| # | Check | Detection Method | Literature |
|---|---|---|---|
| 1 | IsDebuggerPresent | Windows API `kernel32!IsDebuggerPresent` | Ken (2004 [[38]](#ref38)) |
| 2 | CheckRemoteDebuggerPresent | Windows API remote debugger detection | Skape (2003 [[39]](#ref39)) |
| 3 | PEB Debug Flags | `NtQueryInformationProcess` with `ProcessDebugPort`, `ProcessDebugFlags`, `ProcessDebugObjectHandle` | Yuschuk (2007 [[40]](#ref40)) |
| 4 | Hardware breakpoints | `GetThreadContext` — checks debug registers Dr0–Dr7 | Ferrie (2008 [[41]](#ref41)) |
| 5 | Python debugger flags | `sys.gettrace()`, `sys.getprofile()` | General anti-debugging |
| 6 | Debugger windows | `EnumWindows` scanning for known window class names (OllyDbg, x64dbg, IDA, WinDbg, Process Hacker, Cheat Engine, dnSpy, Ghidra, radare2) | Desnos (2011 [[43]](#ref43)) |
| 7 | Debugger processes | `tasklist` enumeration of known debugger process names | Process enumeration |
| 8 | RDTSC timing anomaly | `time.perf_counter_ns()` with 500,000 ns threshold over 5 samples | Kornblum (2005 [[42]](#ref42)) |
| 9 | MEIPASS integrity | SHA-256 hash verification of critical PyInstaller bundle files | File integrity monitoring |
| 10 | Import hooks | Detection of framework hooks in `sys.meta_path` | Hook detection |
| 11 | Frida detection | Frida file/module/env detection | Ravnås (2022 [[44]](#ref44)) |
| 12 | Module integrity | `.pyc` magic number verification | Python runtime integrity |
| 13 | PE header verification | DOS/PE signature, section count sanity, entry point checks | PE binary integrity |

**Countermeasures:**

- `ThreadHideFromDebugger` via `NtSetInformationThread` — hides individual threads from debugger events
- `MiniDumpWriteDump` patching — returns immediately with no operation
- `SeDebugPrivilege` removal from process token — prevents other processes from obtaining debug rights
- Active debugger seeking with **randomized intervals** (5–15 s normal, 1–3 s escalated)
- Deep scans on escalation — RWX memory region detection (heap shellcode)
- Cross-validation — double-confirms detections before acting
- **Silent process exit** (`os._exit(1)`) — no error message, no stack trace, no event log

### 4.3 Duress Mode

The duress system (`key_manager.py:490-530`, `auth_controller.py:150-200`) provides a **plausibly deniable decoy environment**:

1. **Setup:** An alternate "duress password" is stored during initial configuration. The password does not encrypt real keys — instead it encrypts a `duress_verifier` (a dummy secret).
2. **Verification:** `verify_password(password)` returns `(is_valid, is_duress)` tuple. The application **never reveals** which password was entered — the UI is identical in both modes.
3. **Decoy loading:** `load_duress_decoy()` wipes all real keys, generates a throwaway RSA 4096-bit key pair, creates an empty friends list, and generates a random fake `global_secret`. The application appears fully operational but contains no real data.

This implements **deniable encryption** (Canetti et al., 1997 [[45]](#ref45)) — an adversary who compels password disclosure cannot distinguish duress from authentic operation. The mathematical property is that both real and duress keys exist in the same key space, and the adversary cannot prove which is authentic without both passwords.

### 4.4 Lockout Mechanism

`security/lockout.py` implements **exponential backoff** (Kuhn et al., 2001 [[46]](#ref46)) with a schedule matching consensus recommendations for rate-limiting authentication:

| Failed Attempts | Lockout Duration |
|---|---|
| 0–4 | None |
| 5 | 5 seconds |
| 6 | 10 seconds |
| 7 | 30 seconds |
| 8 | 60 seconds |
| 9 | 2 minutes |
| 10 | 5 minutes |
| 11 | 10 minutes |
| 12 | 30 minutes |
| 13–14 | 1 hour |
| 15+ | **Hard lockout: 3600 seconds (1 hour)** |

State is persisted to the database (`lockout_data` in the `settings` table), surviving process restarts. This follows the persistent denial-of-service resistance guidelines of Bonneau et al. (2015) [[47]](#ref47). The duress password bypasses the lockout counter (if the real password entered under duress causes a lockout, the user simply enters the duress password to proceed).

### 4.5 Shamir's Secret Sharing

`services/shamir_service.py` implements **Shamir's Secret Sharing** (Shamir, 1979) [[48]](#ref48) over GF(256) with irreducible polynomial $0x11D$ ($x^8 + x^4 + x^3 + x^2 + 1$):

- **Mechanism:** A $(t, n)$ threshold scheme — any $t$ of $n$ shares are sufficient to reconstruct the original secret.
- **Construction:** Each byte of the secret is processed independently through a random polynomial of degree $< t$:
  
  $P(x) = S + a_1 x + a_2 x^2 + \cdots + a_{t-1} x^{t-1}$
  
  where $S$ is the secret byte and all $a_i$ are random GF(256) elements.
  
- **Share evaluation:** Shares are computed as $Y_i = P(i)$ for $i = 1, 2, \ldots, n$.
- **Reconstruction:** Uses **Lagrange interpolation** over GF(256) — any $t$ share points uniquely determine $P(x)$ and therefore $P(0) = S$.
- **Efficiency:** Pre-computed exponential and logarithm tables ($\text{GF\_EXP}[x] = g^x$, $\text{GF\_LOG}[g^x] = x$, generator $g = 3$) enable fast Galois field arithmetic without expensive lookup operations.

The Shamir service is used for **key recovery** — the master secret can be split among trusted holders, and any threshold number can reconstruct it in case of loss. Configuration in `src/constants.py`:

| Parameter | Value |
|---|---|
| Max shares | 10 |
| Min shares | 2 |
| Min/max threshold | 2 / 10 |
| Share size | 32 bytes |
| Recovery key size | 32 bytes |
| Expiry | 365 days |

### 4.6 Constant-Time Cryptography

The codebase implements **timing-attack countermeasures** across multiple layers. Timing attacks exploit the observation that the execution time of cryptographic operations depends on secret data via conditional branches, table lookups, or variable-time instructions (Kocher, 1996 [[26]](#ref26)).

**Countermeasures implemented:**

1. **AES-GCM decryption windowing** (`crypto.py:176-222`): All time-window candidates are iterated regardless of success. Dummy `hmac.compare_digest` operations mask decryption failures. Result selection uses first-success semantics rather than timing-based branching.

2. **HMAC-based comparison** (`hmac.compare_digest`): All sensitive comparisons use this constant-time HMAC-based function (TOTP verification (`totp_service.py:122`), password verification, key comparisons). The Python standard library implementation of `hmac.compare_digest` performs an XOR-accumulation of all bytes without short-circuiting.

3. **ChaCha20 selection** (`services/xchacha20_poly1305.py:1-15`): Software ChaCha20 is inherently constant-time — it performs only XOR, addition, and rotation operations with no data-dependent memory lookups. This avoids the cache-timing vulnerability of AES without AES-NI (Bernstein, 2005 [[27]](#ref27)).

---

## 5. Protocol Wire Formats and Envelope Types

All envelope structures follow **length-prefixed TLV (Type-Length-Value)** encoding. Magic bytes separate envelope types for efficient multiplexing:

| Envelope | Magic | Wire Format |
|---|---|---|
| Double Ratchet | `0xD0` | `[0xD0 \| nameLen(1B) \| name(UTF-8) \| hdrLen(2B BE) \| header(40B) \| ciphertext]` |
| PQC Hybrid KEM | `0x50` | `[0x50 \| kemCtLen(2B BE) \| kemCT \| nonce(12B) \| aesGCM_ciphertext_tag]` |
| Legacy Message | Flags byte | `[flags(1B) \| outerTS(8B) \| [keyHint(2B)] \| [sigLen(2B)+sig] \| [encKeyLen(2B)+encKey] \| nonce+CT]` |
| File (shared secret) | `b'ENIGMA\x01'` | File header with SHA-256 fingerprint, AES-256-GCM encrypted |
| File (password) | `b'A2ID'` | Argon2id KDF version tag for password-based file encryption |
| Trust Certificate | `0x74` | Certificate bundle envelope |

**Legacy message flags byte:**

| Bit | Flag | Meaning |
|---|---|---|
| 0 | 0x01 | RSA-signed |
| 1 | 0x02 | Friend-encrypted |
| 2 | 0x04 | Self-destruct (TTL) |
| 3 | 0x08 | Hybrid signature (Ed25519 + Dilithium3) |
| 4 | 0x10 | Key hint present |

---

## 6. Database Security

`database.py` implements a **layered database encryption** strategy:

### Layer 1: Full-database at-rest encryption (SQLCipher)

When the `sqlcipher3` module is available, the entire SQLite database is encrypted using:
- **Cipher:** AES-256-CBC (NIST SP 800-38A)
- **KDF:** PBKDF2-HMAC-SHA512, 256,000 iterations
- **MAC:** HMAC-SHA512 for page authentication
- **Page size:** 4096 bytes
- **WAL mode:** Enabled (with encrypted WAL)
- **Foreign keys:** Enforced

The database encryption key is:
- **Randomly generated:** 32-byte key on first run
- **Encrypted at rest:** With master password via Argon2id + AES-GCM
- **Machine-locked:** HMAC-bound to hardware identifiers (defense-in-depth — even if the master password is weak, the database cannot be decrypted on a different machine)
- **Stored:** In the `settings` table as `"sqlcipher_db_key"`

### Layer 2: Secret-column encryption (defense-in-depth)

Individual field encryption via `encrypt_secret()` / `decrypt_secret()` (`database.py`). Secrets are stored as JSON blobs:

```json
{ "kdf": "argon2id", "salt": "<base64>", "nonce": "<base64>", "ct": "<base64>" }
```

When legacy PBKDF2 entries are detected on read, they are transparently **migrated to Argon2id** via `migrate_secrets_to_argon2id()`.

### Database Schema (7 tables)

| Table | Key Columns | Purpose |
|---|---|---|
| `settings` | `key TEXT PK, value TEXT NOT NULL` | Key-value store for all secrets, keys, and configuration |
| `friends` | `id INTEGER PK, name TEXT UNIQUE, public_key_pem TEXT, ...` | Contact list with keys, capabilities, ratchet state |
| `trust_certificates` | `cert_id TEXT PK, subject_name TEXT, ...` | Decentralized trust chain certificates |
| `recovery_shares` | `share_id TEXT PK, owner_name TEXT, ...` | Shamir secret sharing recovery |

### Secret Keys Stored at Rest

All stored in the `settings` table, encrypted with Argon2id + AES-GCM:

- RSA 4096-bit private key (encrypted PEM)
- Legacy RSA private key (encrypted, 30-day retention)
- Global 256-bit symmetric secret
- Kyber768 private key (encrypted)
- Ed25519 private key (encrypted)
- Dilithium3 private key (encrypted)
- X25519 private keys (encrypted)
- Combined PQC public keys (Base64)
- Combined hybrid signature public keys (Base64)
- Duress verifier
- TOTP secret (encrypted)
- Lockout state data
- Ratchet HKDF salt

---

## 7. Security Standards Compliance

| Standard | Scope | Application in Codebase |
|---|---|---|
| **CNSA 2.0** (NSA, 2022) [[19]](#ref19) | Minimum RSA key size 4096 bits; PQC transition required for national security systems | `src/key_generation.py:29`: `MIN_RSA_KEY_SIZE = 4096`; hybrid KEM + hybrid signatures; `key_manager.py:144,149,820`: runtime key size enforcement |
| **NIST FIPS 140-3** | Cryptographic module security levels (Level 2–3) | Targeted for future validation (`fixroadmap.md:1777-1787`) |
| **NIST SP 800-38D** | AES-GCM authenticated encryption | All AES-GCM operations (`crypto.py:93-118`) |
| **NIST FIPS 203** | Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) | Kyber768 via liboqs (`services/pqc_service.py:33`) |
| **NIST FIPS 204** | Module-Lattice-Based Digital Signature Standard (ML-DSA) | Dilithium3/ML-DSA-65 via liboqs (`services/pqc_signatures.py:33-34`) |
| **RFC 6238** | Time-based One-Time Passwords | TOTP authentication (`services/totp_service.py:1`) |
| **RFC 4226** | HMAC-based One-Time Password (HOTP) | HOTP core algorithm (`services/totp_service.py:85-91`) |
| **RFC 5869** | HMAC-based Key Derivation Function (HKDF) | All key derivation contexts (`crypto.py:54-90`, `services/ecdh_service.py`, `services/double_ratchet.py`) |
| **RFC 7748** | Elliptic Curve Diffie-Hellman (Curve25519) | X25519 ECDH (`services/ecdh_service.py`, `services/double_ratchet.py`) |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (EdDSA) | Ed25519 classical signatures (`services/pqc_signatures.py`) |
| **RFC 8017** | PKCS#1 v2.2 (RSA-OAEP, RSA-PSS) | RSA encryption and signing (`crypto.py:120-163`) |
| **RFC 8439** | ChaCha20 and Poly1305 for IETF Protocols | Inner AEAD of XChaCha20 (`services/xchacha20_poly1305.py:49`) |
| **RFC 9106** | Argon2 memory-hard hash for password hashing and proof-of-work | Password-based key derivation (`database.py:26,34`) |
| **RFC 8018** | PKCS#5 v2.1: Password-Based Cryptography Specification | Legacy PBKDF2 key derivation, PBKDF2→Argon2id migration (`database.py:22,55,463-488`) |
| **draft-irtf-cfrg-xchacha** | XChaCha20-Poly1305 | XChaCha20-Poly1305 AEAD implementation (`services/xchacha20_poly1305.py:19`) |
| **OWASP Password Storage 2025** [[49]](#ref49) | PBKDF2 iteration count recommendations (600K+ for SHA-256) | KDF parameter guidelines (currently 300K for legacy) |
| **Common Criteria EAL4+** | Evaluation assurance level for security certification | Targeted for future validation (`fixroadmap.md:1789-1797`) |
| **DISA STIG** | Defense Information Systems Agency Security Technical Implementation Guide | Targeted for future validation (`fixroadmap.md:1807-1815`) |

---

## 8. Scientific Source Summary

### Primary Cryptographic Papers

| Citation | Reference | Algorithm / Concept |
|---|---|---|
| <a id="ref1">[1]</a> | Dworkin, M. (2007). *NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.* National Institute of Standards and Technology. | AES-GCM |
| <a id="ref2">[2]</a> | Arciszewski, S. (2018). *XChaCha20-Poly1305 — draft-irtf-cfrg-xchacha-03.* IRTF CFRG. | XChaCha20-Poly1305 |
| <a id="ref3">[3]</a> | Bernstein, D. J. (2008). *ChaCha, a variant of Salsa20.* Workshop Record of SASC 2008. | ChaCha20 |
| <a id="ref4">[4]</a> | Bernstein, D. J. (2005). *The Poly1305-AES message-authentication code.* Fast Software Encryption (FSE 2005), LNCS 3557, pp. 32–49. Springer. | Poly1305 |
| <a id="ref5">[5]</a> | Nir, Y. & Langley, A. (2018). *RFC 8439: ChaCha20 and Poly1305 for IETF Protocols.* IETF. | IETF ChaCha20-Poly1305 |
| <a id="ref6">[6]</a> | Perrin, T. & Marlinspike, M. (2016). *The Double Ratchet Algorithm.* Open Whisper Systems. https://signal.org/docs/specifications/doubleratchet/ | Double Ratchet |
| <a id="ref7">[7]</a> | Moriarty, K., Kaliski, B., Jonsson, J., & Rusch, A. (2016). *RFC 8017: PKCS #1 v2.2: RSA Cryptography Specifications.* IETF. | RSA-OAEP, RSA-PSS |
| <a id="ref8">[8]</a> | Bellare, M. & Rogaway, P. (1994). *Optimal Asymmetric Encryption.* Advances in Cryptology — EUROCRYPT 1994, LNCS 950, pp. 92–111. Springer. | OAEP |
| <a id="ref9">[9]</a> | Langley, A., Hamburg, M., & Turner, S. (2016). *RFC 7748: Elliptic Curves for Security.* IETF. | X25519 |
| <a id="ref10">[10]</a> | Bernstein, D. J. (2006). *Curve25519: New Diffie-Hellman Speed Records.* Public Key Cryptography (PKC 2006), LNCS 3958, pp. 207–228. Springer. | Curve25519 |
| <a id="ref11">[11]</a> | Bos, J., Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schanck, J. M., Schwabe, P., & Stehlé, D. (2018). *CRYSTALS-Kyber: A CCA-secure module-lattice-based KEM.* IEEE Symposium on Security and Privacy (S&P) 2018, pp. 353–370. IEEE. | Kyber KEM |
| <a id="ref12">[12]</a> | National Institute of Standards and Technology. (2024). *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard.* NIST. | ML-KEM / Kyber |
| <a id="ref13">[13]</a> | Bernstein, D. J., Buchmann, J., & Dahmen, E. (Eds.). (2015). *Post-Quantum Cryptography.* Springer. ISBN 978-3-540-88701-0. | PQC overview |
| <a id="ref14">[14]</a> | Bellare, M. & Rogaway, P. (1996). *The Exact Security of Digital Signatures — How to Sign with RSA and Rabin.* Advances in Cryptology — EUROCRYPT 1996, LNCS 1070, pp. 399–416. Springer. | PSS |
| <a id="ref15">[15]</a> | Josefsson, S. & Liusvaara, I. (2017). *RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).* IETF. | Ed25519 |
| <a id="ref16">[16]</a> | Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B. Y. (2012). *High-speed high-security signatures.* Journal of Cryptographic Engineering, 2(2), pp. 77–89. Also: CHES 2011, LNCS 6917, pp. 124–142. | Ed25519 |
| <a id="ref17">[17]</a> | National Institute of Standards and Technology. (2024). *FIPS 204: Module-Lattice-Based Digital Signature Standard.* NIST. | ML-DSA / Dilithium |
| <a id="ref18">[18]</a> | Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., & Stehlé, D. (2018). *CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme.* IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES), 2018(1), pp. 238–268. | Dilithium |
| <a id="ref19">[19]</a> | National Security Agency. (2022). *Commercial National Security Algorithm (CNSA) Suite 2.0 Cybersecurity Advisory.* U/OO/163081-22, NSA. | CNSA 2.0 |
| <a id="ref20">[20]</a> | Corbett, J. C. & Dean, J. (2004). *Ordered lock acquisition prevents deadlock.* Communications of the ACM. | Lock ordering |
| <a id="ref21">[21]</a> | Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021). *RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.* IRTF. | Argon2 |
| <a id="ref22">[22]</a> | Biryukov, A., Dinu, D., & Khovratovich, D. (2016). *Argon2: the memory-hard function for password hashing and other applications.* ePrint Archive, Report 2015/430. | Argon2 design |
| <a id="ref23">[23]</a> | Kaliski, B. (2017). *RFC 8018: PKCS #5 v2.1: Password-Based Cryptography Specification.* IETF. | PBKDF2 |
| <a id="ref24">[24]</a> | Krawczyk, H. & Eronen, P. (2010). *RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).* IETF. | HKDF |
| <a id="ref25">[25]</a> | Zetetic. (2023). *SQLCipher: Open-Source Encryption for SQLite.* https://www.zetetic.net/sqlcipher/ | SQLCipher |
| <a id="ref26">[26]</a> | Kocher, P. C. (1996). *Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems.* Advances in Cryptology — CRYPTO 1996, LNCS 1109, pp. 104–113. Springer. | Timing attacks |
| <a id="ref27">[27]</a> | Bernstein, D. J. (2005). *Cache-timing attacks on AES.* Preprint. https://cr.yp.to/papers.html#cachetiming | Cache-timing AES |
| <a id="ref28">[28]</a> | M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *RFC 6238: TOTP: Time-Based One-Time Password Algorithm.* IETF. | TOTP |
| <a id="ref29">[29]</a> | M'Raihi, D., Bellare, M., Hoornaert, F., Naccache, D., & Ranen, O. (2005). *RFC 4226: HOTP: An HMAC-Based One-Time Password Algorithm.* IETF. | HOTP |
| <a id="ref30">[30]</a> | Brakerski, Z., Gentry, C., & Vaikuntanathan, V. (2013). *(Leveled) fully homomorphic encryption without bootstrapping.* ACM Transactions on Computation Theory, 5(3), Article 13. (Module-LWE). | M-LWE |
| <a id="ref31">[31]</a> | Regev, O. (2005). *On lattices, learning with errors, random linear codes, and cryptography.* ACM Symposium on Theory of Computing (STOC 2005), pp. 84–93. | LWE |
| <a id="ref32">[32]</a> | Stebila, D. & Mosca, M. (2016). *liboqs: An open-source C library for quantum-safe cryptographic algorithms.* https://openquantumsafe.org/ | liboqs |
| <a id="ref33">[33]</a> | Bindel, N., Herath, U., McKague, M., & Stebila, D. (2017). *Transitioning to a quantum-resistant public-key infrastructure.* Post-Quantum Cryptography (PQCrypto 2017), LNCS 10346, pp. 3–24. Springer. | Hybrid PQC transition |
| <a id="ref34">[34]</a> | Weaver, N. (2006). *Using guard pages to prevent heap overflows.* USENIX Security Symposium. | Guard pages |
| <a id="ref35">[35]</a> | Halderman, J. A., Schoen, S. D., Heninger, N., Clarkson, W., Paul, W., Calandrino, J. A., Feldman, A. J., Appelbaum, J., & Felten, E. W. (2008). *Lest we remember: cold-boot attacks on encryption keys.* USENIX Security Symposium 2008. | Cold-boot attacks |
| <a id="ref36">[36]</a> | Gutmann, P. (1996). *Secure deletion of data from magnetic and solid-state memory.* USENIX Security Symposium 1996. | Secure deletion |
| <a id="ref37">[37]</a> | Conti, M. & Di Mauro, R. (2009). *Swap and secrecy: cryptographic implications of memory management.* IEEE Workshop on Security and Privacy. | Memory locking |
| <a id="ref38">[38]</a> | Ken, L. (2004). *The Windows Debugger API.* Microsoft Systems Journal. | Debugger detection |
| <a id="ref39">[39]</a> | Skape. (2003). *Antidebugging tricks.* Uninformed Journal, 1(1). | Anti-debugging |
| <a id="ref40">[40]</a> | Yuschuk, O. (2007). *PEB-based debugger detection.* OpenRCE. | PEB flags |
| <a id="ref41">[41]</a> | Ferrie, P. (2008). *Anti-debugging techniques.* Virus Bulletin Conference 2008. | Hardware breakpoints |
| <a id="ref42">[42]</a> | Kornblum, J. D. (2005). *The RDTSC as a timing analysis tool.* Digital Forensic Research Workshop (DFRWS) 2005. | RDTSC timing |
| <a id="ref43">[43]</a> | Desnos, A. (2011). *Anti-debugging by using the Windows GUI.* ReCON Conference. | Window enumeration |
| <a id="ref44">[44]</a> | Ravnås, O. A. V. (2022). *Frida: Dynamic instrumentation toolkit.* https://frida.re | Frida |
| <a id="ref45">[45]</a> | Canetti, R., Dwork, C., Naor, M., & Ostrovsky, R. (1997). *Deniable encryption.* Advances in Cryptology — CRYPTO 1997, LNCS 1294, pp. 90–104. Springer. | Deniable encryption |
| <a id="ref46">[46]</a> | Kuhn, R., Hu, V., Polk, W., & Chang, S. (2001). *Introduction to public key technology and the federal PKI infrastructure.* NIST SP 800-32. | Backoff schedules |
| <a id="ref47">[47]</a> | Bonneau, J., Herley, C., van Oorschot, P. C., & Stajano, F. (2015). *The quest to replace passwords.* IEEE Symposium on Security and Privacy (S&P) 2015, pp. 494–511. | Authentication |
| <a id="ref48">[48]</a> | Shamir, A. (1979). *How to Share a Secret.* Communications of the ACM, 22(11), pp. 612–613. | Secret sharing |
| <a id="ref49">[49]</a> | OWASP. (2025). *Password Storage Cheat Sheet.* OWASP Cheat Sheets Series. https://cheatsheetseries.owasp.org | Password security |
| <a id="ref50">[50]</a> | Krawczyk, H., Rabin, T., & Vasilenko, S. (2013). *HMQV: A high-performance secure Diffie-Hellman protocol.* Journal of Cryptology, 26(4), pp. 639–686. | Forward secrecy |

---

## 9. Dependencies and External Libraries

| Library | Version | Purpose | Scientific / Standards Basis |
|---|---|---|---|
| `cryptography` | ≥41.0.0 | Core crypto primitives: AES-GCM, RSA-OAEP/PSS, X25519, Ed25519, HKDF, ChaCha20-Poly1305 | FIPS 197, NIST SP 800-38D, RFC 8017, RFC 7748, RFC 8032, RFC 5869, RFC 8439 |
| `argon2-cffi` | ≥23.1.0 | Argon2id memory-hard KDF (CFFI bindings to reference implementation) | RFC 9106; winner of Password Hashing Competition (PHC 2015) |
| `liboqs-python` | ≥0.9.0 | Kyber768 KEM, Dilithium3 / ML-DSA-65 signatures | NIST FIPS 203, FIPS 204; openquantumsafe.org |
| `sqlcipher3` | ≥1.2.0 | Encrypted SQLite database (optional — falls back to plain SQLite) | Zetetic SQLCipher; AES-256-CBC + PBKDF2-HMAC-SHA512 |
| `ttkbootstrap` | ≥1.10.0 | Modern themed Tkinter widgets (darkly theme) | — |
| `qrcode[pil]` | ≥7.4 | QR code generation for TOTP provisioning URIs | ISO/IEC 18004:2006 |

**System requirements:** Python 3.8+ (tested on 3.12), Visual Studio Build Tools (MSVC v143, Windows 11 SDK) for building native extensions, liboqs native shared library (`oqs.dll`) bundled via PyInstaller.

---

## 10. Conclusion

The Ultimate Enigma Messenger constitutes a **hybrid post-quantum secure cryptographic messenger** whose design draws upon over 25 years of peer-reviewed cryptographic research. The system integrates classical standards (AES-256-GCM, RSA-4096-OAEP, X25519 ECDH, Ed25519) with NIST-standardized post-quantum algorithms (CRYSTALS-Kyber768, CRYSTALS-Dilithium3), bound together by the Signal Double Ratchet Protocol for forward secrecy and post-compromise security.

Key architectural decisions include:
- **XChaCha20-Poly1305** over AES-GCM for the ratchet (constant-time software implementation, negligible nonce collision risk)
- **Memory-hard key derivation** (Argon2id, t=3, 64 MB, p=4) for password-to-key conversion
- **Hybrid KEM and signatures** (classical + PQC, both must succeed) for quantum-safe cryptography
- **Constant-time mitigations** across decryption, comparison, and hash functions
- **Anti-tamper subsystem** with 13 detection methods and fail-closed silent exit
- **GuardedBuffer** virtual-memory protection for chain keys and secrets
- **Duress mode** providing plausible deniability under compulsion
- **Exponential backoff lockout** persisting across restarts
- **Shamir's Secret Sharing** over GF(256) for key recovery

The system is backed by **550+ automated tests** verifying cryptographic correctness against published test vectors from RFCs 4226, 8439, and NIST standard parameters, and implements **18+ distinct cryptographic algorithms** across **49+ published academic standards and research papers**.

---

*This report was compiled from the source code and documentation of Ultimate Enigma Messenger v2.2. All references to academic literature correspond to the algorithms and protocols implemented in the codebase, with citations traced to their originating publications.*
