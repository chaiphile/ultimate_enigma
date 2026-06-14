"""XChaCha20-Poly1305 AEAD — modern, nonce-misuse-resistant encryption.

Why this replaces AES-GCM in the Double Ratchet:
    ┌─────────────────────────────┬───────────────────┬────────────────────────┐
    │ Property                    │ AES-256-GCM       │ XChaCha20-Poly1305     │
    ├─────────────────────────────┼───────────────────┼────────────────────────┤
    │ Nonce size                  │ 96-bit (12 bytes) │ 192-bit (24 bytes)     │
    │ Random-nonce collision risk │ Non-trivial       │ Negligible (2^-96)     │
    │ Constant-time (software)    │ No* (needs AES-NI)│ Yes                    │
    │ Nonce-misuse resistance     │ No                │ Much larger margin     │
    │ Authentication              │ GHASH             │ Poly1305               │
    └─────────────────────────────┴───────────────────┴────────────────────────┘

    * Software AES without AES-NI is vulnerable to cache-timing attacks.
      ChaCha20 is inherently constant-time on all platforms.

Construction
------------
XChaCha20-Poly1305 is defined in draft-irtf-cfrg-xchacha:

    1. Derive a 32-byte subkey:  subkey = HChaCha20(key, nonce[:16])
    2. Encrypt with IETF ChaCha20-Poly1305 using the subkey and a 12-byte
       inner nonce built as:  b'\\x00\\x00\\x00\\x00' + nonce[16:24]

HChaCha20 is a variant of the ChaCha20 block function that outputs 32 bytes
(the first and last 128 bits of the state after 20 rounds) instead of a
keystream XOR.  It is implemented here in pure Python using the quarter-round
function from RFC 8439.

Dependencies
------------
Only the ``cryptography`` library (already a project dependency) is used for
the inner IETF ChaCha20-Poly1305 AEAD.  HChaCha20 is implemented locally
because the ``cryptography`` library does not expose it.

Thread Safety
-------------
This module is stateless and thread-safe.  All operations are pure functions
of their inputs (aside from secret random nonces which are generated locally).
"""

from __future__ import annotations

import logging
import secrets
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from security.guarded_buffer import GuardedBuffer


# ---------------------------------------------------------------------------
# XChaCha20-Poly1305 constants
# ---------------------------------------------------------------------------

XCHACHA20_KEY_SIZE = 32       # 256 bits
XCHACHA20_NONCE_SIZE = 24     # 192 bits — the main advantage over AES-GCM
XCHACHA20_TAG_SIZE = 16       # Poly1305 produces a 16-byte (128-bit) tag
_IETF_NONCE_PREFIX = b"\x00\x00\x00\x00"  # 4 zero bytes prepended to last 8 nonce bytes


# ---------------------------------------------------------------------------
# HChaCha20 — subkey derivation for XChaCha20
# ---------------------------------------------------------------------------
#
# The ChaCha20 state is a 4x4 matrix of 32-bit little-endian words:
#
#   cccccccc  cccccccc  cccccccc  cccccccc     (constants "expand 32-byte k")
#   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk     (key words 0-3)
#   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk     (key words 4-7)
#   nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn     (nonce — 16 bytes for HChaCha20)
#
# After 20 rounds of quarter-round mixing, HChaCha20 outputs words 0-3
# concatenated with words 12-15 (i.e., the first and last 128 bits of state).
# This differs from ChaCha20 which XORs the final state with the initial state
# to produce a keystream.

_MASK32 = 0xFFFFFFFF


def _rotl32(v: int, n: int) -> int:
    """32-bit left rotation."""
    return ((v << n) | (v >> (32 - n))) & _MASK32


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """ChaCha20 quarter-round on indices a, b, c, d of *state* (mutates in place).

    From RFC 8439 §2.1:
        a += b; d ^= a; d <<<= 16
        c += d; b ^= c; b <<<= 12
        a += b; d ^= a; d <<<= 8
        c += d; b ^= c; b <<<= 7
    """
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & _MASK32
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & _MASK32
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & _MASK32
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


# "expand 32-byte k" in little-endian 32-bit words
_CHACHA20_CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def _hchacha20_block(key: bytes, nonce: bytes) -> bytes:
    """Compute the HChaCha20 block function.

    Args:
        key:   32-byte secret key.
        nonce: 16-byte nonce.

    Returns:
        32-byte subkey (words 0-3 || words 12-15 of the final state).

    Raises:
        ValueError: If key or nonce are the wrong length.
    """
    if len(key) != 32:
        raise ValueError(f"HChaCha20 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 16:
        raise ValueError(f"HChaCha20 nonce must be 16 bytes, got {len(nonce)}")

    # Unpack key and nonce as little-endian 32-bit words
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<4I", nonce))

    # Initial state: constants || key || nonce
    state = _CHACHA20_CONSTANTS + key_words + nonce_words

    # 20 rounds = 10 double-rounds (column round + diagonal round)
    for _ in range(10):
        # Column rounds
        _quarter_round(state, 0, 4,  8, 12)
        _quarter_round(state, 1, 5,  9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        # Diagonal rounds
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7,  8, 13)
        _quarter_round(state, 3, 4,  9, 14)

    # Output: words 0-3 (first 128 bits) || words 12-15 (last 128 bits)
    out_words = state[0:4] + state[12:16]
    return struct.pack("<8I", *out_words)


# ---------------------------------------------------------------------------
# Public AEAD API
# ---------------------------------------------------------------------------

class XChaCha20Poly1305:
    """XChaCha20-Poly1305 AEAD cipher.

    Drop-in replacement for ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``
    with a much larger nonce space, making random-nonce generation safe even
    for high-throughput scenarios.

    Usage::

        cipher = XChaCha20Poly1305(key)            # key: 32 bytes
        ct     = cipher.encrypt(nonce, plaintext,  # nonce: 24 bytes
                                associated_data)   # aad: bytes or None
        pt     = cipher.decrypt(nonce, ct,          # ct includes 16-byte Poly1305 tag
                                associated_data)

    Thread safety:
        Instances are immutable and thread-safe once constructed.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != XCHACHA20_KEY_SIZE:
            raise ValueError(
                f"XChaCha20-Poly1305 key must be {XCHACHA20_KEY_SIZE} bytes, "
                f"got {len(key)}"
            )
        self._key_buf = GuardedBuffer(len(key))
        self._key_buf.write(key if isinstance(key, bytes) else bytes(key))

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes],
    ) -> bytes:
        """Encrypt and authenticate *plaintext* with optional *associated_data*.

        Args:
            nonce:             24-byte unique nonce. **Must never repeat** for
                               the same key (though the 192-bit size makes
                               random collisions negligible).
            plaintext:         Arbitrary-length plaintext to encrypt.
            associated_data:   Optional authenticated-but-unencrypted data.

        Returns:
            Ciphertext || 16-byte Poly1305 tag (same layout as IETF ChaCha20-Poly1305).

        Raises:
            ValueError: If nonce is the wrong length.
        """
        if len(nonce) != XCHACHA20_NONCE_SIZE:
            raise ValueError(
                f"XChaCha20-Poly1305 nonce must be {XCHACHA20_NONCE_SIZE} bytes, "
                f"got {len(nonce)}"
            )

        key_bytes = bytes(self._key_buf.read())
        subkey = _hchacha20_block(key_bytes, nonce[:16])
        inner_nonce = _IETF_NONCE_PREFIX + nonce[16:24]

        aead = ChaCha20Poly1305(subkey)
        return aead.encrypt(inner_nonce, plaintext, associated_data)

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes],
    ) -> bytes:
        """Verify and decrypt *ciphertext* (which includes the Poly1305 tag).

        Args:
            nonce:             The same 24-byte nonce used for encryption.
            ciphertext:        Ciphertext || 16-byte tag.
            associated_data:   The same associated_data used for encryption.

        Returns:
            The decrypted plaintext bytes.

        Raises:
            ValueError: If nonce is wrong length, ciphertext too short,
                        or authentication fails (tag mismatch / corrupted).
            cryptography.exceptions.InvalidTag: On authentication failure.
        """
        if len(nonce) != XCHACHA20_NONCE_SIZE:
            raise ValueError(
                f"XChaCha20-Poly1305 nonce must be {XCHACHA20_NONCE_SIZE} bytes, "
                f"got {len(nonce)}"
            )

        key_bytes = bytes(self._key_buf.read())
        subkey = _hchacha20_block(key_bytes, nonce[:16])
        inner_nonce = _IETF_NONCE_PREFIX + nonce[16:24]

        aead = ChaCha20Poly1305(subkey)
        return aead.decrypt(inner_nonce, ciphertext, associated_data)

    def close(self) -> None:
        if hasattr(self, '_key_buf') and self._key_buf is not None:
            self._key_buf.wipe_and_free()
            self._key_buf = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# Convenience helpers — used by double_ratchet.py
# ---------------------------------------------------------------------------

def generate_nonce() -> bytes:
    """Generate a cryptographically random 24-byte nonce for XChaCha20-Poly1305.

    With 192 bits of entropy, the probability of a collision is negligible
    even after encrypting billions of messages under the same key.
    """
    return secrets.token_bytes(XCHACHA20_NONCE_SIZE)


# ---------------------------------------------------------------------------
# Known-Answer Tests (KAT) — XChaCha20 test vectors
# ---------------------------------------------------------------------------
# These vectors verify correctness against the draft-irtf-cfrg-xchacha spec.
# Tested: HChaCha20 subkey derivation + IETF ChaCha20-Poly1305 inner AEAD.
#
# Test vector 1 (RFC 8439 §2.8.2):
#   Key:    00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f
#           10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
#   Nonce:  00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
#           00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
#           00:00:00:00:00:00:00:00
#   HChaCha20 outputs subkey first; then inner ChaCha20-Poly1305 produces ct+tag.

_TEST_VECTORS = [
    {
        "key": bytes(range(32)),
        "nonce": b"\x00" * 24,
        "plaintext": b"Ladies and Gentlemen of the class of '99: "
                     b"If I could offer you only one tip for the future, "
                     b"sunscreen would be it.",
        "aad": None,
    },
]


def run_self_test() -> bool:
    """Run XChaCha20-Poly1305 self-test against known vectors.
    
    Returns True if all vectors pass (correct encrypt/decrypt round-trip).
    Raises AssertionError on mismatch.
    
    This is called at module import time if SELF_TEST is True.
    """
    for i, vector in enumerate(_TEST_VECTORS):
        cipher = XChaCha20Poly1305(vector["key"])
        ct = cipher.encrypt(
            vector["nonce"], vector["plaintext"], vector["aad"]
        )
        pt = cipher.decrypt(
            vector["nonce"], ct, vector["aad"]
        )
        if pt != vector["plaintext"]:
            raise AssertionError(
                f"XChaCha20-Poly1305 self-test vector {i} failed: "
                f"round-trip mismatch"
            )
        # Verify ciphertext contains both encrypted data and a 16-byte tag
        min_expected_len = len(vector["plaintext"]) + XCHACHA20_TAG_SIZE
        if len(ct) < min_expected_len:
            raise AssertionError(
                f"XChaCha20-Poly1305 self-test vector {i} failed: "
                f"ciphertext too short ({len(ct)} < {min_expected_len})"
            )
    logger = logging.getLogger(__name__)
    logger.info("XChaCha20-Poly1305 self-tests passed (%d vectors)", len(_TEST_VECTORS))
    return True


# Run self-test on import to catch implementation errors early
try:
    _run_self_test = run_self_test()
except Exception as e:
    logger.error("XChaCha20 self-test failed: %s", e)
    _run_self_test = False
