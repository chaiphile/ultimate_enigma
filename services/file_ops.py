"""
Standalone file encryption/decryption functions – extracted from file_service.py.

Low-level operations with no dependency on KeyStore or service layer.
"""

import os
import struct
import hashlib
import secrets
import logging
from typing import Optional, Tuple, List, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import database
from crypto import rsa_sign, rsa_verify, sha256_fingerprint
from src.timeout import run_with_timeout
from src.constants import CONCURRENCY_CONSTANTS, CRYPTO_CONSTANTS, KDF_PARAMS
from src.exceptions import CryptoTimeoutError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File format constants
# ---------------------------------------------------------------------------

FILE_MAGIC = b'ENIGMA\x01'

_FILE_KDF_VERSION_ARGON2ID = b'A2ID'
_FILE_KDF_LEGACY_PBKDF2_ITERATIONS = 300_000

_FILE_FLAG_RSA_SIGN = 1
_FILE_FLAG_HYBRID_SIGN = 2

try:
    from services.pqc_signatures import HybridSigner
    _HYBRID_SIG_AVAILABLE = True
except (ImportError, RuntimeError, OSError):
    HybridSigner = None  # type: ignore[assignment,misc]
    _HYBRID_SIG_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_file_bytes(path: str) -> bytes:
    """Read entire file contents. Helper for timeout wrapping."""
    with open(path, 'rb') as f:
        return f.read()


def _pubkey_to_pem(pub) -> str:
    """Helper to convert a public key object to PEM string."""
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')


# ---------------------------------------------------------------------------
# Password-based file encryption/decryption
# ---------------------------------------------------------------------------

def file_encrypt(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a file using AES-GCM with Argon2id-derived key.

    File format: A2ID(4) + salt(16) + nonce(12) + ciphertext
    """
    salt = secrets.token_bytes(database.ARGON2_SALT_LEN)

    kdf_timeout = CONCURRENCY_CONSTANTS.get("ARGON2ID_TIMEOUT", 90.0)
    try:
        key = run_with_timeout(
            database._derive_key_argon2id, kdf_timeout, password, salt
        )
    except CryptoTimeoutError:
        raise ValueError(
            f"Key derivation timed out after {kdf_timeout:.0f}s. "
            "The system may be under heavy load."
        )

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"])

    file_timeout = CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0)
    try:
        plaintext = run_with_timeout(_read_file_bytes, file_timeout, input_path)
    except CryptoTimeoutError:
        raise ValueError(
            f"File read timed out after {file_timeout:.0f}s. "
            "The file may be too large."
        )

    ct = aesgcm.encrypt(nonce, plaintext, None)
    with open(output_path, 'wb') as f:
        f.write(_FILE_KDF_VERSION_ARGON2ID)
        f.write(salt)
        f.write(nonce)
        f.write(ct)


def file_decrypt(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a file with automatic KDF detection.

    Supports Argon2id (new, tagged with A2ID header) and
    PBKDF2-HMAC-SHA256 (legacy, no header).
    """
    kdf_timeout = CONCURRENCY_CONSTANTS.get("ARGON2ID_TIMEOUT", 90.0)

    with open(input_path, 'rb') as f:
        header = f.read(4)
        if header == _FILE_KDF_VERSION_ARGON2ID:
            salt = f.read(16)
            nonce = f.read(12)
            ct = f.read()
            try:
                key = run_with_timeout(
                    database._derive_key_argon2id, kdf_timeout, password, salt
                )
            except CryptoTimeoutError:
                raise ValueError(
                    f"Key derivation timed out after {kdf_timeout:.0f}s. "
                    "The system may be under heavy load."
                )
        else:
            salt = header + f.read(12)
            nonce = f.read(12)
            ct = f.read()

            def _derive_pbkdf2():
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=_FILE_KDF_LEGACY_PBKDF2_ITERATIONS,
                    backend=default_backend()
                )
                return kdf.derive(password.encode())

            try:
                key = run_with_timeout(_derive_pbkdf2, kdf_timeout)
            except CryptoTimeoutError:
                raise ValueError(
                    f"Key derivation timed out after {kdf_timeout:.0f}s."
                )

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted file")

    with open(output_path, 'wb') as f:
        f.write(plaintext)


# ---------------------------------------------------------------------------
# Shared-secret file encryption/decryption
# ---------------------------------------------------------------------------

def file_encrypt_shared(
    input_path: str,
    output_path: str,
    shared_secret: bytes,
    sign: bool = False,
    my_priv=None,
    hybrid_ed_priv=None,
    hybrid_dil_priv: Optional[bytes] = None,
) -> None:
    """Encrypt a file using a shared secret with optional signature.

    File format:
        FILE_MAGIC(7) | flags(1) | fp(16) | salt(16) | nonce(12) |
        [sig_len(2) | sig(variable)] | ciphertext
    """
    salt = secrets.token_bytes(KDF_PARAMS["ARGON2_SALT_LEN"])
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"enigma-file-v1",
        backend=default_backend()
    )
    key = hkdf.derive(shared_secret)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    flags = 0
    signature = b""

    use_hybrid_sig = (
        sign
        and hybrid_ed_priv is not None
        and hybrid_dil_priv is not None
        and _HYBRID_SIG_AVAILABLE
    )

    if use_hybrid_sig:
        flags |= _FILE_FLAG_HYBRID_SIGN
        signature = HybridSigner.sign(plaintext, hybrid_ed_priv, hybrid_dil_priv)
    elif sign and my_priv:
        flags |= _FILE_FLAG_RSA_SIGN
        signature = rsa_sign(plaintext, my_priv)

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"])
    ct = aesgcm.encrypt(nonce, plaintext, None)

    fp = hashlib.sha256(shared_secret).digest()[:16]

    with open(output_path, 'wb') as f:
        f.write(FILE_MAGIC)
        f.write(bytes([flags]))
        f.write(fp)
        f.write(salt)
        f.write(nonce)
        if signature:
            f.write(struct.pack(">H", len(signature)))
            f.write(signature)
        f.write(ct)


def file_decrypt_shared(
    input_path: str,
    output_path: str,
    secrets_dict: Dict[bytes, Tuple[bytes, Optional[str]]],
    friends_for_sig: Optional[List[Tuple[str, object]]] = None,
    friends_hybrid: Optional[List[Tuple[str, bytes, bytes]]] = None,
) -> str:
    """Decrypt a shared-secret encrypted file.

    Returns a signature verification message (may be empty).
    """
    with open(input_path, 'rb') as f:
        magic = f.read(len(FILE_MAGIC))
        if magic != FILE_MAGIC:
            raise ValueError("Not a shared-secret encrypted file (invalid magic)")

        flags_byte = f.read(1)
        if len(flags_byte) < 1:
            raise ValueError("File too short")
        flags = flags_byte[0]
        has_rsa_sign = bool(flags & _FILE_FLAG_RSA_SIGN)
        has_hybrid_sign = bool(flags & _FILE_FLAG_HYBRID_SIGN)

        fp = f.read(16)
        salt = f.read(16)
        nonce = f.read(12)

        signature = b""
        if has_rsa_sign or has_hybrid_sign:
            siglen_bytes = f.read(2)
            if len(siglen_bytes) < 2:
                raise ValueError("File too short")
            siglen = struct.unpack(">H", siglen_bytes)[0]
            signature = f.read(siglen)
            if len(signature) != siglen:
                raise ValueError("File too short")
        ct = f.read()

    if fp not in secrets_dict:
        raise ValueError("No matching shared secret found - fingerprint unknown")

    secret, owner = secrets_dict[fp]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"enigma-file-v1",
        backend=default_backend()
    )
    key = hkdf.derive(secret)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed - wrong shared secret or corrupted file")

    sig_msg = ""

    if has_hybrid_sign and signature and friends_hybrid:
        verified = False
        signer_name = None
        for name, ed_pub_bytes, dil_pub_bytes in friends_hybrid:
            try:
                from crypto import hybrid_verify
                if hybrid_verify(plaintext, signature, ed_pub_bytes, dil_pub_bytes):
                    verified = True
                    signer_name = name
                    break
            except Exception:
                continue
        if verified:
            sig_msg = f"✅ Hybrid Signature Verified (Ed25519 + Dilithium3) from {signer_name}"
        else:
            sig_msg = "⚠️ Hybrid Signature INVALID or sender unknown"

    elif has_rsa_sign and signature and friends_for_sig:
        verified = False
        for name, pub in friends_for_sig:
            if rsa_verify(plaintext, signature, pub):
                verified = True
                sig_msg = f"Signature verified from {name}"
                pem = _pubkey_to_pem(pub)
                fp_key = sha256_fingerprint(pem.encode())
                sig_msg += f" (key fingerprint: {fp_key})"
                break
        if not verified:
            sig_msg = "Signature INVALID or sender unknown"

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return sig_msg
