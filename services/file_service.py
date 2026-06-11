"""
File encryption/decryption service layer.
Handles password and shared-secret file operations, fingerprint detection,
and signature verification.  Keeps UI logic minimal by raising dedicated
exceptions when user confirmation is required.

Timeout Integration:
    Argon2id KDF and large file operations are wrapped in timeouts to
    prevent indefinite blocking when processing large files or under
    heavy system load.
"""

import os
import struct
import hashlib
import secrets
import tempfile
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
from src.constants import CONCURRENCY_CONSTANTS
from src.exceptions import CryptoTimeoutError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File format constants
# ---------------------------------------------------------------------------

FILE_MAGIC = b'ENIGMA\x01'   # 7-byte magic for shared-secret encrypted files

# KDF version tag for password-based file encryption
_FILE_KDF_VERSION_ARGON2ID = b'A2ID'  # 4-byte magic for Argon2id files
_FILE_KDF_LEGACY_PBKDF2_ITERATIONS = 300_000


# ---------------------------------------------------------------------------
# Standalone file encryption/decryption functions
# ---------------------------------------------------------------------------

def file_encrypt(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a file using AES-GCM with Argon2id-derived key.

    File format: A2ID(4) + salt(16) + nonce(12) + ciphertext

    Timeout: The Argon2id KDF is wrapped in a timeout to prevent indefinite
    blocking on memory-hard key derivation.
    """
    salt = secrets.token_bytes(database.ARGON2_SALT_LEN)

    # Wrap KDF in timeout to prevent indefinite blocking
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
    nonce = secrets.token_bytes(12)

    # Read file with timeout for very large files
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

    Timeout: KDF operations and file I/O are wrapped in timeouts.
    """
    file_timeout = CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0)
    kdf_timeout = CONCURRENCY_CONSTANTS.get("ARGON2ID_TIMEOUT", 90.0)

    with open(input_path, 'rb') as f:
        header = f.read(4)
        if header == _FILE_KDF_VERSION_ARGON2ID:
            # New Argon2id format
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
            # Legacy PBKDF2 format: header is actually first 4 bytes of salt
            salt = header + f.read(12)  # remaining 12 bytes of 16-byte salt
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


def file_encrypt_shared(
    input_path: str,
    output_path: str,
    shared_secret: bytes,
    sign: bool = False,
    my_priv=None
) -> None:
    """Encrypt a file using a shared secret with optional RSA signature."""
    salt = secrets.token_bytes(16)
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
    if sign and my_priv:
        signature = rsa_sign(plaintext, my_priv)
        flags |= 1

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
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
    friends_for_sig: Optional[List[Tuple[str, object]]] = None
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
        has_sign = bool(flags & 1)

        fp = f.read(16)
        salt = f.read(16)
        nonce = f.read(12)

        signature = b""
        if has_sign:
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
    if has_sign and signature and friends_for_sig:
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


# ---------------------------------------------------------------------------
# Service exceptions
# ---------------------------------------------------------------------------

class FileServiceError(Exception):
    """Base exception for file service errors."""


class SharedSecretDetected(FileServiceError):
    """Raised when a shared-secret encrypted file (without magic header) is detected.
    The UI should ask the user for confirmation and then call
    :meth:`FileService.decrypt_with_shared_secret` with the provided fingerprint.
    """
    def __init__(self, owner: str, fingerprint: bytes):
        self.owner = owner
        self.fingerprint = fingerprint
        super().__init__(f"Shared secret for '{owner}' detected - confirmation required")


# ---------------------------------------------------------------------------
# FileService class
# ---------------------------------------------------------------------------

class FileService:
    """Service layer for file encryption/decryption operations."""

    def __init__(self, key_store):
        """
        Args:
            key_store: must expose `global_secret`, `my_priv`, `friends`,
                       `get_friend_secret(name)`, and the friend list structure
                       used by `file_decrypt_shared`.
        """
        self._ks = key_store

    # ----------------------------------------------------------------
    # Public API - Encryption
    # ----------------------------------------------------------------
    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        method: str,
        password: Optional[str] = None,
        friend_name: Optional[str] = None,
        sign: bool = False,
    ) -> None:
        """
        Encrypt a file.

        Args:
            input_path: path to the plaintext file.
            output_path: where to write the encrypted file.
            method: one of ``'password'``, ``'global'``, ``'friend'``.
            password: required when *method* is ``'password'``.
            friend_name: required when *method* is ``'friend'``.
            sign: if True, attach an RSA signature (requires a loaded private key).

        Raises:
            FileServiceError: on any error (missing keys, wrong method, etc.).
        """
        if method == "password":
            if not password:
                raise FileServiceError("Password required")
            file_encrypt(input_path, output_path, password)
            return

        # shared-secret based encryption
        if method == "global":
            secret = self._ks.global_secret
            if not secret:
                raise FileServiceError("No global shared secret available")
        elif method == "friend":
            if not friend_name:
                raise FileServiceError("Friend name required")
            secret = self._ks.get_friend_secret(friend_name)
            if not secret:
                raise FileServiceError(f"No shared secret for friend '{friend_name}'")
        else:
            raise FileServiceError(f"Unknown method: {method}")

        my_priv = self._ks.my_priv if sign else None
        file_encrypt_shared(input_path, output_path, secret, sign=sign, my_priv=my_priv)

    # ----------------------------------------------------------------
    # Public API - Decryption
    # ----------------------------------------------------------------
    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: Optional[str] = None,
    ) -> str:
        """
        Decrypt a file, automatically choosing the correct method.

        Returns:
            A signature verification message (may be empty for password-based files).

        Raises:
            SharedSecretDetected: when a shared-secret file (without magic) is found.
            FileServiceError: on missing password, corrupted file, or unknown key.
        """
        # 1. Try magic header
        magic = self._read_magic(input_path)
        if magic == FILE_MAGIC:
            return self._decrypt_shared_file(input_path, output_path)

        # 2. Look for a matching fingerprint (shared-secret file without magic)
        fp_match = self._detect_shared_fingerprint(input_path)
        if fp_match is not None:
            fingerprint, owner = fp_match
            raise SharedSecretDetected(owner, fingerprint)

        # 3. Fallback to password
        if password is None:
            raise FileServiceError("Password required")
        file_decrypt(input_path, output_path, password)
        return ""   # no signature info for password-based files

    def decrypt_with_shared_secret(
        self,
        input_path: str,
        output_path: str,
        fingerprint: bytes,
    ) -> str:
        """
        Decrypt a shared-secret file after the user confirmed the detected fingerprint.
        This method should be called after :class:`SharedSecretDetected` was raised.
        """
        secrets_dict = self._build_secrets_dict()
        if fingerprint not in secrets_dict:
            raise FileServiceError("Unknown shared secret fingerprint")

        # The original file lacks the magic header - reconstruct it in a temp file.
        with open(input_path, "rb") as f:
            data = f.read()

        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmp.write(FILE_MAGIC + data)
            tmp_path = tmp.name
        finally:
            tmp.close()

        try:
            return self._decrypt_shared_file(tmp_path, output_path)
        finally:
            os.unlink(tmp_path)

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------
    def _read_magic(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read(len(FILE_MAGIC))

    def _detect_shared_fingerprint(self, path: str) -> Optional[Tuple[bytes, str]]:
        """If the file contains a known fingerprint at offset 1..16, return (fp, owner)."""
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) < 17:
                return None
            fp = data[1:17]
            secrets_dict = self._build_secrets_dict()
            for stored_fp, (_, owner) in secrets_dict.items():
                if stored_fp == fp:
                    return (stored_fp, owner)
        except Exception:
            pass
        return None

    def _decrypt_shared_file(self, input_path: str, output_path: str) -> str:
        """Decrypt using all available shared secrets and return signature message."""
        secrets_dict = self._build_secrets_dict()
        if not secrets_dict:
            raise FileServiceError("No shared secrets available")
        friends_for_sig = [(name, pub) for name, pub, _ in self._ks.friends]
        sig_msg = file_decrypt_shared(input_path, output_path, secrets_dict, friends_for_sig)
        return sig_msg

    def _build_secrets_dict(self) -> dict:
        """Return a dict mapping fingerprint (16 bytes) -> (secret, owner_name)."""
        secrets_dict = {}
        if self._ks.global_secret:
            fp = hashlib.sha256(self._ks.global_secret).digest()[:16]
            secrets_dict[fp] = (self._ks.global_secret, "Global")
        for name, pub, sec in self._ks.friends:
            if sec:
                fp = hashlib.sha256(sec).digest()[:16]
                secrets_dict[fp] = (sec, name)
        return secrets_dict
