"""
File encryption/decryption service layer.
Handles password and shared-secret file operations, fingerprint detection,
and signature verification.  Keeps UI logic minimal by raising dedicated
exceptions when user confirmation is required.
"""

import os
import tempfile
import hashlib
from typing import Optional, Tuple

from key_manager import (
    file_encrypt,
    file_decrypt,
    file_encrypt_shared,
    file_decrypt_shared,
    FILE_MAGIC,
)


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
        super().__init__(f"Shared secret for '{owner}' detected – confirmation required")


class FileService:
    """Thin wrapper around key_manager file functions, using a KeyStore instance."""

    def __init__(self, key_store):
        """
        Args:
            key_store: must expose `global_secret`, `my_priv`, `friends`,
                       `get_friend_secret(name)`, and the friend list structure
                       used by `file_decrypt_shared`.
        """
        self._ks = key_store

    # ----------------------------------------------------------------
    # Public API – Encryption
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
    # Public API – Decryption
    # ----------------------------------------------------------------
    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: Optional[str] = None,
    ) -> str:
        """
        Decrypt a file, automatically choosing the correct method.

        Behaviour:
            - If the file has the ``FILE_MAGIC`` header, it is treated as a
              shared-secret encrypted file.
            - If the file does **not** have the magic but the first 16 bytes match
              a known shared-secret fingerprint, :class:`SharedSecretDetected` is
              raised (so the UI can ask the user to confirm).
            - Otherwise a password is required – if *password* is omitted,
              :class:`FileServiceError` is raised.

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
        # Build secrets dictionary and verify fingerprint
        secrets_dict = self._build_secrets_dict()
        if fingerprint not in secrets_dict:
            raise FileServiceError("Unknown shared secret fingerprint")

        # The original file lacks the magic header – reconstruct it in a temp file.
        with open(input_path, "rb") as f:
            data = f.read()

        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmp.write(FILE_MAGIC + data)   # data already contains flags+fingerprint+payload
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