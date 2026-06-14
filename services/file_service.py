"""
File encryption/decryption service layer.
Handles password and shared-secret file operations, fingerprint detection,
and signature verification.  Keeps UI logic minimal by raising dedicated
exceptions when user confirmation is required.
"""

import os
import hashlib
import tempfile
import logging
from typing import Optional, Tuple

from key_manager import KeyStore

logger = logging.getLogger(__name__)

# Re-export standalone functions and constants for backward compatibility.
# New code should import from services.file_ops directly.
from services.file_ops import (  # noqa: F401
    FILE_MAGIC,
    file_encrypt,
    file_decrypt,
    file_encrypt_shared,
    file_decrypt_shared,
)


# ---------------------------------------------------------------------------
# Service exceptions
# ---------------------------------------------------------------------------

class FileServiceError(Exception):
    """Base exception for file service errors."""


class SharedSecretDetected(FileServiceError):
    """Raised when a shared-secret encrypted file (without magic header) is detected."""
    def __init__(self, owner: str, fingerprint: bytes):
        self.owner = owner
        self.fingerprint = fingerprint
        super().__init__(f"Shared secret for '{owner}' detected - confirmation required")


# ---------------------------------------------------------------------------
# FileService class
# ---------------------------------------------------------------------------

class FileService:
    """Service layer for file encryption/decryption operations."""

    def __init__(self, key_store: KeyStore):
        self._ks = key_store

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        method: str,
        password: Optional[str] = None,
        friend_name: Optional[str] = None,
        sign: bool = False,
    ) -> None:
        """Encrypt a file using the specified method."""
        if method == "password":
            if not password:
                raise FileServiceError("Password required")
            file_encrypt(input_path, output_path, password)
            return

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
        hybrid_ed_priv = getattr(self._ks, 'my_ed_priv', None) if sign else None
        hybrid_dil_priv = getattr(self._ks, 'my_dil_priv', None) if sign else None
        file_encrypt_shared(
            input_path, output_path, secret,
            sign=sign,
            my_priv=my_priv,
            hybrid_ed_priv=hybrid_ed_priv,
            hybrid_dil_priv=hybrid_dil_priv,
        )

    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: Optional[str] = None,
    ) -> str:
        """Decrypt a file, automatically choosing the correct method."""
        magic = self._read_magic(input_path)
        if magic == FILE_MAGIC:
            return self._decrypt_shared_file(input_path, output_path)

        fp_match = self._detect_shared_fingerprint(input_path)
        if fp_match is not None:
            fingerprint, owner = fp_match
            raise SharedSecretDetected(owner, fingerprint)

        if password is None:
            raise FileServiceError("Password required")
        file_decrypt(input_path, output_path, password)
        return ""

    def decrypt_with_shared_secret(
        self,
        input_path: str,
        output_path: str,
        fingerprint: bytes,
    ) -> str:
        """Decrypt a shared-secret file after user confirmation."""
        secrets_dict = self._build_secrets_dict()
        if fingerprint not in secrets_dict:
            raise FileServiceError("Unknown shared secret fingerprint")

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
        except (OSError, ValueError, KeyError) as e:
            logger.debug("Fingerprint detection failed for %s: %s", path, e)
        return None

    def _decrypt_shared_file(self, input_path: str, output_path: str) -> str:
        """Decrypt using all available shared secrets and return signature message."""
        from services.file_ops import _HYBRID_SIG_AVAILABLE

        secrets_dict = self._build_secrets_dict()
        if not secrets_dict:
            raise FileServiceError("No shared secrets available")
        friends_for_sig = [(name, pub) for name, pub, _ in self._ks.friends]
        friends_hybrid = []
        hybrid_pubs = getattr(self._ks, 'friends_hybrid_sig_pubs', {})
        for name, (ed_pub, dil_pub) in hybrid_pubs.items():
            friends_hybrid.append((name, ed_pub, dil_pub))
        my_combined_pub = getattr(self._ks, 'my_hybrid_sig_combined_pub', None)
        if my_combined_pub and _HYBRID_SIG_AVAILABLE:
            try:
                from services.pqc_signatures import HybridSigner
                my_ed_pub, my_dil_pub = HybridSigner.parse_combined_pub(my_combined_pub)
                friends_hybrid.append(("myself", my_ed_pub, my_dil_pub))
            except (ValueError, TypeError) as e:
                logger.debug("Could not parse hybrid sig combined pub: %s", e)
        sig_msg = file_decrypt_shared(
            input_path, output_path, secrets_dict,
            friends_for_sig=friends_for_sig,
            friends_hybrid=friends_hybrid,
        )
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
