"""Shared cryptographic PEM and password utilities.

Consolidates duplicated helpers from key_manager.py, models/key_store.py,
and crypto.py to satisfy DRY and single-responsibility principles.
"""

from typing import Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from src.secure_string import SecureString


def password_to_bytes(password: Union[str, bytes, SecureString]) -> bytes:
    """Convert a password (str, bytes, or SecureString) to raw bytes."""
    if hasattr(password, 'to_bytes'):
        return password.to_bytes()
    elif isinstance(password, str):
        return password.encode('utf-8')
    elif isinstance(password, bytes):
        return password
    else:
        return str(password).encode('utf-8')


def pem_to_pubkey(pem: str):
    """Load a PEM-encoded public key."""
    return serialization.load_pem_public_key(pem.encode('ascii'), backend=default_backend())


def pem_to_privkey(pem: bytes, password: Union[str, bytes, SecureString]):
    """Load a PEM-encoded private key, decrypting with the given password."""
    pw_bytes = password_to_bytes(password)
    return serialization.load_pem_private_key(pem, password=pw_bytes, backend=default_backend())


def privkey_to_encrypted_pem(priv, password: Union[str, bytes, SecureString]) -> str:
    """Encrypt a private key to PEM format with the given password."""
    pw_bytes = password_to_bytes(password)
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pw_bytes)
    ).decode('ascii')


def pubkey_to_pem(pub) -> str:
    """Encode a public key to PEM string."""
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')
