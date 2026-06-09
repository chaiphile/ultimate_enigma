"""ECDH Key Exchange service – pure crypto, no UI dependency."""

import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from crypto import sha256_fingerprint


class ECDHService:
    """X25519 key agreement operations."""

    INFO = b"enigma-ecdh"
    KEY_LENGTH = 32

    @staticmethod
    def generate_private_key() -> X25519PrivateKey:
        """Generate a new ephemeral X25519 private key."""
        return X25519PrivateKey.generate()

    @staticmethod
    def private_to_public_bytes(private_key: X25519PrivateKey) -> bytes:
        """Extract the raw 32‑byte public key from a private key."""
        pub = private_key.public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def public_bytes_to_key(public_bytes: bytes) -> X25519PublicKey:
        """Convert raw 32‑byte public bytes to an X25519PublicKey object."""
        if len(public_bytes) != 32:
            raise ValueError("Public key must be exactly 32 bytes")
        return X25519PublicKey.from_public_bytes(public_bytes)

    @staticmethod
    def compute_shared_secret(
        private_key: X25519PrivateKey,
        peer_public_bytes: bytes,
    ) -> bytes:
        """Perform the X25519 Diffie‑Hellman exchange. Returns raw 32‑byte shared secret."""
        peer_key = ECDHService.public_bytes_to_key(peer_public_bytes)
        return private_key.exchange(peer_key)

    @staticmethod
    def derive_key(shared_secret_bytes: bytes) -> bytes:
        """Derive a 32‑byte symmetric key from the raw shared secret using HKDF."""
        if len(shared_secret_bytes) != 32:
            raise ValueError("Shared secret must be 32 bytes")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=ECDHService.KEY_LENGTH,
            salt=None,
            info=ECDHService.INFO,
            backend=default_backend(),
        )
        return hkdf.derive(shared_secret_bytes)

    @staticmethod
    def encode_public_key(public_bytes: bytes) -> str:
        """Base64‑encode a raw public key (32 bytes)."""
        return base64.b64encode(public_bytes).decode("ascii")

    @staticmethod
    def decode_public_key(b64_string: str) -> bytes:
        """Decode a Base64 public key, returning raw 32 bytes. Raises ValueError on invalid input."""
        try:
            raw = base64.b64decode(b64_string)
            if len(raw) != 32:
                raise ValueError
            return raw
        except Exception:
            raise ValueError("Invalid Base64 public key")

    @staticmethod
    def fingerprint(public_bytes: bytes) -> str:
        """SHA‑256 fingerprint (first 16 hex chars) of a raw public key."""
        return sha256_fingerprint(public_bytes)

    @classmethod
    def generate_keypair(cls):
        """Return (private_key, raw_public_bytes)."""
        priv = cls.generate_private_key()
        pub = cls.private_to_public_bytes(priv)
        return priv, pub

    @classmethod
    def perform_exchange(cls, peer_public_bytes: bytes, own_private=None):
        """
        High‑level ECDH exchange.
        If `own_private` is None, a new ephemeral keypair is generated.
        Returns (derived_32_byte_key, our_public_bytes).
        """
        if own_private is None:
            own_private, our_pub = cls.generate_keypair()
        else:
            our_pub = cls.private_to_public_bytes(own_private)
        shared = cls.compute_shared_secret(own_private, peer_public_bytes)
        derived = cls.derive_key(shared)
        return derived, our_pub