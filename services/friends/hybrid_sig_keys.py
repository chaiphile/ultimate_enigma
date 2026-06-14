"""
Hybrid signature key management – extracted from FriendsService.
"""

from typing import Optional

import base64

from key_manager import KeyStore
from crypto import sha256_fingerprint
from services.friends.crud import FriendCrudService, FriendsServiceError


class FriendHybridSigKeyService:
    """Manages hybrid signing keys (Ed25519 + Dilithium3) for friends."""

    def __init__(self, key_store: KeyStore, crud: FriendCrudService):
        self._ks = key_store
        self._crud = crud

    def friend_has_hybrid_sig_key(self, name: str) -> bool:
        """Check if a friend has a hybrid signing combined public key stored."""
        return name in self._ks.friends_hybrid_sig_pubs

    def get_my_hybrid_sig_combined_pub(self) -> Optional[str]:
        """Return my hybrid signing combined public key as Base64, or None if not generated."""
        if self._ks.my_hybrid_sig_combined_pub:
            return base64.b64encode(self._ks.my_hybrid_sig_combined_pub).decode()
        return None

    def generate_hybrid_sig_keys(self, master_password: str) -> str:
        """Generate hybrid signing keys (Ed25519 + Dilithium3/ML-DSA-65) and store them.

        Args:
            master_password: Used to encrypt the private key material.

        Returns:
            Base64-encoded combined public key for sharing with friends.

        Raises:
            FriendsServiceError: If key generation fails or liboqs is unavailable.
        """
        try:
            from services.pqc_signatures import HybridSigner
        except (ImportError, RuntimeError, OSError) as e:
            raise FriendsServiceError(
                "Hybrid signatures are not available.\n\n"
                "The liboqs native library is required but could not be loaded.\n"
                "Install it with:\n"
                "  pip install liboqs-python\n"
                "You also need the liboqs shared library (liboqs.dll / liboqs.so) on your system."
            ) from e

        try:
            keys = HybridSigner.generate_keys()
        except Exception as e:
            raise FriendsServiceError(f"Failed to generate hybrid signing keys: {e}") from e

        # Encrypt and store Ed25519 private key (raw 32 bytes)
        import database
        import json
        from contextlib import closing

        ed_priv_bytes = keys['ed_priv'].private_bytes_raw()
        ed_priv_enc = database.encrypt_secret(ed_priv_bytes, master_password)
        dil_priv_enc = database.encrypt_secret(keys['dil_priv'], master_password)
        combined_pub_b64 = base64.b64encode(keys['combined_pub']).decode()

        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("ed25519_priv_encrypted", json.dumps(ed_priv_enc))
                )
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("dilithium_priv_encrypted", json.dumps(dil_priv_enc))
                )
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ("hybrid_sig_combined_pub_b64", combined_pub_b64)
                )
                conn.commit()
        except Exception as e:
            raise FriendsServiceError(f"Failed to store hybrid signing keys: {e}") from e

        # Update in-memory state
        self._ks.my_ed_priv = keys['ed_priv']
        self._ks.my_dil_priv = keys['dil_priv']
        self._ks.my_hybrid_sig_combined_pub = keys['combined_pub']

        return combined_pub_b64

    def import_friend_hybrid_sig_pub(
        self,
        friend_name: str,
        combined_pub_b64: str,
        master_password: str = "",
    ) -> None:
        """Import and store a friend's hybrid signing combined public key.

        Args:
            friend_name: Name of the friend.
            combined_pub_b64: Base64-encoded combined public key.
            master_password: Required if the friend has a shared secret (for re-encryption).

        Raises:
            FriendsServiceError: If import fails or the key is invalid.
        """
        if not self._crud.friend_exists(friend_name):
            raise FriendsServiceError(f"Friend '{friend_name}' not found")

        # Validate the key
        try:
            raw = base64.b64decode(combined_pub_b64)
            if len(raw) < 36:
                raise ValueError("Too short to be a valid hybrid signing combined public key")
            # Attempt to parse it to verify it's valid
            from services.pqc_signatures import HybridSigner
            HybridSigner.parse_combined_pub(raw)
        except Exception as e:
            raise FriendsServiceError(f"Invalid hybrid signing combined public key: {e}") from e

        # Re-save the friend with the new hybrid sig key
        details = self._crud.get_friend_details(friend_name)
        if not details:
            raise FriendsServiceError(f"Friend '{friend_name}' details not found")

        secret = self._crud.get_friend_secret(friend_name)
        x_b64 = self._crud.get_friend_x25519_key(friend_name)
        caps = self._crud.get_friend_capabilities(friend_name)
        pqc_b64 = None
        if friend_name in self._ks.friends_pqc_combined_pub:
            pqc_b64 = base64.b64encode(self._ks.friends_pqc_combined_pub[friend_name]).decode()

        pw = master_password
        if secret and not pw:
            raise FriendsServiceError(
                "Master password required to encrypt shared secret during save"
            )

        self._ks.save_friend(
            name=friend_name,
            pem=details["public_key_pem"],
            shared_secret=secret,
            password=pw,
            x25519_pub_b64=x_b64,
            capabilities=caps if caps else None,
            pqc_combined_pub_b64=pqc_b64,
            hybrid_sig_pub_b64=combined_pub_b64,
        )

    def get_friend_hybrid_sig_pub_b64(self, friend_name: str) -> Optional[str]:
        """Return a friend's hybrid signing combined public key as Base64, or None."""
        if not self.friend_has_hybrid_sig_key(friend_name):
            return None
        ed_pub_bytes, dil_pub_bytes = self._ks.friends_hybrid_sig_pubs[friend_name]
        import struct
        combined = struct.pack(">H", len(ed_pub_bytes)) + ed_pub_bytes
        combined += struct.pack(">H", len(dil_pub_bytes)) + dil_pub_bytes
        return base64.b64encode(combined).decode()

    def get_hybrid_sig_key_fingerprint(self, combined_pub_b64: str) -> Optional[str]:
        """Return a SHA-256 fingerprint of a hybrid signing combined public key.

        Args:
            combined_pub_b64: Base64-encoded combined public key.

        Returns:
            Hex fingerprint string, or None on error.
        """
        try:
            raw = base64.b64decode(combined_pub_b64)
            return sha256_fingerprint(raw)
        except (ValueError, TypeError):
            return None
