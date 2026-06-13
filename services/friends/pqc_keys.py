"""
Post-Quantum Hybrid KEM key management – extracted from FriendsService.
"""

from typing import Optional, Tuple

import base64

from key_manager import KeyStore
from services.pqc_service import HybridKEM, is_pqc_available
from services.friends.crud import FriendsServiceError


class FriendPqcKeyService:
    """Manages Post-Quantum Hybrid KEM key exchange for friends."""

    def __init__(self, key_store: KeyStore):
        self._ks = key_store

    def get_my_pqc_combined_pub(self) -> Optional[str]:
        """Return my PQC combined public key as Base64, or None if not generated."""
        if self._ks.my_pqc_combined_pub:
            return base64.b64encode(self._ks.my_pqc_combined_pub).decode()
        return None

    def generate_pqc_keys(self, master_password: str) -> str:
        """Generate hybrid PQC keys and return the combined public key as Base64.

        Args:
            master_password: Used to encrypt the private key material.

        Returns:
            Base64-encoded combined public key for sharing with friends.

        Raises:
            FriendsServiceError: If key generation fails or liboqs is unavailable.
        """
        if not is_pqc_available():
            raise FriendsServiceError(
                "Post-quantum cryptography is not available.\n\n"
                "The liboqs native library is required but could not be loaded.\n"
                "Install it with:\n"
                "  pip install liboqs-python\n"
                "You also need the liboqs shared library (liboqs.dll / liboqs.so) on your system."
            )
        keys = self._ks.ensure_pqc_keys_full(master_password)
        if not keys:
            raise FriendsServiceError("Failed to generate PQC hybrid keys")
        return base64.b64encode(keys['combined_pub']).decode()

    def pqc_encapsulate(
        self,
        friend_name: str,
        master_password: str,
    ) -> Tuple[str, bytes]:
        """Perform hybrid KEM encapsulation using a friend's PQC combined public key.

        Generates a shared secret and a ciphertext to send to the friend.

        Args:
            friend_name: Name of the friend whose combined_pub to use.
            master_password: Not used directly but validated for consistency.

        Returns:
            (ciphertext_b64, shared_secret) tuple.

        Raises:
            FriendsServiceError: If friend has no PQC key or encapsulation fails.
        """
        combined_pub = self._ks.friends_pqc_combined_pub.get(friend_name)
        if not combined_pub:
            raise FriendsServiceError(
                f"No PQC combined public key stored for '{friend_name}'. "
                "Import their PQC public key first."
            )
        if not is_pqc_available():
            raise FriendsServiceError(
                "Post-quantum cryptography is not available (liboqs not installed)."
            )
        try:
            result = HybridKEM.encapsulate(combined_pub)
            ct_b64 = base64.b64encode(result['ciphertext']).decode()
            return ct_b64, result['shared_secret']
        except Exception as e:
            raise FriendsServiceError(f"PQC encapsulation failed: {e}") from e

    def pqc_decapsulate(
        self,
        ciphertext_b64: str,
        master_password: str,
    ) -> bytes:
        """Perform hybrid KEM decapsulation using local PQC private keys.

        Args:
            ciphertext_b64: Base64-encoded ciphertext received from a friend.
            master_password: Used to decrypt the local PQC private key bundle.

        Returns:
            32-byte shared secret.

        Raises:
            FriendsServiceError: If keys are missing or decapsulation fails.
        """
        bundle = self._ks.load_pqc_bundle(master_password)
        if not bundle:
            # Try generating fresh keys if none exist
            bundle = self._ks.ensure_pqc_keys_full(master_password)
        if not bundle:
            raise FriendsServiceError(
                "PQC keys not available. Generate PQC keys first via the PQC Exchange dialog."
            )
        if not is_pqc_available():
            raise FriendsServiceError(
                "Post-quantum cryptography is not available (liboqs not installed)."
            )
        try:
            ct = base64.b64decode(ciphertext_b64)
            shared_secret = HybridKEM.decapsulate(bundle, ct)
            return shared_secret
        except Exception as e:
            raise FriendsServiceError(f"PQC decapsulation failed: {e}") from e

    def friend_has_pqc_key(self, name: str) -> bool:
        """Check if a friend has a PQC combined public key stored."""
        return name in self._ks.friends_pqc_combined_pub
