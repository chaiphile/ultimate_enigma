"""
Friend management service – pure logic, no UI dependencies.
Uses the KeyStore for persistence and the ECDHService for key exchange.
"""

from typing import List, Dict, Optional, Tuple

from key_manager import KeyStore, pubkey_to_pem
from crypto import sha256_fingerprint
from services.ecdh_service import ECDHService


class FriendsServiceError(Exception):
    """Raised when a friend operation fails."""


class FriendsService:
    """High‑level API for managing friends, shared secrets, and ECDH keys."""

    def __init__(self, key_store: KeyStore):
        self._ks = key_store

    # ------------------------------------------------------------------
    # Query / read
    # ------------------------------------------------------------------
    def get_all_friends(self) -> List[Dict]:
        """
        Return a list of friend summaries suitable for the UI.
        Each dict contains: name, has_shared_secret, rsa_fingerprint,
        ecdh_fingerprint (or None), public_key_pem.
        """
        result = []
        for name, pub, sec in self._ks.friends:
            pem = pubkey_to_pem(pub)
            rsa_fp = sha256_fingerprint(pem.encode())
            ecdh_fp = None
            x_b64 = self._ks.friends_x25519.get(name)
            if x_b64:
                try:
                    raw = ECDHService.decode_public_key(x_b64)
                    ecdh_fp = ECDHService.fingerprint(raw)
                except Exception:
                    pass
            result.append({
                "name": name,
                "has_shared_secret": sec is not None,
                "rsa_fingerprint": rsa_fp,
                "ecdh_fingerprint": ecdh_fp,
                "public_key_pem": pem,
            })
        return result

    def get_friend_details(self, name: str) -> Optional[Dict]:
        """Return a detailed view of one friend, or None if not found."""
        for info in self.get_all_friends():
            if info["name"] == name:
                return info
        return None

    def get_friend_secret(self, name: str) -> Optional[bytes]:
        """Return the shared secret for a friend, or None if none exists."""
        return self._ks.get_friend_secret(name)

    def friend_exists(self, name: str) -> bool:
        """Check whether a friend with that name exists."""
        return any(n == name for n, _, _ in self._ks.friends)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------
    def add_friend(
        self,
        name: str,
        public_key_pem: str,
        shared_secret: Optional[bytes] = None,
        master_password: str = "",
        x25519_pub_b64: Optional[str] = None,
    ) -> None:
        """
        Add a new friend or update an existing one.
        If `shared_secret` is given, `master_password` must be non‑empty.
        """
        if not name.strip():
            raise FriendsServiceError("Friend name cannot be empty")
        if not public_key_pem.strip():
            raise FriendsServiceError("Public key cannot be empty")
        if shared_secret and not master_password:
            raise FriendsServiceError("Master password required to encrypt shared secret")
        if x25519_pub_b64:
            try:
                ECDHService.decode_public_key(x25519_pub_b64)
            except ValueError as e:
                raise FriendsServiceError(f"Invalid X25519 public key: {e}")

        self._ks.save_friend(
            name=name,
            pem=public_key_pem,
            shared_secret=shared_secret,
            password=master_password,
            x25519_pub_b64=x25519_pub_b64,
        )

    def remove_friend(self, name: str) -> None:
        """Remove a friend entirely."""
        if not self.friend_exists(name):
            raise FriendsServiceError(f"Friend '{name}' not found")
        self._ks.remove_friend(name)

    def update_shared_secret(
        self,
        name: str,
        new_secret: bytes,
        master_password: str,
        x25519_pub_b64: Optional[str] = None,
    ) -> None:
        """
        Replace the shared secret (and optionally the ECDH key) for an existing friend.
        `master_password` is required to encrypt the new secret.
        """
        if not self.friend_exists(name):
            raise FriendsServiceError(f"Friend '{name}' not found")
        if not master_password:
            raise FriendsServiceError("Master password required")
        # Retrieve current public key PEM (needed for save_friend which replaces the row)
        current_pub_pem = None
        for fname, pub, _ in self._ks.friends:
            if fname == name:
                current_pub_pem = pubkey_to_pem(pub)
                break
        if not current_pub_pem:
            raise FriendsServiceError("Friend record corrupted – no public key")

        self._ks.save_friend(
            name=name,
            pem=current_pub_pem,
            shared_secret=new_secret,
            password=master_password,
            x25519_pub_b64=x25519_pub_b64,
        )

    def get_my_public_info(self) -> Dict:
        """Return my own RSA public key info (fingerprint and PEM)."""
        if not self._ks.my_pub:
            raise FriendsServiceError("No public key loaded")
        pem = pubkey_to_pem(self._ks.my_pub)
        fp = sha256_fingerprint(pem.encode())
        return {"fingerprint": fp, "public_key_pem": pem}