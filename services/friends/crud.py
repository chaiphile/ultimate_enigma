"""
Friend CRUD, queries, and auth – extracted from FriendsService.
"""

from typing import List, Dict, Optional

import base64

from key_manager import KeyStore, pubkey_to_pem
from crypto import sha256_fingerprint
from services.ecdh_service import ECDHService
from services.ratchet_service import RatchetService


class FriendsServiceError(Exception):
    """Raised when a friend operation fails."""


class FriendCrudService:
    """CRUD operations, queries, and auth for friends."""

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
                except (ValueError, TypeError):
                    pass
            has_ratchet = RatchetService.has_active_ratchet(name)
            caps = self._ks.friends_capabilities.get(name, {})
            supports_dr = bool(caps.get("double_ratchet", False))
            has_pqc = name in self._ks.friends_pqc_combined_pub
            has_hybrid_sig = name in self._ks.friends_hybrid_sig_pubs
            result.append({
                "name": name,
                "has_shared_secret": sec is not None,
                "rsa_fingerprint": rsa_fp,
                "ecdh_fingerprint": ecdh_fp,
                "public_key_pem": pem,
                "has_ratchet": has_ratchet,
                "supports_double_ratchet": supports_dr,
                "has_pqc_key": has_pqc,
                "has_hybrid_sig_key": has_hybrid_sig,
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
        capabilities: Optional[dict] = None,
        pqc_combined_pub_b64: Optional[str] = None,
        hybrid_sig_pub_b64: Optional[str] = None,
    ) -> None:
        """
        Add a new friend or update an existing one.
        If `shared_secret` is given, `master_password` must be non‑empty.
        pqc_combined_pub_b64 is the Base64-encoded hybrid PQC combined public key.
        hybrid_sig_pub_b64 is the Base64-encoded hybrid signing combined public key.
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
        # Validate PQC combined pub if provided
        if pqc_combined_pub_b64:
            try:
                raw = base64.b64decode(pqc_combined_pub_b64)
                if len(raw) < 36:  # minimum: 2+32+2 = 36 bytes for smallest keys
                    raise ValueError("Too short to be a valid combined public key")
            except (ValueError, TypeError) as e:
                raise FriendsServiceError(f"Invalid PQC combined public key: {e}")
        # Validate hybrid sig combined pub if provided
        if hybrid_sig_pub_b64:
            try:
                raw = base64.b64decode(hybrid_sig_pub_b64)
                if len(raw) < 36:
                    raise ValueError("Too short to be a valid hybrid signing combined public key")
            except (ValueError, TypeError) as e:
                raise FriendsServiceError(f"Invalid hybrid signing combined public key: {e}")

        self._ks.save_friend(
            name=name,
            pem=public_key_pem,
            shared_secret=shared_secret,
            password=master_password,
            x25519_pub_b64=x25519_pub_b64,
            capabilities=capabilities,
            pqc_combined_pub_b64=pqc_combined_pub_b64,
            hybrid_sig_pub_b64=hybrid_sig_pub_b64,
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

    # ------------------------------------------------------------------
    # Utility methods for views (avoid direct model access)
    # ------------------------------------------------------------------
    def verify_password(self, password: str) -> bool:
        """Verify master password. Allows views to check auth without accessing KeyStore."""
        return self._ks.verify_password(password)

    def get_friend_names(self) -> List[str]:
        """Return list of all friend names."""
        return [name for name, _, _ in self._ks.friends]

    def friend_has_secret(self, name: str) -> bool:
        """Check if a specific friend has a shared secret configured."""
        for fname, _, sec in self._ks.friends:
            if fname == name:
                return sec is not None
        return False

    def get_friend_x25519_key(self, name: str) -> Optional[str]:
        """Return the X25519 public key (Base64) for a friend, or None if not stored."""
        return self._ks.friends_x25519.get(name)

    def get_friend_capabilities(self, name: str) -> Dict:
        """Return the capabilities dict for a friend, or empty dict if none."""
        return dict(self._ks.friends_capabilities.get(name, {}))
