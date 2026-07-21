"""
Friend CRUD, queries, and auth – extracted from FriendsService.
"""

from typing import List, Dict, Optional
import struct
import base64

from key_manager import KeyStore, pubkey_to_pem
from crypto import sha256_fingerprint, rsa_encrypt_key, rsa_decrypt_key
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

    def _get_friend_existing_keys(self, name: str) -> Dict:
        """Return all current public keys for a friend for preservation during partial updates."""
        current_pem = None
        for fname, pub, _ in self._ks.friends:
            if fname == name:
                current_pem = pubkey_to_pem(pub)
                break
        x25519 = self._ks.friends_x25519.get(name)
        caps = dict(self._ks.friends_capabilities.get(name, {})) or None
        pqc_b64 = None
        if name in self._ks.friends_pqc_combined_pub:
            pqc_b64 = base64.b64encode(self._ks.friends_pqc_combined_pub[name]).decode()
        hybrid_sig_b64 = None
        if name in self._ks.friends_hybrid_sig_pubs:
            ed_pub, dil_pub = self._ks.friends_hybrid_sig_pubs[name]
            combined = (
                struct.pack(">H", len(ed_pub)) + ed_pub
                + struct.pack(">H", len(dil_pub)) + dil_pub
            )
            hybrid_sig_b64 = base64.b64encode(combined).decode()
        return {
            "pem": current_pem,
            "x25519": x25519,
            "caps": caps,
            "pqc_b64": pqc_b64,
            "hybrid_sig_b64": hybrid_sig_b64,
        }

    def update_shared_secret(
        self,
        name: str,
        new_secret: bytes,
        master_password: str,
        x25519_pub_b64: Optional[str] = None,
    ) -> None:
        """Replace the shared secret (and optionally the ECDH key) for an existing friend.

        Preserves all existing public keys (PQC, hybrid sig, capabilities).
        """
        if not self.friend_exists(name):
            raise FriendsServiceError(f"Friend '{name}' not found")
        if not master_password:
            raise FriendsServiceError("Master password required")
        existing = self._get_friend_existing_keys(name)
        if not existing["pem"]:
            raise FriendsServiceError("Friend record corrupted – no public key")
        self._ks.save_friend(
            name=name,
            pem=existing["pem"],
            shared_secret=new_secret,
            password=master_password,
            x25519_pub_b64=x25519_pub_b64 if x25519_pub_b64 is not None else existing["x25519"],
            capabilities=existing["caps"],
            pqc_combined_pub_b64=existing["pqc_b64"],
            hybrid_sig_pub_b64=existing["hybrid_sig_b64"],
        )

    def update_friend_pub_keys(
        self,
        name: str,
        master_password: str,
        new_rsa_pem: Optional[str] = None,
        new_x25519_b64: Optional[str] = None,
        new_pqc_b64: Optional[str] = None,
        new_hybrid_sig_b64: Optional[str] = None,
    ) -> None:
        """Update one or more public keys for an existing friend, preserving all others.

        At least one of the new_* parameters must be provided.
        master_password is required when the friend has a shared secret.
        """
        if not self.friend_exists(name):
            raise FriendsServiceError(f"Friend '{name}' not found")
        if not any([new_rsa_pem, new_x25519_b64, new_pqc_b64, new_hybrid_sig_b64]):
            raise FriendsServiceError("No keys provided to update")
        secret = self.get_friend_secret(name)
        if secret and not master_password:
            raise FriendsServiceError("Master password required to preserve shared secret")

        existing = self._get_friend_existing_keys(name)

        pem = new_rsa_pem or existing["pem"]
        if not pem:
            raise FriendsServiceError("Friend record corrupted – no public key")

        if new_rsa_pem:
            from src.crypto_utils import pem_to_pubkey as _check_pem
            try:
                _check_pem(new_rsa_pem)
            except Exception as e:
                raise FriendsServiceError(f"Invalid RSA public key: {e}") from e

        if new_x25519_b64:
            try:
                ECDHService.decode_public_key(new_x25519_b64)
            except ValueError as e:
                raise FriendsServiceError(f"Invalid X25519 public key: {e}") from e

        if new_pqc_b64:
            try:
                raw = base64.b64decode(new_pqc_b64)
                if len(raw) < 36:
                    raise ValueError("Key too short")
            except Exception as e:
                raise FriendsServiceError(f"Invalid PQC combined public key: {e}") from e

        if new_hybrid_sig_b64:
            try:
                raw = base64.b64decode(new_hybrid_sig_b64)
                if len(raw) < 36:
                    raise ValueError("Key too short")
            except Exception as e:
                raise FriendsServiceError(f"Invalid hybrid signing combined public key: {e}") from e

        self._ks.save_friend(
            name=name,
            pem=pem,
            shared_secret=secret,
            password=master_password if secret else "",
            x25519_pub_b64=new_x25519_b64 if new_x25519_b64 is not None else existing["x25519"],
            capabilities=existing["caps"],
            pqc_combined_pub_b64=new_pqc_b64 if new_pqc_b64 is not None else existing["pqc_b64"],
            hybrid_sig_pub_b64=new_hybrid_sig_b64 if new_hybrid_sig_b64 is not None else existing["hybrid_sig_b64"],
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

    def verify_master_password(self, password: str) -> bool:
        """Verify the real master password, rejecting duress credentials."""
        previous_duress_mode = self._ks.is_duress_mode
        is_valid = self._ks.verify_password(password)
        is_duress = self._ks.is_duress_mode
        self._ks._duress_mode = previous_duress_mode
        return bool(is_valid and not is_duress)

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

    # ------------------------------------------------------------------
    # RSA key helpers for recovery share encryption
    # ------------------------------------------------------------------
    def get_friend_rsa_pub(self, name: str):
        """Return a friend's loaded RSA public key object, or None if not found."""
        for fname, pub, _ in self._ks.friends:
            if fname == name:
                return pub
        return None

    def get_own_rsa_pub(self):
        """Return the local user's RSA public key object, or None if not loaded."""
        return self._ks.my_pub

    def encrypt_share(self, share_bytes: bytes, pub_key) -> bytes:
        """RSA-OAEP encrypt raw share bytes to a recipient's public key."""
        return rsa_encrypt_key(share_bytes, pub_key)

    def decrypt_share(self, encrypted_share: bytes) -> bytes:
        """RSA-OAEP decrypt a share blob using the local private key."""
        if self._ks.my_priv is None:
            raise FriendsServiceError("Private key not loaded — unlock the app first")
        return rsa_decrypt_key(encrypted_share, self._ks.my_priv)
