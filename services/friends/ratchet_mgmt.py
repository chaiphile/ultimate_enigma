"""
Double Ratchet session management for friends – extracted from FriendsService.
"""

from typing import Optional

from key_manager import KeyStore, pubkey_to_pem
from services.ecdh_service import ECDHService
from services.ratchet_service import (
    RatchetService,
    RatchetInitError,
    RatchetServiceError,
)
from services.friends.crud import FriendCrudService, FriendsServiceError


class FriendRatchetManager:
    """Manages Double Ratchet sessions for friends."""

    def __init__(self, key_store: KeyStore, crud: FriendCrudService):
        self._ks = key_store
        self.crud = crud

    def has_active_ratchet(self, name: str) -> bool:
        """Check if a friend has an active Double Ratchet session."""
        return RatchetService.has_active_ratchet(name)

    def init_ratchet(
        self,
        name: str,
        role: str,
        master_password: str,
    ) -> None:
        """Initialize a Double Ratchet session for a friend.

        Uses the stored X25519 public key and shared secret from the
        friend record. The caller must specify 'alice' or 'bob' role.

        Args:
            name: Friend name.
            role: 'alice' (initiator) or 'bob' (responder).
            master_password: Master password to decrypt the shared secret.

        Raises:
            FriendsServiceError: If prerequisites are missing or init fails.
        """
        if not self.crud.friend_exists(name):
            raise FriendsServiceError(f"Friend '{name}' not found")

        # Get shared secret
        secret = self.crud.get_friend_secret(name)
        if not secret:
            raise FriendsServiceError(
                f"No shared secret configured for '{name}'. "
                "Perform ECDH exchange first."
            )

        # Get X25519 public key
        x_b64 = self._ks.friends_x25519.get(name)
        if not x_b64:
            raise FriendsServiceError(
                f"No X25519 public key for '{name}'. "
                "Perform ECDH exchange first."
            )
        try:
            peer_dh_pub_bytes = ECDHService.decode_public_key(x_b64)
        except ValueError as e:
            raise FriendsServiceError(f"Invalid X25519 key for '{name}': {e}")

        # Initialize based on role
        try:
            if role == "alice":
                RatchetService.init_ratchet_alice(name, peer_dh_pub_bytes, secret)
            elif role == "bob":
                RatchetService.init_ratchet_bob(name, peer_dh_pub_bytes, secret)
            else:
                raise FriendsServiceError(f"Invalid role '{role}'. Use 'alice' or 'bob'.")
        except RatchetInitError as e:
            raise FriendsServiceError(f"Ratchet initialization failed: {e}") from e

        # Enable double_ratchet capability automatically
        caps = dict(self._ks.friends_capabilities.get(name, {}))
        caps["double_ratchet"] = True
        # Re-save friend with updated capabilities
        current_pub_pem = None
        for fname, pub, _ in self._ks.friends:
            if fname == name:
                current_pub_pem = pubkey_to_pem(pub)
                break
        if current_pub_pem:
            if not self._ks.verify_password(master_password):
                raise ValueError("Invalid password — cannot save friend")
            self._ks.save_friend(
                name=name,
                pem=current_pub_pem,
                shared_secret=secret,
                password=master_password,
                x25519_pub_b64=x_b64,
                capabilities=caps,
            )

    def reset_ratchet(self, name: str, master_password: str = "") -> bool:
        """Delete the Double Ratchet session for a friend.

        Also disables the double_ratchet capability flag.

        Args:
            name: Friend name.
            master_password: Required if the friend has a shared secret,
                since save_friend must re-encrypt it during REPLACE.

        Returns:
            True if a session was removed, False if none existed.
        """
        if not self.crud.friend_exists(name):
            raise FriendsServiceError(f"Friend '{name}' not found")

        deleted = RatchetService.delete_ratchet(name)

        # Disable capability
        caps = dict(self._ks.friends_capabilities.get(name, {}))
        caps.pop("double_ratchet", None)
        current_pub_pem = None
        x_b64 = self._ks.friends_x25519.get(name)
        for fname, pub, _ in self._ks.friends:
            if fname == name:
                current_pub_pem = pubkey_to_pem(pub)
                break
        if current_pub_pem:
            secret = self.crud.get_friend_secret(name)
            if secret and not master_password:
                raise FriendsServiceError(
                    "Master password required to encrypt shared secret"
                )
            if not self._ks.verify_password(master_password):
                raise ValueError("Invalid password — cannot save friend")
            self._ks.save_friend(
                name=name,
                pem=current_pub_pem,
                shared_secret=secret,
                password=master_password,
                x25519_pub_b64=x_b64,
                capabilities=caps if caps else None,
            )
        return deleted
