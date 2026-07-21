"""FriendsService facade - delegates to focused sub-services."""
from typing import List, Dict, Optional, Tuple
from key_manager import KeyStore
from services.friends.crud import FriendCrudService, FriendsServiceError
from services.friends.ratchet_mgmt import FriendRatchetManager
from services.friends.pqc_keys import FriendPqcKeyService
from services.friends.hybrid_sig_keys import FriendHybridSigKeyService
from services.trust_chain_service import TrustChainService

class FriendsService:
    """High-level API for managing friends. Delegates to focused sub-services."""
    def __init__(self, key_store: KeyStore):
        self._crud = FriendCrudService(key_store)
        self._ratchet = FriendRatchetManager(key_store, self._crud)
        self._pqc = FriendPqcKeyService(key_store)
        self._hybrid_sig = FriendHybridSigKeyService(key_store, self._crud)
        self._trust_chain = None

    def set_trust_chain_service(self, trust_chain_service: 'TrustChainService') -> None:
        """Set the trust chain service after initialization."""
        self._trust_chain = trust_chain_service

    def get_all_friends(self) -> List[Dict]:
        """Return a list of friend summaries suitable for the UI."""
        return self._crud.get_all_friends()

    def get_friend_details(self, name: str) -> Optional[Dict]:
        """Return a detailed view of one friend, or None if not found."""
        return self._crud.get_friend_details(name)

    def get_friend_secret(self, name: str) -> Optional[bytes]:
        """Return the shared secret for a friend, or None if none exists."""
        return self._crud.get_friend_secret(name)

    def friend_exists(self, name: str) -> bool:
        """Check whether a friend with that name exists."""
        return self._crud.friend_exists(name)

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
        """Add a new friend or update an existing one."""
        self._crud.add_friend(
            name=name,
            public_key_pem=public_key_pem,
            shared_secret=shared_secret,
            master_password=master_password,
            x25519_pub_b64=x25519_pub_b64,
            capabilities=capabilities,
            pqc_combined_pub_b64=pqc_combined_pub_b64,
            hybrid_sig_pub_b64=hybrid_sig_pub_b64,
        )

    def remove_friend(self, name: str) -> None:
        """Remove a friend entirely."""
        self._crud.remove_friend(name)

    def update_shared_secret(
        self,
        name: str,
        new_secret: bytes,
        master_password: str,
        x25519_pub_b64: Optional[str] = None,
    ) -> None:
        """Replace the shared secret (and optionally the ECDH key) for an existing friend."""
        self._crud.update_shared_secret(
            name=name,
            new_secret=new_secret,
            master_password=master_password,
            x25519_pub_b64=x25519_pub_b64,
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
        """Update one or more public keys for an existing friend, preserving all others."""
        self._crud.update_friend_pub_keys(
            name=name,
            master_password=master_password,
            new_rsa_pem=new_rsa_pem,
            new_x25519_b64=new_x25519_b64,
            new_pqc_b64=new_pqc_b64,
            new_hybrid_sig_b64=new_hybrid_sig_b64,
        )

    def get_my_public_info(self) -> Dict:
        """Return my own RSA public key info (fingerprint and PEM)."""
        return self._crud.get_my_public_info()

    def verify_password(self, password: str) -> bool:
        """Verify master password."""
        return self._crud.verify_password(password)

    def verify_master_password(self, password: str) -> bool:
        """Verify the real master password, rejecting duress credentials."""
        return self._crud.verify_master_password(password)

    def get_friend_names(self) -> List[str]:
        """Return list of all friend names."""
        return self._crud.get_friend_names()

    def friend_has_secret(self, name: str) -> bool:
        """Check if a specific friend has a shared secret configured."""
        return self._crud.friend_has_secret(name)

    def get_friend_x25519_key(self, name: str) -> Optional[str]:
        """Return the X25519 public key (Base64) for a friend, or None if not stored."""
        return self._crud.get_friend_x25519_key(name)

    def get_friend_capabilities(self, name: str) -> Dict:
        """Return the capabilities dict for a friend, or empty dict if none."""
        return self._crud.get_friend_capabilities(name)

    def has_active_ratchet(self, name: str) -> bool:
        """Check if a friend has an active Double Ratchet session."""
        return self._ratchet.has_active_ratchet(name)

    def init_ratchet(
        self,
        name: str,
        role: str,
        master_password: str,
    ) -> None:
        """Initialize a Double Ratchet session for a friend."""
        self._ratchet.init_ratchet(name, role, master_password)

    def reset_ratchet(self, name: str, master_password: str = "") -> bool:
        """Delete the Double Ratchet session for a friend."""
        return self._ratchet.reset_ratchet(name, master_password)

    def get_my_pqc_combined_pub(self) -> Optional[str]:
        """Return my PQC combined public key as Base64, or None if not generated."""
        return self._pqc.get_my_pqc_combined_pub()

    def generate_pqc_keys(self, master_password: str) -> str:
        """Generate hybrid PQC keys and return the combined public key as Base64."""
        return self._pqc.generate_pqc_keys(master_password)

    def pqc_encapsulate(
        self,
        friend_name: str,
        master_password: str,
    ) -> Tuple[str, bytes]:
        """Perform hybrid KEM encapsulation using a friend's PQC combined public key."""
        return self._pqc.pqc_encapsulate(friend_name, master_password)

    def pqc_decapsulate(
        self,
        ciphertext_b64: str,
        master_password: str,
    ) -> bytes:
        """Perform hybrid KEM decapsulation using local PQC private keys."""
        return self._pqc.pqc_decapsulate(ciphertext_b64, master_password)

    def friend_has_pqc_key(self, name: str) -> bool:
        """Check if a friend has a PQC combined public key stored."""
        return self._pqc.friend_has_pqc_key(name)

    def friend_has_hybrid_sig_key(self, name: str) -> bool:
        """Check if a friend has a hybrid signing combined public key stored."""
        return self._hybrid_sig.friend_has_hybrid_sig_key(name)

    def get_my_hybrid_sig_combined_pub(self) -> Optional[str]:
        """Return my hybrid signing combined public key as Base64, or None if not generated."""
        return self._hybrid_sig.get_my_hybrid_sig_combined_pub()

    def generate_hybrid_sig_keys(self, master_password: str) -> str:
        """Generate hybrid signing keys and return the combined public key as Base64."""
        return self._hybrid_sig.generate_hybrid_sig_keys(master_password)

    def import_friend_hybrid_sig_pub(
        self,
        friend_name: str,
        combined_pub_b64: str,
        master_password: str = "",
    ) -> None:
        """Import and store a friend's hybrid signing combined public key."""
        self._hybrid_sig.import_friend_hybrid_sig_pub(
            friend_name=friend_name,
            combined_pub_b64=combined_pub_b64,
            master_password=master_password,
        )

    def get_friend_hybrid_sig_pub_b64(self, friend_name: str) -> Optional[str]:
        """Return a friend's hybrid signing combined public key as Base64, or None."""
        return self._hybrid_sig.get_friend_hybrid_sig_pub_b64(friend_name)

    def get_hybrid_sig_key_fingerprint(self, combined_pub_b64: str) -> Optional[str]:
        """Return a SHA-256 fingerprint of a hybrid signing combined public key."""
        return self._hybrid_sig.get_hybrid_sig_key_fingerprint(combined_pub_b64)

    # ------------------------------------------------------------------
    # RSA key helpers for recovery share encryption
    # ------------------------------------------------------------------
    def get_friend_rsa_pub(self, name: str):
        """Return a friend's loaded RSA public key object, or None."""
        return self._crud.get_friend_rsa_pub(name)

    def get_own_rsa_pub(self):
        """Return the local user's RSA public key object, or None."""
        return self._crud.get_own_rsa_pub()

    def encrypt_share(self, share_bytes: bytes, pub_key) -> bytes:
        """RSA-OAEP encrypt raw share bytes to a recipient's public key."""
        return self._crud.encrypt_share(share_bytes, pub_key)

    def decrypt_share(self, encrypted_share: bytes) -> bytes:
        """RSA-OAEP decrypt a share blob using the local private key."""
        return self._crud.decrypt_share(encrypted_share)

    # ---- Name helpers ----
    def get_my_name(self) -> str:
        """Return the current display name for ratchet envelopes."""
        return self._crud._ks.my_name

    def set_my_name(self, name: str) -> None:
        """Set the display name for ratchet envelopes."""
        self._crud._ks.set_my_name(name)

    # ---- Trust Chain delegation ----
    def get_trust_level(self, friend_name: str):
        """Get trust level for a friend."""
        if self._trust_chain is None:
            return None
        return self._trust_chain.get_trust_level(friend_name)

    def issue_certificate(self, subject_name, subject_pub_b64, cert_type, validity_days, master_password):
        """Issue a trust certificate."""
        if self._trust_chain is None:
            raise FriendsServiceError("Trust chain service not initialized")
        return self._trust_chain.issue_certificate(subject_name, subject_pub_b64, cert_type, validity_days, master_password)

    def verify_certificate(self, cert_id):
        """Verify a trust certificate."""
        if self._trust_chain is None:
            return False
        return self._trust_chain.verify_certificate(cert_id)

    def revoke_certificate(self, cert_id, reason=""):
        """Revoke a trust certificate."""
        if self._trust_chain is None:
            return
        self._trust_chain.revoke_certificate(cert_id, reason)

    def get_all_certificates(self):
        """Get all trust certificates."""
        if self._trust_chain is None:
            return []
        return self._trust_chain.get_all_certificates()

    def get_certs_for_friend(self, friend_name):
        """Get certificates for a specific friend."""
        if self._trust_chain is None:
            return []
        return self._trust_chain.get_certs_for_friend(friend_name)

    def import_received_certs(self, cert_dicts):
        """Import certificates received from a peer."""
        if self._trust_chain is None:
            return 0
        return self._trust_chain.import_received_certs(cert_dicts)

    def get_pending_certs_for_exchange(self):
        """Get certificates pending export during key exchange."""
        if self._trust_chain is None:
            return []
        return self._trust_chain.get_pending_certs_for_exchange()

    def compute_trust_chain(self, subject_name):
        """Compute trust chain for a subject."""
        if self._trust_chain is None:
            return None
        return self._trust_chain.compute_trust_chain(subject_name)
