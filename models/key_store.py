"""Pure data model and persistence manager for cryptographic keys."""

import json
import base64
import secrets
import threading
import time
import logging
import gc
from typing import List, Tuple, Optional, Dict
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import database
from src.exceptions import KeyStoreError
from services.pqc_service import is_pqc_available

try:
    from services.pqc_signatures import HybridSigner
    _HYBRID_SIG_AVAILABLE = True
except (ImportError, RuntimeError, OSError):
    HybridSigner = None  # type: ignore[assignment,misc]
    _HYBRID_SIG_AVAILABLE = False

logger = logging.getLogger(__name__)

def _pem_to_pubkey(pem: str):
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())

def _pem_to_privkey(pem: bytes, password: bytes):
    return serialization.load_pem_private_key(pem, password=password, backend=default_backend)

def pubkey_to_pem(pub) -> str:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')

def _privkey_to_encrypted_pem(priv, password: bytes) -> str:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    ).decode('ascii')


class KeyStoreModel:
    """Manages loading, saving, and in-memory storage of cryptographic keys.
    
    This class is strictly a data model and persistence manager. It does not
    contain business logic such as file encryption/decryption or password change
    workflows.
    """
    
    def __init__(self):
        self._lock = threading.RLock()
        self.my_pub = None
        self.my_priv = None
        self.legacy_priv = None
        self.global_secret: Optional[bytearray] = None
        self.friends: List[Tuple[str, object, Optional[bytearray]]] = []
        self.friends_x25519: Dict[str, str] = {}
        self.friends_capabilities: Dict[str, dict] = {}
        self.friends_pqc_combined_pub: Dict[str, bytes] = {}
        self.my_kyber_priv: Optional[bytes] = None
        self.my_pqc_combined_pub: Optional[bytes] = None
        self._cached_pqc_bundle: Optional[dict] = None
        self.my_ed_priv = None
        self.my_dil_priv: Optional[bytes] = None
        self.my_hybrid_sig_combined_pub: Optional[bytes] = None
        self.friends_hybrid_sig_pubs: Dict[str, tuple] = {}
        self._needs_rotation = False

    def to_dict(self) -> dict:
        """Serialize non-sensitive metadata to a dictionary for inspection."""
        friend_names = [name for name, _, _ in self.friends]
        return {
            "has_global_secret": self.global_secret is not None,
            "friend_count": len(friend_names),
            "friends": friend_names,
            "has_pqc_keys": self.my_kyber_priv is not None,
            "needs_rotation": self._needs_rotation,
        }

    def load(self, password: str) -> None:
        """Load all keys from the database using the provided password.
        
        Args:
            password: Master password for decrypting stored keys.
            
        Raises:
            KeyStoreError: If loading fails due to missing keys or decryption errors.
        """
        with self._lock:
            conn = database.get_connection()
            try:
                self._load_rsa_keys(conn, password)
                self._load_global_secret(conn, password)
                self._load_pqc_keys(conn, password)
                self._load_hybrid_signing_keys(conn, password)
                self._load_friends(conn, password)
            except KeyStoreError:
                raise
            except Exception as e:
                logger.error("Key loading failed: %s", e)
                raise KeyStoreError(f"Key loading failed: {e}") from e
            finally:
                conn.close()

    def _load_rsa_keys(self, conn, password: str) -> None:
        """Load RSA public and private keys."""
        row = conn.execute("SELECT value FROM settings WHERE key='public_key'").fetchone()
        if not row:
            raise KeyStoreError("Public key not found in database")
        self.my_pub = _pem_to_pubkey(row[0])

        row = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'").fetchone()
        if not row:
            raise KeyStoreError("Encrypted private key not found in database")
        try:
            self.my_priv = _pem_to_privkey(row[0].encode(), password.encode())
        except Exception as e:
            raise KeyStoreError(f"Failed to decrypt private key: {e}") from e

        # Check key size for rotation recommendation
        try:
            key_size = self.my_pub.key_size
            if key_size < 4096:
                self._needs_rotation = True
            else:
                self._needs_rotation = False
        except AttributeError:
            self._needs_rotation = False

        # Load legacy private key if present and not expired
        self.legacy_priv = None
        row_legacy = conn.execute(
            "SELECT value FROM settings WHERE key='legacy_private_key_encrypted'"
        ).fetchone()
        if row_legacy:
            try:
                row_expiry = conn.execute(
                    "SELECT value FROM settings WHERE key='legacy_key_expiry'"
                ).fetchone()
                expiry = float(row_expiry[0]) if row_expiry else 0.0
                if time.time() < expiry:
                    self.legacy_priv = _pem_to_privkey(
                        row_legacy[0].encode(), password.encode()
                    )
                    logger.debug("Legacy RSA key loaded (expires in %.1f days)",
                                 (expiry - time.time()) / 86400)
                else:
                    conn.execute("DELETE FROM settings WHERE key='legacy_private_key_encrypted'")
                    conn.execute("DELETE FROM settings WHERE key='legacy_key_expiry'")
                    conn.commit()
                    logger.info("Expired legacy RSA key removed from database")
            except Exception as e:
                logger.warning("Could not load legacy private key: %s", e)

    def _load_global_secret(self, conn, password: str) -> None:
        """Load the global secret."""
        row = conn.execute("SELECT value FROM settings WHERE key='global_secret'").fetchone()
        if row:
            enc_dict = json.loads(row[0])
            self.global_secret = bytearray(database.decrypt_secret(enc_dict, password))
        else:
            self.global_secret = None

    def _load_pqc_keys(self, conn, password: str) -> None:
        """Load Post-Quantum Cryptography keys."""
        self.my_kyber_priv = None
        self.my_pqc_combined_pub = None
        
        row_kyber = conn.execute(
            "SELECT value FROM settings WHERE key='kyber_priv_encrypted'"
        ).fetchone()
        if row_kyber:
            try:
                kyber_enc_dict = json.loads(row_kyber[0])
                self.my_kyber_priv = database.decrypt_secret(kyber_enc_dict, password)
                logger.debug("Local Kyber private key loaded (%d bytes)", len(self.my_kyber_priv))
            except Exception as e:
                logger.warning("Could not decrypt local Kyber private key: %s", e)

        row_pqc_pub = conn.execute(
            "SELECT value FROM settings WHERE key='pqc_combined_pub_b64'"
        ).fetchone()
        if row_pqc_pub and self.my_kyber_priv:
            try:
                self.my_pqc_combined_pub = base64.b64decode(row_pqc_pub[0])
            except Exception as e:
                logger.warning("Could not decode local PQC combined pub: %s", e)

        # Cache full PQC bundle for decryption if all components are available
        self._cached_pqc_bundle = None
        if self.my_kyber_priv and self.my_pqc_combined_pub:
            row_x25519 = conn.execute(
                "SELECT value FROM settings WHERE key='pqc_x25519_priv_encrypted'"
            ).fetchone()
            if row_x25519:
                try:
                    x25519_priv_bytes = database.decrypt_secret(
                        json.loads(row_x25519[0]), password
                    )
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                    x_priv = X25519PrivateKey.from_private_bytes(x25519_priv_bytes)
                    self._cached_pqc_bundle = {
                        'x25519_priv': x_priv,
                        'kyber_priv': self.my_kyber_priv,
                        'combined_pub': self.my_pqc_combined_pub,
                    }
                    logger.debug("PQC decryption bundle cached successfully")
                except Exception as e:
                    logger.warning("Could not load PQC X25519 priv during load: %s", e)

    def _load_hybrid_signing_keys(self, conn, password: str) -> None:
        """Load hybrid signing keys (Ed25519 + Dilithium3)."""
        self.my_ed_priv = None
        self.my_dil_priv = None
        self.my_hybrid_sig_combined_pub = None
        
        if _HYBRID_SIG_AVAILABLE:
            row_ed = conn.execute(
                "SELECT value FROM settings WHERE key='ed25519_priv_encrypted'"
            ).fetchone()
            row_dil = conn.execute(
                "SELECT value FROM settings WHERE key='dilithium_priv_encrypted'"
            ).fetchone()
            row_hybrid_pub = conn.execute(
                "SELECT value FROM settings WHERE key='hybrid_sig_combined_pub_b64'"
            ).fetchone()
            
            if row_ed and row_dil:
                try:
                    ed_priv_bytes = database.decrypt_secret(
                        json.loads(row_ed[0]), password
                    )
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                    self.my_ed_priv = Ed25519PrivateKey.from_private_bytes(ed_priv_bytes)
                    self.my_dil_priv = database.decrypt_secret(
                        json.loads(row_dil[0]), password
                    )
                    logger.debug("Hybrid signing private keys loaded")
                except Exception as e:
                    logger.warning("Could not load hybrid signing private keys: %s", e)
                    
            if row_hybrid_pub:
                try:
                    self.my_hybrid_sig_combined_pub = base64.b64decode(row_hybrid_pub[0])
                except Exception as e:
                    logger.warning("Could not decode hybrid sig combined pub: %s", e)

    def _load_friends(self, conn, password: str) -> None:
        """Load friend keys and shared secrets."""
        rows = conn.execute(
            "SELECT name, public_key_pem, has_shared_secret, shared_secret_encrypted, "
            "x25519_public_key_b64, capabilities_json, pqc_combined_pub_b64, "
            "hybrid_sig_pub_b64 "
            "FROM friends"
        ).fetchall()
        
        self.friends.clear()
        self.friends_x25519.clear()
        self.friends_capabilities.clear()
        self.friends_pqc_combined_pub.clear()
        self.friends_hybrid_sig_pubs.clear()
        
        for name, pem, has_sec, sec_json, x_b64, cap_json, pqc_pub_b64, hybrid_sig_b64 in rows:
            pub = _pem_to_pubkey(pem)
            secret = None
            if has_sec and sec_json:
                try:
                    sec_dict = json.loads(sec_json)
                    secret = bytearray(database.decrypt_secret(sec_dict, password))
                except Exception as e:
                    logger.warning("Could not decrypt shared secret for friend '%s': %s", name, e)
            
            self.friends.append((name, pub, secret))
            
            if x_b64:
                self.friends_x25519[name] = x_b64
            if cap_json:
                try:
                    self.friends_capabilities[name] = json.loads(cap_json)
                except (json.JSONDecodeError, TypeError):
                    self.friends_capabilities[name] = {}
            else:
                self.friends_capabilities[name] = {}
            if pqc_pub_b64:
                try:
                    self.friends_pqc_combined_pub[name] = base64.b64decode(pqc_pub_b64)
                except Exception:
                    pass
            if hybrid_sig_b64 and _HYBRID_SIG_AVAILABLE:
                try:
                    combined = base64.b64decode(hybrid_sig_b64)
                    ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(combined)
                    self.friends_hybrid_sig_pubs[name] = (ed_pub_bytes, dil_pub_bytes)
                except Exception:
                    pass

    def save_friend(self, name: str, pem: str, shared_secret: Optional[bytes] = None,
                    password: str = "", x25519_pub_b64: Optional[str] = None,
                    capabilities: Optional[dict] = None,
                    pqc_combined_pub_b64: Optional[str] = None,
                    hybrid_sig_pub_b64: Optional[str] = None) -> None:
        """Save a friend's key material to the database and update in-memory state.
        
        Args:
            name: Friend identifier.
            pem: PEM-encoded public key.
            shared_secret: Optional shared secret to encrypt and store.
            password: Master password for encrypting the shared secret.
            x25519_pub_b64: Base64-encoded X25519 public key.
            capabilities: Dictionary of friend capabilities.
            pqc_combined_pub_b64: Base64-encoded PQC combined public key.
            hybrid_sig_pub_b64: Base64-encoded hybrid signing public key.
        """
        if shared_secret:
            if not password:
                raise ValueError("Master password required to encrypt friend shared secret")
            enc = database.encrypt_secret(shared_secret, password)
            has_sec = 1
            sec_enc_json = json.dumps(enc)
        else:
            has_sec = 0
            sec_enc_json = None

        cap_json = json.dumps(capabilities) if capabilities else None
        
        with closing(database.get_connection()) as conn:
            existing_row = conn.execute(
                "SELECT ratchet_state_json FROM friends WHERE name=?", (name,)
            ).fetchone()
            existing_ratchet_json = existing_row[0] if existing_row else None

            conn.execute(
                "INSERT OR REPLACE INTO friends "
                "(name, public_key_pem, has_shared_secret, shared_secret_encrypted, "
                "x25519_public_key_b64, capabilities_json, ratchet_state_json, "
                "pqc_combined_pub_b64, hybrid_sig_pub_b64) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (name, pem, has_sec, sec_enc_json, x25519_pub_b64, cap_json,
                 existing_ratchet_json, pqc_combined_pub_b64, hybrid_sig_pub_b64)
            )
            conn.commit()
            
        pub = _pem_to_pubkey(pem)
        self.friends = [(n, p, s) for (n, p, s) in self.friends if n != name]
        secret_ba = bytearray(shared_secret) if shared_secret else None
        self.friends.append((name, pub, secret_ba))
        
        if x25519_pub_b64:
            self.friends_x25519[name] = x25519_pub_b64
        else:
            self.friends_x25519.pop(name, None)
        if capabilities:
            self.friends_capabilities[name] = capabilities
        else:
            self.friends_capabilities.pop(name, None)
        if pqc_combined_pub_b64:
            try:
                self.friends_pqc_combined_pub[name] = base64.b64decode(pqc_combined_pub_b64)
            except Exception:
                self.friends_pqc_combined_pub.pop(name, None)
        else:
            self.friends_pqc_combined_pub.pop(name, None)
        if hybrid_sig_pub_b64 and _HYBRID_SIG_AVAILABLE:
            try:
                combined = base64.b64decode(hybrid_sig_pub_b64)
                ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(combined)
                self.friends_hybrid_sig_pubs[name] = (ed_pub_bytes, dil_pub_bytes)
            except Exception:
                self.friends_hybrid_sig_pubs.pop(name, None)
        else:
            self.friends_hybrid_sig_pubs.pop(name, None)

    def remove_friend(self, name: str) -> None:
        """Remove a friend from the database and in-memory state."""
        with closing(database.get_connection()) as conn:
            conn.execute("DELETE FROM friends WHERE name=?", (name,))
            conn.commit()
        self.friends = [(n, p, s) for (n, p, s) in self.friends if n != name]
        self.friends_x25519.pop(name, None)
        self.friends_capabilities.pop(name, None)
        self.friends_pqc_combined_pub.pop(name, None)
        self.friends_hybrid_sig_pubs.pop(name, None)

    def get_friend_secret(self, name: str) -> Optional[bytes]:
        """Retrieve a friend's shared secret."""
        for n, _, s in self.friends:
            if n == name:
                return bytes(s) if s is not None else None
        return None

    def wipe(self):
        """Securely erase all sensitive keys from memory."""
        with self._lock:
            if self.global_secret is not None:
                for i in range(len(self.global_secret)):
                    self.global_secret[i] = 0
                self.global_secret = None

            wiped_friends = []
            for name, pub, sec in self.friends:
                if isinstance(sec, bytearray):
                    for i in range(len(sec)):
                        sec[i] = 0
                    wiped_friends.append((name, pub, None))
                else:
                    wiped_friends.append((name, pub, None))
            self.friends = wiped_friends

            self.friends_x25519.clear()
            self.friends_capabilities.clear()
            self.friends_pqc_combined_pub.clear()
            if self.my_kyber_priv is not None:
                self.my_kyber_priv = b'\x00' * len(self.my_kyber_priv)
                self.my_kyber_priv = None
            self.my_pqc_combined_pub = None
            if self.my_dil_priv is not None:
                self.my_dil_priv = b'\x00' * len(self.my_dil_priv)
                self.my_dil_priv = None
            self.my_ed_priv = None
            self.my_hybrid_sig_combined_pub = None
            self.friends_hybrid_sig_pubs.clear()
            self.my_priv = None
            self.my_pub = None
            gc.collect()
