"""
Double Ratchet Protocol for forward secrecy.

Provides:
- Forward secrecy: Compromising current keys doesn't reveal past messages
- Future secrecy (post-compromise security): Compromising current keys
  doesn't reveal future messages after the next DH ratchet step
- Deniable authentication

Based on the Signal Protocol Double Ratchet algorithm.
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets
import struct
import hmac as hmac_module


class RatchetState:
    """Persistent state for one side of a Double Ratchet conversation."""

    def __init__(self):
        # DH ratchet
        self.dh_priv: X25519PrivateKey = None
        self.dh_pub_remote: X25519PublicKey = None
        
        # Chains
        self.root_key: bytes = None
        self.send_chain_key: bytes = None
        self.recv_chain_key: bytes = None
        
        # Message counters (for out-of-order messages)
        self.send_msg_num: int = 0
        self.recv_msg_num: int = 0
        self.prev_send_chain_len: int = 0
        
        # Skipped message keys (for out-of-order delivery)
        self.skipped_keys: dict = {}  # (dh_pub_bytes, msg_num) -> message_key

    @staticmethod
    def _hkdf_rk(rk: bytes, dh_out: bytes) -> tuple:
        """Root key KDF: derives new root key + chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rk,
            info=b"enigma-double-ratchet-v1",
            backend=default_backend()
        )
        output = hkdf.derive(dh_out)
        return output[:32], output[32:]  # new_root_key, new_chain_key

    @staticmethod
    def _hkdf_ck(ck: bytes) -> tuple:
        """Chain key KDF: derives new chain key + message key.
        
        Uses HMAC-based stepping as specified in the Signal Protocol:
        - new_ck = HMAC(ck, 0x02)
        - mk = HMAC(ck, 0x01)
        """
        new_ck = hmac_module.new(ck, b'\x02', hashes.SHA256).digest()
        mk = hmac_module.new(ck, b'\x01', hashes.SHA256).digest()
        return new_ck, mk

    def initialize_as_alice(self, bob_dh_pub: X25519PublicKey, shared_secret: bytes):
        """Initialize the ratchet as Alice (the initiator).
        
        Args:
            bob_dh_pub: Bob's initial DH public key
            shared_secret: Initial shared secret from X3DH or similar handshake
        """
        # Generate our initial DH key pair
        self.dh_priv = X25519PrivateKey.generate()
        self.dh_pub_remote = bob_dh_pub
        
        # Perform initial DH exchange to get root key
        dh_out = self.dh_priv.exchange(bob_dh_pub)
        self.root_key, self.send_chain_key = self._hkdf_rk(shared_secret, dh_out)
        
        # Initialize receive chain with a dummy (will be set on first received message)
        self.recv_chain_key = None
        
        # Initialize counters
        self.send_msg_num = 0
        self.recv_msg_num = 0
        self.prev_send_chain_len = 0

    def initialize_as_bob(self, alice_dh_pub: X25519PublicKey, shared_secret: bytes):
        """Initialize the ratchet as Bob (the responder).
        
        Args:
            alice_dh_pub: Alice's initial DH public key
            shared_secret: Initial shared secret from X3DH or similar handshake
        """
        # Generate our initial DH key pair
        self.dh_priv = X25519PrivateKey.generate()
        self.dh_pub_remote = alice_dh_pub
        
        # Perform initial DH exchange to get root key
        dh_out = self.dh_priv.exchange(alice_dh_pub)
        self.root_key, self.recv_chain_key = self._hkdf_rk(shared_secret, dh_out)
        
        # Initialize send chain with a dummy (will be set on first DH ratchet)
        self.send_chain_key = None
        
        # Initialize counters
        self.send_msg_num = 0
        self.recv_msg_num = 0
        self.prev_send_chain_len = 0

    def dh_ratchet_step(self, remote_pub: X25519PublicKey) -> None:
        """Perform a DH ratchet step when receiving a new DH public key.
        
        This is called when we detect that the remote party has sent us
        a new DH public key (indicating they've performed their own DH ratchet).
        """
        # Derive new root key and receiving chain key
        dh_out = self.dh_priv.exchange(remote_pub)
        self.root_key, self.recv_chain_key = self._hkdf_rk(
            self.root_key, dh_out
        )
        
        # Generate new DH key pair for sending
        self.prev_send_chain_len = self.send_msg_num
        self.send_msg_num = 0
        self.recv_msg_num = 0
        
        self.dh_priv = X25519PrivateKey.generate()
        self.dh_pub_remote = remote_pub
        
        # Derive new sending chain key
        dh_out2 = self.dh_priv.exchange(remote_pub)
        self.root_key, self.send_chain_key = self._hkdf_rk(
            self.root_key, dh_out2
        )

    def encrypt(self, plaintext: bytes) -> tuple:
        """
        Encrypt a message.
        
        Returns:
            (header, ciphertext) where header contains:
                - dh_pub: current DH public key (32 bytes)
                - msg_num: message number (4 bytes, big-endian)
                - prev_chain_len: previous chain length (4 bytes, big-endian)
        """
        if self.send_chain_key is None:
            raise ValueError("Send chain not initialized. Call dh_ratchet_step first.")
        
        # Step the send chain to get a new message key
        self.send_chain_key, message_key = self._hkdf_ck(self.send_chain_key)
        
        # Encrypt with message key using AES-GCM
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(message_key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        
        # Build header
        dh_pub_bytes = self.dh_priv.public_key().public_bytes_raw()
        header = struct.pack(">I", self.send_msg_num)  # msg_num (4 bytes)
        header += struct.pack(">I", self.prev_send_chain_len)  # prev_chain_len (4 bytes)
        header += dh_pub_bytes  # DH public key (32 bytes)
        
        self.send_msg_num += 1
        
        # Immediately zero the message key for security
        message_key = b'\x00' * 32
        
        return header, nonce + ct

    def decrypt(self, header: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt a message, handling out-of-order delivery.
        
        Args:
            header: The message header containing DH pub, msg_num, prev_chain_len
            ciphertext: The encrypted message (nonce + ciphertext)
            
        Returns:
            Decrypted plaintext bytes
        """
        if len(header) < 40:  # 4 + 4 + 32
            raise ValueError("Header too short")
        
        msg_num = struct.unpack(">I", header[:4])[0]
        prev_chain_len = struct.unpack(">I", header[4:8])[0]
        remote_dh_pub_bytes = header[8:40]
        remote_dh_pub = X25519PublicKey.from_public_bytes(remote_dh_pub_bytes)
        
        # Check if we need to do a DH ratchet step
        current_remote_pub_bytes = (
            self.dh_pub_remote.public_bytes_raw() if self.dh_pub_remote else b''
        )
        if remote_dh_pub_bytes != current_remote_pub_bytes:
            self.dh_ratchet_step(remote_dh_pub)
        
        # Try skipped message keys first (for out-of-order delivery)
        skip_key = self.skipped_keys.pop(
            (remote_dh_pub_bytes, msg_num), None
        )
        if skip_key:
            return self._decrypt_with_key(skip_key, ciphertext)
        
        # Skip ahead if needed (store skipped message keys for later)
        while self.recv_msg_num < msg_num:
            # Store skipped message keys
            self.recv_chain_key, mk = self._hkdf_ck(self.recv_chain_key)
            self.skipped_keys[
                (remote_dh_pub_bytes, self.recv_msg_num)
            ] = mk
            self.recv_msg_num += 1
        
        # Decrypt current message
        self.recv_chain_key, message_key = self._hkdf_ck(self.recv_chain_key)
        self.recv_msg_num += 1
        plaintext = self._decrypt_with_key(message_key, ciphertext)
        
        # Zero the message key for security
        message_key = b'\x00' * 32
        
        return plaintext

    @staticmethod
    def _decrypt_with_key(key: bytes, data: bytes) -> bytes:
        """Decrypt data with a given message key."""
        if len(data) < 12:
            raise ValueError("Ciphertext too short")
        nonce = data[:12]
        ct = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)

    def get_local_dh_public_key(self) -> bytes:
        """Get our current DH public key as raw bytes."""
        if self.dh_priv is None:
            raise ValueError("DH key pair not initialized")
        return self.dh_priv.public_key().public_bytes_raw()

    def serialize(self) -> dict:
        """Serialize the ratchet state for storage.
        
        Note: This is a simplified serialization. In production, you'd want
        to use a more robust format and handle private key serialization properly.
        """
        return {
            'root_key': self.root_key.hex() if self.root_key else None,
            'send_chain_key': self.send_chain_key.hex() if self.send_chain_key else None,
            'recv_chain_key': self.recv_chain_key.hex() if self.recv_chain_key else None,
            'send_msg_num': self.send_msg_num,
            'recv_msg_num': self.recv_msg_num,
            'prev_send_chain_len': self.prev_send_chain_len,
            'dh_priv_bytes': self.dh_priv.private_bytes_raw().hex() if self.dh_priv else None,
            'dh_pub_remote_bytes': self.dh_pub_remote.public_bytes_raw().hex() if self.dh_pub_remote else None,
            'skipped_keys': {
                f"{k[0].hex()}:{k[1]}": v.hex() 
                for k, v in self.skipped_keys.items()
            }
        }

    @classmethod
    def deserialize(cls, data: dict) -> 'RatchetState':
        """Deserialize a ratchet state from storage."""
        state = cls()
        
        if data.get('root_key'):
            state.root_key = bytes.fromhex(data['root_key'])
        if data.get('send_chain_key'):
            state.send_chain_key = bytes.fromhex(data['send_chain_key'])
        if data.get('recv_chain_key'):
            state.recv_chain_key = bytes.fromhex(data['recv_chain_key'])
        
        state.send_msg_num = data.get('send_msg_num', 0)
        state.recv_msg_num = data.get('recv_msg_num', 0)
        state.prev_send_chain_len = data.get('prev_send_chain_len', 0)
        
        if data.get('dh_priv_bytes'):
            priv_bytes = bytes.fromhex(data['dh_priv_bytes'])
            state.dh_priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        if data.get('dh_pub_remote_bytes'):
            pub_bytes = bytes.fromhex(data['dh_pub_remote_bytes'])
            state.dh_pub_remote = X25519PublicKey.from_public_bytes(pub_bytes)
        
        if data.get('skipped_keys'):
            state.skipped_keys = {
                (bytes.fromhex(k.split(':')[0]), int(k.split(':')[1])): bytes.fromhex(v)
                for k, v in data['skipped_keys'].items()
            }
        
        return state
