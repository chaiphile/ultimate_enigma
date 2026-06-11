"""Comprehensive unit tests for services/double_ratchet.py – Double Ratchet Protocol."""

import secrets
import struct
import pytest
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from services.double_ratchet import RatchetState


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def shared_secret():
    return secrets.token_bytes(32)


@pytest.fixture
def alice_bob_pair(shared_secret):
    """Create Alice and Bob ratchet states initialized with each other."""
    alice = RatchetState()
    bob = RatchetState()

    # Bob generates his DH key first
    bob_dh_priv = X25519PrivateKey.generate()
    bob_dh_pub = bob_dh_priv.public_key()

    # Initialize Alice with Bob's DH pub
    alice.initialize_as_alice(bob_dh_pub, shared_secret)

    # Alice's DH pub
    alice_dh_pub = alice.dh_priv.public_key()

    # Initialize Bob with Alice's DH pub and his original DH private key
    bob.initialize_as_bob(alice_dh_pub, shared_secret, local_dh_priv=bob_dh_priv)

    return alice, bob


# ---------------------------------------------------------------------------
# Tests: Initialization
# ---------------------------------------------------------------------------

class TestInitialization:
    def test_initialize_as_alice(self, shared_secret):
        state = RatchetState()
        bob_pub = X25519PrivateKey.generate().public_key()
        state.initialize_as_alice(bob_pub, shared_secret)

        assert state.dh_priv is not None
        assert state.dh_pub_remote is not None
        assert state.root_key is not None
        assert state.send_chain_key is not None
        assert state.recv_chain_key is None  # Alice starts with no recv chain
        assert state.send_msg_num == 0
        assert state.recv_msg_num == 0
        assert state.prev_send_chain_len == 0

    def test_initialize_as_bob(self, shared_secret):
        state = RatchetState()
        alice_pub = X25519PrivateKey.generate().public_key()
        state.initialize_as_bob(alice_pub, shared_secret)

        assert state.dh_priv is not None
        assert state.dh_pub_remote is not None
        assert state.root_key is not None
        assert state.recv_chain_key is not None
        assert state.send_chain_key is None  # Bob starts with no send chain
        assert state.send_msg_num == 0
        assert state.recv_msg_num == 0

    def test_different_initial_secrets_different_states(self):
        state1 = RatchetState()
        state2 = RatchetState()
        pub = X25519PrivateKey.generate().public_key()

        state1.initialize_as_alice(pub, secrets.token_bytes(32))
        state2.initialize_as_alice(pub, secrets.token_bytes(32))

        assert state1.root_key != state2.root_key
        assert state1.send_chain_key != state2.send_chain_key


# ---------------------------------------------------------------------------
# Tests: HKDF Functions
# ---------------------------------------------------------------------------

class TestHKDF:
    def test_hkdf_rk_output_length(self):
        rk = secrets.token_bytes(32)
        dh_out = secrets.token_bytes(32)
        new_rk, new_ck = RatchetState._hkdf_rk(rk, dh_out)
        assert len(new_rk) == 32
        assert len(new_ck) == 32

    def test_hkdf_rk_deterministic(self):
        rk = b'\x01' * 32
        dh_out = b'\x02' * 32
        result1 = RatchetState._hkdf_rk(rk, dh_out)
        result2 = RatchetState._hkdf_rk(rk, dh_out)
        assert result1 == result2

    def test_hkdf_ck_output_length(self):
        ck = secrets.token_bytes(32)
        new_ck, mk = RatchetState._hkdf_ck(ck)
        assert len(new_ck) == 32
        assert len(mk) == 32

    def test_hkdf_ck_deterministic(self):
        ck = b'\x03' * 32
        result1 = RatchetState._hkdf_ck(ck)
        result2 = RatchetState._hkdf_ck(ck)
        assert result1 == result2

    def test_hkdf_ck_different_inputs(self):
        ck1 = b'\x01' * 32
        ck2 = b'\x02' * 32
        result1 = RatchetState._hkdf_ck(ck1)
        result2 = RatchetState._hkdf_ck(ck2)
        assert result1 != result2


# ---------------------------------------------------------------------------
# Tests: Encrypt / Decrypt
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_single_message_roundtrip(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        # Alice encrypts using XChaCha20-Poly1305 via the message key derived
        # from the chain. Bob must be able to decrypt with his matching chain.
        header, ct = alice.encrypt(b"Hello Bob!")

        plaintext = bob.decrypt(header, ct)
        assert plaintext == b"Hello Bob!"

    def test_encrypt_uses_xchacha20_nonce_size(self, alice_bob_pair):
        """Verify the ciphertext has a 24-byte nonce (XChaCha20, not AES-GCM)."""
        from services.xchacha20_poly1305 import XCHACHA20_NONCE_SIZE
        alice, bob = alice_bob_pair

        header, ct = alice.encrypt(b"nonce-size-check")
        # The ciphertext starts with the nonce, which must be 24 bytes for XChaCha20
        # (not 12 bytes as in legacy AES-GCM)
        assert len(ct) >= XCHACHA20_NONCE_SIZE
        # Sanity: a 16-byte message + 24-byte nonce + 16-byte tag = 56 bytes
        expected_min = XCHACHA20_NONCE_SIZE + 16 + 16  # nonce + plaintext + tag
        assert len(ct) >= expected_min

    def test_multiple_messages(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        messages = [f"Message {i}".encode() for i in range(5)]

        for msg in messages:
            header, ct = alice.encrypt(msg)
            plaintext = bob.decrypt(header, ct)
            assert plaintext == msg

    def test_bidirectional_communication(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        # Alice sends to Bob
        h1, ct1 = alice.encrypt(b"Hi Bob")
        pt1 = bob.decrypt(h1, ct1)
        assert pt1 == b"Hi Bob"

        # Bob needs to trigger a DH ratchet step to get send_chain_key
        # Bob's first encrypt will trigger a DH ratchet step
        # First, Bob needs to process Alice's message, which should set up
        # the receive chain

        # Actually let's test the simpler case where both can send
        # After Alice sends and Bob receives, Bob can send back
        h2, ct2 = bob.encrypt(b"Hi Alice")
        pt2 = alice.decrypt(h2, ct2)
        assert pt2 == b"Hi Alice"

    def test_encrypt_advances_send_counter(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        assert alice.send_msg_num == 0
        alice.encrypt(b"msg1")
        assert alice.send_msg_num == 1
        alice.encrypt(b"msg2")
        assert alice.send_msg_num == 2

    def test_encrypt_without_send_chain_raises(self):
        state = RatchetState()
        with pytest.raises(ValueError, match="Send chain not initialized"):
            state.encrypt(b"test")

    def test_decrypt_header_too_short(self, alice_bob_pair):
        alice, bob = alice_bob_pair
        with pytest.raises(ValueError, match="Header too short"):
            bob.decrypt(b"\x00" * 10, b"ciphertext")

    def test_empty_message(self, alice_bob_pair):
        alice, bob = alice_bob_pair
        header, ct = alice.encrypt(b"")
        plaintext = bob.decrypt(header, ct)
        assert plaintext == b""


# ---------------------------------------------------------------------------
# Tests: DH Ratchet Step
# ---------------------------------------------------------------------------

class TestDHRatchetStep:
    def test_dh_ratchet_step_changes_keys(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        old_root_key = alice.root_key
        old_dh_priv = alice.dh_priv

        new_remote_pub = X25519PrivateKey.generate().public_key()
        alice.dh_ratchet_step(new_remote_pub)

        assert alice.root_key != old_root_key
        assert alice.dh_priv is not old_dh_priv

    def test_dh_ratchet_step_resets_counters(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        # Send a few messages to advance counters
        for _ in range(3):
            alice.encrypt(b"msg")

        assert alice.send_msg_num == 3

        # DH ratchet step should reset counters
        new_pub = X25519PrivateKey.generate().public_key()
        alice.dh_ratchet_step(new_pub)

        assert alice.send_msg_num == 0
        assert alice.recv_msg_num == 0

    def test_dh_ratchet_step_updates_prev_chain_len(self, alice_bob_pair):
        alice, bob = alice_bob_pair

        for _ in range(5):
            alice.encrypt(b"msg")

        new_pub = X25519PrivateKey.generate().public_key()
        alice.dh_ratchet_step(new_pub)

        assert alice.prev_send_chain_len == 5


# ---------------------------------------------------------------------------
# Tests: Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_serialize_basic(self, alice_bob_pair):
        alice, _ = alice_bob_pair
        data = alice.serialize()

        assert 'root_key' in data
        assert 'send_chain_key' in data
        assert 'recv_chain_key' in data
        assert 'send_msg_num' in data
        assert 'recv_msg_num' in data
        assert 'dh_priv_bytes' in data
        assert 'dh_pub_remote_bytes' in data
        assert 'skipped_keys' in data

    def test_deserialize_roundtrip(self, alice_bob_pair):
        alice, _ = alice_bob_pair

        # Send some messages to build state
        for i in range(3):
            alice.encrypt(f"msg{i}".encode())

        data = alice.serialize()
        restored = RatchetState.deserialize(data)

        assert restored.root_key == alice.root_key
        assert restored.send_chain_key == alice.send_chain_key
        assert restored.send_msg_num == alice.send_msg_num
        assert restored.recv_msg_num == alice.recv_msg_num
        assert restored.prev_send_chain_len == alice.prev_send_chain_len

    def test_deserialize_empty_state(self):
        data = {}
        state = RatchetState.deserialize(data)
        assert state.root_key is None
        assert state.send_chain_key is None
        assert state.recv_chain_key is None
        assert state.send_msg_num == 0

    def test_serialize_deserialize_encrypt_decrypt(self, alice_bob_pair, shared_secret):
        """Serialize Alice, deserialize, and verify encryption still works."""
        alice, bob = alice_bob_pair

        # Send a message first
        h1, ct1 = alice.encrypt(b"before serialize")
        bob.decrypt(h1, ct1)

        # Serialize and restore Alice
        data = alice.serialize()
        restored_alice = RatchetState.deserialize(data)

        # Restored Alice should still be able to encrypt
        h2, ct2 = restored_alice.encrypt(b"after serialize")
        pt2 = bob.decrypt(h2, ct2)
        assert pt2 == b"after serialize"


# ---------------------------------------------------------------------------
# Tests: Skipped Message Keys (Out-of-Order Delivery)
# ---------------------------------------------------------------------------

class TestOutOfOrderDelivery:
    def test_out_of_order_messages(self, alice_bob_pair):
        """Test that Bob can handle out-of-order message delivery."""
        alice, bob = alice_bob_pair

        # Alice sends 3 messages
        msg_data = []
        for i in range(3):
            h, ct = alice.encrypt(f"msg{i}".encode())
            msg_data.append((h, ct, f"msg{i}".encode()))

        # Bob receives them out of order: msg2, msg0, msg1
        h2, ct2, expected2 = msg_data[2]
        h0, ct0, expected0 = msg_data[0]
        h1, ct1, expected1 = msg_data[1]

        # Receive msg2 first (skipping msg0 and msg1)
        pt2 = bob.decrypt(h2, ct2)
        assert pt2 == expected2

        # Now receive msg0 (should use skipped key)
        pt0 = bob.decrypt(h0, ct0)
        assert pt0 == expected0

        # Now receive msg1 (should use skipped key)
        pt1 = bob.decrypt(h1, ct1)
        assert pt1 == expected1

    def test_skipped_keys_stored(self, alice_bob_pair):
        """When messages are skipped, keys should be stored for later."""
        alice, bob = alice_bob_pair

        # Alice sends 3 messages
        messages = []
        for i in range(3):
            h, ct = alice.encrypt(f"msg{i}".encode())
            messages.append((h, ct))

        # Bob receives only the third message (skipping 0 and 1)
        bob.decrypt(messages[2][0], messages[2][1])

        # Skipped keys should be stored
        assert len(bob.skipped_keys) == 2


# ---------------------------------------------------------------------------
# Tests: Get Local DH Public Key
# ---------------------------------------------------------------------------

class TestGetLocalDHPublicKey:
    def test_returns_32_bytes(self, alice_bob_pair):
        alice, _ = alice_bob_pair
        pub = alice.get_local_dh_public_key()
        assert len(pub) == 32
        assert isinstance(pub, bytes)

    def test_uninitialized_raises(self):
        state = RatchetState()
        with pytest.raises(ValueError, match="not initialized"):
            state.get_local_dh_public_key()

    def test_deterministic(self, alice_bob_pair):
        alice, _ = alice_bob_pair
        pub1 = alice.get_local_dh_public_key()
        pub2 = alice.get_local_dh_public_key()
        assert pub1 == pub2


# ---------------------------------------------------------------------------
# Tests: Forward Secrecy
# ---------------------------------------------------------------------------

class TestForwardSecrecy:
    def test_compromised_current_key_cannot_decrypt_past(self, alice_bob_pair):
        """After a DH ratchet step, old message keys should not be recoverable."""
        alice, bob = alice_bob_pair

        # Alice sends a message
        h1, ct1 = alice.encrypt(b"secret past message")
        bob.decrypt(h1, ct1)

        # Save current state (simulating compromise)
        current_root_key = alice.root_key
        current_send_chain_key = alice.send_chain_key

        # Perform DH ratchet steps to change the root key.
        # In real usage this happens when the remote party sends a new DH public key.
        for i in range(3):
            new_remote_pub = X25519PrivateKey.generate().public_key()
            alice.dh_ratchet_step(new_remote_pub)

        # After DH ratchet steps, root key and send chain key must have changed,
        # ensuring forward secrecy: old message keys cannot be re-derived.
        assert alice.root_key != current_root_key
        assert alice.send_chain_key != current_send_chain_key


# ---------------------------------------------------------------------------
# Tests: Decrypt With Key (Static)
# ---------------------------------------------------------------------------

class TestDecryptWithKey:
    """Test the _decrypt_with_key static method which now uses XChaCha20-Poly1305."""

    def test_valid_decrypt(self):
        from services.xchacha20_poly1305 import XChaCha20Poly1305, generate_nonce
        key = secrets.token_bytes(32)
        nonce = generate_nonce()  # 24-byte nonce
        aead = XChaCha20Poly1305(key)
        ct = aead.encrypt(nonce, b"plaintext", None)
        data = nonce + ct
        result = RatchetState._decrypt_with_key(key, data)
        assert result == b"plaintext"

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            RatchetState._decrypt_with_key(secrets.token_bytes(32), b"\x00" * 10)

    def test_wrong_key_raises(self):
        from services.xchacha20_poly1305 import XChaCha20Poly1305, generate_nonce
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = generate_nonce()
        aead = XChaCha20Poly1305(key1)
        ct = aead.encrypt(nonce, b"plaintext", None)
        data = nonce + ct
        with pytest.raises(Exception):
            RatchetState._decrypt_with_key(key2, data)

    def test_large_plaintext_roundtrip(self):
        """XChaCha20-Poly1305 should handle large messages (e.g., attachments)."""
        from services.xchacha20_poly1305 import XChaCha20Poly1305, generate_nonce
        key = secrets.token_bytes(32)
        nonce = generate_nonce()
        large_plaintext = b"A" * (1024 * 1024)  # 1 MB
        aead = XChaCha20Poly1305(key)
        ct = aead.encrypt(nonce, large_plaintext, None)
        data = nonce + ct
        result = RatchetState._decrypt_with_key(key, data)
        assert result == large_plaintext

    def test_empty_plaintext_roundtrip(self):
        from services.xchacha20_poly1305 import XChaCha20Poly1305, generate_nonce
        key = secrets.token_bytes(32)
        nonce = generate_nonce()
        aead = XChaCha20Poly1305(key)
        ct = aead.encrypt(nonce, b"", None)
        data = nonce + ct
        result = RatchetState._decrypt_with_key(key, data)
        assert result == b""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
