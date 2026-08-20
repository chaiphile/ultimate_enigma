"""Comprehensive unit tests for key_manager.py – KeyStore & file encryption."""

import json
import os
import secrets
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from security.guarded_buffer import GuardedBuffer

import database
import key_manager
from key_manager import (
    KeyStore,
    init_db,
    pubkey_to_pem,
)
from services.file_service import (
    file_encrypt,
    file_decrypt,
    file_encrypt_shared,
    file_decrypt_shared,
    FILE_MAGIC,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def password():
    return "TestPassword123!"


@pytest.fixture
def initialized_keystore(password):
    """Create and load a fresh KeyStore."""
    init_db(password)
    ks = KeyStore()
    assert ks.load(password) is True
    return ks


@pytest.fixture
def rsa_keypair():
    priv = rsa.generate_private_key(65537, 3072, default_backend())
    pub = priv.public_key()
    return priv, pub


# ---------------------------------------------------------------------------
# Tests: init_db
# ---------------------------------------------------------------------------

class TestInitDB:
    def test_creates_new_keys(self, password):
        result = init_db(password)
        assert result is True

    def test_does_not_overwrite_existing(self, password):
        init_db(password)
        result = init_db(password)
        assert result is False

    def test_stores_public_key(self, password):
        init_db(password)
        conn = database.get_connection()
        row = conn.execute("SELECT value FROM settings WHERE key='public_key'").fetchone()
        conn.close()
        assert row is not None
        assert "BEGIN PUBLIC KEY" in row[0]

    def test_stores_encrypted_private_key(self, password):
        init_db(password)
        conn = database.get_connection()
        row = conn.execute("SELECT value FROM settings WHERE key='private_key_encrypted'").fetchone()
        conn.close()
        assert row is not None
        assert "BEGIN ENCRYPTED PRIVATE KEY" in row[0]

    def test_stores_global_secret(self, password):
        init_db(password)
        conn = database.get_connection()
        row = conn.execute("SELECT value FROM settings WHERE key='global_secret'").fetchone()
        conn.close()
        assert row is not None
        data = json.loads(row[0])
        assert "salt" in data and "nonce" in data and "ct" in data


# ---------------------------------------------------------------------------
# Tests: KeyStore.load
# ---------------------------------------------------------------------------

class TestKeyStoreLoad:
    def test_load_success(self, initialized_keystore):
        ks = initialized_keystore
        assert ks.my_pub is not None
        assert ks.my_priv is not None
        assert ks.global_secret is not None
        assert len(ks.global_secret) == 32

    def test_load_wrong_password_fails(self, password):
        init_db(password)
        ks = KeyStore()
        assert ks.load("WrongPassword") is False

    def test_friends_initially_empty(self, initialized_keystore):
        assert initialized_keystore.friends == []


# ---------------------------------------------------------------------------
# Tests: KeyStore.verify_password
# ---------------------------------------------------------------------------

class TestVerifyPassword:
    def test_correct_password(self, initialized_keystore, password):
        assert initialized_keystore.verify_password(password) is True

    def test_wrong_password(self, initialized_keystore):
        assert initialized_keystore.verify_password("wrong") is False

    def test_failed_attempts_counter(self, initialized_keystore):
        for _ in range(3):
            initialized_keystore.verify_password("wrong")
        assert initialized_keystore.failed_attempts == 3

    def test_successful_resets_counter(self, initialized_keystore, password):
        initialized_keystore.verify_password("wrong")
        initialized_keystore.verify_password("wrong")
        initialized_keystore.verify_password(password)
        assert initialized_keystore.failed_attempts == 0


# ---------------------------------------------------------------------------
# Tests: KeyStore.save_friend / remove_friend / get_friend_secret
# ---------------------------------------------------------------------------

class TestFriendManagement:
    def test_save_friend_without_secret(self, initialized_keystore):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        initialized_keystore.save_friend("Alice", pem)
        assert any(n == "Alice" for n, _, _ in initialized_keystore.friends)

    def test_save_friend_with_secret(self, initialized_keystore, password):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        secret = secrets.token_bytes(32)
        initialized_keystore.save_friend("Bob", pem, shared_secret=secret, password=password)
        retrieved = initialized_keystore.get_friend_secret("Bob")
        assert retrieved == secret

    def test_save_friend_requires_password_for_secret(self, initialized_keystore):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        with pytest.raises(ValueError, match="Master password required"):
            initialized_keystore.save_friend("Eve", pem, shared_secret=b"\x00" * 32)

    def test_remove_friend(self, initialized_keystore):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        initialized_keystore.save_friend("Charlie", pem)
        initialized_keystore.remove_friend("Charlie")
        assert not any(n == "Charlie" for n, _, _ in initialized_keystore.friends)

    def test_get_friend_secret_nonexistent(self, initialized_keystore):
        assert initialized_keystore.get_friend_secret("Nobody") is None

    def test_update_friend_overwrites(self, initialized_keystore, password):
        priv1 = rsa.generate_private_key(65537, 3072, default_backend())
        pem1 = pubkey_to_pem(priv1.public_key())
        priv2 = rsa.generate_private_key(65537, 3072, default_backend())
        pem2 = pubkey_to_pem(priv2.public_key())

        initialized_keystore.save_friend("Dave", pem1)
        initialized_keystore.save_friend("Dave", pem2)

        dave_entries = [n for n, _, _ in initialized_keystore.friends if n == "Dave"]
        assert len(dave_entries) == 1

    def test_x25519_pub_stored(self, initialized_keystore):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        x_b64 = "dGVzdA=="  # dummy base64
        initialized_keystore.save_friend("XUser", pem, x25519_pub_b64=x_b64)
        assert initialized_keystore.friends_x25519.get("XUser") == x_b64

    def test_ecdh_priv_persisted_and_survives_reload(
        self, initialized_keystore, password
    ):
        """Regression: our ECDH X25519 private must survive a reload so the
        Double Ratchet can re-derive the agreed root key after restart."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        secret = secrets.token_bytes(32)
        ecdh_priv = X25519PrivateKey.generate()
        ecdh_bytes = ecdh_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        initialized_keystore.save_friend(
            "EcdhUser",
            pem,
            shared_secret=secret,
            password=password,
            ecdh_priv_bytes=ecdh_bytes,
        )
        assert initialized_keystore.get_friend_ecdh_priv("EcdhUser") == ecdh_bytes

        # Fresh KeyStore, same password: private must come back decryptable.
        ks2 = KeyStore()
        assert ks2.load(password) is True
        assert ks2.get_friend_ecdh_priv("EcdhUser") == ecdh_bytes
        assert ks2.get_friend_secret("EcdhUser") == secret

    def test_ecdh_priv_requires_password(self, initialized_keystore):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        with pytest.raises(ValueError, match="Master password required"):
            initialized_keystore.save_friend(
                "EcdhNoPw", pem, ecdh_priv_bytes=b"\x00" * 32
            )


# ---------------------------------------------------------------------------
# Tests: KeyStore.update_global_secret
# ---------------------------------------------------------------------------

class TestUpdateGlobalSecret:
    def test_update(self, initialized_keystore, password):
        new_secret = secrets.token_bytes(32)
        initialized_keystore.update_global_secret(new_secret, password)
        assert bytes(initialized_keystore.global_secret) == new_secret

    def test_persists_to_db(self, initialized_keystore, password):
        new_secret = secrets.token_bytes(32)
        initialized_keystore.update_global_secret(new_secret, password)
        # Reload from DB
        ks2 = KeyStore()
        assert ks2.load(password) is True
        assert bytes(ks2.global_secret) == new_secret


# ---------------------------------------------------------------------------
# Tests: KeyStore.wipe
# ---------------------------------------------------------------------------

class TestWipe:
    def test_wipe_clears_secrets(self, initialized_keystore):
        ks = initialized_keystore
        ks.wipe()
        assert ks.global_secret is None
        assert ks.my_priv is None
        assert ks.my_pub is None
        for _, _, sec in ks.friends:
            assert sec is None

    def test_wipe_zeros_bytearray(self, initialized_keystore, password):
        ks = initialized_keystore
        old_secret = ks.global_secret
        ks.wipe()
        assert old_secret is None or (isinstance(old_secret, GuardedBuffer) and old_secret._freed)


# ---------------------------------------------------------------------------
# Tests: KeyStore.get_decryption_snapshot
# ---------------------------------------------------------------------------

class TestDecryptionSnapshot:
    def test_snapshot_contains_priv(self, initialized_keystore):
        priv, friends, secrets_list, legacy_priv = initialized_keystore.get_decryption_snapshot()
        assert priv is not None

    def test_snapshot_contains_global_secret(self, initialized_keystore):
        _, _, secrets_list, _ = initialized_keystore.get_decryption_snapshot()
        assert len(secrets_list) >= 1  # at least global_secret


# ---------------------------------------------------------------------------
# Tests: file_encrypt / file_decrypt (password-based)
# ---------------------------------------------------------------------------

class TestFileEncryptDecryptPassword:
    def test_roundtrip(self, tmp_path):
        plain_file = tmp_path / "plain.txt"
        enc_file = tmp_path / "enc.bin"
        dec_file = tmp_path / "dec.txt"

        plain_file.write_bytes(b"Hello, World!")
        file_encrypt(str(plain_file), str(enc_file), "mypassword")
        file_decrypt(str(enc_file), str(dec_file), "mypassword")
        assert dec_file.read_bytes() == b"Hello, World!"

    def test_wrong_password_raises(self, tmp_path):
        plain_file = tmp_path / "plain.txt"
        enc_file = tmp_path / "enc.bin"
        dec_file = tmp_path / "dec.txt"

        plain_file.write_bytes(b"secret")
        file_encrypt(str(plain_file), str(enc_file), "correct")
        with pytest.raises(ValueError, match="Wrong password"):
            file_decrypt(str(enc_file), str(dec_file), "wrong")

    def test_large_file(self, tmp_path):
        plain_file = tmp_path / "large.bin"
        enc_file = tmp_path / "large.enc"
        dec_file = tmp_path / "large.dec"

        data = secrets.token_bytes(100_000)
        plain_file.write_bytes(data)
        file_encrypt(str(plain_file), str(enc_file), "pw")
        file_decrypt(str(enc_file), str(dec_file), "pw")
        assert dec_file.read_bytes() == data

    def test_empty_file(self, tmp_path):
        plain_file = tmp_path / "empty.txt"
        enc_file = tmp_path / "empty.enc"
        dec_file = tmp_path / "empty.dec"

        plain_file.write_bytes(b"")
        file_encrypt(str(plain_file), str(enc_file), "pw")
        file_decrypt(str(enc_file), str(dec_file), "pw")
        assert dec_file.read_bytes() == b""


# ---------------------------------------------------------------------------
# Tests: file_encrypt_shared / file_decrypt_shared
# ---------------------------------------------------------------------------

class TestFileEncryptDecryptShared:
    @pytest.fixture
    def shared_secret(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def secrets_dict(self, shared_secret):
        import hashlib
        fp = hashlib.sha256(shared_secret).digest()[:16]
        return {fp: (shared_secret, "TestFriend")}

    def test_roundtrip(self, tmp_path, shared_secret, secrets_dict):
        plain = tmp_path / "plain.txt"
        enc = tmp_path / "enc.bin"
        dec = tmp_path / "dec.txt"

        plain.write_bytes(b"shared secret file content")
        file_encrypt_shared(str(plain), str(enc), shared_secret)
        sig_msg = file_decrypt_shared(str(enc), str(dec), secrets_dict)
        assert dec.read_bytes() == b"shared secret file content"

    def test_with_signature(self, tmp_path, shared_secret, secrets_dict, rsa_keypair):
        priv, pub = rsa_keypair
        plain = tmp_path / "signed.txt"
        enc = tmp_path / "signed.enc"
        dec = tmp_path / "signed.dec"

        plain.write_bytes(b"signed content")
        file_encrypt_shared(str(plain), str(enc), shared_secret, sign=True, my_priv=priv)

        friends_for_sig = [("Signer", pub)]
        sig_msg = file_decrypt_shared(str(enc), str(dec), secrets_dict, friends_for_sig)
        assert "Signature verified from Signer" in sig_msg

    def test_wrong_secret_raises(self, tmp_path, shared_secret):
        plain = tmp_path / "p.txt"
        enc = tmp_path / "e.bin"
        dec = tmp_path / "d.txt"

        plain.write_bytes(b"data")
        file_encrypt_shared(str(plain), str(enc), shared_secret)

        wrong_fp = b"\x00" * 16
        wrong_dict = {wrong_fp: (secrets.token_bytes(32), "Wrong")}
        with pytest.raises(ValueError, match="No matching shared secret"):
            file_decrypt_shared(str(enc), str(dec), wrong_dict)

    def test_invalid_magic_raises(self, tmp_path):
        bad_file = tmp_path / "bad.bin"
        bad_file.write_bytes(b"NOT_ENIGMA" + b"\x00" * 100)
        with pytest.raises(ValueError, match="invalid magic"):
            file_decrypt_shared(str(bad_file), str(tmp_path / "out.bin"), {})

    def test_file_magic_header(self, tmp_path, shared_secret):
        plain = tmp_path / "p.txt"
        enc = tmp_path / "e.bin"
        plain.write_bytes(b"test")
        file_encrypt_shared(str(plain), str(enc), shared_secret)
        header = enc.read_bytes()[:len(FILE_MAGIC)]
        assert header == FILE_MAGIC
