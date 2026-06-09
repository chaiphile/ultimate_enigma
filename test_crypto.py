"""Unit tests for crypto module."""

import pytest
import time
import base64
from crypto import (
    encrypt_message, decrypt_message,
    derive_time_key, aes_gcm_encrypt, aes_gcm_decrypt,
    rsa_encrypt_key, rsa_decrypt_key, rsa_sign, rsa_verify,
    WINDOW_SIZE, TIME_STEP, peek_flags, SELF_DESTRUCT_FLAG
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

@pytest.fixture
def rsa_keys():
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    pub = priv.public_key()
    return priv, pub

@pytest.fixture
def shared_secret():
    return b'0' * 32

def test_time_encrypt_decrypt(shared_secret):
    ts = time.time()
    plaintext = b"Hello, world!"
    packet, _ = encrypt_message(plaintext, shared_secret, ts, sign=False)
    result = decrypt_message(packet, shared_secret, my_priv=None, friends=[])
    assert plaintext.decode() in result

def test_sliding_window(shared_secret):
    ts_past = time.time() - TIME_STEP * (WINDOW_SIZE - 1)
    plaintext = b"Old message"
    packet, _ = encrypt_message(plaintext, shared_secret, ts_past, sign=False)
    result = decrypt_message(packet, shared_secret, my_priv=None, friends=[])
    assert plaintext.decode() in result
    
def test_expired_message_fails(shared_secret):
    ts_expired = time.time() - TIME_STEP * (WINDOW_SIZE + 2)
    plaintext = b"Very old"
    packet, _ = encrypt_message(plaintext, shared_secret, ts_expired, sign=False)
    with pytest.raises(ValueError, match=r"Decryption failed – wrong key or stale message"):
        decrypt_message(packet, shared_secret, my_priv=None, friends=[])

def test_friend_encrypt_decrypt(shared_secret, rsa_keys):
    priv, pub = rsa_keys
    ts = time.time()
    plaintext = b"Secret for friend"
    packet, _ = encrypt_message(plaintext, shared_secret, ts, sign=False,
                                encrypt_for_friend_pub=pub)
    result = decrypt_message(packet, shared_secret, my_priv=priv)
    assert plaintext.decode() in result

def test_friend_encrypt_wrong_private_key_fails(shared_secret, rsa_keys):
    priv, pub = rsa_keys
    other_priv = rsa.generate_private_key(65537, 2048, default_backend())
    ts = time.time()
    packet, _ = encrypt_message(b"test", shared_secret, ts, sign=False,
                                encrypt_for_friend_pub=pub)
    with pytest.raises(ValueError):
        decrypt_message(packet, shared_secret, my_priv=other_priv)

def test_sign_verify(shared_secret, rsa_keys):
    priv, pub = rsa_keys
    ts = time.time()
    plaintext = b"Signed message"
    packet, _ = encrypt_message(plaintext, shared_secret, ts, sign=True,
                                my_priv=priv)
    result = decrypt_message(packet, shared_secret, friends=[("test", pub)])
    assert "✅ Signature verified from test" in result
    assert plaintext.decode() in result

def test_sign_unknown_public_key(shared_secret, rsa_keys):
    priv, _ = rsa_keys
    ts = time.time()
    packet, _ = encrypt_message(b"msg", shared_secret, ts, sign=True,
                                my_priv=priv)
    result = decrypt_message(packet, shared_secret, friends=[])
    assert "⚠️ Signature INVALID or sender unknown" in result

def test_self_destruct(shared_secret):
    ts = time.time()
    plaintext = b"Self-destructing"
    packet, _ = encrypt_message(plaintext, shared_secret, ts, sign=False,
                                self_destruct_seconds=1)
    # Immediately decrypt should work
    result = decrypt_message(packet, shared_secret)
    assert plaintext.decode() in result
    # Wait until expiry
    time.sleep(2)
    with pytest.raises(ValueError, match="self-destructed"):
        decrypt_message(packet, shared_secret)

def test_invalid_base64():
    with pytest.raises(Exception):
        base64.b64decode("this is not base64!@@@")

def test_corrupted_packet_flags(shared_secret):
    # create minimal packet then corrupt flags byte
    packet = b'\x00' + b'a'*50
    with pytest.raises(ValueError):
        decrypt_message(packet, shared_secret)

def test_file_encrypt_decrypt(tmp_path):
    from key_manager import file_encrypt, file_decrypt
    data = b"Confidential file content"
    infile = tmp_path / "plain.txt"
    infile.write_bytes(data)
    encfile = tmp_path / "plain.txt.enc"
    pw = "strongpassword"
    file_encrypt(str(infile), str(encfile), pw)
    assert encfile.exists()
    decfile = tmp_path / "plain_dec.txt"
    file_decrypt(str(encfile), str(decfile), pw)
    assert decfile.read_bytes() == data

def test_file_wrong_password(tmp_path):
    from key_manager import file_encrypt, file_decrypt
    data = b"Some data"
    infile = tmp_path / "f.txt"
    infile.write_bytes(data)
    encfile = tmp_path / "f.enc"
    file_encrypt(str(infile), str(encfile), "right")
    with pytest.raises(ValueError, match="Wrong password"):
        file_decrypt(str(encfile), str(infile), "wrong")