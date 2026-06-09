"""Comprehensive unit tests for services/file_service.py."""

import hashlib
import os
import secrets
import pytest
from unittest.mock import MagicMock, patch

from key_manager import FILE_MAGIC, file_encrypt_shared
from services.file_service import FileService, FileServiceError, SharedSecretDetected


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_keystore(global_secret=None, friends=None, my_priv=None):
    ks = MagicMock()
    ks.global_secret = global_secret
    ks.my_priv = my_priv
    ks.friends = friends or []

    def get_friend_secret(name):
        for n, _, s in ks.friends:
            if n == name:
                return s
        return None

    ks.get_friend_secret = get_friend_secret
    return ks


# ---------------------------------------------------------------------------
# Tests: encrypt_file
# ---------------------------------------------------------------------------

class TestFileServiceEncrypt:
    def test_password_method(self, tmp_path):
        ks = _make_mock_keystore()
        svc = FileService(ks)

        plain = tmp_path / "plain.txt"
        enc = tmp_path / "enc.bin"
        plain.write_bytes(b"password encrypted")

        svc.encrypt_file(str(plain), str(enc), method="password", password="pw123")
        assert enc.exists()
        assert enc.read_bytes() != b"password encrypted"

    def test_password_method_no_password_raises(self, tmp_path):
        ks = _make_mock_keystore()
        svc = FileService(ks)
        plain = tmp_path / "p.txt"
        plain.write_bytes(b"data")
        with pytest.raises(FileServiceError, match="Password required"):
            svc.encrypt_file(str(plain), str(tmp_path / "e.bin"), method="password")

    def test_global_method(self, tmp_path):
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = FileService(ks)

        plain = tmp_path / "p.txt"
        enc = tmp_path / "e.bin"
        plain.write_bytes(b"global secret file")

        svc.encrypt_file(str(plain), str(enc), method="global")
        assert enc.exists()
        header = enc.read_bytes()[:len(FILE_MAGIC)]
        assert header == FILE_MAGIC

    def test_global_method_no_secret_raises(self, tmp_path):
        ks = _make_mock_keystore(global_secret=None)
        svc = FileService(ks)
        plain = tmp_path / "p.txt"
        plain.write_bytes(b"data")
        with pytest.raises(FileServiceError, match="No global shared secret"):
            svc.encrypt_file(str(plain), str(tmp_path / "e.bin"), method="global")

    def test_friend_method(self, tmp_path):
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(friends=[("Alice", MagicMock(), secret)])
        svc = FileService(ks)

        plain = tmp_path / "p.txt"
        enc = tmp_path / "e.bin"
        plain.write_bytes(b"friend file")

        svc.encrypt_file(str(plain), str(enc), method="friend", friend_name="Alice")
        assert enc.exists()

    def test_friend_method_no_name_raises(self, tmp_path):
        ks = _make_mock_keystore()
        svc = FileService(ks)
        plain = tmp_path / "p.txt"
        plain.write_bytes(b"data")
        with pytest.raises(FileServiceError, match="Friend name required"):
            svc.encrypt_file(str(plain), str(tmp_path / "e.bin"), method="friend")

    def test_friend_method_no_secret_raises(self, tmp_path):
        ks = _make_mock_keystore(friends=[("Bob", MagicMock(), None)])
        svc = FileService(ks)
        plain = tmp_path / "p.txt"
        plain.write_bytes(b"data")
        with pytest.raises(FileServiceError, match="No shared secret"):
            svc.encrypt_file(str(plain), str(tmp_path / "e.bin"), method="friend", friend_name="Bob")

    def test_unknown_method_raises(self, tmp_path):
        ks = _make_mock_keystore()
        svc = FileService(ks)
        plain = tmp_path / "p.txt"
        plain.write_bytes(b"data")
        with pytest.raises(FileServiceError, match="Unknown method"):
            svc.encrypt_file(str(plain), str(tmp_path / "e.bin"), method="quantum")


# ---------------------------------------------------------------------------
# Tests: decrypt_file
# ---------------------------------------------------------------------------

class TestFileServiceDecrypt:
    def test_decrypt_shared_magic_file(self, tmp_path):
        secret = secrets.token_bytes(32)
        fp = hashlib.sha256(secret).digest()[:16]
        ks = _make_mock_keystore(global_secret=secret)
        svc = FileService(ks)

        plain = tmp_path / "p.txt"
        enc = tmp_path / "e.bin"
        dec = tmp_path / "d.txt"
        plain.write_bytes(b"shared magic file")

        file_encrypt_shared(str(plain), str(enc), secret)
        sig_msg = svc.decrypt_file(str(enc), str(dec))
        assert dec.read_bytes() == b"shared magic file"

    def test_decrypt_password_file(self, tmp_path):
        from key_manager import file_encrypt
        ks = _make_mock_keystore()
        svc = FileService(ks)

        plain = tmp_path / "p.txt"
        enc = tmp_path / "e.bin"
        dec = tmp_path / "d.txt"
        plain.write_bytes(b"password file")

        file_encrypt(str(plain), str(enc), "mypass")
        sig_msg = svc.decrypt_file(str(enc), str(dec), password="mypass")
        assert dec.read_bytes() == b"password file"
        assert sig_msg == ""

    def test_decrypt_no_password_raises(self, tmp_path):
        ks = _make_mock_keystore()
        svc = FileService(ks)
        # Create a non-magic, non-fingerprint file
        f = tmp_path / "random.bin"
        f.write_bytes(secrets.token_bytes(100))
        with pytest.raises(FileServiceError, match="Password required"):
            svc.decrypt_file(str(f), str(tmp_path / "out.bin"))

    def test_decrypt_shared_secret_detected_raises(self, tmp_path):
        """When a file has a known fingerprint but no magic, SharedSecretDetected is raised."""
        secret = secrets.token_bytes(32)
        fp = hashlib.sha256(secret).digest()[:16]
        ks = _make_mock_keystore(global_secret=secret)
        svc = FileService(ks)

        # Build a file that starts with flags + fingerprint (no magic)
        fake_file = tmp_path / "no_magic.bin"
        fake_file.write_bytes(b"\x00" + fp + secrets.token_bytes(50))

        with pytest.raises(SharedSecretDetected) as exc_info:
            svc.decrypt_file(str(fake_file), str(tmp_path / "out.bin"))
        assert exc_info.value.owner == "Global"
        assert exc_info.value.fingerprint == fp

    def test_decrypt_with_shared_secret_after_detection(self, tmp_path):
        """Full flow: detect → confirm → decrypt."""
        secret = secrets.token_bytes(32)
        fp = hashlib.sha256(secret).digest()[:16]
        ks = _make_mock_keystore(global_secret=secret)
        svc = FileService(ks)

        # Create a proper shared-secret file, then strip the magic
        plain = tmp_path / "p.txt"
        enc_full = tmp_path / "enc_full.bin"
        plain.write_bytes(b"detected content")
        file_encrypt_shared(str(plain), str(enc_full), secret)

        # Strip magic to simulate legacy format
        full_data = enc_full.read_bytes()
        stripped = tmp_path / "stripped.bin"
        stripped.write_bytes(full_data[len(FILE_MAGIC):])

        # Should raise SharedSecretDetected
        with pytest.raises(SharedSecretDetected) as exc_info:
            svc.decrypt_file(str(stripped), str(tmp_path / "out1.bin"))

        # Now decrypt with confirmation
        dec = tmp_path / "out2.txt"
        sig_msg = svc.decrypt_with_shared_secret(
            str(stripped), str(dec), exc_info.value.fingerprint
        )
        assert dec.read_bytes() == b"detected content"


# ---------------------------------------------------------------------------
# Tests: _build_secrets_dict
# ---------------------------------------------------------------------------

class TestBuildSecretsDict:
    def test_includes_global(self):
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = FileService(ks)
        d = svc._build_secrets_dict()
        fp = hashlib.sha256(secret).digest()[:16]
        assert fp in d
        assert d[fp][1] == "Global"

    def test_includes_friends(self):
        sec = secrets.token_bytes(32)
        ks = _make_mock_keystore(friends=[("F1", MagicMock(), sec)])
        svc = FileService(ks)
        d = svc._build_secrets_dict()
        fp = hashlib.sha256(sec).digest()[:16]
        assert fp in d
        assert d[fp][1] == "F1"

    def test_empty_when_no_secrets(self):
        ks = _make_mock_keystore(global_secret=None, friends=[])
        svc = FileService(ks)
        d = svc._build_secrets_dict()
        assert d == {}
