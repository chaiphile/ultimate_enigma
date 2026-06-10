"""Comprehensive unit tests for services/encryption_service.py."""

import base64
import secrets
import time
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from services.encryption_service import EncryptionService, EncryptionError, DecryptionError
from crypto import AES_KEY_SIZE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_keystore(
    global_secret=None,
    friends=None,
    my_priv=None,
    my_pub=None,
):
    """Build a mock KeyStore with the required interface."""
    ks = MagicMock()
    ks.global_secret = global_secret or secrets.token_bytes(32)
    ks.my_priv = my_priv
    ks.my_pub = my_pub
    ks.friends = friends or []

    # get_decryption_snapshot returns (my_priv, friends_for_sig, secrets_list)
    secrets_list = []
    if ks.global_secret:
        secrets_list.append(ks.global_secret)
    for _, _, sec in ks.friends:
        if sec is not None:
            secrets_list.append(sec)

    friends_for_sig = [(name, pub) for name, pub, _ in ks.friends]
    ks.get_decryption_snapshot.return_value = (my_priv, friends_for_sig, secrets_list)
    return ks


# ---------------------------------------------------------------------------
# Tests: Encryption
# ---------------------------------------------------------------------------

class TestEncryptionServiceEncrypt:
    def test_encrypt_shared_mode(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        packet, ts = svc.encrypt("Hello", mode="shared", sign=False)
        assert isinstance(packet, bytes)
        assert len(packet) > 0
        assert isinstance(ts, int)

    def test_encrypt_with_signing(self):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        ks = _make_mock_keystore(my_priv=priv)
        svc = EncryptionService(ks)
        packet, ts = svc.encrypt("Signed msg", mode="shared", sign=True)
        assert packet[0] & 1  # sign flag set

    def test_encrypt_rsa_mode(self):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pub = priv.public_key()
        ks = _make_mock_keystore(friends=[("Alice", pub, None)])
        svc = EncryptionService(ks)
        packet, ts = svc.encrypt("RSA msg", friend_name="Alice", mode="rsa", sign=False)
        assert packet[0] & 2  # friend-encrypted flag

    def test_encrypt_rsa_no_friend_raises(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        with pytest.raises(EncryptionError, match="No public key"):
            svc.encrypt("fail", friend_name="Ghost", mode="rsa")

    def test_encrypt_missing_shared_secret_raises(self):
        ks = _make_mock_keystore(global_secret=b"\x00" * 16)  # wrong size
        svc = EncryptionService(ks)
        with pytest.raises(EncryptionError, match="invalid"):
            svc.encrypt("fail", mode="shared")

    def test_encrypt_base64_returns_string(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        b64 = svc.encrypt_base64(plaintext="test", mode="shared", sign=False)
        assert isinstance(b64, str)
        # Must be valid base64
        decoded = base64.b64decode(b64)
        assert len(decoded) > 0

    def test_encrypt_with_self_destruct(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        packet, _ = svc.encrypt("boom", mode="shared", sign=False, self_destruct_seconds=60)
        assert packet[0] & 4  # SELF_DESTRUCT_FLAG

    def test_encrypt_uses_ntp_time_when_available(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        ntp_ts = 1700000000.0
        svc.update_ntp_time(ntp_ts)
        _, ts = svc.encrypt("ntp test", mode="shared", sign=False)
        assert ts == int(ntp_ts)

    def test_encrypt_unknown_friend_raises(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        with pytest.raises(EncryptionError, match="not found"):
            svc.encrypt("fail", friend_name="Nobody", mode="shared")


# ---------------------------------------------------------------------------
# Tests: Decryption
# ---------------------------------------------------------------------------

class TestEncryptionServiceDecrypt:
    def test_decrypt_shared_roundtrip(self):
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = EncryptionService(ks)

        b64 = svc.encrypt_base64(plaintext="roundtrip", mode="shared", sign=False)
        result = svc.decrypt(b64)
        assert "roundtrip" in result

    def test_decrypt_rsa_roundtrip(self):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pub = priv.public_key()
        ks = _make_mock_keystore(
            my_priv=priv,
            friends=[("Alice", pub, None)],
        )
        svc = EncryptionService(ks)

        b64 = svc.encrypt_base64(
            plaintext="rsa roundtrip",
            friend_name="Alice",
            mode="rsa",
            sign=False,
        )
        result = svc.decrypt(b64)
        assert "rsa roundtrip" in result

    def test_decrypt_invalid_base64_raises(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        with pytest.raises(DecryptionError, match="Invalid Base64"):
            svc.decrypt("!!!not-base64!!!")

    def test_decrypt_wrong_key_raises(self):
        secret1 = secrets.token_bytes(32)
        secret2 = secrets.token_bytes(32)

        ks_enc = _make_mock_keystore(global_secret=secret1)
        svc_enc = EncryptionService(ks_enc)
        b64 = svc_enc.encrypt_base64(plaintext="secret", mode="shared", sign=False)

        ks_dec = _make_mock_keystore(global_secret=secret2)
        svc_dec = EncryptionService(ks_dec)
        with pytest.raises(DecryptionError):
            svc_dec.decrypt(b64)

    def test_decrypt_corrupted_packet_raises(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        b64 = base64.b64encode(b"\x00").decode()  # too short to be valid
        with pytest.raises(DecryptionError):
            svc.decrypt(b64)

    def test_decrypt_rsa_without_priv_raises(self):
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pub = priv.public_key()

        ks_enc = _make_mock_keystore(friends=[("Alice", pub, None)])
        svc_enc = EncryptionService(ks_enc)
        b64 = svc_enc.encrypt_base64(
            plaintext="need priv", friend_name="Alice", mode="rsa", sign=False
        )

        # Decryptor has no private key
        ks_dec = _make_mock_keystore(my_priv=None)
        svc_dec = EncryptionService(ks_dec)
        with pytest.raises(DecryptionError, match="private key"):
            svc_dec.decrypt(b64)


# ---------------------------------------------------------------------------
# Tests: NTP time integration
# ---------------------------------------------------------------------------

class TestNTPTimeIntegration:
    def test_update_ntp_time(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        assert svc._ntp_time is None
        svc.update_ntp_time(1700000000.0)
        assert svc._ntp_time == 1700000000.0

    def test_clear_ntp_time(self):
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        svc.update_ntp_time(1700000000.0)
        svc.update_ntp_time(None)
        assert svc._ntp_time is None


# ---------------------------------------------------------------------------
# Tests: Edge Cases & Robustness
# ---------------------------------------------------------------------------

class TestEncryptionEdgeCases:
    def test_encrypt_empty_plaintext(self):
        """Empty string should encrypt and decrypt successfully."""
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = EncryptionService(ks)
        b64 = svc.encrypt_base64(plaintext="", mode="shared", sign=False)
        result = svc.decrypt(b64)
        assert result == ""

    def test_encrypt_large_plaintext(self):
        """Large message (1 MB) should round-trip correctly."""
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = EncryptionService(ks)
        large_text = "A" * (1024 * 1024)
        b64 = svc.encrypt_base64(plaintext=large_text, mode="shared", sign=False)
        result = svc.decrypt(b64)
        assert result == large_text

    def test_encrypt_unicode_plaintext(self):
        """Unicode / emoji content should survive encryption round-trip."""
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = EncryptionService(ks)
        text = "Hello \u4e16\u754c \U0001f600 \u00e9\u00e8\u00ea"
        b64 = svc.encrypt_base64(plaintext=text, mode="shared", sign=False)
        result = svc.decrypt(b64)
        assert result == text

    def test_decrypt_truncated_packet_raises(self):
        """A packet that is valid base64 but too short should raise DecryptionError."""
        ks = _make_mock_keystore()
        svc = EncryptionService(ks)
        # 4 bytes of base64 -> 3 raw bytes, far too small for any valid packet
        b64 = base64.b64encode(b"\x00\x01\x02").decode()
        with pytest.raises(DecryptionError):
            svc.decrypt(b64)

    def test_encrypt_with_multiple_friends_shared_mode(self):
        """Shared mode with friends list present still uses global secret when no friend specified."""
        secret = secrets.token_bytes(32)
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pub = priv.public_key()
        friend_secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(
            global_secret=secret,
            friends=[("Alice", pub, friend_secret)],
        )
        svc = EncryptionService(ks)
        # No friend_name => should use global_secret
        b64 = svc.encrypt_base64(plaintext="multi-friend", mode="shared", sign=False)
        result = svc.decrypt(b64)
        assert "multi-friend" in result

    def test_encrypt_friend_shared_mode_uses_friend_secret(self):
        """When friend_name is given in shared mode, the friend's shared secret is used."""
        global_secret = secrets.token_bytes(32)
        friend_secret = secrets.token_bytes(32)
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pub = priv.public_key()

        ks_enc = _make_mock_keystore(
            global_secret=global_secret,
            friends=[("Bob", pub, friend_secret)],
        )
        svc_enc = EncryptionService(ks_enc)
        b64 = svc_enc.encrypt_base64(
            plaintext="friend-secret-msg", friend_name="Bob", mode="shared", sign=False
        )

        # Decryptor only has the friend secret (not global)
        ks_dec = _make_mock_keystore(
            global_secret=secrets.token_bytes(32),  # different global
            friends=[("Bob", pub, friend_secret)],
        )
        svc_dec = EncryptionService(ks_dec)
        result = svc_dec.decrypt(b64)
        assert "friend-secret-msg" in result

    def test_encrypt_none_global_secret_no_friend_raises(self):
        """If global_secret is wrong size and no friend specified, should raise."""
        ks = _make_mock_keystore(global_secret=b"short")
        svc = EncryptionService(ks)
        with pytest.raises(EncryptionError, match="invalid"):
            svc.encrypt("fail", mode="shared", sign=False)

    def test_decrypt_self_destruct_flag_message(self):
        """Messages with self-destruct flag that have expired should give clear error."""
        secret = secrets.token_bytes(32)
        ks = _make_mock_keystore(global_secret=secret)
        svc = EncryptionService(ks)
        # Create a self-destruct message with 0 seconds (already expired)
        packet, _ = svc.encrypt("gone", mode="shared", sign=False, self_destruct_seconds=0)
        b64 = base64.b64encode(packet).decode()
        # The decrypt should either succeed (if within same second) or raise self-destruct error
        try:
            result = svc.decrypt(b64)
            # If it succeeded, that's fine (same-second edge case)
            assert "gone" in result
        except DecryptionError as e:
            assert "self-destruct" in str(e).lower() or "expired" in str(e).lower()

    def test_concurrent_encryption_independent(self):
        """Two EncryptionService instances with same keys produce independent outputs."""
        secret = secrets.token_bytes(32)
        ks1 = _make_mock_keystore(global_secret=secret)
        ks2 = _make_mock_keystore(global_secret=secret)
        svc1 = EncryptionService(ks1)
        svc2 = EncryptionService(ks2)

        b64_1 = svc1.encrypt_base64(plaintext="concurrent", mode="shared", sign=False)
        b64_2 = svc2.encrypt_base64(plaintext="concurrent", mode="shared", sign=False)

        # Both should decrypt with either service
        assert svc1.decrypt(b64_2) == "concurrent"
        assert svc2.decrypt(b64_1) == "concurrent"

    def test_keystore_with_no_friends_rsa_mode_raises(self):
        """RSA mode with empty friends list should raise clear error."""
        ks = _make_mock_keystore(friends=[])
        svc = EncryptionService(ks)
        with pytest.raises(EncryptionError):
            svc.encrypt("fail", friend_name="Anyone", mode="rsa")
