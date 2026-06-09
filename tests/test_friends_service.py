"""Comprehensive unit tests for services/friends_service.py."""

import secrets
import pytest
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import database
from key_manager import KeyStore, init_db, pubkey_to_pem
from services.friends_service import FriendsService, FriendsServiceError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    fake_db = tmp_path / "test_enigma.db"
    with patch.object(database, "DB_PATH", fake_db):
        yield fake_db


@pytest.fixture
def password():
    return "FriendsTest123!"


@pytest.fixture
def friends_service(password):
    init_db(password)
    ks = KeyStore()
    assert ks.load(password) is True
    return FriendsService(ks), ks, password


@pytest.fixture
def sample_rsa_pem():
    priv = rsa.generate_private_key(65537, 3072, default_backend())
    return pubkey_to_pem(priv.public_key())


# ---------------------------------------------------------------------------
# Tests: get_all_friends
# ---------------------------------------------------------------------------

class TestGetAllFriends:
    def test_empty_initially(self, friends_service):
        svc, ks, pw = friends_service
        assert svc.get_all_friends() == []

    def test_returns_added_friend(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Alice", sample_rsa_pem)
        friends = svc.get_all_friends()
        assert len(friends) == 1
        assert friends[0]["name"] == "Alice"
        assert friends[0]["has_shared_secret"] is False

    def test_includes_fingerprints(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Bob", sample_rsa_pem)
        info = svc.get_all_friends()[0]
        assert "rsa_fingerprint" in info
        assert len(info["rsa_fingerprint"]) == 16


# ---------------------------------------------------------------------------
# Tests: add_friend
# ---------------------------------------------------------------------------

class TestAddFriend:
    def test_add_basic(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Charlie", sample_rsa_pem)
        assert svc.friend_exists("Charlie")

    def test_add_with_shared_secret(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        secret = secrets.token_bytes(32)
        svc.add_friend("Dave", sample_rsa_pem, shared_secret=secret, master_password=pw)
        retrieved = svc.get_friend_secret("Dave")
        assert retrieved == secret

    def test_add_empty_name_raises(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        with pytest.raises(FriendsServiceError, match="empty"):
            svc.add_friend("", sample_rsa_pem)

    def test_add_empty_pem_raises(self, friends_service):
        svc, ks, pw = friends_service
        with pytest.raises(FriendsServiceError, match="Public key cannot be empty"):
            svc.add_friend("Eve", "")

    def test_add_secret_without_password_raises(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        with pytest.raises(FriendsServiceError, match="Master password required"):
            svc.add_friend("Frank", sample_rsa_pem, shared_secret=b"\x00" * 32)

    def test_add_invalid_x25519_raises(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        with pytest.raises(FriendsServiceError, match="Invalid X25519"):
            svc.add_friend("Grace", sample_rsa_pem, x25519_pub_b64="invalid!!!")

    def test_add_with_valid_x25519(self, friends_service, sample_rsa_pem):
        import base64
        svc, ks, pw = friends_service
        x_raw = secrets.token_bytes(32)
        x_b64 = base64.b64encode(x_raw).decode()
        svc.add_friend("Hank", sample_rsa_pem, x25519_pub_b64=x_b64)
        assert ks.friends_x25519.get("Hank") == x_b64

    def test_update_existing_friend(self, friends_service):
        svc, ks, pw = friends_service
        pem1 = pubkey_to_pem(rsa.generate_private_key(65537, 3072, default_backend()).public_key())
        pem2 = pubkey_to_pem(rsa.generate_private_key(65537, 3072, default_backend()).public_key())
        svc.add_friend("Ivy", pem1)
        svc.add_friend("Ivy", pem2)
        friends = svc.get_all_friends()
        ivy_entries = [f for f in friends if f["name"] == "Ivy"]
        assert len(ivy_entries) == 1


# ---------------------------------------------------------------------------
# Tests: remove_friend
# ---------------------------------------------------------------------------

class TestRemoveFriend:
    def test_remove_existing(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Jack", sample_rsa_pem)
        svc.remove_friend("Jack")
        assert not svc.friend_exists("Jack")

    def test_remove_nonexistent_raises(self, friends_service):
        svc, ks, pw = friends_service
        with pytest.raises(FriendsServiceError, match="not found"):
            svc.remove_friend("Ghost")


# ---------------------------------------------------------------------------
# Tests: update_shared_secret
# ---------------------------------------------------------------------------

class TestUpdateSharedSecret:
    def test_update(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Kate", sample_rsa_pem)
        new_secret = secrets.token_bytes(32)
        svc.update_shared_secret("Kate", new_secret, pw)
        assert svc.get_friend_secret("Kate") == new_secret

    def test_update_nonexistent_raises(self, friends_service):
        svc, ks, pw = friends_service
        with pytest.raises(FriendsServiceError, match="not found"):
            svc.update_shared_secret("Nobody", b"\x00" * 32, pw)

    def test_update_no_password_raises(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Leo", sample_rsa_pem)
        with pytest.raises(FriendsServiceError, match="Master password required"):
            svc.update_shared_secret("Leo", b"\x00" * 32, "")


# ---------------------------------------------------------------------------
# Tests: get_friend_details
# ---------------------------------------------------------------------------

class TestGetFriendDetails:
    def test_found(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Mia", sample_rsa_pem)
        details = svc.get_friend_details("Mia")
        assert details is not None
        assert details["name"] == "Mia"

    def test_not_found(self, friends_service):
        svc, ks, pw = friends_service
        assert svc.get_friend_details("Unknown") is None


# ---------------------------------------------------------------------------
# Tests: get_my_public_info
# ---------------------------------------------------------------------------

class TestGetMyPublicInfo:
    def test_returns_info(self, friends_service):
        svc, ks, pw = friends_service
        info = svc.get_my_public_info()
        assert "fingerprint" in info
        assert "public_key_pem" in info
        assert len(info["fingerprint"]) == 16
        assert "BEGIN PUBLIC KEY" in info["public_key_pem"]

    def test_no_key_raises(self):
        ks = MagicMock()
        ks.my_pub = None
        svc = FriendsService(ks)
        with pytest.raises(FriendsServiceError, match="No public key"):
            svc.get_my_public_info()


# ---------------------------------------------------------------------------
# Tests: friend_exists
# ---------------------------------------------------------------------------

class TestFriendExists:
    def test_true(self, friends_service, sample_rsa_pem):
        svc, ks, pw = friends_service
        svc.add_friend("Nora", sample_rsa_pem)
        assert svc.friend_exists("Nora") is True

    def test_false(self, friends_service):
        svc, ks, pw = friends_service
        assert svc.friend_exists("Zara") is False
