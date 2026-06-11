"""Comprehensive unit tests for models/friend_profile.py – Friend Profile Model."""

import json
import pytest
from unittest.mock import patch, MagicMock

import database
from models.friend_profile import FriendProfile


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Redirect DB_PATH to a temporary directory for every test."""
    fake_db = tmp_path / "test_enigma.db"
    with patch.object(database, "DB_PATH", fake_db):
        yield fake_db


@pytest.fixture
def initialized_db():
    """Initialize the database schema."""
    database.init_db()
    return database.get_connection()


def _insert_friend(conn, name, pem="-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
                   has_sec=0, sec_enc=None, x_b64=None, caps=None, ratchet=None, pqc_pub=None):
    """Helper to insert a friend record."""
    conn.execute(
        "INSERT INTO friends (name, public_key_pem, has_shared_secret, "
        "shared_secret_encrypted, x25519_public_key_b64, capabilities_json, "
        "ratchet_state_json, pqc_combined_pub_b64) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (name, pem, has_sec, sec_enc, x_b64, caps, ratchet, pqc_pub)
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Tests: FriendProfile Construction
# ---------------------------------------------------------------------------

class TestFriendProfileConstruction:
    def test_basic_creation(self):
        profile = FriendProfile(name="Alice")
        assert profile.name == "Alice"
        assert profile.public_key is None
        assert profile.shared_secret is None
        assert profile.capabilities == {}
        assert profile.has_active_ratchet is False
        assert profile.pqc_combined_pub is None

    def test_full_creation(self):
        profile = FriendProfile(
            name="Bob",
            public_key=b"fake_key",
            shared_secret=b"fake_secret",
            capabilities={"double_ratchet": True},
            has_active_ratchet=True,
            pqc_combined_pub=b"pqc_pub",
        )
        assert profile.name == "Bob"
        assert profile.public_key == b"fake_key"
        assert profile.shared_secret == b"fake_secret"
        assert profile.capabilities == {"double_ratchet": True}
        assert profile.has_active_ratchet is True
        assert profile.pqc_combined_pub == b"pqc_pub"

    def test_frozen_dataclass(self):
        profile = FriendProfile(name="Charlie")
        with pytest.raises(AttributeError):
            profile.name = "Dave"


# ---------------------------------------------------------------------------
# Tests: Properties
# ---------------------------------------------------------------------------

class TestProperties:
    def test_supports_double_ratchet_true(self):
        profile = FriendProfile(
            name="Alice",
            capabilities={"double_ratchet": True}
        )
        assert profile.supports_double_ratchet is True

    def test_supports_double_ratchet_false(self):
        profile = FriendProfile(
            name="Alice",
            capabilities={"double_ratchet": False}
        )
        assert profile.supports_double_ratchet is False

    def test_supports_double_ratchet_missing(self):
        profile = FriendProfile(name="Alice", capabilities={})
        assert profile.supports_double_ratchet is False

    def test_supports_pqc_true(self):
        profile = FriendProfile(
            name="Bob",
            capabilities={"pqc": True}
        )
        assert profile.supports_pqc is True

    def test_supports_pqc_false(self):
        profile = FriendProfile(name="Bob", capabilities={})
        assert profile.supports_pqc is False


# ---------------------------------------------------------------------------
# Tests: from_database
# ---------------------------------------------------------------------------

class TestFromDatabase:
    def test_load_existing_friend(self, initialized_db):
        _insert_friend(initialized_db, "Alice", caps='{"double_ratchet": true}')
        profile = FriendProfile.from_database("Alice")
        assert profile is not None
        assert profile.name == "Alice"
        assert profile.capabilities == {"double_ratchet": True}
        assert profile.supports_double_ratchet is True

    def test_load_nonexistent_friend(self, initialized_db):
        profile = FriendProfile.from_database("Nobody")
        assert profile is None

    def test_load_with_ratchet_state(self, initialized_db):
        _insert_friend(
            initialized_db, "Bob",
            ratchet='{"root_key": "abc"}'
        )
        profile = FriendProfile.from_database("Bob")
        assert profile is not None
        assert profile.has_active_ratchet is True

    def test_load_without_ratchet_state(self, initialized_db):
        _insert_friend(initialized_db, "Charlie", ratchet=None)
        profile = FriendProfile.from_database("Charlie")
        assert profile is not None
        assert profile.has_active_ratchet is False

    def test_load_with_pqc_pub(self, initialized_db):
        _insert_friend(
            initialized_db, "Dave",
            pqc_pub="base64_encoded_pqc_pub"
        )
        profile = FriendProfile.from_database("Dave")
        assert profile is not None
        assert profile.pqc_combined_pub is not None

    def test_load_corrupted_capabilities(self, initialized_db):
        _insert_friend(
            initialized_db, "Eve",
            caps="NOT VALID JSON"
        )
        profile = FriendProfile.from_database("Eve")
        assert profile is not None
        assert profile.capabilities == {}

    def test_load_with_public_key(self, initialized_db):
        pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----"
        _insert_friend(initialized_db, "Frank", pem=pem)
        profile = FriendProfile.from_database("Frank")
        assert profile is not None
        assert profile.public_key == pem.encode()

    def test_database_error_returns_none(self, initialized_db):
        """If DB error occurs, from_database should return None."""
        # Corrupt the database connection to trigger an error
        initialized_db.close()
        profile = FriendProfile.from_database("Alice")
        # Should return None gracefully
        assert profile is None


# ---------------------------------------------------------------------------
# Tests: list_all
# ---------------------------------------------------------------------------

class TestListAll:
    def test_empty_database(self, initialized_db):
        profiles = FriendProfile.list_all()
        assert profiles == []

    def test_list_multiple_friends(self, initialized_db):
        _insert_friend(initialized_db, "Alice")
        _insert_friend(initialized_db, "Bob")
        _insert_friend(initialized_db, "Charlie")

        profiles = FriendProfile.list_all()
        assert len(profiles) == 3
        names = {p.name for p in profiles}
        assert names == {"Alice", "Bob", "Charlie"}

    def test_list_with_capabilities(self, initialized_db):
        _insert_friend(
            initialized_db, "Alice",
            caps='{"double_ratchet": true, "pqc": false}'
        )
        profiles = FriendProfile.list_all()
        assert len(profiles) == 1
        assert profiles[0].capabilities == {"double_ratchet": True, "pqc": False}

    def test_list_handles_corrupted_json(self, initialized_db):
        _insert_friend(initialized_db, "Alice", caps="BAD JSON")
        _insert_friend(initialized_db, "Bob", caps='{"double_ratchet": true}')

        profiles = FriendProfile.list_all()
        assert len(profiles) == 2

    def test_list_with_mixed_ratchet_states(self, initialized_db):
        _insert_friend(initialized_db, "Alice", ratchet='{"root_key": "abc"}')
        _insert_friend(initialized_db, "Bob", ratchet=None)

        profiles = FriendProfile.list_all()
        alice = [p for p in profiles if p.name == "Alice"][0]
        bob = [p for p in profiles if p.name == "Bob"][0]

        assert alice.has_active_ratchet is True
        assert bob.has_active_ratchet is False

    def test_list_database_error_returns_empty(self, initialized_db):
        """If DB error occurs, list_all should return empty list."""
        initialized_db.close()
        profiles = FriendProfile.list_all()
        assert profiles == []


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_profile_with_all_capabilities(self, initialized_db):
        _insert_friend(
            initialized_db, "FullProfile",
            caps='{"double_ratchet": true, "pqc": true, "hybrid_sig": true}',
            ratchet='{"root_key": "abc"}',
            pqc_pub="base64_pqc_pub",
        )
        profile = FriendProfile.from_database("FullProfile")
        assert profile is not None
        assert profile.supports_double_ratchet is True
        assert profile.supports_pqc is True
        assert profile.has_active_ratchet is True
        assert profile.pqc_combined_pub is not None

    def test_profile_equality(self):
        p1 = FriendProfile(name="Alice", capabilities={"double_ratchet": True})
        p2 = FriendProfile(name="Alice", capabilities={"double_ratchet": True})
        assert p1 == p2

    def test_profile_inequality(self):
        p1 = FriendProfile(name="Alice")
        p2 = FriendProfile(name="Bob")
        assert p1 != p2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
