"""Comprehensive unit tests for services/backup_service.py."""

import json
import secrets
import time
import pytest
from unittest.mock import patch, MagicMock

import database
from key_manager import KeyStore, init_db, pubkey_to_pem
from services.backup_service import BackupService, BackupServiceError, BACKUP_VERSION


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
    return "BackupTest123!"


@pytest.fixture
def key_store(password):
    init_db(password)
    ks = KeyStore()
    assert ks.load(password) is True
    return ks


@pytest.fixture
def backup_service(key_store):
    return BackupService(key_store)


# ---------------------------------------------------------------------------
# Tests: export_backup
# ---------------------------------------------------------------------------

class TestExportBackup:
    def test_export_structure(self, backup_service, password):
        data = backup_service.export_backup(password)
        assert data["version"] == BACKUP_VERSION
        assert "exported_at" in data
        assert "settings" in data
        assert "friends" in data
        assert "hmac" in data

    def test_export_contains_required_settings(self, backup_service, password):
        data = backup_service.export_backup(password)
        settings = data["settings"]
        assert "public_key" in settings
        assert "private_key_encrypted" in settings
        assert "global_secret" in settings

    def test_export_hmac_valid(self, backup_service, password):
        data = backup_service.export_backup(password)
        # Verify HMAC internally
        payload = {
            "version": data["version"],
            "exported_at": data["exported_at"],
            "settings": data["settings"],
            "friends": data["friends"],
        }
        hmac_key = BackupService._derive_hmac_key(password)
        computed = backup_service._compute_hmac(payload, hmac_key)
        assert computed == data["hmac"]

    def test_export_with_friends(self, backup_service, password, key_store):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        key_store.save_friend("TestFriend", pem)

        data = backup_service.export_backup(password)
        assert len(data["friends"]) == 1
        assert data["friends"][0]["name"] == "TestFriend"

    def test_export_timestamp_recent(self, backup_service, password):
        before = int(time.time())
        data = backup_service.export_backup(password)
        after = int(time.time())
        assert before <= data["exported_at"] <= after


# ---------------------------------------------------------------------------
# Tests: import_backup
# ---------------------------------------------------------------------------

class TestImportBackup:
    def test_roundtrip(self, backup_service, password, key_store):
        """Export → wipe → import → verify keys restored."""
        original_secret = bytes(key_store.global_secret)
        export_data = backup_service.export_backup(password)

        # Wipe and reload to simulate fresh state
        key_store.wipe()
        backup_service.import_backup(export_data, password)

        assert bytes(key_store.global_secret) == original_secret
        assert key_store.my_priv is not None
        assert key_store.my_pub is not None

    def test_import_wrong_version_raises(self, backup_service, password):
        data = backup_service.export_backup(password)
        data["version"] = 999
        with pytest.raises(BackupServiceError, match="Unsupported backup version"):
            backup_service.import_backup(data, password)

    def test_import_wrong_password_raises(self, backup_service, password):
        data = backup_service.export_backup(password)
        with pytest.raises(BackupServiceError, match="HMAC verification failed"):
            backup_service.import_backup(data, "WrongPassword")

    def test_import_tampered_data_raises(self, backup_service, password):
        data = backup_service.export_backup(password)
        data["settings"]["public_key"] = "TAMPERED"
        with pytest.raises(BackupServiceError, match="HMAC verification failed"):
            backup_service.import_backup(data, password)

    def test_import_missing_hmac_raises(self, backup_service, password):
        data = backup_service.export_backup(password)
        del data["hmac"]
        with pytest.raises(BackupServiceError, match="missing HMAC"):
            backup_service.import_backup(data, password)

    def test_import_missing_setting_raises(self, backup_service, password):
        data = backup_service.export_backup(password)
        del data["settings"]["public_key"]
        # Re-compute HMAC so it passes that check but fails structural validation
        hmac_key = BackupService._derive_hmac_key(password)
        payload = {
            "version": data["version"],
            "exported_at": data["exported_at"],
            "settings": data["settings"],
            "friends": data["friends"],
        }
        data["hmac"] = backup_service._compute_hmac(payload, hmac_key)
        with pytest.raises(BackupServiceError, match="Missing setting"):
            backup_service.import_backup(data, password)

    def test_import_restores_friends(self, backup_service, password, key_store):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        priv = rsa.generate_private_key(65537, 3072, default_backend())
        pem = pubkey_to_pem(priv.public_key())
        secret = secrets.token_bytes(32)
        key_store.save_friend("BackupFriend", pem, shared_secret=secret, password=password)

        export_data = backup_service.export_backup(password)
        key_store.wipe()
        backup_service.import_backup(export_data, password)

        assert any(n == "BackupFriend" for n, _, _ in key_store.friends)
        retrieved = key_store.get_friend_secret("BackupFriend")
        assert retrieved == secret


# ---------------------------------------------------------------------------
# Tests: Internal helpers
# ---------------------------------------------------------------------------

class TestInternalHelpers:
    def test_canonical_json_deterministic(self):
        obj = {"b": 2, "a": 1}
        c1 = BackupService._canonical_json(obj)
        c2 = BackupService._canonical_json({"a": 1, "b": 2})
        assert c1 == c2

    def test_derive_hmac_key_length(self):
        key = BackupService._derive_hmac_key("test")
        assert len(key) == 32

    def test_derive_hmac_key_deterministic(self):
        k1 = BackupService._derive_hmac_key("same")
        k2 = BackupService._derive_hmac_key("same")
        assert k1 == k2

    def test_derive_hmac_key_different_passwords(self):
        k1 = BackupService._derive_hmac_key("a")
        k2 = BackupService._derive_hmac_key("b")
        assert k1 != k2

    def test_compute_and_verify_hmac(self, backup_service):
        payload = {"test": "data"}
        key = BackupService._derive_hmac_key("pw")
        hmac_val = backup_service._compute_hmac(payload, key)
        assert backup_service._verify_hmac(payload, hmac_val, key) is True

    def test_verify_hmac_wrong_value(self, backup_service):
        payload = {"test": "data"}
        key = BackupService._derive_hmac_key("pw")
        assert backup_service._verify_hmac(payload, "wrong_hmac", key) is False
