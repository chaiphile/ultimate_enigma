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

    def test_set_key_store_retargets_verification(self):
        old_ks = MagicMock()
        old_ks.verify_password.return_value = False
        old_ks.is_duress_mode = False
        new_ks = MagicMock()
        new_ks.verify_password.return_value = False
        new_ks.is_duress_mode = False

        svc = BackupService(old_ks)
        svc.set_key_store(new_ks)
        svc.verify_master_password("pw")

        old_ks.verify_password.assert_not_called()
        new_ks.verify_password.assert_called_once_with("pw")

    def test_verify_master_password_rejects_duress_and_preserves_mode(self):
        class FakeKeyStore:
            def __init__(self):
                self._duress_mode = False

            @property
            def is_duress_mode(self):
                return self._duress_mode

            def verify_password(self, _password):
                self._duress_mode = True
                return True

        ks = FakeKeyStore()
        svc = BackupService(ks)

        assert svc.verify_master_password("duress") is False
        assert ks._duress_mode is False


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
        with pytest.raises((ValueError, BackupServiceError), match="missing keys|missing HMAC"):
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


# ---------------------------------------------------------------------------
# Tests: Versioned File Backups
# ---------------------------------------------------------------------------

class TestVersionedBackups:
    def test_export_backup_to_file_creates_file(self, backup_service, password, tmp_path):
        backup_dir = tmp_path / "backups"
        filepath = backup_service.export_backup_to_file(password, backup_dir=backup_dir)
        assert filepath.exists()
        assert filepath.suffix == ".json"
        assert "enigma_backup_" in filepath.name

    def test_export_backup_to_file_valid_json(self, backup_service, password, tmp_path):
        import json
        backup_dir = tmp_path / "backups"
        filepath = backup_service.export_backup_to_file(password, backup_dir=backup_dir)
        with open(filepath, "r") as f:
            data = json.load(f)
        assert data["version"] == BACKUP_VERSION
        assert "hmac" in data

    def test_list_backups_sorted_newest_first(self, backup_service, password, tmp_path):
        import time as _time
        backup_dir = tmp_path / "backups"
        paths = []
        for _ in range(3):
            p = backup_service.export_backup_to_file(password, backup_dir=backup_dir)
            paths.append(p)
            _time.sleep(1.1)  # ensure distinct timestamps
        listed = backup_service.list_backups(backup_dir=backup_dir)
        assert len(listed) == 3
        # Newest first
        assert listed[0] == paths[-1]
        assert listed[-1] == paths[0]

    def test_prune_old_backups(self, password, tmp_path, key_store):
        backup_dir = tmp_path / "backups"
        svc = BackupService(key_store, backup_dir=backup_dir, max_backups=2)
        import time as _time
        for _ in range(5):
            svc.export_backup_to_file(password, backup_dir=backup_dir)
            _time.sleep(1.1)
        remaining = svc.list_backups(backup_dir=backup_dir)
        assert len(remaining) == 2

    def test_import_backup_from_file_roundtrip(self, backup_service, password, key_store, tmp_path):
        original_secret = bytes(key_store.global_secret)
        backup_dir = tmp_path / "backups"
        filepath = backup_service.export_backup_to_file(password, backup_dir=backup_dir)

        key_store.wipe()
        backup_service.import_backup_from_file(filepath, password)
        assert bytes(key_store.global_secret) == original_secret

    def test_import_from_nonexistent_file_raises(self, backup_service, password, tmp_path):
        fake_path = tmp_path / "nonexistent.json"
        with pytest.raises(BackupServiceError, match="Cannot read backup file"):
            backup_service.import_backup_from_file(fake_path, password)

    def test_import_from_invalid_json_raises(self, backup_service, password, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("NOT JSON {{{")
        with pytest.raises(BackupServiceError, match="Cannot read backup file"):
            backup_service.import_backup_from_file(bad_file, password)

    def test_list_backups_empty_dir(self, backup_service, tmp_path):
        empty_dir = tmp_path / "empty"
        result = backup_service.list_backups(backup_dir=empty_dir)
        assert result == []


# ---------------------------------------------------------------------------
# Tests: Backup Reminder
# ---------------------------------------------------------------------------

class TestBackupReminder:
    def test_should_remind_when_never_backed_up(self, backup_service):
        remind, days = backup_service.should_remind_backup()
        assert remind is True
        assert days is None

    def test_should_not_remind_after_recent_backup(self, backup_service, password, tmp_path):
        backup_dir = tmp_path / "backups"
        backup_service.export_backup_to_file(password, backup_dir=backup_dir)
        remind, days = backup_service.should_remind_backup()
        assert remind is False

    def test_should_remind_after_expired_interval(self, password, tmp_path, key_store):
        backup_dir = tmp_path / "backups"
        svc = BackupService(key_store, backup_dir=backup_dir, reminder_days=1)
        # Manually set last backup to 2 days ago
        old_ts = int(time.time()) - (2 * 86400)
        svc._record_backup_timestamp(old_ts)
        remind, days = svc.should_remind_backup()
        assert remind is True
        assert days >= 2

    def test_get_last_backup_timestamp_none_initially(self, backup_service):
        assert backup_service.get_last_backup_timestamp() is None

    def test_get_last_backup_timestamp_after_export(self, backup_service, password, tmp_path):
        backup_dir = tmp_path / "backups"
        before = int(time.time())
        backup_service.export_backup_to_file(password, backup_dir=backup_dir)
        after = int(time.time())
        ts = backup_service.get_last_backup_timestamp()
        assert ts is not None
        assert before <= ts <= after

    def test_record_backup_timestamp_persists(self, backup_service):
        ts = 1700000000
        backup_service._record_backup_timestamp(ts)
        retrieved = backup_service.get_last_backup_timestamp()
        assert retrieved == ts
