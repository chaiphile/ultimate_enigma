"""Unit tests for services/anomaly_detection_service.py.

Covers model loading (present/missing/corrupt), feature extraction,
scoring/prediction, ANOMALY_DETECTED event publication, graceful
degradation when the model file is unavailable, and cheap integration
with the EncryptionService facade.

sklearn is never imported directly here; the model is mocked with a
simple fake so tests run with or without sklearn installed.
"""

import os
import time

import pytest

# The service imports numpy and joblib at module load. Skip cleanly if
# they are unavailable in this environment (mirrors the service's own
# best-effort degradation, which is only about the *model file*, not the
# runtime dependencies).
np = pytest.importorskip("numpy")
pytest.importorskip("joblib")

from services.anomaly_detection_service import (
    AnomalyDetectionService,
    _extract_lengths,
    MODEL_FILENAME,
)
from models.envelope import RatchetEnvelope, PQCEncvelope
from models.message_score import MessageScore
from services.event_bus import event_bus, Events
from services.encryption import EncryptionService


# ---------------------------------------------------------------------------
# Fakes & fixtures
# ---------------------------------------------------------------------------

class _FakeModel:
    """Minimal stand-in for an IsolationForest (or any score_samples model)."""

    def __init__(self, scores, threshold=-0.5, has_threshold=True):
        self._scores = list(scores)
        if has_threshold:
            self.threshold_ = threshold

    def score_samples(self, arr):
        if arr.shape[0] > len(self._scores):
            raise ValueError("not enough scores for batch")
        return np.asarray(self._scores[: arr.shape[0]], dtype=float)


class _FakeLocalTime:
    """Fixed clock so feature-extraction hour/day are deterministic."""

    tm_hour = 14
    tm_wday = 2


class _RecordingAnomaly:
    """Dummy anomaly service used to observe EncryptionService calls."""

    def __init__(self, enabled=True, raise_on_score=False):
        self.enabled = enabled
        self.raise_on_score = raise_on_score
        self.calls = []

    def score_message(self, friend_name, packet):
        if self.raise_on_score:
            raise RuntimeError("boom")
        self.calls.append((friend_name, packet))


def _make_mock_keystore(global_secret=None):
    """Build a MockKeyStore with just enough to drive legacy encrypt/decrypt."""
    from unittest.mock import MagicMock

    secret = global_secret or os.urandom(32)
    ks = MagicMock()
    ks.global_secret = secret
    ks.my_priv = None
    ks.my_ed_priv = None
    ks.my_dil_priv = None
    ks.friends = []
    ks.friends_capabilities = {}
    ks.friends_pqc_combined_pub = {}
    ks.friends_hybrid_sig_pubs = {}
    ks.my_hybrid_sig_combined_pub = None
    ks.pqc_decryption_bundle = None
    ks.get_decryption_snapshot.return_value = (None, [], [secret], None)
    return ks


@pytest.fixture(autouse=True)
def clean_event_bus():
    """Reset global event bus subscriptions before and after each test."""
    event_bus.clear()
    yield
    event_bus.clear()


@pytest.fixture
def fixed_time(monkeypatch):
    """Pin time.localtime so feature extraction is deterministic."""
    import services.anomaly_detection_service as ad_mod

    monkeypatch.setattr(ad_mod.time, "localtime", lambda: _FakeLocalTime())
    return _FakeLocalTime


@pytest.fixture
def fake_model_load(monkeypatch):
    """Patch joblib.load inside the service to return a _FakeModel."""

    def _patch(scores, threshold=-0.5, has_threshold=True):
        fake = _FakeModel(scores, threshold=threshold, has_threshold=has_threshold)
        import services.anomaly_detection_service as ad_mod

        monkeypatch.setattr(ad_mod, "joblib_load", lambda path: fake)
        return fake

    return _patch


def _ratchet_packet():
    return RatchetEnvelope(
        sender_name="Alice",
        header=b"\x01\x02\x03\x04\x05\x06",
        ciphertext=b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11",
    ).build()


def _pqc_packet():
    return PQCEncvelope(
        kem_ciphertext=bytes(range(16)),
        nonce=b"\x00" * 12,
        aes_ciphertext=bytes(range(32)),
    ).build()


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

class TestModelLoading:
    def test_missing_model_file_is_unavailable(self):
        svc = AnomalyDetectionService(model_path="C:/nonexistent/nope.pkl")
        assert svc._model is None
        assert svc.is_available() is False
        assert svc.enabled is True  # still "enabled", just not available

    def test_corrupt_model_file_is_unavailable(self, tmp_path):
        bogus = tmp_path / "bad.pkl"
        bogus.write_bytes(b"this is not a pickle file at all")
        svc = AnomalyDetectionService(model_path=str(bogus))
        assert svc._model is None
        assert svc.is_available() is False

    def test_load_model_from_mocked_path(self, fake_model_load):
        fake_model_load([0.5, 1.0], threshold=-0.7)
        svc = AnomalyDetectionService(model_path="whatever.pkl")
        assert svc._model is not None
        assert svc.is_available() is True
        assert svc._threshold == -0.7

    def test_model_without_threshold_attribute_defaults(self, fake_model_load):
        """sklearn IsolationForest has no threshold_ attr -> default -0.5."""
        fake_model_load([0.0], has_threshold=False)
        svc = AnomalyDetectionService(model_path="whatever.pkl")
        assert svc._threshold == -0.5

    def test_default_model_path_returns_model_filename(self):
        path = AnomalyDetectionService._default_model_path()
        assert isinstance(path, str)
        assert os.path.basename(path) == MODEL_FILENAME

    def test_default_model_path_prefers_existing_file(self, monkeypatch, tmp_path):
        """When a model file exists next to the source, it should be chosen."""
        existing = tmp_path / MODEL_FILENAME
        existing.write_bytes(b"x")
        import services.anomaly_detection_service as ad_mod

        monkeypatch.setattr(ad_mod.os.path, "isfile", lambda p: p.endswith(MODEL_FILENAME))
        path = AnomalyDetectionService._default_model_path()
        assert path.endswith(MODEL_FILENAME)

    def test_real_model_loads_when_present(self):
        """Integration: if the shipped model exists, it must load (or skip)."""
        path = AnomalyDetectionService._default_model_path()
        if not os.path.isfile(path):
            pytest.skip("anomaly_model.pkl not present in repo")
        svc = AnomalyDetectionService()
        assert svc.is_available() is True
        assert svc._model is not None


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

class TestFeatureExtraction:
    def test_extract_features_ratchet(self, fixed_time):
        packet = _ratchet_packet()
        feats = AnomalyDetectionService._extract_features("Alice", packet)
        assert feats is not None
        assert len(feats) == 7
        size, name_len, env_code, hdr_len, ct_len, hour, day = feats
        assert size == float(len(packet))
        assert name_len == 5.0
        assert env_code == 0.0  # ratchet
        assert hdr_len == 6.0  # len(header)
        assert ct_len == 8.0  # len(ciphertext)
        assert hour == 14.0
        assert day == 2.0

    def test_extract_features_pqc(self, fixed_time):
        packet = _pqc_packet()
        feats = AnomalyDetectionService._extract_features("Bob", packet)
        assert feats is not None
        size, name_len, env_code, hdr_len, ct_len, hour, day = feats
        assert env_code == 1.0  # pqc
        assert hdr_len == 16.0 + 12.0  # kem_ct_len + nonce
        assert ct_len == 32.0  # aes ciphertext
        assert name_len == 3.0

    def test_extract_features_unknown_type(self, fixed_time):
        feats = AnomalyDetectionService._extract_features("Eve", b"\x99\x01\x02\x03")
        assert feats is not None
        size, name_len, env_code, hdr_len, ct_len, hour, day = feats
        assert env_code == -1.0  # unknown
        assert hdr_len == 0.0
        assert ct_len == 4.0  # falls back to full length

    def test_extract_features_empty_packet(self, fixed_time):
        feats = AnomalyDetectionService._extract_features("Eve", b"")
        assert feats is not None
        size, name_len, env_code, hdr_len, ct_len, hour, day = feats
        assert size == 0.0
        assert env_code == -1.0
        assert hdr_len == 0.0
        assert ct_len == 0.0

    def test_extract_features_none_name_returns_none(self):
        assert AnomalyDetectionService._extract_features(None, b"\xd0\x01A") is None

    def test_extract_features_none_packet_returns_none(self):
        assert AnomalyDetectionService._extract_features("Alice", None) is None

    def test_extract_features_fixed_time_components(self, fixed_time):
        feats = AnomalyDetectionService._extract_features("A", b"\x00\x01")
        assert feats[5] == 14.0
        assert feats[6] == 2.0


# ---------------------------------------------------------------------------
# _extract_lengths helpers
# ---------------------------------------------------------------------------

class TestExtractLengths:
    def test_ratchet_truncated_falls_back_to_full_length(self):
        # name_len=3 but packet is too short to hold name + hdr_len
        packet = b"\xd0\x03AB"
        hdr_len, ct_len = _extract_lengths(packet, "ratchet")
        assert hdr_len == 0.0
        assert ct_len == float(len(packet))

    def test_ratchet_header_overrun_clamps_ct_to_zero(self):
        # name_len=1, hdr_len claims 100 but nothing follows; the service
        # trusts the header length and clamps ciphertext length to 0.
        packet = b"\xd0\x01A\x00\x64"
        hdr_len, ct_len = _extract_lengths(packet, "ratchet")
        assert hdr_len == 100.0
        assert ct_len == 0.0

    def test_pqc_truncated_falls_back_to_full_length(self):
        # kem_ct_len=0 but nonce (12B) doesn't fit in a 3-byte packet
        packet = b"\x50\x00\x00"
        hdr_len, ct_len = _extract_lengths(packet, "pqc")
        assert hdr_len == 0.0
        assert ct_len == float(len(packet))

    def test_unknown_type_returns_full_length(self):
        hdr_len, ct_len = _extract_lengths(b"\x99\x00\x01\x02\x03", None)
        assert hdr_len == 0.0
        assert ct_len == 5.0


# ---------------------------------------------------------------------------
# Scoring / prediction
# ---------------------------------------------------------------------------

class TestScoring:
    def test_score_message_normal_not_anomaly(self, fake_model_load):
        fake_model_load([2.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        result = svc.score_message("Alice", _ratchet_packet())
        assert isinstance(result, MessageScore)
        assert result.is_anomaly is False
        assert result.friend_name == "Alice"

    def test_score_message_result_fields(self, fake_model_load):
        fake_model_load([0.75], threshold=-0.5)
        svc = AnomalyDetectionService(model_path="m.pkl")
        packet = _ratchet_packet()
        result = svc.score_message("Alice", packet)
        assert result.score == pytest.approx(0.75)
        assert result.threshold == -0.5
        assert result.envelope_type == "ratchet"
        assert result.packet_size == len(packet)
        assert result.timestamp is not None

    def test_score_message_anomaly_publishes_event(self, fake_model_load):
        fake_model_load([-5.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        received = []

        def handler(**kwargs):
            received.append(kwargs)

        event_bus.subscribe(Events.ANOMALY_DETECTED, handler)
        try:
            result = svc.score_message("Mallory", _ratchet_packet())
        finally:
            event_bus.unsubscribe(Events.ANOMALY_DETECTED, handler)

        assert result is not None
        assert result.is_anomaly is True
        assert len(received) == 1
        assert received[0]["score"] is result

    def test_no_event_published_when_normal(self, fake_model_load):
        fake_model_load([3.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        received = []

        def handler(**kwargs):
            received.append(kwargs)

        event_bus.subscribe(Events.ANOMALY_DETECTED, handler)
        try:
            svc.score_message("Alice", _ratchet_packet())
        finally:
            event_bus.unsubscribe(Events.ANOMALY_DETECTED, handler)
        assert received == []

    def test_threshold_boundary(self, fake_model_load):
        """score == threshold must NOT be flagged; score below it must."""
        fake_model_load([-0.5], threshold=-0.5)
        svc = AnomalyDetectionService(model_path="m.pkl")
        assert svc.score_message("A", _ratchet_packet()).is_anomaly is False

        fake_model_load([-0.5001], threshold=-0.5)
        svc2 = AnomalyDetectionService(model_path="m.pkl")
        assert svc2.score_message("A", _ratchet_packet()).is_anomaly is True

    def test_score_message_disabled_returns_none(self, fake_model_load):
        fake_model_load([-5.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        svc.enabled = False
        assert svc.score_message("Alice", _ratchet_packet()) is None

    def test_score_message_no_model_returns_none(self):
        svc = AnomalyDetectionService(model_path="C:/nonexistent/nope.pkl")
        assert svc.is_available() is False
        assert svc.score_message("Alice", _ratchet_packet()) is None

    def test_score_message_feature_failure_returns_none(self, fake_model_load, monkeypatch):
        fake_model_load([1.0])
        svc = AnomalyDetectionService(model_path="m.pkl")

        def _broken_extract(friend_name, packet):
            return None

        monkeypatch.setattr(
            AnomalyDetectionService, "_extract_features", staticmethod(_broken_extract)
        )
        assert svc.score_message("Alice", _ratchet_packet()) is None

    def test_score_message_model_exception_returns_none(self, fake_model_load):
        fake_model_load([1.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        svc._model.score_samples = lambda arr: (_ for _ in ()).throw(RuntimeError("x"))
        assert svc.score_message("Alice", _ratchet_packet()) is None

    def test_score_message_feature_extraction_exception_returns_none(self, fake_model_load, monkeypatch):
        fake_model_load([1.0])
        svc = AnomalyDetectionService(model_path="m.pkl")

        def _throwing_extract(friend_name, packet):
            raise ValueError("bad metadata")

        monkeypatch.setattr(
            AnomalyDetectionService, "_extract_features", staticmethod(_throwing_extract)
        )
        assert svc.score_message("Alice", _ratchet_packet()) is None


# ---------------------------------------------------------------------------
# enabled property
# ---------------------------------------------------------------------------

class TestEnabledFlag:
    def test_enabled_defaults_true(self, fake_model_load):
        fake_model_load([1.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        assert svc.enabled is True

    def test_enabled_setter_coerces_to_bool(self, fake_model_load):
        fake_model_load([1.0])
        svc = AnomalyDetectionService(model_path="m.pkl")
        svc.enabled = 0
        assert svc.enabled is False
        svc.enabled = 1
        assert svc.enabled is True
        svc.enabled = ""
        assert svc.enabled is False


# ---------------------------------------------------------------------------
# Integration with EncryptionService facade
# ---------------------------------------------------------------------------

class TestEncryptionFacadeIntegration:
    def test_legacy_decrypt_scores_anomaly(self):
        anom = _RecordingAnomaly()
        ks = _make_mock_keystore(global_secret=os.urandom(32))
        svc = EncryptionService(ks, anomaly_service=anom)
        b64 = svc.encrypt_base64(plaintext="hello", mode="shared", sign=False)
        out = svc.decrypt(b64)
        assert "hello" in out
        assert len(anom.calls) == 1
        label, packet = anom.calls[0]
        assert label == "legacy"
        assert isinstance(packet, bytes) and len(packet) > 0

    def test_no_anomaly_service_skips_scoring(self):
        ks = _make_mock_keystore(global_secret=os.urandom(32))
        svc = EncryptionService(ks, anomaly_service=None)
        b64 = svc.encrypt_base64(plaintext="hello", mode="shared", sign=False)
        assert "hello" in svc.decrypt(b64)

    def test_disabled_anomaly_service_skips_scoring(self):
        anom = _RecordingAnomaly(enabled=False)
        ks = _make_mock_keystore(global_secret=os.urandom(32))
        svc = EncryptionService(ks, anomaly_service=anom)
        b64 = svc.encrypt_base64(plaintext="hello", mode="shared", sign=False)
        svc.decrypt(b64)
        assert anom.calls == []

    def test_score_ratchet_anomaly_parses_sender(self):
        anom = _RecordingAnomaly()
        ks = _make_mock_keystore()
        svc = EncryptionService(ks, anomaly_service=anom)
        packet = _ratchet_packet()
        svc._score_ratchet_anomaly(packet)
        assert anom.calls == [("Alice", packet)]

    def test_score_anomaly_swallows_exceptions(self):
        anom = _RecordingAnomaly(raise_on_score=True)
        ks = _make_mock_keystore(global_secret=os.urandom(32))
        svc = EncryptionService(ks, anomaly_service=anom)
        b64 = svc.encrypt_base64(plaintext="hello", mode="shared", sign=False)
        # Should not raise even though scoring explodes.
        assert "hello" in svc.decrypt(b64)
