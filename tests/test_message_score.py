"""Unit tests for models/message_score.py.

Covers construction, attribute access, frozen dataclass semantics,
equality/repr/hashing, confidence normalization, and edge cases.
"""

from datetime import datetime

import pytest
from dataclasses import FrozenInstanceError

from models.message_score import MessageScore


def _make_score(**overrides):
    """Build a fully-populated MessageScore, overriding any field."""
    base = {
        "friend_name": "Alice",
        "score": -0.5,
        "is_anomaly": True,
        "threshold": -0.5,
        "envelope_type": "ratchet",
        "packet_size": 128,
        "timestamp": datetime(2026, 1, 1, 12, 0, 0),
    }
    base.update(overrides)
    return MessageScore(**base)


# ---------------------------------------------------------------------------
# Construction & attribute access
# ---------------------------------------------------------------------------

class TestConstruction:
    def test_construction_sets_attributes(self):
        ts = datetime(2026, 6, 1, 9, 30, 0)
        score = MessageScore(
            friend_name="Bob",
            score=-1.25,
            is_anomaly=True,
            threshold=-0.5,
            envelope_type="pqc",
            packet_size=512,
            timestamp=ts,
        )
        assert score.friend_name == "Bob"
        assert score.score == -1.25
        assert score.is_anomaly is True
        assert score.threshold == -0.5
        assert score.envelope_type == "pqc"
        assert score.packet_size == 512
        assert score.timestamp == ts

    def test_requires_all_fields(self):
        """Dataclass has no defaults - missing args must raise TypeError."""
        with pytest.raises(TypeError):
            MessageScore(friend_name="Alice", score=0.0)  # type: ignore[call-arg]

    def test_frozen_raises_on_mutation(self):
        score = _make_score()
        with pytest.raises(FrozenInstanceError):
            score.score = 1.0  # type: ignore[misc]

    def test_frozen_raises_on_attribute_assignment(self):
        score = _make_score()
        with pytest.raises(FrozenInstanceError):
            score.envelope_type = "legacy"  # type: ignore[misc]

    def test_empty_friend_name_allowed(self):
        score = _make_score(friend_name="")
        assert score.friend_name == ""

    def test_zero_packet_size_allowed(self):
        score = _make_score(packet_size=0)
        assert score.packet_size == 0

    def test_float_score_preserved(self):
        score = _make_score(score=-3.14159)
        assert score.score == -3.14159

    def test_timestamp_preserved(self):
        ts = datetime(2025, 12, 31, 23, 59, 59)
        score = _make_score(timestamp=ts)
        assert score.timestamp == ts


# ---------------------------------------------------------------------------
# Equality, repr, hashing
# ---------------------------------------------------------------------------

class TestSemantics:
    def test_equality_same_values(self):
        a = _make_score()
        b = _make_score()
        assert a == b

    def test_inequality_different_score(self):
        assert _make_score(score=-0.5) != _make_score(score=-1.0)

    def test_inequality_different_friend(self):
        assert _make_score(friend_name="Alice") != _make_score(friend_name="Bob")

    def test_inequality_different_anomaly_flag(self):
        assert _make_score(is_anomaly=True) != _make_score(is_anomaly=False)

    def test_repr_contains_fields(self):
        r = repr(_make_score())
        assert "MessageScore" in r
        assert "Alice" in r
        assert "-0.5" in r
        assert "ratchet" in r

    def test_hashable(self):
        score = _make_score()
        assert hash(score) == hash(_make_score())
        assert len({_make_score(), _make_score()}) == 1


# ---------------------------------------------------------------------------
# Confidence property
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_confidence_midpoint_at_zero(self):
        """score=0 -> (0 - -1)/2 = 0.5."""
        assert _make_score(score=0.0).confidence == pytest.approx(0.5)

    def test_confidence_positive_normal(self):
        """score=1 -> (1 - -1)/2 = 1.0."""
        assert _make_score(score=1.0).confidence == pytest.approx(1.0)

    def test_confidence_negative_anomalous(self):
        """score=-1 -> 0.0."""
        assert _make_score(score=-1.0).confidence == pytest.approx(0.0)

    def test_confidence_at_threshold(self):
        """score=-0.5 (a typical IsolationForest threshold) -> 0.25."""
        assert _make_score(score=-0.5).confidence == pytest.approx(0.25)

    def test_confidence_clamps_above_one(self):
        assert _make_score(score=5.0).confidence == 1.0

    def test_confidence_clamps_below_zero(self):
        assert _make_score(score=-5.0).confidence == 0.0

    def test_confidence_lower_score_lower_confidence(self):
        high = _make_score(score=-0.2).confidence
        low = _make_score(score=-0.8).confidence
        assert low < high

    def test_confidence_boundaries_are_inclusive(self):
        """The property never returns values outside [0, 1]."""
        for score in (-10.0, -1.0, -0.5, 0.0, 0.7, 1.0, 10.0):
            conf = _make_score(score=score).confidence
            assert 0.0 <= conf <= 1.0
