"""Message score data model for anomaly detection results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class MessageScore:
    """Holds the anomaly score and classification for a scored message.

    Attributes:
        friend_name: The sender/recipient of the scored message.
        score: Raw anomaly score from the Isolation Forest
               (negative = anomalous, positive = normal).
        is_anomaly: True if the score falls below the threshold.
        threshold: The cutoff value used for classification.
        envelope_type: Type of envelope ('ratchet', 'pqc', 'legacy').
        packet_size: Size of the raw packet in bytes.
        timestamp: When the scoring occurred.
    """

    friend_name: str
    score: float
    is_anomaly: bool
    threshold: float
    envelope_type: str
    packet_size: int
    timestamp: datetime

    @property
    def confidence(self) -> float:
        """Return a normalized confidence value (0-1) where lower scores
        (more anomalous) produce lower confidence."""
        return max(0.0, min(1.0, (self.score - (-1.0)) / 2.0))
