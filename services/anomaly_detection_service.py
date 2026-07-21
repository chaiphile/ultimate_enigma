"""Anomaly Detection Service — Isolation Forest on message metadata.

Uses a pre-trained Isolation Forest model to score incoming messages
based solely on metadata available before or after decryption, without
accessing plaintext content. This is a zero-knowledge anomaly detector.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from typing import Optional, Tuple

import numpy as np
from joblib import load as joblib_load

from models.message_score import MessageScore
from models.envelope import identify_envelope_type
from services.event_bus import event_bus, Events

logger = logging.getLogger(__name__)

# Default path for the pre-trained model
MODEL_FILENAME = "anomaly_model.pkl"

# Envelope type → numeric code for model input
_ENVELOPE_CODES = {
    "ratchet": 0,
    "pqc": 1,
    "legacy": 2,
    None: -1,
}


class AnomalyDetectionService:
    """Scores messages for anomalous metadata using Isolation Forest.

    The model was trained offline on synthetic metadata that mimics
    normal chat patterns. It expects a 7-element feature vector:
    [packet_size, name_length, env_type_code, header_len, ct_len,
     hour_of_day, day_of_week].

    Thread-safe for concurrent scoring (model is read-only after load).
    """

    def __init__(self, model_path: Optional[str] = None) -> None:
        """Load the pre-trained Isolation Forest model.

        Args:
            model_path: Path to the .pkl file. If None, looks for
                        ``anomaly_model.pkl`` next to this source file,
                        then falls back to the project root.
        """
        self._model_path = model_path or self._default_model_path()
        self._model = self._load_model(self._model_path)
        self._threshold: float = getattr(self._model, "threshold_", -0.5)
        self._enabled: bool = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the model was loaded successfully."""
        return self._model is not None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = bool(value)

    def score_message(
        self,
        friend_name: str,
        packet: bytes,
    ) -> Optional[MessageScore]:
        """Score an incoming message packet for anomaly.

        Extracts metadata from the raw packet (no decryption needed)
        and runs the Isolation Forest inference.

        Args:
            friend_name: Sender's name as extracted from the envelope.
            packet: Raw binary message packet.

        Returns:
            A MessageScore if the model is available and scoring
            succeeds, or None if the model is unavailable.
        """
        if not self._enabled or self._model is None:
            return None

        try:
            features = self._extract_features(friend_name, packet)
            if features is None:
                return None

            # model expects a 2D array of shape (n_samples, n_features)
            arr = np.asarray(features, dtype=np.float64).reshape(1, -1)
            score = float(self._model.score_samples(arr)[0])

            is_anomaly = score < self._threshold

            env_type_str = identify_envelope_type(packet) or "unknown"

            result = MessageScore(
                friend_name=friend_name,
                score=score,
                is_anomaly=is_anomaly,
                threshold=self._threshold,
                envelope_type=env_type_str,
                packet_size=len(packet),
                timestamp=datetime.utcnow(),
            )

            if is_anomaly:
                logger.warning(
                    "Anomaly detected from '%s': score=%.4f "
                    "(threshold=%.4f, type=%s, size=%d)",
                    friend_name,
                    score,
                    self._threshold,
                    env_type_str,
                    len(packet),
                )
                event_bus.publish(
                    Events.ANOMALY_DETECTED,
                    score=result,
                )

            return result

        except Exception as exc:
            logger.debug("Anomaly scoring failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Feature extraction (metadata only, no plaintext)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_features(
        friend_name: str,
        packet: bytes,
    ) -> Optional[Tuple[float, float, float, float, float, float, float]]:
        """Build a 7-element feature vector from message metadata.

        All values are derived from the raw packet bytes and the
        friend name — no decrypted content is accessed.

        Returns:
            (packet_size, name_length, env_type_code, header_len,
             ciphertext_len, hour_of_day, day_of_week)
            or None if extraction fails.
        """
        try:
            packet_size = float(len(packet))
            name_length = float(len(friend_name))
            env_type = identify_envelope_type(packet)
            env_code = float(_ENVELOPE_CODES.get(env_type, -1))

            header_len, ct_len = _extract_lengths(packet, env_type)

            now = time.localtime()
            hour = float(now.tm_hour)
            day = float(now.tm_wday)

            return (
                packet_size,
                name_length,
                env_code,
                header_len,
                ct_len,
                hour,
                day,
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    @staticmethod
    def _default_model_path() -> str:
        """Return the default model path, searching near this file and root."""
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(here, "..", MODEL_FILENAME),
            os.path.join(here, "..", "..", MODEL_FILENAME),
            os.path.join(os.getcwd(), MODEL_FILENAME),
        ]
        for path in candidates:
            normalized = os.path.normpath(path)
            if os.path.isfile(normalized):
                return normalized
        # Fall back to project root
        return os.path.normpath(os.path.join(here, "..", MODEL_FILENAME))

    @staticmethod
    def _load_model(path: str):
        """Load the pickle file, returning None on failure."""
        try:
            model = joblib_load(path)
            logger.info("Anomaly detection model loaded from '%s'", path)
            return model
        except Exception as exc:
            logger.error("Failed to load anomaly model from '%s': %s", path, exc)
            return None


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _extract_lengths(
    packet: bytes, env_type: Optional[str]
) -> Tuple[float, float]:
    """Extract header-like and ciphertext-like byte lengths from a packet.

    This is a best-effort parse that works without fully deserializing.
    """
    try:
        if env_type == "ratchet" and len(packet) > 4:
            offset = 2  # magic(1) + name_len(1)
            name_len = packet[1]
            offset += name_len
            if offset + 2 <= len(packet):
                hdr_len = int.from_bytes(packet[offset : offset + 2], "big")
                offset += 2 + hdr_len
                ct_len = max(0, len(packet) - offset)
                return float(hdr_len), float(ct_len)
        elif env_type == "pqc" and len(packet) > 3:
            offset = 1  # magic
            kem_len = int.from_bytes(packet[offset : offset + 2], "big")
            offset += 2 + kem_len + 12  # + nonce
            ct_len = max(0, len(packet) - offset)
            return float(kem_len + 12), float(ct_len)
    except Exception:
        pass
    return 0.0, float(len(packet))
