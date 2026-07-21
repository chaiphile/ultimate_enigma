"""
Models package for Ultimate Enigma MVC architecture.

Provides structured data objects that replace raw dictionaries and tuples
throughout the service and controller layers.
"""

from models.friend_profile import FriendProfile
from models.envelope import (
    RatchetEnvelope,
    PQCEncvelope,
    RATCHET_ENVELOPE_MAGIC,
    PQC_ENVELOPE_MAGIC,
    identify_envelope_type,
)
from models.message_score import MessageScore

__all__ = [
    "FriendProfile",
    "RatchetEnvelope",
    "PQCEncvelope",
    "RATCHET_ENVELOPE_MAGIC",
    "PQC_ENVELOPE_MAGIC",
    "identify_envelope_type",
    "MessageScore",
]
