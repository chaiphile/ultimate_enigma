"""
Friend Profile Model.

Encapsulates all friend-specific data including identity, capabilities,
and ratchet session status into a single immutable-style data object.
Replaces scattered dictionary and tuple representations throughout the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass(frozen=True)
class FriendProfile:
    """Immutable representation of a friend's profile and session state.

    Attributes:
        name: Unique friend identifier string.
        public_key: Raw bytes of the friend's RSA or X25519 public key, or None.
        shared_secret: Raw bytes of the pre-shared symmetric key, or None.
        capabilities: Dictionary of boolean/string capability flags
                      (e.g., {"double_ratchet": True, "pqc": False}).
        has_active_ratchet: True if a Double Ratchet session is currently stored.
        pqc_combined_pub: Raw bytes of the friend's PQC combined public key, or None.
    """

    name: str
    public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    capabilities: Dict[str, Any] = field(default_factory=dict)
    has_active_ratchet: bool = False
    pqc_combined_pub: Optional[bytes] = None

    @property
    def supports_double_ratchet(self) -> bool:
        """Return True if the friend advertises Double Ratchet capability."""
        return bool(self.capabilities.get("double_ratchet", False))

    @property
    def supports_pqc(self) -> bool:
        """Return True if the friend advertises PQC capability."""
        return bool(self.capabilities.get("pqc", False))
