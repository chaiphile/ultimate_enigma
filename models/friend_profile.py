"""
Friend Profile Model.

Encapsulates all friend-specific data including identity, capabilities,
and ratchet session status into a single immutable-style data object.
Replaces scattered dictionary and tuple representations throughout the codebase.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from contextlib import closing
from database import get_connection, DatabaseError

logger = logging.getLogger(__name__)


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

    @classmethod
    def from_database(cls, friend_name: str) -> Optional[FriendProfile]:
        """Load a FriendProfile from the database by name.

        Args:
            friend_name: The exact name of the friend to look up.

        Returns:
            A populated FriendProfile instance, or None if not found.
        """
        try:
            with closing(get_connection()) as conn:
                row = conn.execute(
                    "SELECT name, public_key_pem, shared_secret_encrypted, "
                    "capabilities_json, ratchet_state_json, pqc_combined_pub_b64 "
                    "FROM friends WHERE name=?",
                    (friend_name,),
                ).fetchone()

                if row is None:
                    return None

                caps_raw = row[3]
                capabilities: Dict[str, Any] = {}
                if caps_raw:
                    try:
                        capabilities = json.loads(caps_raw)
                    except (json.JSONDecodeError, TypeError):
                        logger.warning(
                            "Corrupted capabilities JSON for '%s', using empty dict",
                            friend_name,
                        )

                return cls(
                    name=row[0],
                    public_key=row[1].encode() if row[1] else None,
                    shared_secret=None,  # shared_secret_encrypted is JSON, not raw bytes
                    capabilities=capabilities,
                    has_active_ratchet=row[4] is not None,
                    pqc_combined_pub=row[5].encode() if row[5] else None,
                )

        except DatabaseError as exc:
            logger.error(
                "Failed to load FriendProfile for '%s': %s", friend_name, exc
            )
            return None

    @classmethod
    def list_all(cls) -> list[FriendProfile]:
        """Load all friend profiles from the database.

        Returns:
            A list of FriendProfile instances. Empty list on error.
        """
        profiles: list[FriendProfile] = []
        try:
            with closing(get_connection()) as conn:
                rows = conn.execute(
                    "SELECT name, public_key_pem, shared_secret_encrypted, "
                    "capabilities_json, ratchet_state_json, pqc_combined_pub_b64 "
                    "FROM friends"
                ).fetchall()

                for row in rows:
                    caps_raw = row[3]
                    capabilities: Dict[str, Any] = {}
                    if caps_raw:
                        try:
                            capabilities = json.loads(caps_raw)
                        except (json.JSONDecodeError, TypeError):
                            capabilities = {}

                    profiles.append(
                        cls(
                            name=row[0],
                            public_key=row[1].encode() if row[1] else None,
                            shared_secret=None,  # shared_secret_encrypted is JSON
                            capabilities=capabilities,
                            has_active_ratchet=row[4] is not None,
                            pqc_combined_pub=row[5].encode() if row[5] else None,
                        )
                    )

        except DatabaseError as exc:
            logger.error("Failed to list FriendProfiles: %s", exc)

        return profiles
