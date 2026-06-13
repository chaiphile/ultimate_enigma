"""
Friend Repository – data access layer for FriendProfile persistence.

Keeps FriendProfile as a pure data model while centralising all
database queries in one place.
"""

from __future__ import annotations

import json
import logging
from contextlib import closing
from typing import Optional, List, Dict, Any

from database import get_connection, DatabaseError
from models.friend_profile import FriendProfile

logger = logging.getLogger(__name__)


def _row_to_profile(row: tuple) -> FriendProfile:
    """Convert a database row tuple into a FriendProfile instance."""
    caps_raw = row[3]
    capabilities: Dict[str, Any] = {}
    if caps_raw:
        try:
            capabilities = json.loads(caps_raw)
        except (json.JSONDecodeError, TypeError):
            capabilities = {}

    return FriendProfile(
        name=row[0],
        public_key=row[1].encode() if row[1] else None,
        shared_secret=None,
        capabilities=capabilities,
        has_active_ratchet=row[4] is not None,
        pqc_combined_pub=row[5].encode() if row[5] else None,
    )


def get_friend_profile(friend_name: str) -> Optional[FriendProfile]:
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

            return _row_to_profile(row)

    except DatabaseError as exc:
        logger.error(
            "Failed to load FriendProfile for '%s': %s", friend_name, exc
        )
        return None


def list_all_friend_profiles() -> List[FriendProfile]:
    """Load all friend profiles from the database.

    Returns:
        A list of FriendProfile instances. Empty list on error.
    """
    profiles: List[FriendProfile] = []
    try:
        with closing(get_connection()) as conn:
            rows = conn.execute(
                "SELECT name, public_key_pem, shared_secret_encrypted, "
                "capabilities_json, ratchet_state_json, pqc_combined_pub_b64 "
                "FROM friends"
            ).fetchall()

            for row in rows:
                profiles.append(_row_to_profile(row))

    except DatabaseError as exc:
        logger.error("Failed to list FriendProfiles: %s", exc)

    return profiles
