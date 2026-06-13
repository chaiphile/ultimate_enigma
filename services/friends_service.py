"""Backward-compatibility shim - FriendsService is now in services.friends package."""
from services.friends.friends_facade import FriendsService, FriendsServiceError

__all__ = ["FriendsService", "FriendsServiceError"]
