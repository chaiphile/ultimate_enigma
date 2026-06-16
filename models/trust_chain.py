"""
Trust Chain Certificate Models.

Defines structured data objects for a decentralized trust chain certificate
system. Certificates bind identities to public keys with expiration, revocation,
and hierarchical trust levels. Recovery shares enable threshold key recovery
across trusted contacts.
"""

from __future__ import annotations

import uuid
import time
import base64
import logging
import enum
from dataclasses import dataclass, field
from typing import List, Dict, Any

from src.constants import CRYPTO_CONSTANTS

logger = logging.getLogger(__name__)


class CertificateType(enum.Enum):
    """Type of trust certificate."""

    IDENTITY = "identity"
    RECOVERY = "recovery"
    DELEGATION = "delegation"


class TrustLevel(enum.Enum):
    """Trust level derived from a set of valid certificates."""

    NONE = 0
    BASIC = 1
    VERIFIED = 2
    TRUSTED = 3


class RevocationStatus(enum.Enum):
    """Revocation and expiration status of a certificate."""

    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass(frozen=True)
class TrustCertificate:
    """A single trust chain certificate binding an identity to a public key.

    Certificates are signed by an issuer and have a validity window. They can be
    revoked explicitly or considered expired once the current time exceeds not_after.

    Attributes:
        cert_id: UUID4 string identifying this certificate.
        subject_name: The identity this certificate is about.
        subject_pub: Combined hybrid signature public key of the subject.
        issuer_name: The identity that signed this certificate.
        issuer_pub: Combined hybrid signature public key of the issuer.
        cert_type: Type of certificate (IDENTITY, RECOVERY, DELEGATION).
        not_before: Epoch timestamp when the certificate becomes valid.
        not_after: Epoch timestamp when the certificate expires.
        signature: Hybrid signature over subject_pub + cert_type.value + not_before + not_after.
        revoked: Whether this certificate has been explicitly revoked.
        revocation_reason: Human-readable reason for revocation, empty if not revoked.
        received_from: Who sent this certificate; empty string if self-issued.
        created_at: Epoch timestamp when this certificate object was created.
    """

    cert_id: str
    subject_name: str
    subject_pub: bytes
    issuer_name: str
    issuer_pub: bytes
    cert_type: CertificateType
    not_before: float
    not_after: float
    signature: bytes
    revoked: bool = False
    revocation_reason: str = ""
    received_from: str = ""
    created_at: float = 0.0

    def is_expired(self) -> bool:
        """Check whether the current time exceeds the certificate's not_after timestamp."""
        return time.time() > self.not_after

    def status(self) -> RevocationStatus:
        """Return the current revocation status of this certificate."""
        if self.revoked:
            return RevocationStatus.REVOKED
        if self.is_expired():
            return RevocationStatus.EXPIRED
        return RevocationStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this certificate to a JSON-compatible dictionary.

        Byte fields are encoded as Base64 strings. Enum values are serialized as
        their string representation.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        return {
            "cert_id": self.cert_id,
            "subject_name": self.subject_name,
            "subject_pub_b64": _b64_encode(self.subject_pub),
            "issuer_name": self.issuer_name,
            "issuer_pub_b64": _b64_encode(self.issuer_pub),
            "cert_type": self.cert_type.value,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_b64": _b64_encode(self.signature),
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
            "received_from": self.received_from,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TrustCertificate:
        """Deserialize a TrustCertificate from a dictionary.

        Args:
            d: Dictionary previously produced by to_dict().

        Returns:
            A new TrustCertificate instance.

        Raises:
            KeyError: If required fields are missing.
            ValueError: If certificate type is not recognized.
        """
        cert_type = CertificateType(d["cert_type"])
        logger.debug("Deserializing trust certificate %s for subject '%s'",
                      d["cert_id"], d.get("subject_name", "unknown"))
        return cls(
            cert_id=d["cert_id"],
            subject_name=d["subject_name"],
            subject_pub=_b64_decode(d["subject_pub_b64"]),
            issuer_name=d["issuer_name"],
            issuer_pub=_b64_decode(d["issuer_pub_b64"]),
            cert_type=cert_type,
            not_before=float(d["not_before"]),
            not_after=float(d["not_after"]),
            signature=_b64_decode(d["signature_b64"]),
            revoked=bool(d.get("revoked", False)),
            revocation_reason=str(d.get("revocation_reason", "")),
            received_from=str(d.get("received_from", "")),
            created_at=float(d.get("created_at", 0.0)),
        )


@dataclass
class RecoveryShare:
    """A threshold recovery share held by a trusted contact.

    In a K-of-N recovery scheme, each holder stores one encrypted share. When K
    or more shares are collected, the owner's private key can be reconstructed.

    Attributes:
        share_id: UUID4 string identifying this share.
        owner_name: The identity whose key this share can help recover.
        share_index: 1-based index of this share within the N total shares.
        total_shares: Total number of shares created (N in K-of-N).
        threshold: Minimum shares needed for recovery (K in K-of-N).
        encrypted_share: AES-GCM encrypted share data.
        holder_name: The identity currently holding this share.
        holder_pub_b64: Base64-encoded hybrid sig public key of the holder.
        created_at: Epoch timestamp when this share was created.
    """

    share_id: str
    owner_name: str
    share_index: int
    total_shares: int
    threshold: int
    encrypted_share: bytes
    holder_name: str
    holder_pub_b64: str
    created_at: float

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this recovery share to a JSON-compatible dictionary.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        return {
            "share_id": self.share_id,
            "owner_name": self.owner_name,
            "share_index": self.share_index,
            "total_shares": self.total_shares,
            "threshold": self.threshold,
            "encrypted_share": _b64_encode(self.encrypted_share),
            "holder_name": self.holder_name,
            "holder_pub_b64": self.holder_pub_b64,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> RecoveryShare:
        """Deserialize a RecoveryShare from a dictionary.

        Args:
            d: Dictionary previously produced by to_dict().

        Returns:
            A new RecoveryShare instance.

        Raises:
            KeyError: If required fields are missing.
            ValueError: If numeric fields are invalid.
        """
        logger.debug("Deserializing recovery share %s for owner '%s'",
                      d["share_id"], d.get("owner_name", "unknown"))
        return cls(
            share_id=d["share_id"],
            owner_name=d["owner_name"],
            share_index=int(d["share_index"]),
            total_shares=int(d["total_shares"]),
            threshold=int(d["threshold"]),
            encrypted_share=_b64_decode(d["encrypted_share"]),
            holder_name=d["holder_name"],
            holder_pub_b64=d["holder_pub_b64"],
            created_at=float(d["created_at"]),
        )


def compute_trust_level(certs: List[TrustCertificate]) -> TrustLevel:
    """Compute the trust level for a subject based on their valid certificates.

    Expired and revoked certificates are filtered out. The resulting trust level
    is determined by the count of remaining valid certificates:

        - 0 valid certificates -> TrustLevel.NONE
        - 1 valid certificate  -> TrustLevel.BASIC
        - 2 valid certificates -> TrustLevel.VERIFIED
        - 3+ valid certificates -> TrustLevel.TRUSTED

    Args:
        certs: List of TrustCertificate objects for a single subject.

    Returns:
        The computed TrustLevel.
    """
    valid_count = sum(1 for c in certs if c.status() == RevocationStatus.VALID)
    logger.debug("Trust computation: %d total certs, %d valid",
                 len(certs), valid_count)

    if valid_count >= 3:
        return TrustLevel.TRUSTED
    if valid_count == 2:
        return TrustLevel.VERIFIED
    if valid_count == 1:
        return TrustLevel.BASIC
    return TrustLevel.NONE
