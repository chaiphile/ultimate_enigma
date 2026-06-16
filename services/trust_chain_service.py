"""Trust Chain Certificate Service.

Manages certificate issuance, verification, revocation, and trust chain
validation for the decentralized trust chain system. Certificates bind
identities to public keys with hybrid signatures (Ed25519 + Dilithium3).

Thread-safety: All mutable operations acquire an RLock. Read-only queries
acquire the lock briefly for consistent snapshots.
"""

import uuid
import time
import struct
import logging
import base64
import threading
from typing import List, Dict, Any, Optional

from key_manager import KeyStore
from models.trust_chain import (
    TrustCertificate,
    CertificateType,
    TrustLevel,
    RevocationStatus,
    compute_trust_level,
)
from services.shamir_service import ShamirService
from services.event_bus import event_bus, Events
from src.constants import TRUST_CHAIN_CONSTANTS
from src.exceptions import (
    CertificateError,
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateSignatureError,
)

logger = logging.getLogger(__name__)


class TrustChainService:
    """Core trust chain certificate service.

    Issues, verifies, revokes, and validates trust certificates using
    hybrid signatures (Ed25519 + Dilithium3). Tracks trust levels based
    on valid certificate counts from unique issuers.

    Args:
        key_store: KeyStore instance with hybrid signing keys.
    """

    def __init__(self, key_store: KeyStore) -> None:
        self._ks = key_store
        self._shamir = ShamirService()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def issue_certificate(
        self,
        subject_name: str,
        subject_pub_b64: str,
        cert_type: str,
        validity_days: int,
        master_password: str,
    ) -> TrustCertificate:
        """Issue a trust certificate for a subject.

        Creates a new certificate signed with the local hybrid signing
        key pair (Ed25519 + Dilithium3) and persists it to the database.

        Args:
            subject_name: Identity of the certificate subject.
            subject_pub_b64: Base64-encoded combined hybrid public key.
            cert_type: One of 'identity', 'recovery', 'delegation'.
            validity_days: Number of days the certificate is valid.
            master_password: Required for key access.

        Returns:
            The newly created TrustCertificate.

        Raises:
            CertificateError: If issuance fails (missing keys, friend not
                found, or database error).
        """
        with self._lock:
            if not self._ks.my_ed_priv or not self._ks.my_dil_priv:
                raise CertificateError(
                    "Hybrid signing keys not loaded. Generate keys first."
                )

            friend_names = [n for n, _, _ in self._ks.friends]
            if subject_name not in friend_names:
                raise CertificateError(
                    f"Subject '{subject_name}' not found in friends list"
                )

            try:
                ct = CertificateType(cert_type)
            except ValueError:
                raise CertificateError(f"Invalid certificate type: {cert_type}")

            min_days = TRUST_CHAIN_CONSTANTS["MIN_CERT_VALIDITY_DAYS"]
            max_days = TRUST_CHAIN_CONSTANTS["MAX_CERT_VALIDITY_DAYS"]
            if not (min_days <= validity_days <= max_days):
                raise CertificateError(
                    f"Validity days must be between {min_days} and {max_days}, "
                    f"got {validity_days}"
                )

            now = time.time()
            not_before = now
            not_after = now + (validity_days * 86400)

            subject_pub_bytes = base64.b64decode(subject_pub_b64)
            data = (
                subject_pub_bytes
                + ct.value.encode()
                + struct.pack(">d", not_before)
                + struct.pack(">d", not_after)
            )

            try:
                from services.pqc_signatures import HybridSigner

                signature = HybridSigner.sign(
                    data, self._ks.my_ed_priv, self._ks.my_dil_priv
                )
            except (RuntimeError, OSError) as e:
                raise CertificateError(
                    f"Hybrid signing failed: {e}"
                ) from e

            cert_id = str(uuid.uuid4())
            cert = TrustCertificate(
                cert_id=cert_id,
                subject_name=subject_name,
                subject_pub=subject_pub_bytes,
                issuer_name=self._ks.my_name,
                issuer_pub=bytes(self._ks.my_hybrid_sig_combined_pub),
                cert_type=ct,
                not_before=not_before,
                not_after=not_after,
                signature=signature,
                revoked=False,
                revocation_reason="",
                received_from="",
                created_at=now,
            )

            import database

            try:
                database.save_trust_certificate(cert.to_dict())
            except Exception as e:
                raise CertificateError(
                    f"Failed to persist certificate: {e}"
                ) from e

            logger.info(
                "Issued %s certificate %s for '%s' (expires in %d days)",
                ct.value, cert_id[:8], subject_name, validity_days,
            )

            event_bus.publish(Events.CERTIFICATE_ISSUED, cert=cert)
            return cert

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def _expected_issuer_pub(self, issuer_name: str) -> Optional[bytes]:
        """Return the known combined hybrid-sig public key for an issuer.

        Looks up the issuer's pinned hybrid signing key. The issuer may be
        the local user (``my_name``) or a known friend. Returns ``None`` if
        the issuer is unknown or has no hybrid signing key on file.
        """
        if issuer_name == self._ks.my_name and self._ks.my_hybrid_sig_combined_pub:
            return bytes(self._ks.my_hybrid_sig_combined_pub)

        pair = self._ks.friends_hybrid_sig_pubs.get(issuer_name)
        if not pair:
            return None
        ed_pub_bytes, dil_pub_bytes = pair
        return (
            struct.pack(">H", len(ed_pub_bytes)) + ed_pub_bytes
            + struct.pack(">H", len(dil_pub_bytes)) + dil_pub_bytes
        )

    def _verify_cert_object(self, cert: TrustCertificate) -> None:
        """Verify a certificate's signature against its issuer's pinned key.

        Confirms the embedded ``issuer_pub`` matches the locally pinned key
        for ``issuer_name`` (defeating forged-issuer attacks), then verifies
        the hybrid signature over the canonical signed data.

        Raises:
            CertificateSignatureError: If the issuer is unknown, the embedded
                key does not match the pinned key, or the signature is invalid.
        """
        import hmac as _hmac

        expected_pub = self._expected_issuer_pub(cert.issuer_name)
        if expected_pub is None:
            raise CertificateSignatureError(
                f"Unknown issuer '{cert.issuer_name}' — no pinned hybrid "
                f"signing key to validate against"
            )
        if not _hmac.compare_digest(bytes(cert.issuer_pub), expected_pub):
            raise CertificateSignatureError(
                f"Issuer key mismatch for '{cert.issuer_name}': embedded "
                f"public key does not match the pinned key"
            )

        ct = cert.cert_type
        data = (
            cert.subject_pub
            + ct.value.encode()
            + struct.pack(">d", cert.not_before)
            + struct.pack(">d", cert.not_after)
        )

        try:
            from services.pqc_signatures import HybridSigner

            ed_pub_bytes, dil_pub_bytes = HybridSigner.parse_combined_pub(
                cert.issuer_pub
            )
            ed_pub = HybridSigner.load_ed_public_key(ed_pub_bytes)
            valid = HybridSigner.verify(
                data, cert.signature, ed_pub, dil_pub_bytes
            )
        except (RuntimeError, OSError) as e:
            raise CertificateSignatureError(
                f"Hybrid verification failed: {e}"
            ) from e

        if not valid:
            raise CertificateSignatureError(
                f"Certificate {cert.cert_id} signature is invalid"
            )

    def verify_certificate(self, cert_id: str) -> bool:
        """Verify a trust certificate's full validity chain.

        Checks revocation, expiration, issuer identity, and hybrid signature
        integrity. The issuer's combined public key embedded in the
        certificate must match the locally pinned key for the issuer before
        the signature is checked.

        Args:
            cert_id: UUID string identifying the certificate.

        Returns:
            True if all checks pass.

        Raises:
            CertificateRevokedError: If the certificate has been revoked.
            CertificateExpiredError: If the certificate has expired.
            CertificateSignatureError: If the issuer is unknown/mismatched or
                the hybrid signature is invalid.
            CertificateError: If the certificate cannot be found.
        """
        with self._lock:
            cert = self._load_certificate(cert_id)

            if cert.revoked:
                raise CertificateRevokedError(
                    f"Certificate {cert_id} has been revoked: "
                    f"{cert.revocation_reason or 'no reason given'}"
                )

            if cert.is_expired():
                raise CertificateExpiredError(
                    f"Certificate {cert_id} expired at {cert.not_after}"
                )

            self._verify_cert_object(cert)

            logger.debug("Certificate %s verified successfully", cert_id[:8])
            return True

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke_certificate(
        self, cert_id: str, reason: str = ""
    ) -> None:
        """Revoke a trust certificate by ID.

        Marks the certificate as revoked in the database and publishes
        a revocation event.

        Args:
            cert_id: UUID string identifying the certificate.
            reason: Human-readable revocation reason.

        Raises:
            CertificateError: If the certificate cannot be found.
        """
        with self._lock:
            cert = self._load_certificate(cert_id)

            revoked_cert = TrustCertificate(
                cert_id=cert.cert_id,
                subject_name=cert.subject_name,
                subject_pub=cert.subject_pub,
                issuer_name=cert.issuer_name,
                issuer_pub=cert.issuer_pub,
                cert_type=cert.cert_type,
                not_before=cert.not_before,
                not_after=cert.not_after,
                signature=cert.signature,
                revoked=True,
                revocation_reason=reason or "unspecified",
                received_from=cert.received_from,
                created_at=cert.created_at,
            )

            import database

            try:
                database.save_trust_certificate(revoked_cert.to_dict())
            except Exception as e:
                raise CertificateError(
                    f"Failed to persist revocation: {e}"
                ) from e

            logger.info(
                "Revoked certificate %s (reason: %s)",
                cert_id[:8], reason or "unspecified",
            )

            event_bus.publish(
                Events.CERTIFICATE_REVOKED,
                cert_id=cert_id,
                reason=reason,
            )

    # ------------------------------------------------------------------
    # Trust Level Computation
    # ------------------------------------------------------------------

    def get_trust_level(self, friend_name: str) -> TrustLevel:
        """Compute trust level for a friend based on valid certificates.

        Counts valid (non-expired, non-revoked) certificates from unique
        issuers and maps the count to a trust level.

        Args:
            friend_name: Identity of the friend.

        Returns:
            Computed TrustLevel enum.
        """
        with self._lock:
            certs = self.get_certs_for_friend(friend_name)
            return compute_trust_level(certs)

    def get_trust_info(self, friend_name: str) -> Dict[str, Any]:
        """Return a summary dict for a friend suitable for view display.

        Combines trust level, certificate count, dates, signers, and a
        badge emoji into a single dict.

        Args:
            friend_name: Identity of the friend.

        Returns:
            Dict with keys: trust_level, certificate_count,
            last_certificate_date, nearest_expiry, signers, badge.
        """
        with self._lock:
            certs = self.get_certs_for_friend(friend_name)
            trust_level = compute_trust_level(certs)

            level_map = {
                TrustLevel.TRUSTED: "trusted",
                TrustLevel.VERIFIED: "partially_trusted",
                TrustLevel.BASIC: "partially_trusted",
                TrustLevel.NONE: "untrusted",
            }
            level_str = level_map.get(trust_level, "untrusted")

            badge_map = {
                "trusted": "🟢",
                "partially_trusted": "🟡",
                "untrusted": "⚪",
            }
            badge = badge_map.get(level_str, "⚪")

            valid_certs = [c for c in certs if not c.revoked and not c.is_expired()]
            cert_count = len(valid_certs)

            last_date = "—"
            nearest_expiry = "—"
            if valid_certs:
                latest = max(c.created_at for c in valid_certs)
                last_date = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(latest)
                )
                earliest_expiry = min(c.not_after for c in valid_certs)
                nearest_expiry = time.strftime(
                    "%Y-%m-%d", time.localtime(earliest_expiry)
                )

            signers = sorted({c.issuer_name for c in valid_certs}) or "—"

            return {
                "trust_level": level_str,
                "certificate_count": cert_count,
                "last_certificate_date": last_date,
                "nearest_expiry": nearest_expiry,
                "signers": signers,
                "badge": badge,
            }

    # ------------------------------------------------------------------
    # Certificate Queries
    # ------------------------------------------------------------------

    def get_all_certificates(self) -> List[TrustCertificate]:
        """Load all certificates from the database.

        Returns:
            List of all TrustCertificate objects.
        """
        import database

        with self._lock:
            try:
                rows = database.get_trust_certificates_for()
            except Exception as e:
                logger.error("Failed to load certificates: %s", e)
                return []
            return [TrustCertificate.from_dict(row) for row in rows]

    def get_certs_for_friend(self, friend_name: str) -> List[TrustCertificate]:
        """Load certificates where the given friend is the subject.

        Args:
            friend_name: Identity of the certificate subject.

        Returns:
            List of TrustCertificate objects for the friend.
        """
        import database

        with self._lock:
            try:
                rows = database.get_trust_certificates_for(
                    subject_name=friend_name
                )
            except Exception as e:
                logger.error(
                    "Failed to load certificates for '%s': %s",
                    friend_name, e,
                )
                return []
            return [TrustCertificate.from_dict(row) for row in rows]

    def get_certs_issued_by_me(self) -> List[TrustCertificate]:
        """Load certificates issued by the local user.

        Returns:
            List of TrustCertificate objects where issuer_name matches
            my_name.
        """
        import database

        with self._lock:
            my_name = self._ks.my_name
            try:
                rows = database.get_trust_certificates_for(
                    issuer_name=my_name
                )
            except Exception as e:
                logger.error(
                    "Failed to load certificates issued by '%s': %s",
                    my_name, e,
                )
                return []
            return [TrustCertificate.from_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Exchange Helpers
    # ------------------------------------------------------------------

    def get_pending_certs_for_exchange(self) -> List[Dict[str, Any]]:
        """Return self-issued certificates not yet sent to peers.

        Queries certificates where received_from is empty (self-issued)
        and returns them as dicts suitable for embedding in a key
        exchange message.

        Returns:
            List of certificate dicts for embedding in exchanges.
        """
        with self._lock:
            my_certs = self.get_certs_issued_by_me()
            pending = []
            for cert in my_certs:
                cert_dict = cert.to_dict()
                cert_dict["_exchange_flag"] = True
                pending.append(cert_dict)
            logger.debug(
                "Found %d pending certificates for exchange", len(pending)
            )
            return pending

    def import_received_certs(self, cert_dicts: List[Dict[str, Any]]) -> int:
        """Import certificates received from a peer.

        Validates basic structure, persists each certificate with
        received_from set, and publishes a CERTIFICATE_RECEIVED event.

        Args:
            cert_dicts: List of certificate dicts from a peer.

        Returns:
            Number of certificates successfully imported.
        """
        import database

        with self._lock:
            imported = 0
            for cert_dict in cert_dicts:
                try:
                    cert = TrustCertificate.from_dict(cert_dict)

                    if not cert.subject_name or not cert.issuer_name:
                        logger.warning(
                            "Skipping cert with missing subject/issuer"
                        )
                        continue

                    if not cert.signature:
                        logger.warning(
                            "Skipping cert %s with empty signature",
                            cert.cert_id[:8],
                        )
                        continue

                    # Cryptographically verify the certificate before trusting
                    # it. This confirms the issuer is a pinned identity and the
                    # hybrid signature is valid, preventing forged certificates
                    # from inflating a subject's computed trust level.
                    try:
                        self._verify_cert_object(cert)
                    except CertificateSignatureError as e:
                        logger.warning(
                            "Rejecting unverifiable cert %s: %s",
                            cert.cert_id[:8], e,
                        )
                        continue

                    if cert.received_from == "":
                        cert = TrustCertificate(
                            cert_id=cert.cert_id,
                            subject_name=cert.subject_name,
                            subject_pub=cert.subject_pub,
                            issuer_name=cert.issuer_name,
                            issuer_pub=cert.issuer_pub,
                            cert_type=cert.cert_type,
                            not_before=cert.not_before,
                            not_after=cert.not_after,
                            signature=cert.signature,
                            revoked=cert.revoked,
                            revocation_reason=cert.revocation_reason,
                            received_from=self._ks.my_name,
                            created_at=cert.created_at,
                        )

                    database.save_trust_certificate(cert.to_dict())
                    imported += 1
                except (KeyError, ValueError, TypeError) as e:
                    logger.warning("Failed to import cert: %s", e)
                    continue

            if imported > 0:
                logger.info("Imported %d certificate(s) from peer", imported)

            return imported

    # ------------------------------------------------------------------
    # Trust Chain Visualization
    # ------------------------------------------------------------------

    def compute_trust_chain(self, subject_name: str) -> Dict[str, Any]:
        """Build a trust chain visualization for a subject.

        Returns a dict with the subject's trust level, all certificates,
        and a list of unique signers.

        Args:
            subject_name: Identity of the subject.

        Returns:
            Dict with keys: subject, trust_level, certificates, signers.
        """
        with self._lock:
            certs = self.get_certs_for_friend(subject_name)
            trust_level = compute_trust_level(certs)

            cert_entries = []
            for c in certs:
                status = c.status()
                cert_entries.append({
                    "issuer": c.issuer_name,
                    "type": c.cert_type.value,
                    "expiry": c.not_after,
                    "status": status.value,
                    "revoked": c.revoked,
                    "received_from": c.received_from,
                })

            signers = sorted({c.issuer_name for c in certs})

            return {
                "subject": subject_name,
                "trust_level": trust_level,
                "certificates": cert_entries,
                "signers": signers,
            }

    # ------------------------------------------------------------------
    # Single Certificate Export
    # ------------------------------------------------------------------

    def export_single_certificate(self, cert_id: str) -> Dict[str, Any]:
        """Export a single certificate by ID as a serializable dict.

        Args:
            cert_id: UUID string identifying the certificate.

        Returns:
            Dict suitable for JSON serialization.

        Raises:
            CertificateError: If the certificate cannot be found.
        """
        with self._lock:
            cert = self._load_certificate(cert_id)
            return cert.to_dict()

    # ------------------------------------------------------------------
    # Delegation Powers
    # ------------------------------------------------------------------

    def get_delegation_certs_held_by_me(self) -> List[TrustCertificate]:
        """Return valid delegation certs where the local user is the subject.

        These are certs granting the local user authority to act on the
        issuer's behalf.

        Returns:
            List of valid, non-expired DELEGATION certificates.
        """
        import database

        with self._lock:
            my_name = self._ks.my_name
            try:
                rows = database.get_trust_certificates_for(subject_name=my_name)
            except Exception as e:
                logger.error("Failed to load delegation certs for me: %s", e)
                return []
            certs = [TrustCertificate.from_dict(row) for row in rows]
            return [
                c for c in certs
                if c.cert_type == CertificateType.DELEGATION
                and c.status() == RevocationStatus.VALID
            ]

    def update_delegator_pub_key(
        self,
        delegator_name: str,
        new_combined_pub_b64: str,
        master_password: str,
    ) -> None:
        """Update a delegator's stored hybrid signing public key."""
        with self._lock:
            self._assert_delegation(delegator_name)
            try:
                from services.pqc_signatures import HybridSigner
                raw = base64.b64decode(new_combined_pub_b64)
                HybridSigner.parse_combined_pub(raw)
            except Exception as e:
                raise CertificateError(
                    f"Invalid hybrid signing public key: {e}"
                ) from e
            self._delegated_save(
                delegator_name, master_password,
                hybrid_sig_pub_b64=new_combined_pub_b64,
            )
            logger.info(
                "Delegate '%s' updated hybrid sig pub key for '%s'",
                self._ks.my_name, delegator_name,
            )
            event_bus.publish(
                Events.FRIEND_LIST_CHANGED,
                source="delegation_key_update",
                friend_name=delegator_name,
            )

    def update_delegator_x25519_key(
        self,
        delegator_name: str,
        new_x25519_b64: str,
        master_password: str,
    ) -> None:
        """Update a delegator's stored X25519 public key."""
        with self._lock:
            self._assert_delegation(delegator_name)
            try:
                raw = base64.b64decode(new_x25519_b64)
                if len(raw) != 32:
                    raise ValueError(
                        f"X25519 key must be 32 bytes, got {len(raw)}"
                    )
            except Exception as e:
                raise CertificateError(
                    f"Invalid X25519 public key: {e}"
                ) from e
            self._delegated_save(
                delegator_name, master_password,
                x25519_pub_b64=new_x25519_b64,
            )
            logger.info(
                "Delegate '%s' updated X25519 key for '%s'",
                self._ks.my_name, delegator_name,
            )
            event_bus.publish(
                Events.FRIEND_LIST_CHANGED,
                source="delegation_key_update",
                friend_name=delegator_name,
            )

    def update_delegator_pem(
        self,
        delegator_name: str,
        new_pem: str,
        master_password: str,
    ) -> None:
        """Update a delegator's stored RSA public key (PEM)."""
        with self._lock:
            self._assert_delegation(delegator_name)
            try:
                from src.crypto_utils import pem_to_pubkey as _pem_to_pubkey
                _pem_to_pubkey(new_pem)
            except Exception as e:
                raise CertificateError(
                    f"Invalid RSA public key PEM: {e}"
                ) from e
            self._delegated_save(
                delegator_name, master_password,
                pem=new_pem,
            )
            logger.info(
                "Delegate '%s' updated RSA PEM for '%s'",
                self._ks.my_name, delegator_name,
            )
            event_bus.publish(
                Events.FRIEND_LIST_CHANGED,
                source="delegation_key_update",
                friend_name=delegator_name,
            )

    def update_delegator_pqc_key(
        self,
        delegator_name: str,
        new_pqc_b64: str,
        master_password: str,
    ) -> None:
        """Update a delegator's stored PQC combined public key."""
        with self._lock:
            self._assert_delegation(delegator_name)
            try:
                raw = base64.b64decode(new_pqc_b64)
                if len(raw) < 32:
                    raise ValueError("PQC combined key is too short")
            except Exception as e:
                raise CertificateError(
                    f"Invalid PQC combined public key: {e}"
                ) from e
            self._delegated_save(
                delegator_name, master_password,
                pqc_combined_pub_b64=new_pqc_b64,
            )
            logger.info(
                "Delegate '%s' updated PQC key for '%s'",
                self._ks.my_name, delegator_name,
            )
            event_bus.publish(
                Events.FRIEND_LIST_CHANGED,
                source="delegation_key_update",
                friend_name=delegator_name,
            )

    def remove_all_delegator_optional_keys(
        self,
        delegator_name: str,
        master_password: str,
    ) -> None:
        """Clear all optional public keys for a delegator.

        Clears X25519, PQC combined, and hybrid signing keys.
        Preserves the RSA PEM (core identity key).
        """
        with self._lock:
            self._assert_delegation(delegator_name)
            self._delegated_save(
                delegator_name, master_password,
                x25519_pub_b64=None,
                pqc_combined_pub_b64=None,
                hybrid_sig_pub_b64=None,
            )
            logger.info(
                "Delegate '%s' cleared all optional keys for '%s'",
                self._ks.my_name, delegator_name,
            )
            event_bus.publish(
                Events.FRIEND_LIST_CHANGED,
                source="delegation_key_update",
                friend_name=delegator_name,
            )

    def revoke_delegator_recovery_shares(self, delegator_name: str) -> int:
        """Delete all local recovery share records for a delegator.

        Requires a valid DELEGATION certificate. Removes records from
        the recovery_shares table (distributed shares the delegator
        sent to others) and from held_shares (any copy held locally
        on behalf of the delegator).

        Returns:
            Total number of records deleted.

        Raises:
            CertificateError: If no valid delegation cert exists.
        """
        with self._lock:
            self._assert_delegation(delegator_name)

            import database as _db

            distributed = _db.get_recovery_shares_for(delegator_name)
            distributed_count = len(distributed)
            _db.delete_recovery_shares_for(delegator_name)

            held_count = 0
            for row in _db.get_all_held_shares():
                if row.get("owner_name") == delegator_name:
                    _db.delete_held_share(row["share_id"])
                    held_count += 1

            total = distributed_count + held_count
            logger.info(
                "Delegate '%s' revoked %d recovery share record(s) for '%s' "
                "(%d distributed + %d held)",
                self._ks.my_name, total, delegator_name,
                distributed_count, held_count,
            )
            return total

    def revoke_all_certs_for_delegator(self, delegator_name: str) -> int:
        """Revoke all valid certificates where delegator_name is the subject.

        Requires a valid DELEGATION certificate from delegator_name to the
        local user. Marks every non-revoked, non-expired certificate for
        the delegator as revoked in the database.

        Args:
            delegator_name: Name of the friend who granted delegation.

        Returns:
            Number of certificates successfully revoked.

        Raises:
            CertificateError: If no valid delegation cert exists or querying
                the database fails.
        """
        with self._lock:
            delegation_certs = self.get_delegation_certs_held_by_me()
            if not any(c.issuer_name == delegator_name for c in delegation_certs):
                raise CertificateError(
                    f"No valid delegation certificate from '{delegator_name}'. "
                    "Cannot revoke their certificates."
                )

            import database as _db

            try:
                rows = _db.get_trust_certificates_for(subject_name=delegator_name)
            except Exception as e:
                raise CertificateError(
                    f"Failed to query certificates: {e}"
                ) from e

            certs = [TrustCertificate.from_dict(row) for row in rows]
            to_revoke = [c for c in certs if not c.revoked and not c.is_expired()]
            reason = f"Revoked by delegate {self._ks.my_name}"

            revoked_count = 0
            for cert in to_revoke:
                revoked_cert = TrustCertificate(
                    cert_id=cert.cert_id,
                    subject_name=cert.subject_name,
                    subject_pub=cert.subject_pub,
                    issuer_name=cert.issuer_name,
                    issuer_pub=cert.issuer_pub,
                    cert_type=cert.cert_type,
                    not_before=cert.not_before,
                    not_after=cert.not_after,
                    signature=cert.signature,
                    revoked=True,
                    revocation_reason=reason,
                    received_from=cert.received_from,
                    created_at=cert.created_at,
                )
                try:
                    _db.save_trust_certificate(revoked_cert.to_dict())
                    revoked_count += 1
                except Exception as e:
                    logger.warning(
                        "Failed to revoke cert %s: %s", cert.cert_id[:8], e
                    )

            logger.info(
                "Delegate '%s' revoked %d cert(s) for '%s'",
                self._ks.my_name, revoked_count, delegator_name,
            )

            if revoked_count > 0:
                event_bus.publish(
                    Events.CERTIFICATE_REVOKED,
                    cert_id=None,
                    reason=reason,
                )

            return revoked_count

    # ------------------------------------------------------------------
    # Bundle Export
    # ------------------------------------------------------------------

    def export_trust_bundle(self) -> Dict[str, Any]:
        """Export all certificates from the local store as a bundle.

        Includes both self-issued and received certificates for full backup.

        Returns:
            Dict with keys: bundle_id, issuer_name, exported_at,
            certificates (list of serialized cert dicts).
        """
        with self._lock:
            all_certs = self.get_all_certificates()
            return {
                "bundle_id": str(uuid.uuid4()),
                "issuer_name": self._ks.my_name,
                "exported_at": time.time(),
                "certificates": [c.to_dict() for c in all_certs],
            }

    def export_delegation_certificates(self) -> Dict[str, Any]:
        """Export all delegation-type certificates from the local store.

        Includes both self-issued and received delegation certs so the
        holder can share proof of their granted authority.

        Returns:
            Dict with keys: bundle_id, issuer_name, exported_at,
            cert_type_filter, certificates.
        """
        with self._lock:
            all_certs = self.get_all_certificates()
            delegation_certs = [
                c for c in all_certs
                if c.cert_type == CertificateType.DELEGATION
            ]
            return {
                "bundle_id": str(uuid.uuid4()),
                "issuer_name": self._ks.my_name,
                "exported_at": time.time(),
                "cert_type_filter": "delegation",
                "certificates": [c.to_dict() for c in delegation_certs],
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_delegation(self, delegator_name: str) -> None:
        """Raise CertificateError if no valid delegation cert exists from delegator_name.

        Must be called inside self._lock.
        """
        certs = self.get_delegation_certs_held_by_me()
        if not any(c.issuer_name == delegator_name for c in certs):
            raise CertificateError(
                f"No valid delegation certificate from '{delegator_name}'."
            )

    def _delegated_save(
        self,
        delegator_name: str,
        master_password: str,
        **overrides,
    ) -> None:
        """Load the current friend record and re-save with field overrides.

        Reads public_key_pem, x25519, capabilities, pqc_combined_pub, and
        reconstructs hybrid_sig_pub_b64 from in-memory state, then applies
        any caller-supplied overrides before calling KeyStore.save_friend.

        Must be called inside self._lock.
        """
        import database as _db
        import json
        import struct
        from contextlib import closing

        with closing(_db.get_connection()) as conn:
            row = conn.execute(
                "SELECT public_key_pem, x25519_public_key_b64, "
                "capabilities_json, pqc_combined_pub_b64 "
                "FROM friends WHERE name=?",
                (delegator_name,),
            ).fetchone()

        if row is None:
            raise CertificateError(
                f"'{delegator_name}' not found in friends list"
            )

        pem, x_b64, cap_json, pqc_b64 = row
        caps = json.loads(cap_json) if cap_json else None

        hybrid_b64 = None
        if delegator_name in self._ks.friends_hybrid_sig_pubs:
            ed_pub, dil_pub = self._ks.friends_hybrid_sig_pubs[delegator_name]
            combined = (
                struct.pack(">H", len(ed_pub)) + ed_pub
                + struct.pack(">H", len(dil_pub)) + dil_pub
            )
            hybrid_b64 = base64.b64encode(combined).decode()

        kwargs = {
            "x25519_pub_b64": x_b64,
            "capabilities": caps,
            "pqc_combined_pub_b64": pqc_b64,
            "hybrid_sig_pub_b64": hybrid_b64,
        }
        kwargs.update(overrides)
        final_pem = kwargs.pop("pem", pem)

        secret = self._ks.get_friend_secret(delegator_name)
        try:
            self._ks.save_friend(
                name=delegator_name,
                pem=final_pem,
                shared_secret=secret,
                password=master_password,
                **kwargs,
            )
        except Exception as e:
            raise CertificateError(
                f"Failed to update friend record: {e}"
            ) from e

    def _load_certificate(self, cert_id: str) -> TrustCertificate:
        """Load a single certificate by ID.

        Args:
            cert_id: UUID string identifying the certificate.

        Returns:
            The TrustCertificate.

        Raises:
            CertificateError: If the certificate is not found.
        """
        import database

        try:
            rows = database.get_trust_certificates_for()
        except Exception as e:
            raise CertificateError(
                f"Failed to query certificate: {e}"
            ) from e

        for row in rows:
            if row["cert_id"] == cert_id:
                return TrustCertificate.from_dict(row)

        raise CertificateError(f"Certificate {cert_id} not found")
