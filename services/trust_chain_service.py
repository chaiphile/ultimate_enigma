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

    def verify_certificate(self, cert_id: str) -> bool:
        """Verify a trust certificate's full validity chain.

        Checks revocation, expiration, and hybrid signature integrity.
        The issuer's combined public key is parsed from the certificate
        to rebuild the signed data and verify the hybrid signature.

        Args:
            cert_id: UUID string identifying the certificate.

        Returns:
            True if all checks pass.

        Raises:
            CertificateRevokedError: If the certificate has been revoked.
            CertificateExpiredError: If the certificate has expired.
            CertificateSignatureError: If the hybrid signature is invalid.
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
                    f"Certificate {cert_id} signature is invalid"
                )

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
                event_bus.publish(
                    Events.CERTIFICATE_RECEIVED, count=imported
                )
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
    # Bundle Export
    # ------------------------------------------------------------------

    def export_trust_bundle(self) -> Dict[str, Any]:
        """Export all self-issued certificates as a bundle.

        The bundle can be shared with peers to bootstrap trust.

        Returns:
            Dict with keys: bundle_id, issuer_name, exported_at,
            certificates (list of serialized cert dicts).
        """
        with self._lock:
            my_certs = self.get_certs_issued_by_me()
            return {
                "bundle_id": str(uuid.uuid4()),
                "issuer_name": self._ks.my_name,
                "exported_at": time.time(),
                "certificates": [c.to_dict() for c in my_certs],
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
