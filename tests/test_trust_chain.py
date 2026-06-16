"""Comprehensive unit tests for models/trust_chain.py – Trust Chain Certificates."""

import time
import uuid
import base64
import pytest

from models.trust_chain import (
    TrustCertificate,
    RecoveryShare,
    CertificateType,
    TrustLevel,
    RevocationStatus,
    compute_trust_level,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cert(**overrides) -> TrustCertificate:
    """Create a TrustCertificate with sensible defaults for testing."""
    defaults = dict(
        cert_id=str(uuid.uuid4()),
        subject_name="Alice",
        subject_pub=b'\x01' * 32,
        issuer_name="Bob",
        issuer_pub=b'\x02' * 32,
        cert_type=CertificateType.IDENTITY,
        not_before=time.time() - 1,
        not_after=time.time() + 86400,
        signature=b'\x03' * 64,
    )
    defaults.update(overrides)
    return TrustCertificate(**defaults)


# ---------------------------------------------------------------------------
# Tests: TrustCertificate Model
# ---------------------------------------------------------------------------

class TestTrustCertificateModel:
    def test_create_certificate(self):
        """Test creating a TrustCertificate with all fields."""
        cert = _make_cert(subject_name="Alice", issuer_name="Bob")
        assert cert.subject_name == "Alice"
        assert cert.issuer_name == "Bob"
        assert cert.revoked is False
        assert cert.status() == RevocationStatus.VALID

    def test_certificate_expiry(self):
        """Expired certificate should report EXPIRED status."""
        cert = _make_cert(
            not_before=time.time() - 86400 * 2,
            not_after=time.time() - 86400,
        )
        assert cert.is_expired() is True
        assert cert.status() == RevocationStatus.EXPIRED

    def test_certificate_revoked_status(self):
        """Revoked certificate should report REVOKED status."""
        cert = _make_cert(revoked=True)
        assert cert.status() == RevocationStatus.REVOKED

    def test_certificate_valid_not_yet_expired(self):
        """Certificate within validity window should be VALID."""
        cert = _make_cert(
            not_before=time.time() - 10,
            not_after=time.time() + 86400,
        )
        assert cert.is_expired() is False
        assert cert.status() == RevocationStatus.VALID

    def test_to_dict_and_from_dict(self):
        """Certificate should survive serialization roundtrip."""
        cert = _make_cert(cert_id="test-123", subject_name="Alice")
        d = cert.to_dict()
        restored = TrustCertificate.from_dict(d)
        assert restored.cert_id == "test-123"
        assert restored.subject_name == "Alice"
        assert restored.subject_pub == cert.subject_pub
        assert restored.cert_type == CertificateType.IDENTITY

    def test_to_dict_base64_encodes_bytes(self):
        """to_dict should base64-encode byte fields."""
        cert = _make_cert()
        d = cert.to_dict()
        assert isinstance(d["subject_pub_b64"], str)
        assert isinstance(d["issuer_pub_b64"], str)
        assert isinstance(d["signature_b64"], str)

    def test_from_dict_restores_enums(self):
        """from_dict should restore enum types correctly."""
        cert = _make_cert(cert_type=CertificateType.RECOVERY)
        d = cert.to_dict()
        restored = TrustCertificate.from_dict(d)
        assert restored.cert_type == CertificateType.RECOVERY

    def test_to_dict_contains_all_fields(self):
        """to_dict should include all serializable fields."""
        cert = _make_cert(
            revoked=True,
            revocation_reason="compromised",
            received_from="Charlie",
            created_at=12345.0,
        )
        d = cert.to_dict()
        assert d["revoked"] is True
        assert d["revocation_reason"] == "compromised"
        assert d["received_from"] == "Charlie"
        assert d["created_at"] == 12345.0

    def test_certificate_defaults(self):
        """Default optional fields should be set correctly."""
        cert = _make_cert()
        assert cert.revoked is False
        assert cert.revocation_reason == ""
        assert cert.received_from == ""
        assert cert.created_at == 0.0

    def test_delegation_certificate_type(self):
        """DELEGATION cert type should serialize/deserialize correctly."""
        cert = _make_cert(cert_type=CertificateType.DELEGATION)
        d = cert.to_dict()
        restored = TrustCertificate.from_dict(d)
        assert restored.cert_type == CertificateType.DELEGATION


# ---------------------------------------------------------------------------
# Tests: compute_trust_level
# ---------------------------------------------------------------------------

class TestComputeTrustLevel:
    def test_no_certs(self):
        """Empty list should yield NONE."""
        assert compute_trust_level([]) == TrustLevel.NONE

    def test_one_valid_cert(self):
        """One valid certificate should yield BASIC."""
        cert = _make_cert()
        assert compute_trust_level([cert]) == TrustLevel.BASIC

    def test_two_valid_certs(self):
        """Two valid certificates should yield VERIFIED."""
        certs = [_make_cert(cert_id=str(i)) for i in range(2)]
        assert compute_trust_level(certs) == TrustLevel.VERIFIED

    def test_three_valid_certs(self):
        """Three valid certificates should yield TRUSTED."""
        certs = [_make_cert(cert_id=str(i)) for i in range(3)]
        assert compute_trust_level(certs) == TrustLevel.TRUSTED

    def test_four_valid_certs(self):
        """Four valid certificates should yield TRUSTED."""
        certs = [_make_cert(cert_id=str(i)) for i in range(4)]
        assert compute_trust_level(certs) == TrustLevel.TRUSTED

    def test_expired_certs_excluded(self):
        """Expired certs should not count toward trust level."""
        expired = _make_cert(
            not_before=time.time() - 86400 * 2,
            not_after=time.time() - 86400,
        )
        assert compute_trust_level([expired]) == TrustLevel.NONE

    def test_revoked_certs_excluded(self):
        """Revoked certs should not count toward trust level."""
        revoked = _make_cert(revoked=True)
        assert compute_trust_level([revoked]) == TrustLevel.NONE

    def test_mixed_valid_and_expired(self):
        """Only valid certs should count."""
        valid = _make_cert(cert_id="valid")
        expired = _make_cert(
            cert_id="expired",
            not_before=time.time() - 86400 * 2,
            not_after=time.time() - 86400,
        )
        assert compute_trust_level([valid, expired]) == TrustLevel.BASIC

    def test_mixed_valid_and_revoked(self):
        """Only valid certs should count."""
        valid = _make_cert(cert_id="valid")
        revoked = _make_cert(cert_id="revoked", revoked=True)
        assert compute_trust_level([valid, revoked]) == TrustLevel.BASIC

    def test_mixed_all_three_statuses(self):
        """Two valid plus one expired/revoked should yield VERIFIED."""
        valid1 = _make_cert(cert_id="v1")
        valid2 = _make_cert(cert_id="v2")
        expired = _make_cert(
            cert_id="expired",
            not_before=time.time() - 86400 * 2,
            not_after=time.time() - 86400,
        )
        assert compute_trust_level([valid1, valid2, expired]) == TrustLevel.VERIFIED

    def test_trust_level_boundary_three(self):
        """Exactly 3 valid certs should be TRUSTED."""
        certs = [_make_cert(cert_id=str(i)) for i in range(3)]
        assert compute_trust_level(certs) == TrustLevel.TRUSTED


# ---------------------------------------------------------------------------
# Tests: RecoveryShare Model
# ---------------------------------------------------------------------------

class TestRecoveryShareModel:
    def test_to_dict_and_from_dict(self):
        """RecoveryShare should survive serialization roundtrip."""
        share = RecoveryShare(
            share_id="share-1",
            owner_name="Alice",
            share_index=1,
            total_shares=3,
            threshold=2,
            encrypted_share=b'\xAA' * 32,
            holder_name="Bob",
            holder_pub_b64=base64.b64encode(b'\xBB' * 32).decode(),
            created_at=1000.0,
        )
        d = share.to_dict()
        restored = RecoveryShare.from_dict(d)
        assert restored.share_id == "share-1"
        assert restored.owner_name == "Alice"
        assert restored.threshold == 2
        assert restored.encrypted_share == b'\xAA' * 32

    def test_to_dict_base64_encodes_share(self):
        """to_dict should base64-encode the encrypted_share field."""
        share = RecoveryShare(
            share_id="s1", owner_name="A", share_index=1,
            total_shares=3, threshold=2, encrypted_share=b'\xFF' * 16,
            holder_name="B", holder_pub_b64="pub", created_at=0.0,
        )
        d = share.to_dict()
        assert isinstance(d["encrypted_share"], str)

    def test_roundtrip_preserves_all_fields(self):
        """All fields should survive serialization roundtrip."""
        share = RecoveryShare(
            share_id="share-99",
            owner_name="Carol",
            share_index=3,
            total_shares=5,
            threshold=3,
            encrypted_share=b'\xCC' * 64,
            holder_name="Dave",
            holder_pub_b64=base64.b64encode(b'\xDD' * 32).decode(),
            created_at=9999.5,
        )
        d = share.to_dict()
        restored = RecoveryShare.from_dict(d)
        assert restored.share_id == "share-99"
        assert restored.owner_name == "Carol"
        assert restored.share_index == 3
        assert restored.total_shares == 5
        assert restored.threshold == 3
        assert restored.encrypted_share == b'\xCC' * 64
        assert restored.holder_name == "Dave"
        assert restored.holder_pub_b64 == share.holder_pub_b64
        assert restored.created_at == 9999.5

    def test_different_shares_different_ids(self):
        """Different shares should have different share_ids."""
        share1 = RecoveryShare(
            share_id="s1", owner_name="A", share_index=1,
            total_shares=3, threshold=2, encrypted_share=b'\x01' * 16,
            holder_name="B", holder_pub_b64="pub", created_at=0.0,
        )
        share2 = RecoveryShare(
            share_id="s2", owner_name="A", share_index=2,
            total_shares=3, threshold=2, encrypted_share=b'\x02' * 16,
            holder_name="B", holder_pub_b64="pub", created_at=0.0,
        )
        assert share1.share_id != share2.share_id
        assert share1.share_index != share2.share_index


# ---------------------------------------------------------------------------
# Tests: import_received_certs signature/issuer verification
# ---------------------------------------------------------------------------

try:
    import oqs  # noqa: F401
    _OQS_AVAILABLE = True
except Exception:
    _OQS_AVAILABLE = False


class _FakeKeyStore:
    """Minimal KeyStore stand-in exposing only what TrustChainService reads."""

    def __init__(self, my_name="Me"):
        self.my_name = my_name
        self.my_hybrid_sig_combined_pub = None
        self.friends_hybrid_sig_pubs = {}
        self.friends = []
        self.my_ed_priv = None
        self.my_dil_priv = None


@pytest.mark.skipif(
    not _OQS_AVAILABLE,
    reason="liboqs required to forge/verify real hybrid certificate signatures",
)
class TestImportReceivedCertsVerification:
    """import_received_certs must cryptographically verify before trusting."""

    def _issuer_setup(self):
        """Create a hybrid keypair and a service whose only friend is the
        issuer, with the issuer's combined pub pinned. Returns (service, keys)."""
        import struct
        from services.pqc_signatures import HybridSigner
        from services.trust_chain_service import TrustChainService

        keys = HybridSigner.generate_keys()
        ed_pub = keys["ed_pub_bytes"]
        dil_pub = keys["dil_pub_bytes"]

        ks = _FakeKeyStore(my_name="Me")
        # Pin issuer "Bob" with his real hybrid signing public key.
        ks.friends_hybrid_sig_pubs["Bob"] = (ed_pub, dil_pub)
        svc = TrustChainService(ks)
        return svc, keys

    def _signed_cert_dict(self, keys, subject_name="Alice"):
        import struct
        from services.pqc_signatures import HybridSigner

        not_before = time.time() - 1
        not_after = time.time() + 86400
        subject_pub = b"\x11" * 32
        ct = CertificateType.IDENTITY
        data = (
            subject_pub
            + ct.value.encode()
            + struct.pack(">d", not_before)
            + struct.pack(">d", not_after)
        )
        signature = HybridSigner.sign(data, keys["ed_priv"], keys["dil_priv"])
        combined_pub = keys["combined_pub"]
        cert = TrustCertificate(
            cert_id=str(uuid.uuid4()),
            subject_name=subject_name,
            subject_pub=subject_pub,
            issuer_name="Bob",
            issuer_pub=combined_pub,
            cert_type=ct,
            not_before=not_before,
            not_after=not_after,
            signature=signature,
            received_from="",
        )
        return cert.to_dict()

    def test_valid_cert_is_imported(self):
        svc, keys = self._issuer_setup()
        imported = svc.import_received_certs([self._signed_cert_dict(keys)])
        assert imported == 1

    def test_forged_signature_is_rejected(self):
        svc, keys = self._issuer_setup()
        cert_dict = self._signed_cert_dict(keys)
        # Tamper with the signature.
        cert_dict["signature_b64"] = base64.b64encode(b"\x00" * 100).decode()
        imported = svc.import_received_certs([cert_dict])
        assert imported == 0

    def test_unknown_issuer_is_rejected(self):
        svc, keys = self._issuer_setup()
        # Remove the pinned issuer key so the issuer is unknown.
        svc._ks.friends_hybrid_sig_pubs.clear()
        imported = svc.import_received_certs([self._signed_cert_dict(keys)])
        assert imported == 0

    def test_issuer_key_substitution_is_rejected(self):
        """A valid signature under an attacker key whose name impersonates a
        pinned issuer must fail the embedded-vs-pinned key match."""
        from services.pqc_signatures import HybridSigner

        svc, keys = self._issuer_setup()
        attacker = HybridSigner.generate_keys()
        # Attacker signs a cert claiming issuer "Bob" but with their own key.
        cert_dict = self._signed_cert_dict(attacker)  # signed correctly...
        # ...but issuer_pub now embeds the attacker's key, not Bob's pinned key.
        imported = svc.import_received_certs([cert_dict])
        assert imported == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
