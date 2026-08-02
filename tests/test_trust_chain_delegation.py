"""Tests for the Delegation Powers of the trust chain.

Covers the delegation methods in services/trust_chain_service.py:

    - get_delegation_certs_held_by_me
    - update_delegator_pub_key
    - update_delegator_x25519_key
    - update_delegator_pem
    - update_delegator_pqc_key
    - remove_all_delegator_optional_keys
    - revoke_delegator_recovery_shares
    - revoke_all_certs_for_delegator

These tests use a real KeyStore against the conftest isolated DB and plant
DELEGATION certificates directly through database.save_trust_certificate
(the delegation methods inspect certificate status/type only, they never
re-verify the hybrid signature, so synthetic keys are sufficient and liboqs
is not required).
"""

import time
import uuid
import base64
import struct
from contextlib import closing

import pytest

import database
from key_manager import KeyStore
from models.trust_chain import TrustCertificate, CertificateType
from services.trust_chain_service import TrustChainService
from src.exceptions import CertificateError
from src.crypto_utils import pubkey_to_pem

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from services.event_bus import event_bus, Events

_MASTER_PASSWORD = "correct-horse-battery-staple"

# Two distinct valid RSA public keys (2048-bit is fine here — the delegation
# code only round-trips the PEM through save_friend, it does not enforce the
# 4096-bit CNSA minimum).
_RSA_KEY = rsa.generate_private_key(65537, 2048, default_backend())
_PEM_A = pubkey_to_pem(_RSA_KEY.public_key())
_PEM_B = pubkey_to_pem(
    rsa.generate_private_key(65537, 2048, default_backend()).public_key()
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _combined_pub(ed_len=32, dil_len=1952) -> bytes:
    """Build a syntactically valid combined hybrid signing public key.

    Format matches HybridSigner: [ed_len(2) | ed_pub | dil_len(2) | dil_pub].
    Pure struct layout — no liboqs required.
    """
    return (
        struct.pack(">H", ed_len) + b"\xAA" * ed_len
        + struct.pack(">H", dil_len) + b"\xBB" * dil_len
    )


def _make_service(my_name="Me") -> TrustChainService:
    """Create a TrustChainService backed by a real KeyStore on the isolated DB."""
    ks = KeyStore()
    ks.set_my_name(my_name)
    return TrustChainService(ks)


def _add_friend(ks: KeyStore, name: str, pem: str = _PEM_A) -> None:
    """Register a friend (the future delegator) in the KeyStore/DB."""
    ks.save_friend(name=name, pem=pem, password=_MASTER_PASSWORD)


def _grant_delegation(svc: TrustChainService, delegator: str = "Alice") -> TrustCertificate:
    """Plant a valid DELEGATION cert granting the local user authority."""
    cert = TrustCertificate(
        cert_id=str(uuid.uuid4()),
        subject_name=svc._ks.my_name,
        subject_pub=b"\x01" * 32,
        issuer_name=delegator,
        issuer_pub=b"\x02" * 32,
        cert_type=CertificateType.DELEGATION,
        not_before=time.time() - 10,
        not_after=time.time() + 86400,
        signature=b"\x03" * 64,
    )
    database.save_trust_certificate(cert.to_dict())
    return cert


def _revoke_cert(svc: TrustChainService, cert: TrustCertificate) -> None:
    """Revoke a planted certificate through the service."""
    svc.revoke_certificate(cert.cert_id, reason="test")

def _revoke_cert_direct(cert: TrustCertificate) -> None:
    """Revoke a planted certificate by re-saving it as revoked (bypasses events)."""
    revoked = TrustCertificate(
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
        revocation_reason="test",
        received_from=cert.received_from,
        created_at=cert.created_at,
    )
    database.save_trust_certificate(revoked.to_dict())


def _make_cert(subject_name: str, **overrides) -> TrustCertificate:
    """Create and persist a certificate for a given subject."""
    defaults = dict(
        cert_id=str(uuid.uuid4()),
        subject_name=subject_name,
        subject_pub=b"\x11" * 32,
        issuer_name="Issuer",
        issuer_pub=b"\x22" * 32,
        cert_type=CertificateType.IDENTITY,
        not_before=time.time() - 10,
        not_after=time.time() + 86400,
        signature=b"\x33" * 64,
    )
    defaults.update(overrides)
    cert = TrustCertificate(**defaults)
    database.save_trust_certificate(cert.to_dict())
    return cert


def _friend_row(name: str):
    """Return the friends table row for a name (or None)."""
    with closing(database.get_connection()) as conn:
        return conn.execute(
            "SELECT public_key_pem, x25519_public_key_b64, capabilities_json, "
            "pqc_combined_pub_b64, hybrid_sig_pub_b64 FROM friends WHERE name=?",
            (name,),
        ).fetchone()


def _distributed_share(owner_name: str, share_id: str = None) -> dict:
    """A recovery_shares row the delegator distributed to others."""
    return {
        "share_id": share_id or str(uuid.uuid4()),
        "owner_name": owner_name,
        "share_index": 1,
        "total_shares": 3,
        "threshold": 2,
        "encrypted_share_b64": base64.b64encode(b"\xDD" * 32).decode(),
        "holder_name": "Holder",
        "holder_pub_b64": base64.b64encode(b"\xEE" * 32).decode(),
        "created_at": 1000.0,
    }


def _held_share(owner_name: str, share_id: str = None) -> dict:
    """A held_shares row the local user stores on the delegator's behalf."""
    return {
        "share_id": share_id or str(uuid.uuid4()),
        "owner_name": owner_name,
        "holder_name": "Me",
        "share_index": 2,
        "total_shares": 3,
        "threshold": 2,
        "plaintext_share_b64": base64.b64encode(b"\xCA" * 32).decode(),
        "created_at": 1000.0,
    }


# ---------------------------------------------------------------------------
# get_delegation_certs_held_by_me
# ---------------------------------------------------------------------------

class TestGetDelegationCertsHeldByMe:
    def test_returns_empty_with_no_certs(self):
        svc = _make_service()
        assert svc.get_delegation_certs_held_by_me() == []

    def test_returns_valid_delegation_certs(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        cert = _grant_delegation(svc, "Alice")
        held = svc.get_delegation_certs_held_by_me()
        assert len(held) == 1
        assert held[0].cert_id == cert.cert_id
        assert held[0].cert_type == CertificateType.DELEGATION
        assert held[0].issuer_name == "Alice"

    def test_excludes_revoked_delegation(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        cert = _grant_delegation(svc, "Alice")
        _revoke_cert_direct(cert)
        assert svc.get_delegation_certs_held_by_me() == []

    def test_excludes_expired_delegation(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        cert = _grant_delegation(svc, "Alice")
        _revoke_cert_direct(cert)
        expired = TrustCertificate(
            cert_id=str(uuid.uuid4()),
            subject_name=svc._ks.my_name,
            subject_pub=b"\x01" * 32,
            issuer_name="Bob",
            issuer_pub=b"\x02" * 32,
            cert_type=CertificateType.DELEGATION,
            not_before=time.time() - 86400 * 2,
            not_after=time.time() - 86400,
            signature=b"\x03" * 64,
        )
        database.save_trust_certificate(expired.to_dict())
        assert svc.get_delegation_certs_held_by_me() == []

    def test_excludes_non_delegation_types(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _make_cert(svc._ks.my_name)  # IDENTITY cert for me
        assert svc.get_delegation_certs_held_by_me() == []

    def test_excludes_delegation_for_other_subjects(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        # A delegation cert whose subject is someone else, not me.
        other = TrustCertificate(
            cert_id=str(uuid.uuid4()),
            subject_name="Charlie",
            subject_pub=b"\x01" * 32,
            issuer_name="Alice",
            issuer_pub=b"\x02" * 32,
            cert_type=CertificateType.DELEGATION,
            not_before=time.time() - 10,
            not_after=time.time() + 86400,
            signature=b"\x03" * 64,
        )
        database.save_trust_certificate(other.to_dict())
        held = svc.get_delegation_certs_held_by_me()
        assert len(held) == 1
        assert held[0].subject_name == svc._ks.my_name

    def test_returns_delegation_certs_from_multiple_issuers(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _add_friend(svc._ks, "Bob")
        _grant_delegation(svc, "Alice")
        _grant_delegation(svc, "Bob")
        assert len(svc.get_delegation_certs_held_by_me()) == 2


# ---------------------------------------------------------------------------
# update_delegator_pub_key
# ---------------------------------------------------------------------------

class TestUpdateDelegatorPubKey:
    def test_success_updates_hybrid_sig_key(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        new_b64 = base64.b64encode(_combined_pub()).decode()

        svc.update_delegator_pub_key("Alice", new_b64, _MASTER_PASSWORD)

        row = _friend_row("Alice")
        assert row[4] == new_b64
        assert "Alice" in svc._ks.friends_hybrid_sig_pubs
        ed_pub, dil_pub = svc._ks.friends_hybrid_sig_pubs["Alice"]
        assert len(ed_pub) == 32 and len(dil_pub) == 1952

    def test_invalid_base64_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        with pytest.raises(CertificateError):
            svc.update_delegator_pub_key("Alice", "!!!not-base64!!!", _MASTER_PASSWORD)

    def test_malformed_combined_key_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        # Valid base64 but not a parseable combined pub (too short for header).
        bad = base64.b64encode(b"\x00\x05ab").decode()
        with pytest.raises(CertificateError):
            svc.update_delegator_pub_key("Alice", bad, _MASTER_PASSWORD)

    def test_delegation_still_valid_after_update(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        new_b64 = base64.b64encode(_combined_pub()).decode()
        svc.update_delegator_pub_key("Alice", new_b64, _MASTER_PASSWORD)
        assert len(svc.get_delegation_certs_held_by_me()) == 1

    def test_requires_friend_in_friends_list(self):
        svc = _make_service()
        # Delegation cert exists, but no friends table row for the delegator.
        _grant_delegation(svc, "Ghost")
        with pytest.raises(CertificateError):
            svc.update_delegator_pub_key(
                "Ghost", base64.b64encode(_combined_pub()).decode(), _MASTER_PASSWORD
            )


# ---------------------------------------------------------------------------
# update_delegator_x25519_key
# ---------------------------------------------------------------------------

class TestUpdateDelegatorX25519Key:
    def test_success_updates_x25519_key(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        new_b64 = base64.b64encode(b"\x09" * 32).decode()

        svc.update_delegator_x25519_key("Alice", new_b64, _MASTER_PASSWORD)

        assert _friend_row("Alice")[1] == new_b64
        assert svc._ks.friends_x25519.get("Alice") == new_b64

    def test_wrong_length_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        for size in (31, 33):
            bad = base64.b64encode(b"\x09" * size).decode()
            with pytest.raises(CertificateError):
                svc.update_delegator_x25519_key("Alice", bad, _MASTER_PASSWORD)

    def test_invalid_base64_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        with pytest.raises(CertificateError):
            svc.update_delegator_x25519_key("Alice", "@@@@", _MASTER_PASSWORD)


# ---------------------------------------------------------------------------
# update_delegator_pem
# ---------------------------------------------------------------------------

class TestUpdateDelegatorPem:
    def test_success_updates_pem(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")

        svc.update_delegator_pem("Alice", _PEM_B, _MASTER_PASSWORD)

        assert _friend_row("Alice")[0] == _PEM_B

    def test_invalid_pem_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        with pytest.raises(CertificateError):
            svc.update_delegator_pem("Alice", "-----BEGIN PUBLIC KEY-----\nnot-a-key", _MASTER_PASSWORD)


# ---------------------------------------------------------------------------
# update_delegator_pqc_key
# ---------------------------------------------------------------------------

class TestUpdateDelegatorPqcKey:
    def test_success_updates_pqc_key(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        new_b64 = base64.b64encode(b"\x5A" * 100).decode()

        svc.update_delegator_pqc_key("Alice", new_b64, _MASTER_PASSWORD)

        assert _friend_row("Alice")[3] == new_b64
        assert svc._ks.friends_pqc_combined_pub.get("Alice") == b"\x5A" * 100

    def test_short_key_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        short = base64.b64encode(b"\x5A" * 31).decode()
        with pytest.raises(CertificateError):
            svc.update_delegator_pqc_key("Alice", short, _MASTER_PASSWORD)

    def test_invalid_base64_rejected(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        with pytest.raises(CertificateError):
            svc.update_delegator_pqc_key("Alice", "not-b64", _MASTER_PASSWORD)


# ---------------------------------------------------------------------------
# remove_all_delegator_optional_keys
# ---------------------------------------------------------------------------

class TestRemoveAllDelegatorOptionalKeys:
    def _setup_populated(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        svc.update_delegator_x25519_key(
            "Alice", base64.b64encode(b"\x09" * 32).decode(), _MASTER_PASSWORD
        )
        svc.update_delegator_pqc_key(
            "Alice", base64.b64encode(b"\x5A" * 64).decode(), _MASTER_PASSWORD
        )
        svc.update_delegator_pub_key(
            "Alice", base64.b64encode(_combined_pub()).decode(), _MASTER_PASSWORD
        )
        return svc

    def test_success_clears_optional_keys_and_preserves_pem(self):
        svc = self._setup_populated()
        original_pem = _friend_row("Alice")[0]

        svc.remove_all_delegator_optional_keys("Alice", _MASTER_PASSWORD)

        row = _friend_row("Alice")
        assert row[1] is None        # x25519 cleared
        assert row[3] is None        # pqc cleared
        assert row[4] is None        # hybrid sig cleared
        assert row[0] == original_pem  # PEM preserved
        assert "Alice" not in svc._ks.friends_x25519
        assert "Alice" not in svc._ks.friends_pqc_combined_pub
        assert "Alice" not in svc._ks.friends_hybrid_sig_pubs

    def test_idempotent_when_already_empty(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")

        svc.remove_all_delegator_optional_keys("Alice", _MASTER_PASSWORD)
        # Second call must not raise even though everything is already None.
        svc.remove_all_delegator_optional_keys("Alice", _MASTER_PASSWORD)


# ---------------------------------------------------------------------------
# revoke_delegator_recovery_shares
# ---------------------------------------------------------------------------

class TestRevokeDelegatorRecoveryShares:
    def test_success_removes_distributed_and_held(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        database.save_recovery_share(_distributed_share("Alice"))
        database.save_recovery_share(_distributed_share("Alice"))
        database.save_held_share(_held_share("Alice"))

        total = svc.revoke_delegator_recovery_shares("Alice")

        assert total == 3
        assert database.get_recovery_shares_for("Alice") == []
        assert all(r["owner_name"] != "Alice" for r in database.get_all_held_shares())

    def test_returns_zero_when_no_shares(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        assert svc.revoke_delegator_recovery_shares("Alice") == 0

    def test_only_affects_target_delegator(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _add_friend(svc._ks, "Bob")
        _grant_delegation(svc, "Alice")
        database.save_recovery_share(_distributed_share("Alice"))
        database.save_recovery_share(_distributed_share("Bob"))
        database.save_held_share(_held_share("Bob"))

        total = svc.revoke_delegator_recovery_shares("Alice")

        assert total == 1
        assert database.get_recovery_shares_for("Bob") != []
        assert len(database.get_all_held_shares()) == 1


# ---------------------------------------------------------------------------
# revoke_all_certs_for_delegator
# ---------------------------------------------------------------------------

class TestRevokeAllCertsForDelegator:
    def test_success_revokes_valid_certs(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        delegation = _grant_delegation(svc, "Alice")
        c1 = _make_cert("Alice")
        c2 = _make_cert("Alice")

        revoked = svc.revoke_all_certs_for_delegator("Alice")

        assert revoked == 2
        from database import get_trust_certificates_for
        rows = {r["cert_id"]: r for r in get_trust_certificates_for(subject_name="Alice")}
        assert rows[c1.cert_id]["revoked"] == 1
        assert rows[c2.cert_id]["revoked"] == 1
        # The delegation cert itself (subject=me) is untouched.
        assert len(svc.get_delegation_certs_held_by_me()) == 1
        assert delegation.revoked is False

    def test_skips_revoked_and_expired_certs(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        valid = _make_cert("Alice")
        already_revoked = _make_cert("Alice", revoked=True)
        expired = _make_cert(
            "Alice",
            not_before=time.time() - 86400 * 2,
            not_after=time.time() - 86400,
        )

        revoked = svc.revoke_all_certs_for_delegator("Alice")

        assert revoked == 1
        from database import get_trust_certificates_for
        rows = {r["cert_id"]: r for r in get_trust_certificates_for(subject_name="Alice")}
        assert rows[valid.cert_id]["revoked"] == 1
        assert rows[already_revoked.cert_id]["revoked"] == 1
        assert rows[expired.cert_id]["revoked"] == 0

    def test_returns_zero_when_no_certs(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        assert svc.revoke_all_certs_for_delegator("Alice") == 0

    def test_idempotent_second_call(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        _make_cert("Alice")
        assert svc.revoke_all_certs_for_delegator("Alice") == 1
        assert svc.revoke_all_certs_for_delegator("Alice") == 0


# ---------------------------------------------------------------------------
# Delegation state transitions / shared guards
# ---------------------------------------------------------------------------

class TestDelegationGuards:
    def test_all_mutations_require_valid_delegation(self):
        """Every delegation mutation raises CertificateError without a valid
        delegation cert from the named delegator."""
        svc = _make_service()
        _add_friend(svc._ks, "Alice")

        good_x = base64.b64encode(b"\x09" * 32).decode()
        good_pqc = base64.b64encode(b"\x5A" * 32).decode()
        good_pub = base64.b64encode(_combined_pub()).decode()

        ops = [
            lambda: svc.update_delegator_pub_key("Alice", good_pub, _MASTER_PASSWORD),
            lambda: svc.update_delegator_x25519_key("Alice", good_x, _MASTER_PASSWORD),
            lambda: svc.update_delegator_pem("Alice", _PEM_A, _MASTER_PASSWORD),
            lambda: svc.update_delegator_pqc_key("Alice", good_pqc, _MASTER_PASSWORD),
            lambda: svc.remove_all_delegator_optional_keys("Alice", _MASTER_PASSWORD),
            lambda: svc.revoke_delegator_recovery_shares("Alice"),
            lambda: svc.revoke_all_certs_for_delegator("Alice"),
        ]
        for op in ops:
            with pytest.raises(CertificateError):
                op()

    def test_updates_fail_after_delegation_revoked(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        cert = _grant_delegation(svc, "Alice")
        _revoke_cert(svc, cert)
        good_x = base64.b64encode(b"\x09" * 32).decode()
        with pytest.raises(CertificateError):
            svc.update_delegator_x25519_key("Alice", good_x, _MASTER_PASSWORD)

    def test_revoke_shares_fails_after_delegation_revoked(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        cert = _grant_delegation(svc, "Alice")
        database.save_recovery_share(_distributed_share("Alice"))
        _revoke_cert(svc, cert)
        with pytest.raises(CertificateError):
            svc.revoke_delegator_recovery_shares("Alice")
        # Records are left untouched when the guard fails.
        assert len(database.get_recovery_shares_for("Alice")) == 1

    def test_unknown_delegator_name(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        good_x = base64.b64encode(b"\x09" * 32).decode()
        with pytest.raises(CertificateError):
            svc.update_delegator_x25519_key("Eve", good_x, _MASTER_PASSWORD)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class TestDelegationEvents:
    def test_key_update_publishes_friend_list_changed(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        counts = {"friend_list_changed": 0}

        def handler(**kwargs):
            counts["friend_list_changed"] += 1
            assert kwargs.get("friend_name") == "Alice"

        event_bus.subscribe(Events.FRIEND_LIST_CHANGED, handler)
        try:
            svc.update_delegator_x25519_key(
                "Alice", base64.b64encode(b"\x09" * 32).decode(), _MASTER_PASSWORD
            )
            svc.remove_all_delegator_optional_keys("Alice", _MASTER_PASSWORD)
        finally:
            event_bus.unsubscribe(Events.FRIEND_LIST_CHANGED, handler)
        assert counts["friend_list_changed"] == 2

    def test_revoke_all_publishes_certificate_revoked(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        _make_cert("Alice")
        counts = {"revoked": 0}

        def handler(**kwargs):
            counts["revoked"] += 1
            assert kwargs.get("reason") == f"Revoked by delegate {svc._ks.my_name}"

        event_bus.subscribe(Events.CERTIFICATE_REVOKED, handler)
        try:
            svc.revoke_all_certs_for_delegator("Alice")
        finally:
            event_bus.unsubscribe(Events.CERTIFICATE_REVOKED, handler)
        assert counts["revoked"] == 1

    def test_revoke_all_publishes_no_event_when_zero(self):
        svc = _make_service()
        _add_friend(svc._ks, "Alice")
        _grant_delegation(svc, "Alice")
        counts = {"revoked": 0}

        def handler(**kwargs):
            counts["revoked"] += 1

        event_bus.subscribe(Events.CERTIFICATE_REVOKED, handler)
        try:
            svc.revoke_all_certs_for_delegator("Alice")
        finally:
            event_bus.unsubscribe(Events.CERTIFICATE_REVOKED, handler)
        assert counts["revoked"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
