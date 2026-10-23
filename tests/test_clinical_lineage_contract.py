"""Offline signed-evidence contracts; no target, database or guard override."""

import copy
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest

from assurance_reference.clinical_lineage import RetainedClinicalLineage, authorization_packet
from assurance_reference.lineage_gate import LineageUnavailable, QualificationEvidenceGate, attach_qualification_lineage
from assurance_reference.session_credentials import AuthenticatedSession
from regulated_core.canonical import canonical_bytes
from test_host_contract import contract, compose  # noqa: F401
from test_lineage_gate import decision_case

# ruff: noqa: F811


def attached():
    decision, qualifications, recorder, issuer = decision_case()
    verification = dict(qualifications=qualifications, recorder=recorder, permit_authority=issuer.key_id)
    return attach_qualification_lineage(decision, **verification), verification


def store(verification, principal="fixture:requester", tenant="fixture:tenant"):
    def forbidden():
        raise AssertionError("offline packet validation must perform no I/O")
    return RetainedClinicalLineage(pool=SimpleNamespace(connection=forbidden),
        sessions=SimpleNamespace(admit=forbidden), authenticated=AuthenticatedSession(
            tenant, principal, "fixture", "synthetic-session", 200), **verification)


def test_retained_packet_is_exact_detached_historical_evidence():
    decision, verification = attached()
    packet = authorization_packet(decision, tenant="fixture:tenant", principal="fixture:requester")
    assert packet["evidence"] == decision.evidence
    assert packet["nonce"] == decision.permit.permit.permit.nonce
    assert "committed" not in packet
    state = {"packet": packet, "digest": sha256(canonical_bytes(packet)).hexdigest()}
    reopened = store(verification)._decode(state, "fixture:nonce")
    assert reopened == packet
    reopened["evidence"]["retained_original"]["value"] = "changed copy"
    assert state["packet"]["evidence"]["retained_original"]["value"] == "exact"


@pytest.mark.parametrize("tenant,principal", [
    ("other", "fixture:requester"), ("fixture:tenant", "other"),
])
def test_packet_refuses_foreign_authenticated_identity(tenant, principal):
    with pytest.raises(LineageUnavailable):
        authorization_packet(attached()[0], tenant=tenant, principal=principal)


@pytest.mark.parametrize("change", ["digest", "tenant", "principal", "nonce", "permit", "envelope"])
def test_readback_refuses_corrupt_or_rebound_packet(change):
    decision, verification = attached()
    packet = authorization_packet(decision, tenant="fixture:tenant", principal="fixture:requester")
    state = {"packet": copy.deepcopy(packet), "digest": sha256(canonical_bytes(packet)).hexdigest()}
    if change == "digest":
        state["digest"] = "0" * 64
    else:
        if change in {"tenant", "principal", "nonce"}:
            state["packet"][change] = "other"
        elif change == "permit":
            state["packet"]["evidence"]["qualification_lineage"]["signed_target_permit"]["permit"]["nonce"] = "other"
        else:
            state["packet"]["evidence"]["authorization_decision"]["record_hash"] = "0" * 64
        # Integrity alone cannot bless a different identity or decision binding.
        state["digest"] = sha256(canonical_bytes(state["packet"])).hexdigest()
    with pytest.raises(LineageUnavailable):
        store(verification)._decode(state, "fixture:nonce")


def test_packet_refuses_unattached_or_inconsistent_gate_answer():
    decision, _, _, _ = decision_case()
    with pytest.raises(LineageUnavailable):
        authorization_packet(decision, tenant="fixture:tenant", principal="fixture:requester")
    decision, _ = attached()
    changed = copy.deepcopy(decision.evidence)
    changed["qualification_lineage"]["signed_target_permit"]["signature"]["key_id"] = "other"
    with pytest.raises(LineageUnavailable, match="differs from the verified"):
        authorization_packet(replace(decision, evidence=changed),
            tenant="fixture:tenant", principal="fixture:requester")


def test_clinician_namespaces_differ_without_io_and_sink_must_be_explicit(contract):
    _, verification = attached()
    assert store(verification)._pool.namespace != store(verification, principal="other")._pool.namespace
    with pytest.raises(ValueError):
        RetainedClinicalLineage(pool=None, sessions=None, authenticated=None, **verification)
    with pytest.raises(TypeError, match="retain method"):
        QualificationEvidenceGate(SimpleNamespace(_engine=compose(contract).factory.engine), retention=object())


@pytest.mark.parametrize("field", ["permit-signature", "decision-signature", "report", "authority"])
def test_readback_requires_signatures_and_pinned_reports_even_with_matching_storage_digest(field):
    decision, verification = attached()
    packet = authorization_packet(decision, tenant="fixture:tenant", principal="fixture:requester")
    if field == "permit-signature":
        packet["evidence"]["qualification_lineage"]["signed_target_permit"]["signature"]["value"] = "00" * 64
    elif field == "decision-signature":
        packet["evidence"]["authorization_decision"]["signature"]["value"] = "00" * 64
    elif field == "report":
        packet["evidence"]["qualification_lineage"]["reports"][0]["dataset_reference"]["digest"] = "0" * 64
    else:
        verification["permit_authority"] = "not-the-host-authority"
    state = {"packet": packet, "digest": sha256(canonical_bytes(packet)).hexdigest()}
    with pytest.raises(LineageUnavailable):
        store(verification)._decode(state, "fixture:nonce")
