"""Offline clinical preparation persistence contracts; no approval or target effect."""
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
import json

import pytest

from assurance_reference.clinical_review_attempts import (
    ClinicalReviewStateError, RetainedClinicalReviewAttempts, prepare_packet,
)
from assurance_reference.session_credentials import AuthenticatedSession
from factory.ledger import FileArtifactStore
from factory.projectos.governed_release import GovernedContract, PreparedArtifact, ReleaseTarget
from factory.projectos.regulated import EmissionContext
from factory.tenant import TenantContext


def preparation(tmp_path):
    body = b"Fictional clinical review artifact; no patient data."
    tenant = TenantContext(tenant_id="fictional-workspace", display_name="Fixture")
    address = FileArtifactStore(tmp_path / "artifacts").put(tenant, body)
    path = str((tmp_path / "final.docx").resolve())
    context = EmissionContext(tenant=tenant.tenant_id, actor_id="clinician-a",
        now_us=100, not_after_us=1000, nonce="attempt-one", action_id="finalise:" + "a" * 64,
        project_id="consultation:document", vertical_name="health", release_target=path)
    binding = {"schema": "health/session-admission/v1", "user_id": "clinician-a",
        "username": "fixture-a", "workspace_id": tenant.tenant_id, "reference": "session-one", "expires_at": 1.0}
    base = {"clinical_session": binding, "session_id": "consultation", "doc_id": "document",
            "document_digest": "a" * 64, "body": "Fictional clinical text"}
    contract = GovernedContract(base, PreparedArtifact({"artifact_sha256": address}, body),
        ReleaseTarget("filesystem", path, "absent"), mission="clinical-writing:fixture").for_approval()
    return context, contract, address, body


def reader(principal="clinician-a"):
    def no_io(*args, **kwargs):
        raise AssertionError("offline decode must not access database or session authority")
    return RetainedClinicalReviewAttempts(pool=SimpleNamespace(connection=no_io),
        sessions=SimpleNamespace(admit=no_io),
        authenticated=AuthenticatedSession("fictional-workspace", principal, "fixture-a", "session-one", 1000000))


def test_exact_prepared_bytes_session_and_deadline_survive_detached_read(tmp_path):
    context, contract, address, body = preparation(tmp_path)
    packet = prepare_packet(context=context, contract=contract, artifact_address=address, artifact=body)
    encoded = json.dumps(packet, sort_keys=True, separators=(",", ":"), allow_nan=False)
    state = {"packet_json": encoded, "digest": sha256(encoded.encode()).hexdigest()}
    reopened = reader()._decode(state, context.nonce)
    assert reopened == packet
    assert reopened["context"]["not_after_us"] == context.not_after_us
    assert reopened["contract"]["clinical_session"] == contract["clinical_session"]
    assert reopened["artifact_sha256"] == sha256(body).hexdigest()
    assert "approval" not in reopened and reopened["context"]["approval"] is None
    reopened["contract"]["body"] = "separate local display copy"
    assert packet["contract"]["body"] == "Fictional clinical text"
    assert not (tmp_path / "final.docx").exists()


@pytest.mark.parametrize("field,value", [("approval", "already-approved"), ("is_producer", True),
                                         ("not_after_us", 100)])
def test_unprepared_context_is_refused_before_any_io(tmp_path, field, value):
    context, contract, address, body = preparation(tmp_path)
    with pytest.raises(ClinicalReviewStateError):
        prepare_packet(context=replace(context, **{field: value}), contract=contract,
                       artifact_address=address, artifact=body)


def test_owner_namespace_cannot_decode_another_owners_preparation(tmp_path):
    context, contract, address, body = preparation(tmp_path)
    packet = prepare_packet(context=context, contract=contract, artifact_address=address, artifact=body)
    encoded = json.dumps(packet, sort_keys=True, separators=(",", ":"), allow_nan=False)
    state = {"packet_json": encoded, "digest": sha256(encoded.encode()).hexdigest()}
    with pytest.raises(ClinicalReviewStateError):
        reader("clinician-b")._decode(state, context.nonce)


def test_incomplete_retained_record_is_not_reconstructed_from_defaults():
    with pytest.raises(ClinicalReviewStateError):
        reader()._decode({"packet_json": "", "digest": ""}, "attempt-one")


@pytest.mark.parametrize("expires", [1792150200.123456, 1e20])
def test_session_float_bytes_survive_outer_json_roundtrip(tmp_path, expires):
    context, contract, address, body = preparation(tmp_path)
    contract["clinical_session"]["expires_at"] = expires
    packet = prepare_packet(context=context, contract=contract, artifact_address=address, artifact=body)
    encoded = json.dumps(packet, sort_keys=True, separators=(",", ":"), allow_nan=False)
    # Simulate serialization of the envelope only; the SQL roundtrip remains pending.
    state = json.loads(json.dumps({"packet_json": encoded, "digest": sha256(encoded.encode()).hexdigest()}))
    restored = reader()._decode(state, context.nonce)
    assert restored["contract"]["clinical_session"]["expires_at"] == expires
    assert state["packet_json"] == encoded


@pytest.mark.parametrize("packet", [None, {}, {"context": None}])
def test_malformed_preparation_has_typed_refusal_before_store_access(packet):
    with pytest.raises(ClinicalReviewStateError):
        reader().retain(packet)
