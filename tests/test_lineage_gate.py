"""Read-only evidence attachment and delegation, without a receiving target."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.lineage_gate import LineageUnavailable, QualificationEvidenceGate, attach_qualification_lineage
from factory.projectos.regulated import EmissionDecision
from regulated_core.clock import ClockReading
from regulated_core.engine import TargetAuthorization
from regulated_core.evidence import DecisionRecorder
from regulated_core.models import Action, ActionEffect, Actor, Assertion, Decision, PolicyContext, PolicyRef
from regulated_core.qualification import QualificationError
from regulated_core.signing import Ed25519Signer
from test_host_contract import contract, compose  # noqa: F401
from test_qualification_lineage import lineage_case, signed

# ruff: noqa: F811


class FixtureClock:
    domain = "fixture:clock"

    def read(self):
        return ClockReading(self.domain, 150)

    def now_us(self):
        return 150


def decision_case():
    qualifications, issuer, permit, _ = lineage_case()
    evidence_key = Ed25519Signer("fixture:evidence")
    qualifications._trust.register_signer(evidence_key)
    recorder = DecisionRecorder(evidence_key, qualifications._trust, clock=FixtureClock())
    assertion = Assertion("fixture:assertion", "fixture:tenant", "fixture:text", "c" * 64)
    action = Action("fixture:release", ActionEffect.EXTERNAL)
    context = PolicyContext("fixture:tenant", Actor("fixture:requester", "fixture:tenant", frozenset()),
                            "fixture:purpose", "fixture:correlation", 150)
    policy = PolicyRef("fixture", "policy", "1")
    envelope = recorder.record(assertion, action, context, policy,
                               Decision.allow("SYNTHETIC_ONLY", "Offline signed evidence fixture; no target"))
    permit = replace(permit, decision_record_id=envelope.record.record_id, decision_record_hash=envelope.record_hash)
    authorization = TargetAuthorization(True, "synthetic", "allow", envelope, signed(issuer, permit),
                                        assertion, action, context, policy)
    return (EmissionDecision(True, "synthetic", {"retained_original": {"value": "exact"}}, authorization),
            qualifications, recorder, issuer)


def test_attachment_retains_original_evidence_and_exact_opaque_authorization():
    decision, qualifications, recorder, issuer = decision_case()
    result = attach_qualification_lineage(decision, qualifications=qualifications,
        recorder=recorder, permit_authority=issuer.key_id)
    assert result.permit is decision.permit
    assert result.allowed == decision.allowed and result.reason == decision.reason
    assert result.evidence["retained_original"] == decision.evidence["retained_original"]
    assert "qualification_lineage" not in decision.evidence
    assert result.evidence["authorization_decision"]["record_hash"] == decision.permit.envelope.record_hash
    assert result.evidence["qualification_lineage"]["decision_record_hash"] == decision.permit.envelope.record_hash
    assert recorder.entries() == (decision.permit.envelope,)


@pytest.mark.parametrize("field,value", [
    ("decision_record_id", "different"), ("decision_record_hash", "f" * 64),
    ("tenant_id", "fixture:other"), ("principal", "fixture:other"),
    ("assertion_id", "fixture:other"), ("action_id", "fixture:other"),
    ("clock_domain", "fixture:other"),
])
def test_attachment_refuses_even_signed_binding_mismatches(field, value):
    decision, qualifications, recorder, issuer = decision_case()
    changed = replace(decision.permit.permit.permit, **{field: value})
    decision = replace(decision, permit=replace(decision.permit, permit=signed(issuer, changed)))
    with pytest.raises(QualificationError, match="bind the verified decision"):
        attach_qualification_lineage(decision, qualifications=qualifications,
                                     recorder=recorder, permit_authority=issuer.key_id)


def test_attachment_preserves_refusal_and_refuses_missing_authority_or_overwrite():
    refused = EmissionDecision(False, "pending", {"original": True})
    assert attach_qualification_lineage(refused, qualifications=None, recorder=None, permit_authority="") is refused
    decision, qualifications, recorder, issuer = decision_case()
    for altered in (replace(decision, permit=None), replace(decision, evidence={"qualification_lineage": {}})):
        with pytest.raises(QualificationError):
            attach_qualification_lineage(altered, qualifications=qualifications,
                                         recorder=recorder, permit_authority=issuer.key_id)


def test_wrapper_delegates_authority_calls_and_cleans_up_failed_attachment(contract):
    engine = compose(contract).factory.engine
    calls = []
    decision, _, _, _ = decision_case()
    refused = EmissionDecision(False, "pending")
    answer = [refused]

    def authorize(**request):
        calls.append(("authorize", request))
        return answer[0]

    def commit(**request):
        calls.append(("commit", request))
        return "delegated unchanged"

    gate = SimpleNamespace(_engine=engine, authorize_release=authorize, commit_release=commit,
        _return_unreleased_reservation=lambda auth: calls.append(("cleanup", auth)))
    wrapper = QualificationEvidenceGate(gate)
    assert wrapper.authorize_release(marker="original") is refused
    assert wrapper.commit_release(marker="receiver") == "delegated unchanged"
    assert calls == [("authorize", {"marker": "original"}), ("commit", {"marker": "receiver"})]
    answer[0] = decision
    # This independently signed fixture is outside this composed host's domain;
    # the intact evidence guard refuses it before any allowed answer is returned.
    with pytest.raises(LineageUnavailable):
        wrapper.authorize_release(marker="mismatched fixture")
    assert calls[-1] == ("cleanup", decision.permit)


def test_wrapper_requires_reference_engine():
    with pytest.raises(TypeError):
        QualificationEvidenceGate(SimpleNamespace(_engine=object()))
