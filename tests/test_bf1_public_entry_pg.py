"""B-F1 through each application's public release entry (C050-BF1-G1).

Education, Health and the product vertical each call their gate's ordinary ``authorize_release`` for the exact
prepared bytes. A request with no approval, no policy for its content, or no verification evidence is refused there:
not allowed, no permit, nonce unspent, nothing written. The policy and evidence cases carry a completed approval, so
nothing but the missing item can refuse them. "No policy" names a content type no policy owns and "no evidence" is a
verifier that produced nothing: the request's subject, not a guard, is what changes; every guard runs unchanged.
Fictional data; isolated PostgreSQL; actual restricted logins.
"""
from dataclasses import replace
import json

import pytest

from assurance_reference.lineage_gate import QualificationEvidenceGate
from factory.projectos.governed_release import PREPARATION_FIELD
from factory.tenant import TenantContext
from regulated_core.models import Actor
from regulated_core.projectos_gate import _RegulatedGateBase
from test_clinical_finalisation import clinical, roles  # noqa: F401
from test_education_session_release import education, reviewed_context  # noqa: F401
from test_product_spec_authority import approve, product  # noqa: F401

CASES = ["no-approval", "no-policy", "no-evidence"]
SIGNS = {"no-approval": ("APPROVAL_MISSING", "SECOND_REVIEW", "approval", "review"),
         "no-policy": ("NO_POLICY", "no policy"), "no-evidence": ("CHECK_FAILED", "CONTROL_MISSING")}


def _inner(gate):
    assert isinstance(gate, QualificationEvidenceGate) and isinstance(gate._gate, _RegulatedGateBase)
    return gate._gate


def _request(monkeypatch, gate, case, unapproved, approved):
    inner = _inner(gate)
    if case == "no-policy":
        monkeypatch.setattr(inner, "CONTENT_TYPE", "fixture:content-no-policy-owns")
    elif case == "no-evidence":
        monkeypatch.setattr(inner, "_verify_for_context", lambda *args, **kwargs: ())
    return unapproved if case == "no-approval" else approved


def _assert_refused(decision, permits, context, case):
    assert not decision.allowed and decision.permit is None, decision
    assert not permits.used(context.tenant, context.nonce)
    said = decision.reason + json.dumps(decision.evidence, default=str)
    assert any(sign in said for sign in SIGNS[case]), (case, said[:2000])


@pytest.mark.parametrize("case", CASES)
def test_education_public_entry_refuses(education, monkeypatch, case):  # noqa: F811
    app = education
    approved = reviewed_context(app)
    gate = app.gates["requester"]
    context = _request(monkeypatch, gate, case, replace(app.context, approval=None), approved)
    context = replace(context, now_us=app.clock.now_us())
    decision = gate.authorize_release(spec=app.spec, contract=app.contract, out_path=str(app.path),
                                      context=context, artifact=app.body)
    _assert_refused(decision, app.stores.permits, context, case)
    assert not app.path.exists()


@pytest.mark.parametrize("case", CASES)
def test_health_public_entry_refuses(clinical, monkeypatch, case):  # noqa: F811
    c = clinical
    gate = c.finaliser._gate
    record, context, contract, content = c.finaliser._prepare_finalisation(c.session, c.document, c.clinician)
    certificate = gate.request_approval(
        contract, context, (Actor(c.clinician.user_id, c.finaliser._workspace, frozenset({"clinician"})),))
    chosen = _request(monkeypatch, gate, case, replace(context, approval=None), replace(context, approval=certificate))
    chosen = replace(chosen, now_us=c.finaliser._now_us())
    decision = gate.authorize_release(spec=c.finaliser._spec, contract=contract, out_path=c.finaliser._target(record),
                                      context=chosen, artifact=content)
    _assert_refused(decision, c.stores.permits, chosen, case)
    assert not list(c.records.rglob("*.docx"))


@pytest.mark.parametrize("case", CASES)
def test_product_public_entry_refuses(product, monkeypatch, case):  # noqa: F811
    c = product
    gate = c.gates["requester"]
    approved = approve(c)
    contract = c.engine.governed_contract("inventory", tenant=c.tenant, context=c.context)
    record = c.state.load("inventory")[PREPARATION_FIELD]
    body = c.engine._artifact_store.get(TenantContext(tenant_id=c.tenant, display_name=c.tenant),
                                        record["artifact_address"])
    context = _request(monkeypatch, gate, case, replace(c.context, approval=None), approved)
    context = replace(context, now_us=c.clock.now_us())
    decision = gate.authorize_release(spec=c.spec, contract=contract, out_path=str(c.path), context=context,
                                      artifact=body)
    _assert_refused(decision, c.stores.permits, context, case)
    assert not c.path.exists()
