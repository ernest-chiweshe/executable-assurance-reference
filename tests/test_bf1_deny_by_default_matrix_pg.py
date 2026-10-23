"""B-F1: Education, Health and the product vertical release through one deny-by-default path.

Each application's gate is a ``_RegulatedGateBase`` over the same qualified reference engine, wrapped by the same
qualification-evidence gate (E and H as signed-pack ``RulebookGate``, P as a host-signed ``DocumentGate``). On each,
an otherwise ordinary release request with no policy for its content, no completed approval, or no verification
evidence is refused at that shared engine: denied, no permit, nonce unspent, nothing written. The product vertical's
VerticalSpec is the unchanged ``product_spec_spec()`` with only the regulated attachment added. Lawful releases on
all three are in test_three_application_matrix.py, test_education_session_release.py, test_clinical_finalisation.py
and test_product_spec_authority.py. Fictional data; isolated PostgreSQL; actual restricted logins.
"""
from dataclasses import fields, replace

import pytest

from assurance_reference.lineage_gate import QualificationEvidenceGate
from assurance_reference.qualified_engine import QualifiedReferenceEngine
from factory.projectos.governed_release import PREPARATION_FIELD
from factory.tenant import TenantContext
from factory.verticals.product_spec.spec import product_spec_spec
from regulated_core.projectos_gate import _RegulatedGateBase
from test_clinical_finalisation import clinical, roles  # noqa: F401
from test_education_session_release import education  # noqa: F401
from test_product_spec_authority import product  # noqa: F401

EXPECTED = {"no-policy": {"NO_POLICY"}, "no-approval": {"APPROVAL_MISSING", "SECOND_REVIEW"},
            "no-evidence": {"CHECK_FAILED", "CONTROL_MISSING"}}


def _refused(gate, contract, context, out_path, body, permits, case):
    assertion, action, capability, policy_context = gate._build(contract, context)
    if case == "no-policy":
        assertion = replace(assertion, content_type="fixture:content-no-policy-owns", verifications=())
    elif case == "no-evidence":
        assertion = replace(assertion, verifications=())
    nonce = "bf1-" + case
    refused = gate._engine.authorize_for_target(
        vertical=gate.VERTICAL, capability=capability, assertion=assertion, action=action, ctx=policy_context,
        output=body, target=gate.target_for(out_path, context.tenant), permit_ttl_us=60_000_000, nonce=nonce,
        not_after_us=context.not_after_us)
    assert not refused.authorized and refused.permit is None
    assert not permits.used(context.tenant, nonce)
    codes = set(refused.envelope.record.decision.reason_codes)
    assert codes & EXPECTED[case], (case, codes)
    return codes


def _shared_path(gate):
    assert isinstance(gate, QualificationEvidenceGate)
    assert isinstance(gate._gate, _RegulatedGateBase)
    assert isinstance(gate._engine, QualifiedReferenceEngine)


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_education_refuses_at_the_shared_gate(education, case):  # noqa: F811
    app = education
    gate = app.gates["requester"]
    _shared_path(gate)
    _refused(gate, app.contract, replace(app.context, now_us=app.clock.now_us()), str(app.path), app.body,
             app.stores.permits, case)
    assert not app.path.exists()


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_health_refuses_at_the_shared_gate(clinical, case):  # noqa: F811
    c = clinical
    gate = c.gate
    _shared_path(gate)
    record, context, contract, content = c.finaliser._prepare_finalisation(c.session, c.document, c.clinician)
    _refused(gate, contract, replace(context, now_us=c.clock.now_us()), c.finaliser._target(record), content,
             c.stores.permits, case)
    assert not list(c.records.rglob("*.docx"))


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_product_refuses_at_the_shared_gate(product, case):  # noqa: F811
    c = product
    gate = c.gates["requester"]
    _shared_path(gate)
    contract = c.engine.governed_contract("inventory", tenant=c.tenant, context=c.context)
    # The exact prepared release bytes, read from the project's content-addressed preparation record.
    record = c.state.load("inventory")[PREPARATION_FIELD]
    body = c.engine._artifact_store.get(TenantContext(tenant_id=c.tenant, display_name=c.tenant),
                                        record["artifact_address"])
    _refused(gate, contract, replace(c.context, now_us=c.clock.now_us()), str(c.path), body, c.stores.permits,
             case)
    assert not c.path.exists()


def test_product_vertical_spec_is_unchanged_apart_from_its_regulated_attachment(product):  # noqa: F811
    c = product
    original = product_spec_spec()
    assert original.regulated is None and c.spec.regulated is not None
    for f in fields(original):
        if f.name != "regulated":
            assert getattr(c.spec, f.name) == getattr(original, f.name), f.name
    assert c.domain_packs == ()
