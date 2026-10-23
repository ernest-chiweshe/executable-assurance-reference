"""B-F7a: tenant context flows through authorization, credentials and persistence on Education, Health and the
product vertical; a cross-tenant request is refused at authorization and is indistinguishable from a missing
resource. Fictional tenants and people; isolated PostgreSQL; actual restricted logins.
"""
from dataclasses import replace

from factory.projectos.regulated import EmissionContext
from regulated_core.approval_evidence import ReviewError
from test_clinical_finalisation import clinical, roles  # noqa: F401
from test_education_session_release import education  # noqa: F401
from test_product_spec_authority import approve, product  # noqa: F401
from factory.health_ui.clinical_checks import CHECK_IDS
from regulated_core.models import Actor


def _refusal(call):
    try:
        call()
    except Exception as error:  # noqa: BLE001 - the observable refusal is what is compared
        return type(error).__name__, str(error)
    return None


def test_education_cross_tenant_review_is_indistinguishable_from_a_missing_review(education):  # noqa: F811
    app = education
    opened = app.gates["requester"].open_review(spec=app.spec, contract=app.contract, context=app.context)
    app.sessions.provision_identity("school-b", "requester", "requester.b", "fictional-password-002")
    foreign = app.sessions.authenticate("school-b", app.sessions.login("school-b", "requester.b",
                                                                       "fictional-password-002"))
    gate = app.make_gate(foreign)
    context = replace(app.context, tenant="school-b", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    other = _refusal(lambda: gate.get_review(**common, context=context, review_id=opened["review_id"]))
    missing = _refusal(lambda: gate.get_review(**common, context=context, review_id="review:" + "0" * 48))
    assert other is not None and other == missing and other[0] == ReviewError.__name__
    refused = gate.authorize_release(spec=app.spec, contract=app.contract, out_path=str(app.path),
                                     artifact=app.body, context=replace(context, approval=opened["review_id"]))
    assert not refused.allowed and not app.path.exists()


def test_health_cross_tenant_document_is_indistinguishable_from_a_missing_document(clinical):  # noqa: F811
    c = clinical
    named = {"session_id": c.session.session_id, "doc_id": c.document.doc_id, "document_digest": c.document.digest()}
    foreign = EmissionContext(tenant="health-foreign-workspace", actor_id=c.clinician.user_id,
                              now_us=c.clock.now_us())
    for check in CHECK_IDS:
        verifier = c.verifiers.resolve(check)
        other = verifier.verify_context("", named, foreign)
        missing = verifier.verify_context("", {**named, "session_id": "case-missing"},
                                          replace(foreign, tenant=c.clinician.workspace_id))
        assert other == missing


def test_product_engine_refuses_a_foreign_tenant_context_without_effect(product):  # noqa: F811
    """The product engine is composed per authenticated tenant; a foreign tenant reaches projects only through the
    server-bound entry, where another tenant's project is refused exactly like a missing one
    (test_project_entry_pg.py::test_another_tenants_project_is_not_found, 404 for both). Behind that entry, a foreign
    tenant context presented to this tenant's engine is still refused before any effect."""
    c = product
    approved = approve(c)  # A genuinely approved release, so the refusal below is the tenant's, not the review's.
    foreign = replace(approved, tenant="product-foreign-tenant")
    refused = _refusal(lambda: c.engine.release("inventory", str(c.path), context=foreign))
    assert refused is not None and not c.path.exists()
    c.engine.release("inventory", str(c.path), context=approved)
    assert c.path.exists()


def test_health_release_refuses_a_foreign_tenant_context_at_authorization(clinical):  # noqa: F811
    """Health's public authorize_release, for a genuinely approved final record, refused for a foreign workspace
    context: not allowed, no permit, nothing written. The same request in the owner's workspace is authorized, so the
    refusal is the tenant's, not the review's."""
    c = clinical
    gate = c.finaliser._gate
    record, context, contract, content = c.finaliser._prepare_finalisation(c.session, c.document, c.clinician)
    certificate = gate.request_approval(
        contract, context, (Actor(c.clinician.user_id, c.finaliser._workspace, frozenset({"clinician"})),))
    approved = replace(context, approval=certificate, now_us=c.finaliser._now_us())
    request = dict(spec=c.finaliser._spec, contract=contract, out_path=c.finaliser._target(record), artifact=content)
    foreign = gate.authorize_release(**request, context=replace(approved, tenant="health-foreign-workspace"))
    assert not foreign.allowed and foreign.permit is None, foreign
    assert not list(c.records.rglob("*.docx"))
    own = gate.authorize_release(**request, context=replace(approved, now_us=c.finaliser._now_us()))
    assert own.allowed, own.reason
