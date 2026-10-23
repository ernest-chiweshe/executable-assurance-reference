"""Existing neutral product_spec workflow on the reference authority path.

No domain pack is installed or activated. The signed local fixture policy is
an explicit test authority, not a claim of owner signature or deployment.
"""

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

from assurance_reference.document_gate import SignedReferenceDocumentGate
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.project_state import compose_project_state
from assurance_reference.session_credentials import SESSION_FIELD, SessionBoundCredentials
from factory.ledger import FileArtifactStore
from factory.projectos.engine import ProjectEngine
from factory.projectos.spec import RegulatedBlock
from factory.verticals.product_spec.export import export_product_spec_markdown, render_product_spec_markdown
from factory.verticals.product_spec.spec import (build_product_spec_contract, make_product_spec_runner,
                                               product_spec_spec)
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE, issue_certificate
from regulated_core.document_gate import VerifierRegistry
from regulated_core.models import Outcome
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer


def _product_spec_fixture_policy(issuer, clock, *, risk_tier=3):
    """Issue a distinct synthetic policy; retain the ordinary tier-three profile."""
    if type(risk_tier) is not int or risk_tier not in (3, 4):
        raise ValueError("product fixture risk tier must be exactly three or four")
    return document_policy(issuer, vertical="product-spec", policy_id=("local-release" if risk_tier == 3 else "local-release-tier4"),
        version=("fixture-1" if risk_tier == 3 else "fixture-tier4-1"), jurisdictions=("fixture",), effective_from_us=clock.now_us(),
        effective_until_us=clock.now_us() + 120_000_000, content={
            "schema": "regulated/policy-content/v1", "content_types": ["product-spec:document"],
            "risk_tier": risk_tier, "retention_years": 1,
            "verifiers": {"product-spec:readiness": {"kind": "deterministic", "version": "1"}},
            "actions": {
                "product-spec:draft": {"effect": "reversible", "required_outcomes": ["product-spec:readiness"]},
                "product-spec:release": {"effect": "external", "required_outcomes": ["product-spec:readiness"],
                    "mission_budget": {"units": 1, "limit": 1},
                    "approval": {"role_groups": ([["reviewer"]] if risk_tier == 3 else
                        [["reviewer"], ["independent_reviewer"]]), "minimum_approvers": (1 if risk_tier == 3 else 2),
                        "requester_may_approve": False, "expires_after_hours": 1}}}})


def build_product_spec_fixture(roles, tmp_path, *, factory, clock_source=None, session_type=LocalSessions,
                               partitioned_lifecycle=True, signer_factory=Ed25519Signer,
                           tier4_directory=None, tier4_cooling_off_us=0, fixture_risk_tier=3):
    """Use an explicitly supplied offline stage runner, real sessions and reviews."""
    if type(fixture_risk_tier) is not int or fixture_risk_tier not in (3, 4):
        raise ValueError("product fixture risk tier must be exactly three or four")
    stores, authorities, alerts, qualifications, report, keys = configuration(
        roles, tmp_path, clock_source=clock_source, partitioned_lifecycle=partitioned_lifecycle,
        signer_factory=signer_factory, tier4_directory=tier4_directory,
        tier4_cooling_off_us=tier4_cooling_off_us)
    clock, trust = authorities.clock, authorities.trust
    tenant = "product-fixture-" + uuid4().hex
    sessions = session_type(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    identities = {}
    certificates = CertificateRegistry(trust, {keys["issuer"].key_id: DEMONSTRATION_CERTIFICATE})
    principals = ("requester", "reviewer") + (
        ("independent_reviewer",) if fixture_risk_tier == 4 else ())
    for principal in principals:
        sessions.provision_identity(tenant, principal, principal + ".local", "fictional-password-001")
        identities[principal] = sessions.authenticate(tenant, sessions.login(
            tenant, principal + ".local", "fictional-password-001"))
    certificates.present(issue_certificate(keys["issuer"], subject_id="reviewer", role="reviewer",
        jurisdiction="fixture", expires_at_us=clock.now_us() + 120_000_000))
    if fixture_risk_tier == 4:
        certificates.present(issue_certificate(keys["issuer"], subject_id="independent_reviewer",
            role="independent_reviewer", jurisdiction="fixture",
            expires_at_us=clock.now_us() + 120_000_000))
    verifiers = VerifierRegistry()

    def readiness(draft, contract):
        complete = (contract.get("format_version") == "product-spec/1.0"
                    and len(str(contract.get("spec", "")).split()) >= 80
                    and all(str(contract.get(field, "")).strip() for field in ("problem", "solution", "scope")))
        return (Outcome.PASS, ()) if complete else (Outcome.FAIL, ("PRODUCT_SPEC_NOT_READY",))

    verifiers.register("product-spec:readiness", readiness)
    document = _product_spec_fixture_policy(keys["issuer"], clock, risk_tier=fixture_risk_tier)
    spec = replace(product_spec_spec(), regulated=RegulatedBlock(
        policy_ref=f"{document.vertical}/{document.policy_id}", policy_digest=document.digest(),
        pack_version="document:" + document.digest(), intended_use="product-spec release"))
    gates = {}
    for principal, authenticated in identities.items():
        credentials = SessionBoundCredentials(trust, keys["credential"], sessions, certificates,
                                              sessions=sessions, authenticated=authenticated)
        configured = replace(authorities, credential_verifier=credentials, host_verifiers=verifiers,
                              verifier_signers={"product-spec:readiness": keys["verifier"]})
        host = compose_reference_host(stores, configured, alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
        from assurance_reference.lineage_gate import QualificationEvidenceGate
        gates[principal] = QualificationEvidenceGate(SignedReferenceDocumentGate(
            factory=host.factory, document=document, authority=keys["issuer"].key_id))
    state = compose_project_state(pool=roles.project_state, sessions=sessions,
                                  authenticated=identities["requester"], namespace="product-spec")

    def contract(saved, approved):
        result = build_product_spec_contract(saved, approved)
        return {**result, "body": render_product_spec_markdown(result),
                SESSION_FIELD: identities["requester"].binding(),
                "provenance": {"run_id": "fictional-local-product-spec", "model_id": "scripted-offline"}}

    engine = ProjectEngine(spec, runner=make_product_spec_runner(factory), contract_builder=contract,
        exporter=export_product_spec_markdown, emission_gate=gates["requester"], state_store=state,
        root=str(tmp_path / "projects"), artifact_store=FileArtifactStore(tmp_path / "private-artifacts"),
        clock=lambda: clock.now_us() / 1e6)
    return SimpleNamespace(engine=engine, gates=gates, spec=spec, state=state, tenant=tenant,
        identities=identities, sessions=sessions, stores=stores, clock=clock, document=document,
        report=report, path=tmp_path / "product-spec.md", domain_packs=(),
        certify=lambda principal, role: certificates.present(issue_certificate(keys["issuer"],
            subject_id=principal, role=role, jurisdiction="fixture", expires_at_us=clock.now_us() + 120_000_000)),
        public_keys={key.key_id: key.public_key_bytes.hex() for key in keys.values()})
