"""Actual local pack installation and intact gate construction; no release."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import hashlib

import pytest

from assurance_reference.domain_host import ReferenceDomainHost
from assurance_reference.qualified_engine import QualifiedReferenceEngine
from assurance_reference.reviewed_evidence import SourceReleaseGuard
from assurance_reference.reviewed_source_bindings import ReviewedSourceBindings
from factory.packs.demonstrations import APPROVAL_SHA256, EVIDENCE_CHECK, USES, build_demonstration_pack
from factory.packs.registry import PackRegistry
from factory.packs.rulebook import RulebookPolicy
from regulated_core.signing import Ed25519Signer
from test_host_contract import ConstructionSigner
from test_host_contract import contract as contract


@pytest.mark.parametrize("use", tuple(USES))
def test_installed_pack_builds_exact_surface_gate(contract, tmp_path, use):
    requirements = (Path(__file__).parent / "private-inputs/approved-requirements.md").read_bytes()
    assert hashlib.sha256(requirements).hexdigest() == APPROVAL_SHA256
    publisher = Ed25519Signer("synthetic:x25-publisher")
    policy = Ed25519Signer("synthetic:x25-policy")
    trust = contract.authorities.trust
    for signer in (publisher, policy):
        trust.register_signer(signer)
    target = tmp_path / "bundle"
    build_demonstration_pack(target, use=use, publisher=publisher,
                             rulebook_authority=policy, approved_requirements=requirements)
    registry = PackRegistry(trust=trust, activation=contract.stores.activation)
    installed = registry.install(target, publisher_key_id=publisher.key_id, today="2026-10-16")
    assert isinstance(installed.rulebook, RulebookPolicy)
    assert registry.get(installed.reference) is installed
    release = installed.rulebook.actions("external")[0]
    approval = installed.rulebook.effective_content["rules"][release]["approval"]
    assert approval["role_groups"] == [[role] for role in USES[use]["roles"]]
    signers = dict(contract.authorities.verifier_signers)
    for check in installed.rulebook.check_ids():
        signer = ConstructionSigner("synthetic:x25-verifier:" + check)
        trust.register_signer(signer)
        signers[check] = signer
    shared = ReferenceDomainHost(
        stores=contract.stores,
        authorities=replace(contract.authorities, verifier_signers=signers),
        alerts=contract.alerts, qualifications=contract.qualifications,
        floor_not_used_reason="Offline installed X25 gate construction only",
    )
    adapter = ReviewedSourceBindings(
        domain_host=shared, pack_ids={use: installed.manifest.id},
        credentials={use: lambda request: contract.authorities.credential_verifier},
        source_authorities={use: frozenset({contract.keys["evidence"].key_id})},
        credential_authorities={use: {"synthetic-provider": contract.keys["credential"].key_id}},
    )
    # An absent surface declaration is an ordinary incomplete configuration.
    with pytest.raises(ValueError, match="surface must bind"):
        shared.gate(installed, registry, None)
    document = installed.rulebook.document
    surface = SimpleNamespace(spec=SimpleNamespace(regulated=SimpleNamespace(
        pack_version=installed.reference,
        policy_ref=f"{document.vertical}/{document.policy_id}",
        policy_digest=document.digest(),
    )))
    gate = shared.gate(installed, registry, surface)
    assert gate.pack is installed and gate.registry is registry
    assert isinstance(gate._engine, QualifiedReferenceEngine)
    assert isinstance(gate.source_reviews, SourceReleaseGuard)
    assert gate.source_reviews.source is adapter.source
    assert gate.source_reviews.pack is installed and gate.source_reviews.registry is registry
    assert EVIDENCE_CHECK in gate.verifiers
    assert gate._credverify is contract.authorities.credential_verifier
    assert registry.ledger is contract.stores.activation
