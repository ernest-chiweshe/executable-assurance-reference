"""Offline composition contracts with intact authority checks and no effects."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.domain_host import ReferenceDomainHost
from assurance_reference.host_runtime import ReferencePackGateFactory
from assurance_reference.qualified_engine import QualifiedReferenceEngine
from factory.domain_host import DomainBinding, UnboundDomain
from test_host_contract import contract as contract


def host(c, **changes):
    return ReferenceDomainHost(stores=c.stores, authorities=changes.get("authorities", c.authorities),
        alerts=c.alerts, qualifications=c.qualifications,
        floor_not_used_reason="Offline reference domain composition fixture")


def pack(name="education", checks=("fixture:check",)):
    return SimpleNamespace(manifest=SimpleNamespace(id="fixture." + name),
                           rulebook=SimpleNamespace(check_ids=lambda: checks))


def bind(h, c, name="education", credentials=None, **changes):
    binding = DomainBinding("fixture." + name, name,
        credentials if credentials is not None else lambda request: c.authorities.credential_verifier,
        verifiers=lambda request: c.authorities.host_verifiers,
        credential_authorities={"fixture-provider": c.keys["credential"].key_id}, **changes)
    h.bind(binding)
    return binding


@pytest.mark.parametrize("name", ["education", "health", "product_spec"])
def test_domains_compose_reference_engine_on_shared_stores(contract, name):
    shared = host(contract)
    bind(shared, contract, name)
    result = shared.compose_for(pack(name), None, None)
    assert result.stores is contract.stores
    assert isinstance(result.factory, ReferencePackGateFactory)
    assert isinstance(result.factory.engine, QualifiedReferenceEngine)
    assert result.factory.engine.targets.clock is contract.authorities.clock


def test_unknown_domain_refuses_before_any_credentials(contract):
    shared = host(contract)
    with pytest.raises(UnboundDomain):
        shared.gate(pack(), None, None)


def test_missing_check_key_refuses_before_credentials(contract):
    shared = host(contract)
    def unused(request):
        raise AssertionError("missing signing configuration must refuse first")
    bind(shared, contract, credentials=unused)
    with pytest.raises(ValueError, match="verifier signing keys"):
        shared.compose_for(pack(checks=("unknown:check",)), None, None)


def test_domain_credentials_must_retain_session_admission(contract):
    shared = host(contract)
    bind(shared, contract, credentials=lambda request: object())
    with pytest.raises(ValueError, match="session admission"):
        shared.compose_for(pack(), None, None)


def test_public_gate_requires_session_admission_before_pack_construction(contract):
    shared = host(contract)
    bind(shared, contract, credentials=lambda request: object())
    # Exercise the public entrance with all guards intact. The shared template
    # was valid, but this domain's resolved credentials cannot admit a release.
    with pytest.raises(ValueError, match="reference host requires receiving-side session admission"):
        shared.gate(pack(), None, None)


def test_domain_cannot_reuse_emission_key_as_credential_authority(contract):
    shared = host(contract)
    shared.bind(DomainBinding("fixture.education", "education",
        lambda request: contract.authorities.credential_verifier,
        credential_authorities={"fixture-provider": contract.keys["emission"].key_id}))
    with pytest.raises(ValueError, match="separated"):
        shared.compose_for(pack(), None, None)


def test_delegation_declaration_needs_both_shared_services(contract):
    shared = host(contract)
    bind(shared, contract, delegates=True)
    with pytest.raises(ValueError, match="signer and source status"):
        shared.compose_for(pack(), None, None)


def test_incomplete_shared_configuration_is_rejected_at_construction(contract):
    with pytest.raises(ValueError, match="session admission"):
        host(contract, authorities=replace(contract.authorities, credential_verifier=object()))


def test_configured_floor_is_retained_for_every_domain(contract):
    from test_host_contract import bound_floor
    floor = bound_floor(contract)
    shared = ReferenceDomainHost(stores=contract.stores, authorities=contract.authorities,
        alerts=contract.alerts, qualifications=contract.qualifications, generation_floor=floor)
    for name in ("education", "health", "product_spec"):
        bind(shared, contract, name)
        result = shared.compose_for(pack(name), None, None)
        assert result.factory.engine._generation_floor is floor


def test_host_restriction_jurisdiction_and_review_binding_survive(contract):
    restrictions, extension, alarm = object(), object(), object()
    shared = host(contract, authorities=replace(contract.authorities,
        restrictions=restrictions, required_jurisdiction="fixture", outage_alarm=alarm))
    bind(shared, contract, review_extension=lambda request: extension)
    result = shared.compose_for(pack(), None, None)
    assert result.factory.engine._restrictions is restrictions
    assert result.factory.required_jurisdiction == "fixture"
    assert result.factory.review_extension_factory is extension
    assert result.factory.outage_alarm is alarm


def test_caller_verifier_map_changes_do_not_change_host_policy(contract):
    signers = dict(contract.authorities.verifier_signers)
    shared = host(contract, authorities=replace(contract.authorities, verifier_signers=signers))
    bind(shared, contract)
    signers.clear()
    assert shared.compose_for(pack(), None, None).factory.verifier_signers["fixture:check"] is contract.keys["verifier"]


def test_request_inputs_are_read_only_and_host_owned(contract):
    shared = host(contract)
    def credentials(request):
        assert request.host is shared
        assert request.inputs["case_id"] == "synthetic"
        with pytest.raises(TypeError):
            request.inputs["case_id"] = "changed"
        return contract.authorities.credential_verifier
    bind(shared, contract, credentials=credentials)
    shared.compose_for(pack(), None, None, case_id="synthetic")
