"""Reference admission refuses unsupported host composition without authority.

These are intact factory/configuration checks using synthetic adapter stubs;
no unsupported host executes, and no security guard is changed or removed.
"""
from types import SimpleNamespace

import pytest

from assurance_reference.governance_targets import (
    pack_activation_target, pack_pin_target, pack_rollback_target, pack_revocation_target,
    roster_target, require_governance_composition,
)
from factory.packs.lifecycle_pg import PostgresActivationLedger
from factory.packs.registry import PackRegistry
from regulated_core.choke_points import credential_issuance_target, egress_target, channel_target
from regulated_core.governance_targets import qualification_target, issuer_target, GovernanceLog
from regulated_core.persistence_pg import PostgresMissionBudget
from regulated_core.signing import TrustDirectory
from test_reference_host_budget_contract import composition
from roster_verifier_fixture import verified_store


def unsupported(kind, engine, request, uses):
    options = dict(tenant_id=request["ctx"].tenant_id, authority=engine.targets,
                   uses=uses, log=GovernanceLog())
    adapter = SimpleNamespace(governance_receipt=lambda *a: None, receipt=lambda *a: None,
        status=lambda *a: None, issue=lambda *a: None, deliver=lambda *a: None)
    if kind == "checker":
        return qualification_target(adapter, SimpleNamespace(verification_class="synthetic"), **options)
    if kind == "issuer":
        return issuer_target(adapter, "synthetic:issuer", **options)
    if kind == "credential":
        return credential_issuance_target(adapter, "synthetic:slot", **options)
    if kind == "egress":
        return egress_target(adapter, "synthetic:endpoint", **options)
    return channel_target(adapter, "synthetic:channel", **options)


@pytest.mark.parametrize("kind", ["checker", "issuer", "credential", "egress", "channel"])
@pytest.mark.parametrize("sibling", [False, True])
def test_unsupported_governance_composition_refuses_before_reservation_signing_or_effect(tmp_path, kind, sibling):
    engine, request, signer, budget, events, uses = composition(
        tmp_path, {"limit": 1, "units": 1}, sibling=sibling)
    target = unsupported(kind, engine, request, uses)
    with pytest.raises(TypeError, match="supported reference governance factory"):
        engine.authorize_for_target(**{**request, "target": target}, nonce="unsupported")
    assert signer.calls == 0 and events == []
    assert not uses.used(request["ctx"].tenant_id, "unsupported")
    assert engine._recorder.entries(request["ctx"].tenant_id) == ()
    # No authorization object exists: composition must be checked before commit
    # examines one or dispatches any receiving operation.
    with pytest.raises(TypeError, match="supported reference governance factory"):
        engine.commit(None, b"synthetic", target)


@pytest.mark.parametrize("factory,args", [
    (pack_activation_target, ("course@1#digest",)),
    (pack_pin_target, ("course@1#digest", "fixture")),
    (pack_rollback_target, ("course@1", "course@1#digest")),
    (pack_revocation_target, ("course@1#digest",)),
    (roster_target, ("synthetic:installation",)),
])
def test_supported_factory_requires_same_allocator_as_reference_engine(factory, args):
    budget = PostgresMissionBudget(pool=None)
    host = (verified_store(installation=args[0])[0] if factory is roster_target else
            PackRegistry(trust=TrustDirectory(), activation=PostgresActivationLedger("", pool=None)))
    authority = host._proof_verifier.authority if factory is roster_target else None
    target = factory(host, *args, budget=budget, tenant_id="fixture", authority=authority,
                     uses=None, log=GovernanceLog())
    require_governance_composition(target, budget)
    with pytest.raises(TypeError, match="engine's durable budget"):
        require_governance_composition(target, PostgresMissionBudget(pool=None))
