"""Constructor-only checks on the explicit scratch adaptation; no effect calls."""
from types import SimpleNamespace as NS

import pytest

from regulated_core.document_gate import DocumentGate, VerifierRegistry
from regulated_core.pack_gate import PackGateFactory, RulebookGate
from regulated_core.projectos_gate import _RegulatedGateBase
from test_host_contract import NoIORetention


def make(kind, **options):
    if kind == "project":
        return _RegulatedGateBase(object(), verifier_signers={}, **options)
    document = NS(vertical="fictional", content={})
    if kind == "document":
        policy = NS(document=document, content_types={"fictional"}, risk_tier=1,
                    action_ids=lambda category: ())
        return DocumentGate(object(), policy=policy, verifiers=VerifierRegistry(),
                            verifier_signers={}, pack_version="fictional", **options)
    if kind == "pack":
        policy = NS(retention_years=7, document=document, content_types={"fictional"},
                    effective_content={}, actions=lambda category: ["fictional:render"])
        return RulebookGate(pack=NS(rulebook=policy), registry=object(), engine=object(),
                            verifiers={}, verifier_signers={}, credential_verifier=object(),
                            **options)
    return PackGateFactory(trust=None, engine=None, host_verifiers=None,
                           verifier_signers={}, credential_verifier=None, intended_uses=None,
                           **options)


def incomplete(missing):
    store = NoIORetention()
    return NS(**{name: getattr(store, name) for name in ("anchor", "fetch", "verify")
                 if name != missing})


@pytest.mark.parametrize("kind", ["project", "document", "pack", "factory"])
@pytest.mark.parametrize("store", [None, object(), incomplete("anchor"),
                                   incomplete("fetch"), incomplete("verify")])
def test_adapted_constructors_reject_incomplete_retention(kind, store):
    with pytest.raises(ValueError, match="explicit retention operations"):
        make(kind, worm=store)


@pytest.mark.parametrize("kind", ["project", "document", "pack", "factory"])
def test_adapted_constructors_accept_valid_no_io_store(kind):
    store = NoIORetention()
    gate = make(kind, worm=store)
    assert (gate.worm if kind == "factory" else gate._worm) is store


@pytest.mark.parametrize("kind", ["project", "document", "pack", "factory"])
def test_required_argument_remains_required(kind):
    with pytest.raises(TypeError, match="worm"):
        make(kind)
