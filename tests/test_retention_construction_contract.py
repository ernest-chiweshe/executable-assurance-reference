"""Reference startup refusals, before policy loading or any database/effect access."""

from dataclasses import fields, replace
from types import SimpleNamespace

import pytest

from assurance_reference.document_gate import SignedReferenceDocumentGate
from assurance_reference.host_runtime import ReferencePackGateFactory
from test_host_contract import NoIORetention, compose, contract  # noqa: F401


def incomplete_store(missing):
    return SimpleNamespace(**{name: getattr(NoIORetention(), name)
                              for name in ("anchor", "fetch", "verify") if name != missing})


@pytest.mark.parametrize("missing", ["anchor", "fetch", "verify"])
def test_host_rejects_each_incomplete_retention_contract(contract, missing):  # noqa: F811
    with pytest.raises(ValueError, match="explicit retention operations"):
        compose(contract, authorities=replace(contract.authorities, worm=incomplete_store(missing)))


@pytest.mark.parametrize("retention", [None, object(), incomplete_store("anchor"),
                                      incomplete_store("fetch"), incomplete_store("verify")])
def test_direct_reference_pack_factory_rejects_incomplete_store(contract, retention):  # noqa: F811
    factory = compose(contract).factory
    with pytest.raises(ValueError, match="explicit retention operations"):
        replace(factory, worm=retention)


def test_reference_factory_requires_explicit_store_and_preserves_valid_store(contract):  # noqa: F811
    factory = compose(contract).factory
    parameters = {field.name: getattr(factory, field.name) for field in fields(factory)}
    assert ReferencePackGateFactory(**parameters).worm is contract.authorities.worm
    del parameters["worm"]
    with pytest.raises(TypeError, match="worm"):
        ReferencePackGateFactory(**parameters)


@pytest.mark.parametrize("retention", [None, object(), incomplete_store("anchor"),
                                      incomplete_store("fetch"), incomplete_store("verify")])
def test_document_composition_refuses_before_loading_policy(retention):
    # Deliberately no engine or document methods: the invalid configuration must
    # stop at construction, before those components can be consulted.
    with pytest.raises(ValueError, match="explicit retention operations"):
        SignedReferenceDocumentGate(factory=SimpleNamespace(worm=retention),
                                    document=object(), authority="fictional-authority")
