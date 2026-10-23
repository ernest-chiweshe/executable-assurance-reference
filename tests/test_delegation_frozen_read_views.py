"""Exact read-view comparisons with the hash-pinned, attribution-cleaned frozen delegation facade.

The frozen and recovered classes share the reference engine and durable fixture.
This compares public read results/refusals on the same input and state; it does
not claim equivalence of the entire historical production composition.
"""
from dataclasses import replace
import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import os
from pathlib import Path

from a08_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.approval_exchange import ReviewError
from regulated_core.delegation_review import DelegationRootExchange
from regulated_core.signing import Ed25519Signer
from synthetic_bounded_education import build_bounded_education_fixture, SYNTHETIC_PUBLISHER
from test_delegation_root_journey import unbound_receiving_source


# The original pin remains recorded in public-attribution-sanitization.json.
# Only attribution comments/docstring differ; comparison assertions are unchanged.
FROZEN_SHA256 = "cfb5270c56baf08633c96bcf211308f5c9d9cca0868f07ec7fe6ae80f1338f32"


def frozen_facade():
    original = Path(__file__).with_name("delegation_review.py.original")
    assert hashlib.sha256(original.read_bytes()).hexdigest() == FROZEN_SHA256
    loader = SourceFileLoader("regulated_core._a08_frozen_delegation_review", str(original))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module.DelegationRootExchange


def observed_read(exchange, method, contract, context, review_id):
    try:
        return ("value", getattr(exchange, method)(contract, context, review_id))
    except ReviewError as error:
        return ("refusal", type(error).__name__, str(error))


def test_same_stored_input_has_exact_frozen_and_recovered_read_results(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    bundle = tmp_path / "signed-budget-pack"
    build_bounded_education_fixture(bundle, publisher=publisher)
    app = build_education_fixture(
        roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
        fixture_budget_limit=None, fixture_validity_us=300_000_000,
        delegation_signer=Ed25519Signer("fictional:delegation-review"),
        delegation_source_status=unbound_receiving_source,
    )
    gate = app.gates["requester"]
    # Original and recovered read methods receive exactly the same real gate,
    # store, contract and authenticated owner context. No guard is replaced.
    original = frozen_facade()(gate, app.stores.reviews)
    recovered = DelegationRootExchange(gate, app.stores.reviews)
    context = replace(app.context, nonce="frozen-facade-views", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    opened = gate.open_delegation_review(
        **common, context=context, destinations=(str(app.path),),
        expires_in_us=120_000_000, admit_within_us=90_000_000, delegable=True,
    )
    rid = opened["delegation_review_id"]
    request = dict(**common, delegation_review_id=rid)

    def compare(expected_status, admitted=False):
        current = replace(context, now_us=app.clock.now_us())
        before = app.stores.reviews.get(current.tenant, rid)
        evidence = app.stores.recorder.entries(current.tenant)
        left = observed_read(original, "get", app.contract, current, rid)
        right = observed_read(recovered, "get", app.contract, current, rid)
        assert left == right and left[0] == "value"
        assert left[1]["status"] == expected_status
        left_root = observed_read(original, "root", app.contract, current, rid)
        right_root = observed_read(recovered, "root", app.contract, current, rid)
        assert left_root == right_root
        if admitted:
            assert left_root[0] == "value"
            assert left_root[1]["root_digest"] == left[1]["root_digest"]
        else:
            assert left_root == (
                "refusal", "ReviewError", "this delegation review has not admitted a root",
            )
        assert app.stores.reviews.get(current.tenant, rid) == before
        assert app.stores.recorder.entries(current.tenant) == evidence

    compare("awaiting-review")
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        gate_for_reviewer = app.gates[principal]
        gate_for_reviewer.grant_delegation_review(
            **request, role=role, context=replace(context, actor_id=principal,
                                                 now_us=app.clock.now_us()),
        )
        compare("approved" if principal == "head" else "awaiting-review")
    gate.admit_delegation(**request, context=replace(context, now_us=app.clock.now_us()))
    compare("admitted", admitted=True)
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain(context.tenant)
