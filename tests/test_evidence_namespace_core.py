"""SPEC020 exact formats and shared local publication; no namespace caller activation."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_reference.protected_head import FileNamespaceHeadStore, FileProtectedHeadStore
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.evidence import GENESIS
from regulated_core.evidence_map import MemorySparseMap, EMPTY, key_digest
from regulated_core.evidence_namespace import (
    NamespaceHead, StateValue, Transition, advance_chain, sign_namespace_head,
    state_key, verify_namespace_extension, verify_namespace_head,
)
from regulated_core.evidence_service import EvidenceError
from regulated_core.merkle import MemoryMerkleLog, EMPTY_ROOT
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_evidence_service_formats import Clock, case


def publication_args(args):
    result = dict(args)
    result["advancing_heads"] = result.pop("allowed_keys")
    result["existing_heads"] = {}
    return result


def namespace_case(scope_type="tenant"):
    clock = Clock()
    signer = Ed25519Signer("fixture:namespace-sealer", Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
    trust = TrustDirectory(); trust.register_signer(signer)
    keys = frozenset({signer.key_id})
    scope = dict(scope_type=scope_type, scope_id="alpha", namespace="budget")
    arguments = dict(**scope, clock_domain=clock.domain, trust=trust, allowed_keys=keys)
    signing = dict(**scope, signer=signer, clock=clock, trust=trust, signing_keys=keys, historical_keys={})
    empty = sign_namespace_head(version=0, tree_root=EMPTY_ROOT, map_root=EMPTY[0], chain=GENESIS,
                                previous=None, consistency=(), **signing)
    tree, mapping, chain, leaves = MemoryMerkleLog(), MemorySparseMap(), GENESIS, []
    key = state_key(**scope, kind="mission", identifier=["mission", "alpha"])
    for seq in range(3):
        item = Transition(**scope, key=key.hex(), history_sequence=seq,
                          history_head=digest_hex({"seq": seq}), content_digest=digest_hex({"units": seq}))
        leaves.append(item)
        tree.append(item.bytes()); mapping.update(key, item.state_value().bytes())
        chain = advance_chain(chain, item)
    clock.value = 200
    head = sign_namespace_head(version=3, tree_root=tree.root(), map_root=mapping.root, chain=chain,
                               previous=empty, consistency=(), **signing)
    return clock, signer, trust, arguments, signing, empty, head, tree, mapping, leaves


def test_exact_wire_body_and_three_transition_chain():
    clock, signer, _, args, _, empty, head, tree, mapping, leaves = namespace_case()
    assert clock.calls == 2
    assert empty.body() == {"schema": "regulated/ns-head/v2", "map_schema": "regulated/evidence-map/v2", "scope_type": "tenant", "scope_id": "alpha",
                            "namespace": "budget", "version": 0, "tree_root": EMPTY_ROOT.hex(),
                            "map_root": EMPTY[0].hex(), "chain": GENESIS, "previous_head_digest": GENESIS,
                            "key_id": signer.key_id, "clock_domain": clock.domain, "issued_at_us": 100}
    assert head.version == head.tree_size == 3 and head.previous_head_digest == empty.digest()
    assert verify_namespace_extension(empty, head, (), **args)
    assert head.tree_root == tree.root().hex() and head.map_root == mapping.root.hex()
    chain = bytes(32)
    for item in leaves:
        expected = {"schema": "regulated/ns-transition/v1", "scope_type": item.scope_type,
                    "scope_id": item.scope_id, "namespace": item.namespace, "key": item.key,
                    "history_sequence": item.history_sequence, "history_head": item.history_head,
                    "content_digest": item.content_digest}
        assert item.bytes() == canonical_bytes(expected)
        assert Transition.from_bytes(item.bytes()) == item
        assert StateValue.from_bytes(item.state_value().bytes()) == item.state_value()
        chain = sha256(chain + sha256(b"\0" + canonical_bytes(expected)).digest()).digest()
    assert head.chain == chain.hex()
    assert NamespaceHead.from_document(json.loads(canonical_bytes(head.document()))) == head


def test_state_keys_domain_separate_scope_namespace_kind_and_composite_id():
    base = state_key("tenant", "alpha", "budget", "mission", ["a", "b"])
    others = [state_key("installation", "alpha", "budget", "mission", ["a", "b"]),
              state_key("tenant", "beta", "budget", "mission", ["a", "b"]),
              state_key("tenant", "alpha", "scope", "mission", ["a", "b"]),
              state_key("tenant", "alpha", "budget", "other", ["a", "b"]),
              state_key("tenant", "alpha", "budget", "mission", "a,b"),
              key_digest("alpha", "mission", ["a", "b"])]
    assert len(set([base, *others])) == 7
    for scope, identifier in (("unknown", "id"), ("tenant", ("a", "b")), ("tenant", [float("nan")]),
                              ("tenant", [{1: "invalid JSON key"}])):
        with pytest.raises(EvidenceError): state_key(scope, "alpha", "budget", "mission", identifier)


@pytest.mark.parametrize("field,value", [("scope_type", "installation"), ("scope_id", "beta"),
                                          ("namespace", "scope"), ("clock_domain", "other")])
def test_valid_head_signature_does_not_allow_scope_substitution(field, value):
    _, signer, _, args, _, _, head, *_ = namespace_case()
    changed = replace(head, **{field: value}); changed = replace(changed, signature=signer.sign(changed.body()))
    assert not verify_namespace_head(changed, **args)


def test_head_signature_key_domain_and_strict_shape():
    _, signer, _, args, _, empty, head, *_ = namespace_case()
    assert verify_namespace_head(head, **args)
    assert not verify_namespace_head(replace(head, signature=replace(head.signature, value="00" * 64)), **args)
    assert not verify_namespace_head(head, **(args | {"allowed_keys": frozenset({"other"})}))
    for bad in (replace(empty, tree_root="f" * 64), replace(empty, chain="f" * 64),
                replace(empty, previous_head_digest="f" * 64), replace(head, version=True)):
        bad = replace(bad, signature=signer.sign(bad.body()))
        assert not verify_namespace_head(bad, **args)
    document = json.loads(canonical_bytes(head.document())); document["body"]["tenant"] = "alpha"
    with pytest.raises(EvidenceError): NamespaceHead.from_document(document)


def test_multileaf_seal_pins_previous_sealed_head_and_refuses_time_fork():
    clock, signer, _, args, signing, empty, head, tree, mapping, _ = namespace_case()
    assert verify_namespace_extension(head, head, (), **args)
    for change in ({"previous_head_digest": GENESIS}, {"issued_at_us": 99}, {"tree_root": "f" * 64}):
        bad = replace(head, **change); bad = replace(bad, signature=signer.sign(bad.body()))
        # Initial empty-prefix consistency needs no tree proof; root provenance
        # is the sealer's responsibility, so only the first two are extension errors.
        if "tree_root" not in change:
            assert not verify_namespace_extension(empty, bad, (), **args)
    fork = replace(head, map_root="f" * 64); fork = replace(fork, signature=signer.sign(fork.body()))
    assert not verify_namespace_extension(head, fork, (), **args)
    assert not verify_namespace_extension(head, empty, (), **args)
    clock.value = 50
    with pytest.raises(EvidenceError):
        sign_namespace_head(version=3, tree_root=tree.root(), map_root=mapping.root, chain=head.chain,
                            previous=empty, consistency=(), **signing)


def test_nonempty_prefix_consistency_is_required_before_signing():
    clock, signer, _, args, signing, empty, head, tree, mapping, _ = namespace_case()
    first = replace(head, version=1, tree_root=tree.root(1).hex(), previous_head_digest=empty.digest())
    first = replace(first, signature=signer.sign(first.body()))
    calls = clock.calls
    with pytest.raises(EvidenceError, match="consistency"):
        sign_namespace_head(version=3, tree_root=tree.root(), map_root=mapping.root, chain=head.chain,
                            previous=first, consistency=(), **signing)
    assert clock.calls == calls + 1
    valid = sign_namespace_head(version=3, tree_root=tree.root(), map_root=mapping.root, chain=head.chain,
                                previous=first, consistency=tree.consistency(1, 3), **signing)
    assert verify_namespace_extension(first, valid, tree.consistency(1, 3), **args)


@pytest.mark.parametrize("scope_type", ["tenant", "installation", "verification_class"])
def test_namespace_store_publication_recovery_and_scope_paths(tmp_path, monkeypatch, scope_type):
    _, _, _, args, _, empty, head, *_ = namespace_case(scope_type)
    store = FileNamespaceHeadStore(tmp_path, **publication_args(args))
    assert store.directory == tmp_path / "heads" / scope_type / sha256(b"alpha").hexdigest() / "budget"
    store.advance(None, empty, ())
    original = store._replace_current
    def outage(_): raise OSError("namespace pointer outage")
    monkeypatch.setattr(store, "_replace_current", outage)
    with pytest.raises(OSError): store.advance(empty, head, ())
    monkeypatch.setattr(store, "_replace_current", original)
    assert store.read() == head
    assert store.advance(empty, head, ()) == head


def test_namespace_and_decision_stores_reject_each_others_heads(tmp_path, case):
    _, _, _, args, _, _, head, *_ = namespace_case()
    namespace_store = FileNamespaceHeadStore(tmp_path, **publication_args(args))
    with pytest.raises(EvidenceError): namespace_store.advance(None, case[6][0], ())
    decision_store = FileProtectedHeadStore(tmp_path, tenant="alpha", clock_domain=args["clock_domain"],
                                            trust=args["trust"], existing_heads={}, advancing_heads=args["allowed_keys"])
    with pytest.raises(EvidenceError): decision_store.advance(None, head, ())


def test_wrong_namespace_publication_latches_even_with_valid_signature(tmp_path):
    _, signer, _, args, _, empty, head, *_ = namespace_case()
    store = FileNamespaceHeadStore(tmp_path, **publication_args(args)); store.advance(None, empty, ())
    wrong = replace(head, namespace="scope"); wrong = replace(wrong, signature=signer.sign(wrong.body()))
    store._path(2).write_bytes(canonical_bytes({"schema":"regulated/head-publication/v1", "counter":2,
                                               "head":wrong.document(), "consistency":()}))
    with pytest.raises(EvidenceError): store.read()
    assert (store.directory / "LATCH").exists()


def test_invalid_transition_and_state_value_shapes_refuse():
    *_, leaves = namespace_case()
    for item in (replace(leaves[0], key="invalid"), replace(leaves[0], history_sequence=True),
                 replace(leaves[0], namespace="../budget")):
        with pytest.raises(EvidenceError): item.bytes()
    with pytest.raises(EvidenceError): Transition.from_bytes(b" " + leaves[0].bytes())
    with pytest.raises(EvidenceError): StateValue(True, GENESIS, GENESIS).bytes()
    with pytest.raises(EvidenceError): StateValue.from_bytes(b"{}")
    with pytest.raises(EvidenceError): advance_chain("invalid", leaves[0])
