from test_evidence_namespace_core import publication_args
"""Valid outer representations around hostile namespace/publication inputs."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from assurance_reference.protected_head import FileNamespaceHeadStore
from regulated_core.canonical import canonical_bytes
from regulated_core.evidence import GENESIS
from regulated_core.evidence_namespace import (NamespaceHead, sign_namespace_head,
                                             verify_namespace_head, verify_namespace_extension)
from regulated_core.evidence_service import EvidenceError
from regulated_core.signing import Ed25519Signer
from test_evidence_namespace_core import namespace_case
from test_evidence_service_formats import case
from test_protected_head_core import store_for


def replace_pinned_file(store, counter, head, proof=()):
    data = canonical_bytes({"schema": "regulated/head-publication/v1", "counter": counter,
                            "head": head.document(), "consistency": tuple(h.hex() for h in proof)})
    store._path(counter).write_bytes(data)
    (store.directory / "CURRENT").write_bytes(canonical_bytes({"counter": counter, "hash": sha256(data).hexdigest()}))


@pytest.mark.parametrize("mode", ["decision", "namespace"])
def test_matching_current_hash_cannot_authenticate_forged_head_signature(tmp_path, case, mode):
    if mode == "decision":
        store, head = store_for(tmp_path, case), case[6][0]
    else:
        _, _, _, args, _, empty, _, *_ = namespace_case()
        store, head = FileNamespaceHeadStore(tmp_path, **publication_args(args)), empty
    store.advance(None, head, ())
    forged = replace(head, signature=replace(head.signature, value="00" * 64))
    replace_pinned_file(store, 1, forged)
    with pytest.raises(EvidenceError, match="refused"):
        store.read()
    assert (store.directory / "LATCH").exists()


@pytest.mark.parametrize("field,value", [("scope_type", "installation"), ("scope_id", "other"),
                                          ("namespace", "scope")])
def test_namespace_current_hash_does_not_allow_validly_signed_wrong_scope(tmp_path, field, value):
    _, signer, _, args, _, empty, *_ = namespace_case()
    store = FileNamespaceHeadStore(tmp_path, **publication_args(args)); store.advance(None, empty, ())
    wrong = replace(empty, **{field: value}); wrong = replace(wrong, signature=signer.sign(wrong.body()))
    replace_pinned_file(store, 1, wrong)
    with pytest.raises(EvidenceError): store.read()
    assert (store.directory / "LATCH").exists()


def nonempty_pair():
    parts = namespace_case()
    _, signer, _, args, _, empty, head, tree, *_ = parts
    first = replace(head, version=1, tree_root=tree.root(1).hex(), previous_head_digest=GENESIS)
    first = replace(first, signature=signer.sign(first.body()))
    later = replace(head, previous_head_digest=first.digest())
    later = replace(later, signature=signer.sign(later.body()))
    assert verify_namespace_head(first, **args) and verify_namespace_head(later, **args)
    return parts, first, later


@pytest.mark.parametrize("route", ["advance", "recovery"])
def test_namespace_adapter_refuses_valid_signed_fork_without_consistency(tmp_path, route):
    parts, first, later = nonempty_pair()
    args, tree = parts[3], parts[7]
    store = FileNamespaceHeadStore(tmp_path, **publication_args(args)); store.advance(None, first, ())
    assert verify_namespace_extension(first, later, tree.consistency(1, 3), **args)
    if route == "advance":
        with pytest.raises(EvidenceError): store.advance(first, later, ())
        assert not store._path(2).exists()
        assert store.read() == first
    else:
        store._path(2).write_bytes(canonical_bytes({"schema": "regulated/head-publication/v1", "counter": 2,
                                                  "head": later.document(), "consistency": ()}))
        with pytest.raises(EvidenceError): store.read()
        assert (store.directory / "LATCH").exists()


def test_head_body_key_and_signature_key_must_be_identical_even_if_both_trusted():
    _, _, trust, args, _, _, head, *_ = namespace_case()
    other = Ed25519Signer("fixture:other-sealer"); trust.register_signer(other)
    signed = replace(head, signature=other.sign(head.body()))
    assert trust.verify(signed.body(), signed.signature)
    assert not verify_namespace_head(signed, **(args | {"allowed_keys": args["allowed_keys"] | {other.key_id}}))


@pytest.mark.parametrize("damage", ["previous", "proof"])
def test_initial_seal_requires_genesis_reference_and_empty_prefix_proof(damage):
    _, signer, _, args, _, _, head, *_ = namespace_case()
    initial = replace(head, previous_head_digest="f" * 64 if damage == "previous" else GENESIS)
    initial = replace(initial, signature=signer.sign(initial.body()))
    assert verify_namespace_head(initial, **args)
    assert not verify_namespace_extension(None, initial, (b"x" * 32,) if damage == "proof" else (), **args)


def test_nonempty_extension_requires_correct_consistency_independently_of_signatures():
    parts, first, later = nonempty_pair()
    args, tree = parts[3], parts[7]
    proof = tree.consistency(1, 3)
    assert verify_namespace_extension(first, later, proof, **args)
    for malformed in ((), (b"x" * 32,) + proof[1:], proof + (b"x" * 32,)):
        assert not verify_namespace_extension(first, later, malformed, **args)


@pytest.mark.parametrize("version", [2, 3])
def test_nonadvancing_seal_refused_before_clock_or_signing(version, monkeypatch):
    clock, signer, _, _, signing, _, head, tree, mapping, _ = namespace_case()
    calls = clock.calls
    signed = []
    original = signer.sign
    def counted(body):
        signed.append(body)
        return original(body)
    monkeypatch.setattr(signer, "sign", counted)
    with pytest.raises(EvidenceError, match="must advance"):
        sign_namespace_head(version=version, tree_root=tree.root(version), map_root=mapping.root,
                            chain=head.chain, previous=head, consistency=(), **signing)
    assert clock.calls == calls and not signed


def test_namespace_document_requires_explicit_typed_signature_encoding():
    head = namespace_case()[6]
    document = json.loads(canonical_bytes(head.document()))
    document["signature"].pop("alg")  # Signature would otherwise silently fill the default.
    with pytest.raises(EvidenceError, match="representation"):
        NamespaceHead.from_document(document)
