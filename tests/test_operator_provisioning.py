"""Synthetic intact local operator contracts; no hosted IAM equivalence."""
from dataclasses import asdict, replace
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from assurance_reference.operator_provisioning import (
    OperatorScope, PinnedAuthority, ProvisioningStopped, provision_pinned_authorities,
)
from factory.education_workbench.service import WorkbenchError
from factory.packs.collections import InMemoryPackCollectionStore
from factory.packs.examples import build_education_pack
from factory.packs.registry import PackRegistry
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer, TrustDirectory


class ObservedStore(InMemoryPackCollectionStore):
    def __init__(self):
        super().__init__()
        self.writes = 0
        self.fail_on = None
        self.bad_readback = False

    def put(self, *args, **kwargs):
        self.writes += 1
        if self.writes == self.fail_on:
            raise RuntimeError("synthetic private store failure")
        return super().put(*args, **kwargs)

    def get(self, *args, **kwargs):
        row = super().get(*args, **kwargs)
        if self.bad_readback and row is not None:
            return replace(row, version=row.version + 1)
        return row


@pytest.fixture
def host(tmp_path):
    now = 1_789_056_000_000_000
    trust = TrustDirectory()
    publisher = Ed25519Signer("synthetic:publisher")
    authority = Ed25519Signer("synthetic:school")
    other = Ed25519Signer("synthetic:other-school")
    for signer in (publisher, authority, other):
        trust.register_signer(signer)
    store = ObservedStore()
    root = tmp_path / "pack"
    manifest = build_education_pack(root, publisher=publisher, rulebook_authority=authority)
    registry = PackRegistry(trust=trust, collections=store)
    registry.install(root, publisher_key_id=publisher.key_id, today="2026-09-10")
    registry.activate(manifest.reference, at="2026-09-10T00:00:00Z")
    scope = OperatorScope("synthetic-tenant", "synthetic-school", "synthetic-class",
                          manifest.reference, authority.key_id, authority.key_id)
    docs = {}
    principals = {"teacher": "synthetic-teacher", "student": "synthetic-learner",
                  "head-of-department": "synthetic-reviewer"}
    for role, principal in principals.items():
        content = {"tenant_id": scope.tenant, "class_id": scope.class_id, "role": role,
                   "principal": principal, "status": "active",
                   "given_name": "Synthetic", "family_name": role}
        if role == "head-of-department":
            content.update(school_id=scope.school, owner_approval_ref="synthetic-approval")
        docs[role] = document_policy(
            authority, vertical="education",
            policy_id=("school-reviewer-appointment" if role == "head-of-department"
                       else "school-enrollment"),
            version="1", content=content, jurisdictions=(),
            effective_from_us=now - 10, effective_until_us=now + 1_000_000,
        )
    paths = {}
    def pins():
        result = []
        for role, doc in docs.items():
            path = tmp_path / (role + ".json")
            raw = (json.dumps(asdict(doc), sort_keys=True) + "\n").encode()
            path.write_bytes(raw)
            paths[role] = path
            result.append(PinnedAuthority(role, principals[role], path,
                                          sha256(raw).hexdigest(), doc.digest()))
        return result
    checks = []
    members = set(principals.values())
    def member(tenant, principal):
        checks.append((tenant, principal, store.writes))
        return tenant == scope.tenant and principal in members
    def run(**kwargs):
        selected = kwargs.pop("pins", None)
        if selected is None:
            selected = pins()
        return provision_pinned_authorities(
            registry, store, trust, member, scope=kwargs.pop("scope", scope),
            pins=selected, now_us=kwargs.pop("now_us", now), **kwargs)
    return SimpleNamespace(run=run, scope=scope, docs=docs, pins=pins, paths=paths,
                           store=store, checks=checks, members=members, other=other, authority=authority, now=now)


def test_default_preflight_checks_all_members_without_writes(host):
    result = host.run()
    assert result["status"] == "preflight-clear"
    assert host.store.writes == 0
    assert len(host.checks) == 3 and all(item[2] == 0 for item in host.checks)
    assert result["authorities"] == []


def test_explicit_execution_reads_back_three_exact_signed_authorities(host):
    result = host.run(execute=True)
    assert result["status"] == "provisioned-and-read-back"
    assert host.store.writes == 3
    assert len(result["authorities"]) == 3
    assert all(item[2] == 0 for item in host.checks)
    for item in result["authorities"]:
        assert item["digest"] == host.docs[item["role"]].digest()
        assert item["revision"] == 1


@pytest.mark.parametrize("change", ["expired", "future", "unsigned", "other-authority",
                                   "wrong-tenant", "wrong-school"])
def test_invalid_last_document_is_refused_before_any_write(host, change):
    role = "head-of-department"
    doc = host.docs[role]
    if change == "unsigned":
        host.docs[role] = replace(doc, signature=replace(doc.signature, value=""))
    else:
        content = dict(doc.content)
        if change == "wrong-tenant":
            content["tenant_id"] = "another-tenant"
        if change == "wrong-school":
            content["school_id"] = "another-school"
        host.docs[role] = document_policy(
            host.other if change == "other-authority" else host.authority,
            vertical=doc.vertical, policy_id=doc.policy_id, version=doc.version,
            content=content, jurisdictions=(),
            effective_from_us=(host.now + 1 if change == "future"
                               else doc.effective_from_us),
            effective_until_us=(host.now if change == "expired"
                                else doc.effective_until_us))
    with pytest.raises((ValueError, WorkbenchError)):
        host.run(execute=True)
    assert host.store.writes == 0


@pytest.mark.parametrize("pin_kind", ["file", "document", "principal", "pack"])
def test_explicit_pins_fail_before_writes(host, pin_kind):
    pins = host.pins()
    scope = host.scope
    if pin_kind == "file":
        pins[-1] = replace(pins[-1], file_sha256="0" * 64)
    elif pin_kind == "document":
        pins[-1] = replace(pins[-1], document_digest="0" * 64)
    elif pin_kind == "principal":
        pins[-1] = replace(pins[-1], principal="operator-key")
    else:
        scope = replace(scope, pack_reference=scope.pack_reference + "-other")
    with pytest.raises(ValueError):
        host.run(pins=pins, scope=scope, execute=True)
    assert host.store.writes == 0


def test_unknown_last_individual_refuses_whole_preflight(host):
    host.members.remove("synthetic-reviewer")
    with pytest.raises(ValueError, match="membership"):
        host.run(execute=True)
    assert host.store.writes == 0
    assert len(host.checks) == 3


def test_partial_write_receipt_preserves_completed_readback_and_requires_inspection(host):
    host.store.fail_on = 2
    with pytest.raises(ProvisioningStopped) as caught:
        host.run(execute=True)
    receipt = caught.value.receipt
    assert receipt["status"] == "stopped-inspect-state" and receipt["retry"] is False
    assert receipt["attempted_role"] == "student"
    assert receipt["attempted_write_outcome"] == "inspect-state"
    assert len(receipt["authorities"]) == 1
    assert receipt["authorities"][0]["role"] == "teacher"
    assert "synthetic private store failure" not in json.dumps(receipt)
    assert host.store.writes == 2


def test_readback_mismatch_stops_before_next_write(host):
    host.store.bad_readback = True
    with pytest.raises(ProvisioningStopped) as caught:
        host.run(execute=True)
    assert host.store.writes == 1
    assert caught.value.receipt["authorities"] == []
    assert caught.value.receipt["attempted_role"] == "teacher"


def test_exact_signed_replay_retains_revisions_without_extra_writes(host):
    host.run(execute=True)
    again = host.run(execute=True)
    assert host.store.writes == 3
    assert [item["revision"] for item in again["authorities"]] == [1, 1, 1]


def test_execution_choice_must_be_boolean(host):
    with pytest.raises(ValueError):
        host.run(execute="yes")
    assert host.store.writes == 0
