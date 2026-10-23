"""X-17 signed enrollment with an explicit local memory-store boundary.

These are operator-contract tests, not durable-store or production enrollment
claims. Existing restricted PostgreSQL tests qualify the separate storage path.
"""

from types import SimpleNamespace

import pytest

from factory.education_workbench.provisioning import provision_enrollment
from factory.education_workbench.service import WorkbenchError
from factory.packs.collections import CollectionConflict, InMemoryPackCollectionStore
from factory.packs.examples import EDUCATION_ID, build_education_pack
from factory.packs.registry import PackRegistry
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer, TrustDirectory


@pytest.fixture
def enrollment(tmp_path):
    return build_enrollment(tmp_path, InMemoryPackCollectionStore())


def build_enrollment(tmp_path, store):
    """Share the exact signed operator contract across explicit storage drivers."""
    now = 1_789_056_000_000_000
    trust = TrustDirectory()
    keys = {name: Ed25519Signer("fictional-enrollment:" + name)
            for name in ("publisher", "school", "other-school")}
    for key in keys.values():
        trust.register_signer(key)
    root = tmp_path / "pack"
    manifest = build_education_pack(root, publisher=keys["publisher"], rulebook_authority=keys["school"])
    registry = PackRegistry(trust=trust, collections=store)
    registry.install(root, publisher_key_id=keys["publisher"].key_id, today="2026-09-10")
    registry.activate(manifest.reference, at="2026-09-10T00:00:00Z")

    def document(version, *, signer="school", status="active", start=None, end=None):
        return document_policy(keys[signer], vertical="education", policy_id="school-enrollment",
            version=str(version), content={"tenant_id": "fictional-school", "principal": "teacher",
                "class_id": "class-a", "role": "teacher", "status": status,
                "given_name": "Fictional", "family_name": "Teacher"}, jurisdictions=(),
            effective_from_us=now - 10 if start is None else start,
            effective_until_us=now + 1_000_000 if end is None else end)

    def apply(document, expected_revision=None):
        return provision_enrollment(registry, store, document, trust=trust,
            school_authority=keys["school"].key_id, now_us=now, expected_revision=expected_revision)

    return SimpleNamespace(document=document, apply=apply, store=store, now=now)


def test_exact_signed_replay_is_idempotent_and_newer_revocation_advances(enrollment):
    e = enrollment
    signed = e.document(1)
    first = e.apply(signed)
    assert first.version == 1 and first.payload["enrollmentGeneration"] == 1
    assert first.payload["enrollmentDocumentDigest"] == signed.digest()
    assert e.apply(signed, expected_revision=1) == first
    revoked = e.document(2, status="tobedeleted")
    second = e.apply(revoked, expected_revision=1)
    assert second.version == 2 and second.payload["enrollmentGeneration"] == 2
    assert second.payload["status"] == "tobedeleted"
    assert e.apply(revoked, expected_revision=1) == second
    with pytest.raises(WorkbenchError, match="older signed enrollment"):
        e.apply(signed, expected_revision=2)
    assert e.store.get(EDUCATION_ID, second.collection, second.tenant_id, second.key) == second


@pytest.mark.parametrize("change", ["wrong-school", "expired", "future", "same-generation", "older-effective-time"])
def test_untrusted_stale_or_nonmonotonic_enrollment_preserves_current_state(enrollment, change):
    e = enrollment
    first = e.apply(e.document(1))
    options = {"wrong-school": {"signer": "other-school"},
               "expired": {"end": e.now}, "future": {"start": e.now + 1},
               "same-generation": {"status": "tobedeleted"},
               "older-effective-time": {"start": e.now - 11}}[change]
    candidate = e.document(1 if change == "same-generation" else 2, **options)
    with pytest.raises(WorkbenchError):
        e.apply(candidate, expected_revision=1)
    assert e.store.get(EDUCATION_ID, first.collection, first.tenant_id, first.key) == first


def test_stale_compare_and_swap_cannot_overwrite_a_newer_operator_write(enrollment):
    e = enrollment
    initial = e.apply(e.document(1))
    # Two operators observed the same revision. The second applies after the
    # first has committed: a deterministic stale-CAS interleaving, not a stress test.
    first_expected = second_expected = initial.version
    winner = e.apply(e.document(2, status="tobedeleted"), expected_revision=first_expected)
    with pytest.raises(CollectionConflict):
        e.apply(e.document(3), expected_revision=second_expected)
    assert e.store.get(EDUCATION_ID, winner.collection, winner.tenant_id, winner.key) == winner
