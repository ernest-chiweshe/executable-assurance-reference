"""CORE009-v2 policy-overlap regressions; intact runtime, no database or guard removal.

Derived from the independently reported coverage gap and supplemental cases.
Positive controls distinguish policy rejection from an invalid fixture.
"""
import pytest

from assurance_reference.protected_head import FileProtectedHeadStore, FileNamespaceHeadStore
from regulated_core.evidence import GENESIS
from regulated_core.evidence_key_policy import valid_policy, key_allowed, copy_retirements
from regulated_core.evidence_map import EMPTY
from regulated_core.evidence_service import EvidenceError, MemoryEvidenceService, sign_head, verify_head
from regulated_core.evidence_service_pg import PostgresEvidenceService
from regulated_core.evidence_namespace import sign_namespace_head, verify_namespace_head
from regulated_core.merkle import EMPTY_ROOT, MAX_SIZE
from test_evidence_service_formats import case
from test_evidence_namespace_core import namespace_case, publication_args


def overlap(key):
    return {key: {"retired_after_size": 0}}


@pytest.mark.parametrize("size", [0, 1, MAX_SIZE])
def test_policy_helpers_reject_overlap_at_and_beyond_cutoff(size):
    active = frozenset({"key"})
    retired = overlap("key")
    assert valid_policy(active, {})
    assert key_allowed("key", size, active, {})
    assert not valid_policy(active, retired)
    assert not key_allowed("key", size, active, retired)
    with pytest.raises(ValueError):
        copy_retirements(active, retired)


def test_evidence_head_verification_rejects_overlap(case):
    clock, signer, _, trust, keys, _, heads, _ = case
    args = dict(tenant="tenant", clock_domain=clock.domain, trust=trust, allowed_keys=keys)
    assert verify_head(heads[-1], **args)
    assert not verify_head(heads[-1], **args, historical_keys=overlap(signer.key_id))


def test_evidence_signing_rejects_overlap_before_clock_read(case):
    clock, signer, _, trust, keys, *_ = case
    args = dict(tenant="tenant", tree_size=0, tree_root=EMPTY_ROOT, map_root=EMPTY[0],
                last_entry_hash=GENESIS, previous=None, signer=signer, clock=clock,
                trust=trust, signing_keys=keys)
    signed = sign_head(**args, historical_keys={})
    assert verify_head(signed, tenant="tenant", clock_domain=clock.domain, trust=trust, allowed_keys=keys)
    calls = clock.calls
    with pytest.raises(EvidenceError):
        sign_head(**args, historical_keys=overlap(signer.key_id))
    assert clock.calls == calls


@pytest.mark.parametrize("service_type", [MemoryEvidenceService, PostgresEvidenceService])
def test_service_constructors_reject_overlap_without_database(case, service_type):
    clock, signer, _, trust, keys, *_ = case
    args = dict(tenant="tenant", signer=signer, clock=clock, trust=trust, signing_keys=keys,
                envelope_keys_allowed=keys, envelope_domains=frozenset({clock.domain}))
    assert service_type(**args, historical_head_keys={}).signing_keys == keys
    with pytest.raises(EvidenceError):
        service_type(**args, historical_head_keys=overlap(signer.key_id))


def test_evidence_protected_store_rejects_overlap(tmp_path, case):
    clock, signer, _, trust, keys, *_ = case
    args = dict(tenant="tenant", clock_domain=clock.domain, trust=trust, advancing_heads=keys)
    assert FileProtectedHeadStore(tmp_path, **args, existing_heads={}).advancing_heads == keys
    with pytest.raises(EvidenceError):
        FileProtectedHeadStore(tmp_path, **args, existing_heads=overlap(signer.key_id))


@pytest.mark.parametrize("scope_type", ["tenant", "installation"])
def test_namespace_verification_rejects_overlap(scope_type):
    _, signer, _, args, _, _, head, *_ = namespace_case(scope_type)
    assert verify_namespace_head(head, **args)
    assert not verify_namespace_head(head, **args, historical_keys=overlap(signer.key_id))


@pytest.mark.parametrize("scope_type", ["tenant", "installation"])
def test_namespace_signing_rejects_overlap_before_clock_read(scope_type):
    clock, signer, _, args, signing, *_ = namespace_case(scope_type)
    fields = dict(version=0, tree_root=EMPTY_ROOT, map_root=EMPTY[0], chain=GENESIS,
                  previous=None, consistency=())
    signed = sign_namespace_head(**fields, **signing)
    assert verify_namespace_head(signed, **args)
    calls = clock.calls
    with pytest.raises(EvidenceError):
        sign_namespace_head(**fields, **(signing | {"historical_keys": overlap(signer.key_id)}))
    assert clock.calls == calls


@pytest.mark.parametrize("scope_type", ["tenant", "installation"])
def test_namespace_protected_store_rejects_overlap(tmp_path, scope_type):
    _, signer, _, args, *_ = namespace_case(scope_type)
    settings = publication_args(args)
    assert FileNamespaceHeadStore(tmp_path, **settings).advancing_heads == args["allowed_keys"]
    with pytest.raises(EvidenceError):
        FileNamespaceHeadStore(tmp_path, **(settings | {"existing_heads": overlap(signer.key_id)}))
