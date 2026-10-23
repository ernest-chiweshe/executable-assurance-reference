"""Protected tenant evidence-history configuration for the reference host."""

from __future__ import annotations

from dataclasses import asdict
import json

import pytest

from assurance_reference.pinned_histories import (
    PINNED_HISTORY_SCHEMA,
    PinnedHistoryConfigError,
    load_pinned_histories,
)
from regulated_core.evidence import GENESIS
from regulated_core.evidence_checkpoints_pg import Checkpoint
from regulated_core.signing import Ed25519Signer, TrustDirectory


PROFILE = "fixture-authority-v1"


def _trust(*signers):
    trust = TrustDirectory()
    for signer in signers:
        trust.register_signer(signer)
    return trust


def _checkpoint(signer, tenant="tenant-a"):
    body = {
        "schema": "regulated/evidence-checkpoint/v1",
        "tenant": tenant,
        "from_seq": 0,
        "to_seq": 0,
        "previous_digest": GENESIS,
        "last_entry_hash": "a" * 64,
        "profile": PROFILE,
    }
    return Checkpoint(
        tenant=tenant,
        from_seq=0,
        to_seq=0,
        previous_digest=GENESIS,
        last_entry_hash="a" * 64,
        profile=PROFILE,
        signature=signer.sign(body),
    )


def _checkpoint_json(checkpoint):
    return {
        **checkpoint.body(),
        "signature": asdict(checkpoint.signature),
    }


def _catalog(current, *, tenants=None, keys=None, bound=32):
    return {
        "schema": PINNED_HISTORY_SCHEMA,
        "profile": PROFILE,
        "current_evidence_key_id": current,
        "evidence_key_ids": keys or [current],
        "max_entries": bound,
        "tenants": tenants
        or [{"tenant_id": "tenant-a", "checkpoints": [], "head_digest": GENESIS}],
    }


def _write(tmp_path, value):
    path = tmp_path / "pinned-evidence-history.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _load(path, trust, current, keys=None):
    return load_pinned_histories(
        path,
        profile=PROFILE,
        trust=trust,
        expected_current_key_id=current,
        expected_evidence_key_ids=keys or frozenset({current}),
    )


def test_relative_catalog_path_refuses(tmp_path, monkeypatch) -> None:
    signer = Ed25519Signer("evidence:current")
    trust = _trust(signer)
    relative = _write(tmp_path, _catalog(signer.key_id)).name
    monkeypatch.chdir(tmp_path)
    with pytest.raises(PinnedHistoryConfigError, match="absolute path"):
        _load(relative, trust, signer.key_id)


def test_exact_empty_history_binds_one_tenant(tmp_path) -> None:
    signer = Ed25519Signer("evidence:current")
    trust = _trust(signer)
    histories = _load(
        _write(tmp_path, _catalog(signer.key_id)), trust, signer.key_id,
    )
    assert histories is not None
    verifier = histories.for_tenant("tenant-a")
    assert verifier.history.tenant == "tenant-a"
    assert verifier.history.head_digest == GENESIS
    assert verifier.current_key == signer.key_id
    assert verifier.max_entries == 32
    with pytest.raises(PinnedHistoryConfigError, match="not configured"):
        histories.for_tenant("tenant-b")


def test_signed_checkpoint_and_retained_key_domain_are_validated(tmp_path) -> None:
    old = Ed25519Signer("evidence:old")
    current = Ed25519Signer("evidence:current")
    trust = _trust(old, current)
    checkpoint = _checkpoint(old)
    tenants = [{
        "tenant_id": "tenant-a",
        "checkpoints": [_checkpoint_json(checkpoint)],
        "head_digest": checkpoint.digest(),
    }]
    keys = frozenset({old.key_id, current.key_id})
    histories = _load(
        _write(
            tmp_path,
            _catalog(current.key_id, tenants=tenants, keys=sorted(keys)),
        ),
        trust,
        current.key_id,
        keys,
    )
    assert histories is not None
    verifier = histories.for_tenant("tenant-a")
    assert verifier.history.checkpoints == (checkpoint,)
    assert verifier.evidence_key_ids == keys


@pytest.mark.parametrize(
    "change",
    ["wrong-current", "wrong-keys", "duplicate-tenant", "extra-field", "unbounded"],
)
def test_catalog_must_match_managed_host_and_exact_shape(tmp_path, change) -> None:
    current = Ed25519Signer("evidence:current")
    other = Ed25519Signer("evidence:other")
    trust = _trust(current, other)
    raw = _catalog(current.key_id)
    if change == "wrong-current":
        raw["current_evidence_key_id"] = other.key_id
    elif change == "wrong-keys":
        raw["evidence_key_ids"] = [current.key_id, other.key_id]
    elif change == "duplicate-tenant":
        raw["tenants"] = [*raw["tenants"], dict(raw["tenants"][0])]
    elif change == "extra-field":
        raw["unexpected"] = True
    else:
        raw["max_entries"] = 4_097
    with pytest.raises(PinnedHistoryConfigError):
        _load(_write(tmp_path, raw), trust, current.key_id)


@pytest.mark.parametrize("change", ["head", "signature", "tenant", "profile"])
def test_altered_checkpoint_history_refuses(tmp_path, change) -> None:
    signer = Ed25519Signer("evidence:current")
    trust = _trust(signer)
    checkpoint = _checkpoint(signer)
    encoded = _checkpoint_json(checkpoint)
    head = checkpoint.digest()
    if change == "head":
        head = "b" * 64
    elif change == "signature":
        encoded["last_entry_hash"] = "b" * 64
    elif change == "tenant":
        encoded["tenant"] = "tenant-b"
    else:
        encoded["profile"] = "other"
    raw = _catalog(
        signer.key_id,
        tenants=[{
            "tenant_id": "tenant-a",
            "checkpoints": [encoded],
            "head_digest": head,
        }],
    )
    with pytest.raises(PinnedHistoryConfigError, match="failed validation"):
        _load(_write(tmp_path, raw), trust, signer.key_id)


def test_duplicate_json_field_refuses(tmp_path) -> None:
    signer = Ed25519Signer("evidence:current")
    trust = _trust(signer)
    path = tmp_path / "pinned-evidence-history.json"
    path.write_text(
        '{"schema":"reference/pinned-evidence-histories/v1",'
        '"schema":"reference/pinned-evidence-histories/v1"}',
        encoding="utf-8",
    )
    with pytest.raises(PinnedHistoryConfigError, match="duplicate field"):
        _load(path, trust, signer.key_id)


def test_one_verifier_per_tenant_and_catalog_snapshot_survives_file_change(tmp_path):
    signer = Ed25519Signer("evidence:current")
    trust = _trust(signer)
    path = _write(tmp_path, _catalog(signer.key_id, tenants=[
        {"tenant_id": tenant, "checkpoints": [], "head_digest": GENESIS}
        for tenant in ("tenant-a", "tenant-b")]))
    histories = _load(path, trust, signer.key_id)
    a = histories.for_tenant("tenant-a")
    assert histories.for_tenant("tenant-a") is a
    assert histories.for_tenant("tenant-b") is not a
    path.write_text("{}", encoding="utf-8")
    assert histories.for_tenant("tenant-a") is a
    with pytest.raises(PinnedHistoryConfigError):
        _load(path, trust, signer.key_id)


def test_profile_is_selected_by_host_not_catalog(tmp_path):
    signer = Ed25519Signer("evidence:current")
    raw = _catalog(signer.key_id)
    raw["profile"] = "request-chosen-profile"
    with pytest.raises(PinnedHistoryConfigError, match="managed host"):
        _load(_write(tmp_path, raw), _trust(signer), signer.key_id)


@pytest.mark.parametrize("bound", [True, 0, -1, 1.5])
def test_invalid_numeric_bound_refuses(tmp_path, bound):
    signer = Ed25519Signer("evidence:current")
    with pytest.raises(PinnedHistoryConfigError, match="bound"):
        _load(_write(tmp_path, _catalog(signer.key_id, bound=bound)), _trust(signer), signer.key_id)


def test_catalog_byte_limit_is_enforced(tmp_path):
    signer = Ed25519Signer("evidence:current")
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * 1_048_577)
    with pytest.raises(PinnedHistoryConfigError, match="bounded file"):
        _load(path, _trust(signer), signer.key_id)


def test_unknown_evidence_key_refuses_before_loading(tmp_path):
    signer = Ed25519Signer("evidence:untrusted")
    with pytest.raises(PinnedHistoryConfigError, match="key configuration"):
        _load(_write(tmp_path, _catalog(signer.key_id)), TrustDirectory(), signer.key_id)


@pytest.mark.parametrize("shape", ["extra", "missing"])
def test_tenant_entry_requires_exact_field_set(tmp_path, shape):
    signer = Ed25519Signer("evidence:current")
    raw = _catalog(signer.key_id)
    entry = raw["tenants"][0]
    if shape == "extra":
        entry["unexpected"] = True
    else:
        del entry["checkpoints"]
    with pytest.raises(PinnedHistoryConfigError, match="tenant evidence history.*shape"):
        _load(_write(tmp_path, raw), _trust(signer), signer.key_id)


def test_checkpoint_requires_exact_field_set(tmp_path):
    signer = Ed25519Signer("evidence:current")
    checkpoint = _checkpoint(signer)
    encoded = {**_checkpoint_json(checkpoint), "unexpected": True}
    raw = _catalog(signer.key_id, tenants=[{
        "tenant_id": "tenant-a",
        "checkpoints": [encoded],
        "head_digest": checkpoint.digest(),
    }])
    with pytest.raises(PinnedHistoryConfigError, match="checkpoint.*shape"):
        _load(_write(tmp_path, raw), _trust(signer), signer.key_id)
