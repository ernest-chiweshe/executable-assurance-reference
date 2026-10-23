"""Synthetic host-custody contracts; no release or external evidence store."""

from dataclasses import replace
from hashlib import sha1, sha256
import json
from pathlib import Path

import pytest

from assurance_reference.current_evidence import CurrentSnapshotVerifier
from factory.packs.demonstration_checks import EvidenceSnapshot
from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome


USES = frozenset({"education", "health", "product_spec"})


def snapshot():
    return EvidenceSnapshot(
        "tenant-a", "fictional-case", "1", "Fictional evidence",
        (("source", "edition-1", "Fictional supported statement."),),
        (("source", "Fictional supported statement."),),
        ("Synthetic evidence only; no qualification claim.",), 100, 200,
    )


class ObservedEvidence:
    def __init__(self, value):
        self.value, self.calls = value, []

    def current(self, tenant, use, case_id):
        self.calls.append((tenant, use, case_id))
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


@pytest.mark.parametrize("use", sorted(USES))
def test_each_use_reads_current_host_revision_and_never_reuses_an_accepted_snapshot(use):
    original = snapshot()
    source = ObservedEvidence(original)
    verifier = CurrentSnapshotVerifier(source, use, allowed_uses=USES)
    context = EmissionContext(tenant="tenant-a", actor_id="host-authenticated", now_us=150)
    assert verifier.verify_context(original.render(), original.contract(), context) == (Outcome.PASS, ())
    current = replace(original, revision="2")
    source.value = current
    assert verifier.verify_context(original.render(), original.contract(), context)[0] is Outcome.FAIL
    assert verifier.verify_context(current.render(), current.contract(), context) == (Outcome.PASS, ())
    source.value = None
    assert verifier.verify_context(current.render(), current.contract(), context)[0] is Outcome.FAIL
    assert source.calls == [("tenant-a", use, "fictional-case")] * 4


@pytest.mark.parametrize("observation", ["missing", "degraded", "tenant", "case"])
def test_unavailable_or_misbound_host_evidence_never_falls_back_to_contract(observation):
    original = snapshot()
    values = {"missing": None, "degraded": RuntimeError("synthetic unavailable"),
              "tenant": replace(original, tenant="tenant-b"),
              "case": replace(original, case_id="other-fictional-case")}
    source = ObservedEvidence(values[observation])
    verifier = CurrentSnapshotVerifier(source, "education", allowed_uses=USES)
    context = EmissionContext(tenant="tenant-a", actor_id="host-authenticated", now_us=150)
    assert verifier.verify_context(original.render(), original.contract(), context)[0] is Outcome.FAIL
    assert source.calls == [("tenant-a", "education", "fictional-case")]


def test_absent_context_does_not_read_host_and_request_tenant_does_not_select_custody():
    original = snapshot()
    source = ObservedEvidence(original)
    verifier = CurrentSnapshotVerifier(source, "health", allowed_uses=USES)
    contract = {**original.contract(), "tenant": "tenant-b"}
    assert verifier.verify_context(original.render(), contract, None)[0] is Outcome.FAIL
    assert source.calls == []
    context = EmissionContext(tenant="tenant-a", actor_id="host-authenticated", now_us=150)
    assert verifier.verify_context(original.render(), contract, context) == (Outcome.PASS, ())
    assert source.calls == [("tenant-a", "health", "fictional-case")]


@pytest.mark.parametrize("case_id", [None, "", " ", 1])
def test_invalid_case_never_reaches_host(case_id):
    original = snapshot()
    source = ObservedEvidence(original)
    verifier = CurrentSnapshotVerifier(source, "education", allowed_uses=USES)
    context = EmissionContext(tenant="tenant-a", actor_id="host-authenticated", now_us=150)
    assert verifier.verify_context(original.render(), {**original.contract(), "case_id": case_id}, context)[0] is Outcome.FAIL
    assert source.calls == []


@pytest.mark.parametrize("use,allowed", [("unknown", USES), ("education", frozenset()),
                                       ("education", {"education"}),
                                       ("education", frozenset({"education", ""}))])
def test_composition_requires_explicit_valid_host_use(use, allowed):
    with pytest.raises(ValueError):
        CurrentSnapshotVerifier(ObservedEvidence(snapshot()), use, allowed_uses=allowed)


def test_composition_requires_host_reader():
    with pytest.raises(ValueError):
        CurrentSnapshotVerifier(None, "education", allowed_uses=USES)


def test_derivation_preserves_pinned_original_and_identifies_the_new_wrapper():
    root = Path(__file__).resolve().parents[1]
    record = json.loads((root / "docs/provenance/current-evidence/derivation.json").read_bytes())
    raw = (root / record["retained_original"]).read_bytes()
    assert sha256(raw).hexdigest() == record["source_sha256"]
    assert sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == record["source_git_blob"]
    assert record["source_git_blob"] == "bd88829b5dbd35e8801b1c9897b34c55bfabc7db"
    assert sha256((root / record["derived_path"]).read_bytes()).hexdigest() == record["derived_sha256"]
