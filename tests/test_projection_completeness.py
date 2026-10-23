"""Offline field accounting for signed snapshots; no authority or target effect."""

import copy
import hashlib
import json
from dataclasses import fields

import pytest
from securesystemslib.dsse import Envelope

from assurance_reference.projections import project, run
from regulated_core.models import Action, Annotation, ApprovalRequirement, Decision, DecisionRecord, PolicyRef
from regulated_core.signing import Ed25519Signer
from test_external_attestation import external_key
from test_projections import canonical, fixture_bundle


def complete_bundle():
    bundle = fixture_bundle()
    signer = Ed25519Signer("fixture:complete-records")
    bundle["public_keys"] = {signer.key_id: signer.public_key_bytes.hex()}
    previous = "0" * 64
    for seq, entry in enumerate(bundle["entries"]):
        record = entry["record"]
        record.update(record_id=f"record:{seq}", assertion_id="fixture:assertion",
                      assertion_digest="a" * 64, actor_id="fixture:requester",
                      purpose="fixture:projection", correlation_id="fixture:correlation",
                      action={"action_id": "fixture:release", "effect": "external", "destination": ""},
                      policy={"vertical": "education", "policy_id": "fixture:policy", "version": "1", "digest": "b" * 64})
        record["decision"].update(annotations=[{"kind": "fixture", "message": "synthetic only"}], approval=None)
        if seq == 0:
            record["decision"]["approval"] = {
                "role_groups": [["role:teacher"], ["role:head"]], "minimum_approvers": 2,
                "scope": "fixture:release", "reason": "dual review", "expires_after_us": 1000,
                "requester_may_approve": False,
            }
        entry["prev_hash"] = previous
        entry["record_hash"] = hashlib.sha256(canonical(record)).hexdigest()
        link = {key: entry[key] for key in ("seq", "prev_hash", "record_hash")}
        signature = signer.sign_bytes(canonical(dict(link, schema="regulated/evidence/v2", clock_domain=entry["domain"])))
        entry["signature"] = {"key_id": signature.key_id, "alg": signature.alg, "value": signature.value}
        previous = hashlib.sha256(canonical(dict(link, schema="regulated/evidence-chain/v2", clock_domain=entry["domain"]))).hexdigest()
    bundle["unknown/support~artifact"] = {"empty": [], "absent": None, "flag": False, "opaque": {}}
    return bundle


def project_complete(bundle, signer):
    return project(bundle, signer, complete=True, system_name="Synthetic reference", provider="Synthetic fixture")


def test_four_views_share_exact_source_and_field_inventory_without_authority_claims():
    bundle = complete_bundle()
    before = copy.deepcopy(bundle)
    signer = Ed25519Signer("fixture:report")
    views = project_complete(bundle, signer)
    assert set(views) == {"human", "audit", "regulator", "attestation"}
    parsed = Envelope.from_dict(copy.deepcopy(views["attestation"]))
    key = external_key(signer)
    assert parsed.verify([key], threshold=1) == {signer.key_id: key}
    predicate = json.loads(parsed.payload)["predicate"]
    assert predicate["source_bundle"] == before == bundle
    assert predicate["regulator"] == views["regulator"]
    assert predicate["audit"] == views["audit"]
    assert predicate["human_report_sha256"] == hashlib.sha256(views["human"].encode()).hexdigest()
    assert views["regulator"]["source_digest"] == views["audit"]["source_digest"]
    assert views["regulator"]["verified_chain_heads"] == views["audit"]["heads"]
    inventory = views["audit"]["field_inventory"]
    assert inventory == views["regulator"]["field_inventory"]
    pointers = {row["source_pointer"] for row in inventory}
    assert len(pointers) == len(inventory)
    assert "/unknown~1support~0artifact/empty" in pointers
    assert "/unknown~1support~0artifact/absent" in pointers
    assert "/unknown~1support~0artifact/opaque" in pointers
    # Independently resolve every pointer and reconstruct the expected leaf set.
    expected = set()
    def walk(value, prefix=""):
        if isinstance(value, dict) and value:
            for name, item in value.items():
                walk(item, prefix + "/" + name.replace("~", "~0").replace("/", "~1"))
        elif isinstance(value, list) and value:
            for number, item in enumerate(value):
                walk(item, prefix + "/" + str(number))
        else:
            expected.add(prefix)
    walk(bundle)
    assert pointers == expected
    for row in inventory:
        value = bundle
        for part in row["source_pointer"].split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            value = value[int(part)] if isinstance(value, list) else value[part]
        assert row["value_sha256"] == hashlib.sha256(canonical(value)).hexdigest()
    assert views["regulator"]["record_fields_complete"] is True
    assert views["regulator"]["application_evidence_complete"] is False
    assert "not established" in views["regulator"]["8_declaration_of_conformity"]["status"]
    assert "Approval required; this decision alone does not permit release" in views["human"]
    assert "Denied" in views["human"]
    assert "PERMITTED" not in views["human"]
    assert "no independent identity anchor" in views["human"]


REQUIRED = [(path, item.name) for path, model in (
    ((), DecisionRecord), (("action",), Action), (("policy",), PolicyRef),
    (("decision",), Decision), (("decision", "approval"), ApprovalRequirement),
    (("decision", "annotations", 0), Annotation)) for item in fields(model)]


class NoSigning:
    def sign_bytes(self, data):
        raise AssertionError("incomplete or invalid evidence must be refused before signing")


@pytest.mark.parametrize("path,missing", REQUIRED)
def test_each_required_record_field_is_refused_before_report_signing(path, missing):
    bundle = complete_bundle()
    value = bundle["entries"][0]["record"]
    for part in path:
        value = value[part]
    del value[missing]
    with pytest.raises(ValueError, match="required evidence fields missing"):
        project_complete(bundle, NoSigning())


@pytest.mark.parametrize("change", ["record", "chain", "signature"])
def test_complete_field_presence_does_not_bypass_chain_verification(change):
    bundle = complete_bundle()
    entry = bundle["entries"][0]
    if change == "record":
        entry["record"]["purpose"] = "fixture:changed"
    elif change == "chain":
        entry["prev_hash"] = "f" * 64
    else:
        entry["signature"]["value"] = "00" * 64
    with pytest.raises(ValueError):
        project_complete(bundle, NoSigning())


def test_missing_labels_or_approval_cannot_produce_complete_view(tmp_path):
    bundle = complete_bundle()
    with pytest.raises(ValueError, match="labels required"):
        project(bundle, NoSigning(), complete=True)
    bundle["entries"][0]["record"]["decision"]["approval"] = None
    source = tmp_path / "source.json"
    source.write_bytes(canonical(bundle))
    output = tmp_path / "views"
    with pytest.raises(ValueError, match="required evidence object missing"):
        run(source, output, complete=True, system_name="fixture", provider="fixture")
    assert not output.exists()


def test_complete_file_export_preserves_bytes_and_writes_all_views(tmp_path):
    source = tmp_path / "source.json"
    raw = json.dumps(complete_bundle(), indent=3).encode() + b"\n"
    source.write_bytes(raw)
    output = tmp_path / "views"
    run(source, output, complete=True, system_name="fixture", provider="fixture")
    assert (output / "source-evidence.json").read_bytes() == raw
    envelope = json.loads((output / "attestation.dsse.json").read_bytes())
    predicate = json.loads(Envelope.from_dict(copy.deepcopy(envelope)).payload)["predicate"]
    assert json.loads((output / "regulator.json").read_bytes()) == predicate["regulator"]
    assert json.loads((output / "audit.json").read_bytes()) == predicate["audit"]
    assert hashlib.sha256((output / "reader.md").read_bytes()).hexdigest() == predicate["human_report_sha256"]


@pytest.mark.parametrize("complete", [False, True])
def test_local_education_export_uses_its_original_chain_field(complete):
    bundle = complete_bundle()
    bundle["schema"] = "reference/local-education-example/v1"
    bundle["chain"] = bundle.pop("entries")
    before = copy.deepcopy(bundle)
    views = project(bundle, Ed25519Signer("fixture:report"), complete=complete,
                    system_name="fixture", provider="fixture")
    predicate = json.loads(Envelope.from_dict(copy.deepcopy(views["attestation"])).payload)["predicate"]
    assert predicate["source_bundle"] == before == bundle
    assert views["audit"]["heads"][0]["source"] == "chain"
    assert views["audit"]["trace"][0]["source"] == "chain[0]"
    if complete:
        assert views["regulator"]["2_detailed_description"][0]["source_pointer"] == "/chain/0/record"
        assert any(row["source_pointer"] == "/chain/0/record/record_id"
                   for row in views["audit"]["field_inventory"])


@pytest.mark.parametrize("layout", ["ambiguous", "unknown"])
def test_ambiguous_or_undeclared_chain_layout_refuses_before_signing(layout):
    bundle = complete_bundle()
    bundle["chain"] = copy.deepcopy(bundle["entries"])
    bundle["schema"] = "reference/local-education-example/v1"
    if layout == "unknown":
        del bundle["entries"]
        bundle["schema"] = "unknown:layout"
    with pytest.raises(ValueError, match="evidence chain"):
        project_complete(bundle, NoSigning())
