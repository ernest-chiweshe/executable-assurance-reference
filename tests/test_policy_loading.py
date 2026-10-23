"""Offline intact synthetic policy-file contracts; no production identities."""
import json
from dataclasses import replace

import pytest

from assurance_reference.policy_loading import (
    ContentIdentity,
    HistoricalPolicyObservation,
    PolicyFileLoader,
    PolicyLoadRefused,
    observe_historical_policy,
    public_trust_from_file,
)
from regulated_core.canonical import digest_hex
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer

START, END = 1_000_000, 2_000_000


def identity(content):
    # Synthetic application semantics intentionally exclude current staff.
    return ContentIdentity(digest_hex(content["promises"]), content["version"])


def write_document(path, document):
    path.write_text(json.dumps({
        **document.signed_body(),
        "signature": {"key_id": document.signature.key_id,
                      "value": document.signature.value, "alg": document.signature.alg},
        "digest": document.digest(),
    }), encoding="utf-8")


@pytest.fixture
def fixture(tmp_path):
    signer = Ed25519Signer("fixture:x11-policy-authority")
    trust_path = tmp_path / "external-public-trust.json"
    trust_path.write_text(json.dumps({
        "schema": "care/trust-keys/v1",
        "keys": [{"key_id": signer.key_id, "public_key_hex": signer.public_key_bytes.hex(),
                  "alg": signer.alg}],
    }), encoding="utf-8")
    document = document_policy(
        signer, vertical="synthetic-support", policy_id="routing", version="v1",
        content={"version": "v1", "promises": {"hours": 9}, "staff": ["fixture:historical-staff"]},
        jurisdictions=("synthetic",), effective_from_us=START, effective_until_us=END)
    path = tmp_path / "policy.json"
    write_document(path, document)
    loader = PolicyFileLoader(trust_path, "synthetic-support", "routing", signer.key_id)
    return tmp_path, signer, path, document, loader


@pytest.mark.parametrize("at", [START, END - 1])
def test_verified_document_at_effective_boundaries(fixture, at):
    _, _, path, document, loader = fixture
    loaded = loader.load(path, at_us=at, document_digest=document.digest())
    assert loaded == document


@pytest.mark.parametrize("at", [START - 1, END])
def test_outside_effective_window_is_refused(fixture, at):
    _, _, path, _, loader = fixture
    with pytest.raises(PolicyLoadRefused, match="effective window"):
        loader.load(path, at_us=at)


@pytest.mark.parametrize("field,value", [
    ("vertical", "other-vertical"), ("policy_id", "other-policy"),
    ("authority", "fixture:other-authority"),
])
def test_host_identity_is_required(fixture, field, value):
    _, _, path, _, loader = fixture
    with pytest.raises(PolicyLoadRefused):
        replace(loader, **{field: value}).load(path, at_us=START)


def test_external_trust_must_know_signer(fixture):
    root, _, path, _, loader = fixture
    other = Ed25519Signer("fixture:separate-public-root")
    trust = root / "other-public-trust.json"
    trust.write_text(json.dumps({
        "schema": "care/trust-keys/v1",
        "keys": [{"key_id": other.key_id, "public_key_hex": other.public_key_bytes.hex()}],
    }), encoding="utf-8")
    with pytest.raises(PolicyLoadRefused, match="not trusted"):
        replace(loader, trust_path=trust).load(path, at_us=START)


def test_document_pin_is_separate_from_content_pin(fixture):
    _, _, path, document, loader = fixture
    content_pin = identity(document.content).digest
    assert content_pin != document.digest()
    with pytest.raises(PolicyLoadRefused, match="host pin"):
        loader.load(path, at_us=START, document_digest=content_pin)


def test_historical_lookup_uses_recorded_time_and_content_identity(fixture):
    root, _, _, document, loader = fixture
    expected = identity(document.content)
    write_document(root / (expected.digest + ".signed.json"), document)
    observed = observe_historical_policy(
        loader, archive=root, expected=expected, at_us=START,
        identify_content=identity, document_digest=document.digest())
    assert isinstance(observed, HistoricalPolicyObservation)
    assert observed.content_digest == expected.digest
    assert observed.document_digest == document.digest()
    assert observed.observed_at_us == START
    assert json.loads(observed.content_json) == document.content
    assert not hasattr(observed, "signature")  # Cannot directly substitute for a PolicyDocument.
    with pytest.raises(PolicyLoadRefused, match="effective window"):
        loader.load(root / (expected.digest + ".signed.json"), at_us=END)


def test_historical_lookup_requires_application_version(fixture):
    root, _, _, document, loader = fixture
    expected = identity(document.content)
    write_document(root / (expected.digest + ".signed.json"), document)
    with pytest.raises(PolicyLoadRefused, match="content or version"):
        observe_historical_policy(
            loader, archive=root, expected=replace(expected, version="v2"),
            at_us=START, identify_content=identity)


def test_historical_lookup_does_not_fall_back_to_current(fixture):
    root, signer, _, document, loader = fixture
    expected = identity(document.content)
    current = document_policy(
        signer, vertical=document.vertical, policy_id=document.policy_id, version="v2",
        content={"version": "v2", "promises": {"hours": 4}, "staff": ["fixture:current-staff"]},
        jurisdictions=("synthetic",), effective_from_us=START, effective_until_us=0)
    write_document(root / (identity(current.content).digest + ".signed.json"), current)
    with pytest.raises(PolicyLoadRefused, match="could not be read"):
        observe_historical_policy(loader, archive=root, expected=expected,
                                  at_us=START, identify_content=identity)


def test_history_rechecks_application_content_under_selected_name(fixture):
    root, _, _, document, loader = fixture
    expected = ContentIdentity(digest_hex({"hours": 18}), "v1")
    write_document(root / (expected.digest + ".signed.json"), document)
    with pytest.raises(PolicyLoadRefused, match="content or version"):
        observe_historical_policy(loader, archive=root, expected=expected,
                                  at_us=START, identify_content=identity)


def test_application_parser_cannot_change_verified_snapshot(fixture):
    root, _, _, document, loader = fixture
    expected = identity(document.content)
    write_document(root / (expected.digest + ".signed.json"), document)

    def parse_copy(content):
        result = identity(content)
        content["staff"] = ["fixture:current-staff"]
        return result

    result = observe_historical_policy(loader, archive=root, expected=expected,
                                       at_us=START, identify_content=parse_copy)
    assert json.loads(result.content_json)["staff"] == ["fixture:historical-staff"]


@pytest.mark.parametrize("keys", [[], [{"key_id": "fixture:blank", "public_key_hex": ""}]])
def test_trust_requires_public_keys(fixture, keys):
    root, _, _, _, _ = fixture
    path = root / "incomplete-trust.json"
    path.write_text(json.dumps({"schema": "care/trust-keys/v1", "keys": keys}), encoding="utf-8")
    with pytest.raises(PolicyLoadRefused):
        public_trust_from_file(path)


def test_trust_rejects_private_material_field(fixture):
    root, signer, _, _, _ = fixture
    path = root / "nonpublic-trust.json"
    path.write_text(json.dumps({
        "schema": "care/trust-keys/v1",
        "keys": [{"key_id": signer.key_id, "public_key_hex": signer.public_key_bytes.hex(),
                  "private_key": "synthetic-placeholder-no-key"}],
    }), encoding="utf-8")
    with pytest.raises(PolicyLoadRefused, match="public key fields only"):
        public_trust_from_file(path)


@pytest.mark.parametrize("at", [True, 1.5, -1])
def test_observation_requires_exact_time_unit(fixture, at):
    _, _, path, _, loader = fixture
    with pytest.raises(PolicyLoadRefused, match="microseconds"):
        loader.load(path, at_us=at)
