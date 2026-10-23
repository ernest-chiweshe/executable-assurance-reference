"""Intact frozen care-parser compatibility using fictional signed routing data."""
import json
from dataclasses import replace

import pytest

from assurance_reference.policy_loading import ContentIdentity, PolicyFileLoader, observe_historical_policy
from factory.care.contracts import CareRefused, IssueClass, Queue, RoutingPolicy, Targets
from factory.care.policy import Capability, parse_policy_content, policy_content, require_capability
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer


def identify_care(content):
    policy, _staff = parse_policy_content(content)
    return ContentIdentity(policy.digest, policy.version)


@pytest.fixture
def routing_fixture(tmp_path):
    owner = "operator:fixture-queue-owner"
    policy = RoutingPolicy(
        policy_id="fixture-care-routing", version="fixture-v1", timezone="UTC",
        business_days=(1, 2, 3, 4, 5), business_start_hour=8, business_end_hour=17,
        targets={"free": Targets(18, 0, 0)},
        queues={"general": Queue("general", owner, "Synthetic care queue", last_resort=True)},
        routes={issue: "general" for issue in IssueClass},
        retention_months_after_close=24, region="fixture-region", courier="fixture-courier")
    minimum = frozenset({Capability.ASSIGN, Capability.RESPOND, Capability.QUEUE_MANAGE})
    historical_staff = {owner: minimum, "operator:fixture-prior-responder": frozenset({Capability.RESPOND})}
    current_staff = {owner: minimum}
    signer = Ed25519Signer("fixture:care-document-authority")
    trust_path = tmp_path / "public-trust.json"
    trust_path.write_text(json.dumps({
        "schema": "care/trust-keys/v1",
        "keys": [{"key_id": signer.key_id, "public_key_hex": signer.public_key_bytes.hex()}],
    }), encoding="utf-8")
    document = document_policy(
        signer, vertical="care", policy_id="routing", version=policy.version,
        content=policy_content(policy, historical_staff), jurisdictions=("synthetic",),
        effective_from_us=1_000_000, effective_until_us=2_000_000)
    archive_path = tmp_path / (policy.digest + ".signed.json")
    archive_path.write_text(json.dumps({
        **document.signed_body(),
        "signature": {"key_id": document.signature.key_id,
                      "value": document.signature.value, "alg": document.signature.alg},
        "digest": document.digest(),
    }), encoding="utf-8")
    loader = PolicyFileLoader(trust_path, "care", "routing", signer.key_id)
    return tmp_path, policy, document, loader, historical_staff, current_staff


def test_exact_original_parser_preserves_routing_digest_and_promises(routing_fixture):
    root, policy, document, loader, old_staff, _ = routing_fixture
    observation = observe_historical_policy(
        loader, archive=root, expected=ContentIdentity(policy.digest, policy.version),
        at_us=1_500_000, identify_content=identify_care, document_digest=document.digest())
    recovered, recovered_staff = parse_policy_content(json.loads(observation.content_json))
    assert recovered == policy
    assert recovered_staff == old_staff
    assert observation.content_digest == policy.digest
    assert observation.document_digest == document.digest()
    assert observation.content_digest != observation.document_digest
    assert recovered.targets_for("free").first_response_hours == 18


def test_historical_roster_does_not_supply_current_staff_authority(routing_fixture):
    root, policy, document, loader, _, current_staff = routing_fixture
    observation = observe_historical_policy(
        loader, archive=root, expected=ContentIdentity(policy.digest, policy.version),
        at_us=1_500_000, identify_content=identify_care)
    _, historical_staff = parse_policy_content(json.loads(observation.content_json))
    current_policy = replace(policy, version="fixture-v2")
    _, verified_current_staff = parse_policy_content(policy_content(current_policy, current_staff))
    old_actor = "operator:fixture-prior-responder"
    assert Capability.RESPOND in historical_staff[old_actor]
    with pytest.raises(CareRefused) as refused:
        require_capability(verified_current_staff, old_actor, Capability.RESPOND)
    assert refused.value.code == "FORBIDDEN"
    # The resolver returns only observation data; it never installs the historical roster.
    assert observation.document_digest == document.digest()


def test_original_content_digest_excludes_staff_but_document_digest_binds_staff(routing_fixture):
    _, policy, old_document, _, _, current_staff = routing_fixture
    current_content = policy_content(policy, current_staff)
    assert identify_care(current_content) == identify_care(old_document.content)
    signer = Ed25519Signer("fixture:care-current-document-authority")
    current_document = document_policy(
        signer, vertical="care", policy_id="routing", version=policy.version,
        content=current_content, jurisdictions=("synthetic",), effective_from_us=2_000_000)
    assert current_document.digest() != old_document.digest()
