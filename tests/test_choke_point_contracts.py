"""Offline request contracts for the recovered choke points; no outbound effects."""

import json

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.choke_points import (
    AgentMessagePolicy, CredentialIssuancePolicy, EgressPolicy,
    credential_change_check, credential_request_bytes, egress_bytes,
    egress_change_check, idempotency_key, message_bytes, message_change_check,
)
from regulated_core.permit import EmissionError


@pytest.mark.parametrize("kind,body,subject,change", [
    ("credential", credential_request_bytes("fixture-slot", holder="fixture-human",
        scope=("read-fixture",), purpose="synthetic", ttl_us=100), "fixture-slot",
        {"holder": "fixture-human", "scope": ["read-fixture"], "purpose": "synthetic",
         "ttl_us": 100}),
    ("inter-agent", message_bytes("fixture-channel", sender="one", recipient="two",
        body="synthetic message"), "fixture-channel",
        {"sender": "one", "recipient": "two", "body": "synthetic message"}),
    ("egress", egress_bytes("fixture-endpoint", media_type="text/plain",
        payload="synthetic output"), "fixture-endpoint",
        {"media_type": "text/plain", "payload": "synthetic output"}),
])
def test_exact_request_serialization(kind, body, subject, change):
    value = json.loads(body)
    assert body == canonical_bytes(value)
    assert value["kind"] == kind and value["subject"] == subject
    assert value["change"] == change
    assert set(value) == {"schema", "kind", "subject", "change"}


@pytest.mark.parametrize("changes", [
    {"ttl_us": 0}, {"ttl_us": True}, {"ttl_us": 101}, {"scope": []},
    {"scope": ["read-fixture", "read-fixture"]}, {"holder": " "},
    {"purpose": ""}, {"extra_field": "synthetic"},
])
def test_credential_request_refuses_unbounded_or_extra_fields(changes):
    valid = {"holder": "fixture-human", "scope": ["read-fixture"],
             "purpose": "synthetic", "ttl_us": 100}
    check = credential_change_check(max_ttl_us=100)
    check(valid)
    with pytest.raises(EmissionError):
        check({**valid, **changes})


@pytest.mark.parametrize("changes", [
    {"sender": "two"}, {"recipient": ""}, {"body": ""},
    {"body": "\u00e9\u00e9\u00e9"}, {"extra_field": "synthetic"},
])
def test_channel_request_refuses_invalid_or_oversize_message(changes):
    valid = {"sender": "one", "recipient": "two", "body": "\u00e9\u00e9"}
    check = message_change_check(max_bytes=4)
    check(valid)
    with pytest.raises(EmissionError):
        check({**valid, **changes})


@pytest.mark.parametrize("changes", [
    {"media_type": " "}, {"payload": ""}, {"payload": "\u00e9\u00e9\u00e9"},
    {"extra_field": "synthetic"},
])
def test_egress_request_refuses_invalid_or_oversize_payload(changes):
    valid = {"media_type": "text/plain", "payload": "\u00e9\u00e9"}
    check = egress_change_check(max_bytes=4)
    check(valid)
    with pytest.raises(EmissionError):
        check({**valid, **changes})


def test_egress_idempotency_identity_binds_every_component():
    args = ["fixture-tenant", "egress:send", "fixture-nonce", "a" * 64]
    key = idempotency_key(*args)
    assert len(key) == 64 and set(key) <= set("0123456789abcdef")
    assert key == idempotency_key(*args)
    for position in range(4):
        changed = list(args)
        changed[position] += "-different"
        assert idempotency_key(*changed) != key


@pytest.mark.parametrize("policy", [CredentialIssuancePolicy, EgressPolicy, AgentMessagePolicy])
def test_policy_identity_binds_configuration_and_refuses_invalid_values(policy):
    original = policy(approvers=1, window_us=100)
    assert original.ref.digest != policy(approvers=2, window_us=100).ref.digest
    assert original.ref.digest != policy(approvers=1, window_us=101).ref.digest
    for settings in ({"approvers": True}, {"approvers": -1}, {"window_us": 0},
                     {"window_us": True}):
        with pytest.raises(ValueError):
            policy(**settings)
    if policy is CredentialIssuancePolicy:
        with pytest.raises(ValueError):
            policy(approvers=0)
