"""Signed synthetic completion observations; no target effect is invoked."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.alerts import AlertUnavailable
from assurance_reference.timing_observations import (
    CompletionObservation, SignedCompletionObservation, TimingObservationRecorder,
)
from regulated_core.canonical import digest_hex
from regulated_core.signing import Ed25519Signer
from test_alerts import alert_case, outcome_case  # noqa: F401

# Pytest resolves imported fixtures through same-named arguments.
# ruff: noqa: F811


@pytest.fixture
def observation_case(outcome_case):
    _, authorization, _, pool, journal = outcome_case
    observer = Ed25519Signer("fixture:completion-observer")
    journal.trust.register_signer(observer)
    permit = authorization.permit
    p = permit.permit
    event = CompletionObservation(p.tenant_id, digest_hex(p.signed_body()), p.clock_domain,
                                  p.expires_at_us, p.expires_at_us + 1, True)
    recorder = TimingObservationRecorder(journal=journal,
        permit_key_ids={permit.signature.key_id}, observer_key_ids={observer.key_id})
    return SimpleNamespace(permit=permit, event=event, observer=observer, recorder=recorder,
                           journal=journal, pool=pool)


def signed(case, event):
    return SignedCompletionObservation(event, case.observer.sign(event.body()))


@pytest.mark.parametrize("lower,upper,classification", [
    (-2, -1, "BEFORE_EXPIRY"), (-1, 0, "UNCERTAIN"), (-1, 1, "UNCERTAIN"),
    (0, 0, "LATE"), (0, 1, "LATE"), (1, 2, "LATE"),
])
def test_signed_interval_classification_and_retained_provenance(observation_case, lower, upper, classification):
    c = observation_case
    expiry = c.permit.permit.expires_at_us
    event = replace(c.event, earliest_completion_us=expiry + lower, latest_completion_us=expiry + upper)
    identifier = c.recorder.record(c.permit, signed(c, event))
    payload = c.journal.read(identifier, tenant_id=event.tenant_id)["payload"]
    assert payload["classification"] == classification
    assert payload["code"] == "SYNTHETIC_COMPLETION_" + classification
    assert payload["observation"] == event.body()
    assert payload["synthetic"] is True
    assert payload["outcome"] == "unknown"
    assert payload["requires_reconciliation"] is True
    assert payload["effect_invoked"] is False
    assert payload["authority_time_us"] is None


@pytest.mark.parametrize("change", [
    {"tenant_id": "other-school"}, {"permit_hash": "0" * 64},
    {"clock_domain": "other:clock"}, {"earliest_completion_us": -1},
    {"earliest_completion_us": True}, {"latest_completion_us": 0}, {"synthetic": "true"},
])
def test_misbound_or_invalid_signed_observation_is_not_retained(observation_case, change):
    c = observation_case
    event = replace(c.event, **change)
    with pytest.raises(ValueError):
        c.recorder.record(c.permit, signed(c, event))
    with c.pool.connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_alerts_v1").fetchone()[0] == 0


def test_signatures_and_observer_role_are_verified(observation_case):
    c = observation_case
    altered = replace(c.event, latest_completion_us=c.event.latest_completion_us + 1)
    with pytest.raises(ValueError, match="observer signature"):
        c.recorder.record(c.permit, SignedCompletionObservation(altered, c.observer.sign(c.event.body())))
    other = Ed25519Signer("fixture:trusted-but-not-observer")
    c.journal.trust.register_signer(other)
    with pytest.raises(ValueError, match="observer signature"):
        c.recorder.record(c.permit, SignedCompletionObservation(c.event, other.sign(c.event.body())))
    altered_permit = replace(c.permit, permit=replace(c.permit.permit, nonce="altered"))
    with pytest.raises(ValueError, match="permit signature"):
        c.recorder.record(altered_permit, signed(c, c.event))


def test_missing_store_and_failed_signer_cannot_claim_durable_alert(observation_case):
    c = observation_case
    class UnavailableSigner:
        def sign(self, payload):
            raise OSError("fixture signer unavailable")
    original = c.journal.signer
    c.journal.signer = UnavailableSigner()
    with pytest.raises(AlertUnavailable):
        c.recorder.record(c.permit, signed(c, c.event))
    c.journal.signer = original
    # Fixture-owned schema only. Simulate missing storage, not disabled guards.
    with c.pool.connection() as conn, conn.transaction():
        conn.execute("DROP TABLE reference_alerts_v1")
    with pytest.raises(AlertUnavailable):
        c.recorder.record(c.permit, signed(c, c.event))


def test_reporter_requires_separate_explicit_observer_identity(observation_case):
    c = observation_case
    with pytest.raises(ValueError):
        TimingObservationRecorder(journal=c.journal, permit_key_ids={"one"}, observer_key_ids={"one"})
