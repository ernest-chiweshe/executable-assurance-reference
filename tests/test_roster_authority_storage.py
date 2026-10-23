"""Intact offline storage-observation checks; no database writes."""
import json
from types import SimpleNamespace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.governance_roster import GovernanceRoster, RosterMember, roster_change_bytes
from regulated_core.governance_targets import issue_bootstrap
from regulated_core.persistence_pg import PersistenceError
from roster_verifier_fixture import verified_store


def valid_first_row():
    store, signer = verified_store()
    roster = GovernanceRoster("fixture", 1, (RosterMember("reviewer", frozenset({"governance-approver"}),
                                                       "synthetic-line"),),
                              frozenset({signer.key_id}), True)
    proof = issue_bootstrap(signer, tenant_id="fixture", kind="governance-roster",
                            subject="fixture", output=roster_change_bytes(roster))
    body = store._proof_verifier.encode(SimpleNamespace(
        authority_proof=proof, change={"roster": roster.as_fields()}))
    row = (1, roster.digest(), canonical_bytes(body).decode(), "fixture",
           "governance:change-roster", "bootstrap:" + proof.change_digest, proof.change_digest)
    return store._proof_verifier, roster, row


def test_valid_bootstrap_storage_round_trip_keeps_original_authority():
    verifier, roster, row = valid_first_row()
    assert verifier.verify_rows([row], "fixture") == [(roster, tuple(row[3:]))]


@pytest.mark.parametrize("raw", ["{}", "null", "", '{"schema":"unrecognized"}'])
def test_incomplete_storage_observation_fails_closed(raw):
    verifier, _, row = valid_first_row()
    with pytest.raises(PersistenceError):
        verifier.verify_rows([(*row[:2], raw, *row[3:])], "fixture")


def test_incomplete_latest_observation_does_not_return_earlier_valid_state():
    verifier, _, row = valid_first_row()
    incomplete = (2, "", "{}", "fixture", "governance:change-roster", "", "")
    with pytest.raises(PersistenceError):
        verifier.verify_rows([row, incomplete], "fixture")


def test_missing_authority_is_refused_before_encoding_a_change():
    verifier, _, _ = valid_first_row()
    with pytest.raises(PersistenceError, match="original signed authority"):
        verifier.encode(SimpleNamespace(authority_proof=None))


def test_installation_configuration_is_checked_even_for_empty_history():
    verifier, _, _ = valid_first_row()
    with pytest.raises(PersistenceError, match="installation differs"):
        verifier.verify_rows([], "different-configuration")


def test_stored_authority_envelope_retains_verifiable_signature():
    verifier, _, row = valid_first_row()
    body = json.loads(row[2])
    assert body["authority"]["type"] == "bootstrap"
    assert body["authority"]["fields"]["signature"]["key_id"] in verifier.bootstrap_key_ids


def test_bootstrap_trust_declines_unchanged_authority_observation(monkeypatch):
    verifier, roster, row = valid_first_row()
    assert verifier.verify_rows([row], "fixture")[0][0] == roster
    with monkeypatch.context() as observation:
        observation.setattr(verifier.bootstrap_trust, "verify", lambda body, signature: False)
        with pytest.raises(PersistenceError, match="bootstrap authority does not verify"):
            verifier.verify_rows([row], "fixture")
    assert verifier.verify_rows([row], "fixture")[0][0] == roster


def test_bootstrap_known_key_outside_configured_pin_is_refused(monkeypatch):
    from regulated_core.signing import Ed25519Signer

    verifier, roster, row = valid_first_row()
    other = Ed25519Signer("synthetic:other-configured-bootstrap")
    verifier.bootstrap_trust.register_signer(other)
    assert verifier.verify_rows([row], "fixture")[0][0] == roster
    with monkeypatch.context() as observation:
        observation.setattr(verifier, "bootstrap_key_ids", frozenset({other.key_id}))
        with pytest.raises(PersistenceError, match="bootstrap authority does not verify"):
            verifier.verify_rows([row], "fixture")
    assert verifier.verify_rows([row], "fixture")[0][0] == roster
