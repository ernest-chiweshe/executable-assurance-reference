"""Ordinary reviewed Education releases after lawful synthetic pack changes."""
from dataclasses import replace
import json
import os

import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.packs.registry import PackRegistry
from pack_withdrawal_fixture import PackWithdrawalFixture
from partitioned_governance_fixture import GovernedFixture
from regulated_core.signing import Ed25519Signer
from regulated_core.target import Outcome
from synthetic_health_versions import build_synthetic_education_version
from test_pack_rulebook_release_contracts import fresh_review


class GovernedRegistryFixture(PackRegistry):
    def authorize(self, engine, **parameters):
        return engine.authorize_for_target(**parameters)


def pin_other_version(roles, tmp_path):
    governance = GovernedFixture(roles)
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        governance.trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    registry = GovernedRegistryFixture(trust=governance.trust, activation=governance.packs.ledger)
    original = registry.install(FIXTURES / "bundles" / "education-0.1.2",
                                publisher_key_id=PUBLISHER, today="2026-10-14")
    publisher = Ed25519Signer("fixture:education-lifecycle-publisher")
    governance.trust.register_signer(publisher)
    bundle = tmp_path / "synthetic-version"
    build_synthetic_education_version(bundle, version="99.0.1", publisher=publisher)
    newer = registry.install(bundle, publisher_key_id=publisher.key_id, today="2026-10-14")
    governance.packs = registry
    activated, _, _, _ = governance.enact("governance-office", {"activate": newer.reference, "at": "fixture"})
    assert activated.outcome is Outcome.COMMITTED, activated.detail
    result, _, _, _ = governance.enact("governance-office",
                                      {"pin": newer.reference, "tenant": "school-a"})
    assert result.outcome is Outcome.COMMITTED, result.detail
    rolled_back, _, _, _ = governance.enact("governance-office", {
        "rollback": original.manifest.id, "rollback_to": original.reference,
        "at": "fixture", "reason": "Synthetic retained tenant pin"})
    assert rolled_back.outcome is Outcome.COMMITTED, rolled_back.detail
    assert registry.activation_for("school-a", original.manifest.id).reference == newer.reference
    assert registry.activation_for("other-application-tenant", original.manifest.id).reference == original.reference


@pytest.mark.parametrize("change", ["retained", "withdrawn", "tenant-pin-mismatch"])
def test_pack_authority_is_rechecked_before_authorization(tmp_path, change):
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path / "application", partitioned_lifecycle=True)
    context = fresh_review(app)
    # Each operation uses the unchanged signed governance workflow before any
    # application target authorization is requested.
    if change == "withdrawn":
        PackWithdrawalFixture(roles, "education-0.1.2").withdraw()
    elif change == "tenant-pin-mismatch":
        pin_other_version(roles, tmp_path)
    context = replace(context, now_us=app.clock.now_us())
    gate = app.gates["requester"]
    decision = gate.authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert not app.path.exists() and not app.stores.permits.used(context.tenant, context.nonce)
    if change == "retained":
        assert decision.allowed and decision.permit.permit is not None, decision.reason
        outcome = gate.commit_release(spec=app.spec, contract=app.contract, context=context,
            decision=decision, artifact=app.body, out_path=str(app.path))
        assert outcome.state == "committed" and app.path.read_bytes() == app.body
    else:
        assert not decision.allowed and decision.permit is None
        entries = app.stores.recorder.entries(context.tenant)
        recorded = [entry for entry in entries
                    if entry.record_hash == decision.evidence["refusal_record_hash"]]
        assert len(recorded) == 1
        assert recorded[0].record.record_id == decision.evidence["refusal_record_id"]
        assert recorded[0].record.decision.reason_codes == ("PACK_AUTHORITY_REFUSED",)
        assert app.stores.recorder.verify_entry(recorded[0])
    assert app.stores.recorder.verify_chain(context.tenant)
