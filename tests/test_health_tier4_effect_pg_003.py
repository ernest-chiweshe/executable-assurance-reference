"""Synthetic Health application tier-four effect matrix with intact guards."""
from dataclasses import fields, replace
from hashlib import sha256
import os
import json
from pathlib import Path
import time

import pytest

from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_roles import provision_local_roles, LocalPool
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from factory.health_ui.documents import FINALISATION_PENDING, FINALISATION_COMMITTED, FINALISATION_FAILED, SIGNED
from regulated_core.approval_exchange import ReviewError
from regulated_core.persistence_pg import PostgresClearanceStore
from regulated_core.signing import Ed25519Signer
from regulated_core.tier4 import issue_clearance
from synthetic_tier4_health import build_tier4_health_fixture
from test_clinical_review_composition_pg_002 import populate


class FictionalDirectory:
    def __init__(self):
        self.lines = {}

    def reporting_line(self, tenant_id, subject_id):
        return self.lines.get((tenant_id, subject_id))


CASES = (
    ("lawful", None),
    ("one-human", "quorum"),
    ("same-line", "TIER4_SAME_REPORTING_LINE"),
    ("unknown-line", "TIER4_REPORTING_LINE_UNKNOWN"),
    ("no-clearance", "TIER4_MONITOR_NOT_CLEARED"),
    ("cooling", "TIER4_COOLING_OFF"),
    ("membership-inactive", "membership changed"),
    ("jurisdiction-changed", "membership changed"),
)


@pytest.mark.parametrize("partitioned", [True], ids=["partitioned"])  # legacy profile refused since candidate 060
@pytest.mark.parametrize("case,refusal", CASES, ids=[c[0] for c in CASES])
def test_health_review_to_receiving_effect(partitioned, case, refusal, tmp_path):
    provision = provision_partitioned_local_roles if partitioned else provision_local_roles
    roles = provision(os.environ["FACTORY_TEST_DB_URL"])
    try:
        publisher = Ed25519Signer("fixture:health-tier4-publisher")
        bundle = tmp_path / "signed-synthetic-health"
        build_tier4_health_fixture(bundle, publisher=publisher)
        directory, keys = FictionalDirectory(), {}
        def fixture_signer(key_id):
            key = Ed25519Signer(key_id)
            keys[key_id] = key
            return key
        period = 60_000_000 if case == "cooling" else 1_000_000
        app = build_clinical_fixture(roles, tmp_path, partitioned_lifecycle=partitioned,
            synthetic_pack_directory=bundle, synthetic_publisher=publisher,
            signer_factory=fixture_signer, tier4_directory=directory, tier4_cooling_off_us=period)
        tenant = app.clinician.workspace_id
        directory.lines[(tenant, app.review_identities["owner"].principal)] = "fictional-clinical"
        if case != "unknown-line":
            directory.lines[(tenant, app.review_identities["peer"].principal)] = (
                "fictional-clinical" if case == "same-line" else "fictional-peer")
        session, document = populate(app)
        opened = app.finaliser.begin_review(session, document, app.clinician)
        record = document.finalisation
        packet = app.review_attempts.get(record.nonce)
        assert app.review_grant("owner", session, document).grant()["status"] == "awaiting-review"
        if refusal == "quorum":
            with pytest.raises(ReviewError, match="required quorum"):
                app.finaliser.complete_review(session, document, app.clinician)
            assert document.finalisation.state == FINALISATION_PENDING
        else:
            assert app.review_grant("peer", session, document).grant()["status"] == "approved"
            contract, context = app.finaliser.review_request(session, document, app.clinician)
            approved = app.gate.resolve_review_context(spec=app.spec, contract=contract,
                context=replace(context, approval=opened["review_id"])).approval
            assert set(approved.certificate.approver_ids) == {
                identity.principal for identity in app.review_identities.values()}
            if case != "no-clearance":
                clearance = issue_clearance(keys["reference-host-fixture:monitor"], approved.envelope,
                                             cleared_at_us=app.clock.now_us())
                PostgresClearanceStore(pool=roles.monitor_ingress).put(clearance)
                assert app.stores.clearances.get(tenant, approved.envelope.record.record_id) == clearance
            end = approved.envelope.record.decided_at_us + period
            if case == "cooling":
                assert app.clock.now_us() < end
            else:
                deadline = time.monotonic() + 10
                while app.clock.now_us() < end:
                    assert time.monotonic() < deadline, "ordinary cooling-off wait exceeded its bound"
                    time.sleep(0.02)
            if case == "membership-inactive":
                # Synthetic operator-state transition only. IdentityStore has
                # no public membership-deactivation API; this does not qualify
                # an administration endpoint or weaken a runtime guard.
                peer = app.review_identities["peer"].principal
                assert app.membership.active_member(peer, tenant) is not None
                with app.membership._lock:
                    candidate = json.loads(json.dumps(app.membership._data))
                    members = [u for u in candidate["users"] if u["user_id"] == peer]
                    assert len(members) == 1 and members[0]["active"] is True
                    members[0]["active"] = False
                    app.membership._validate(candidate)
                    app.membership._flush(candidate)
                    app.membership._data = candidate
                assert app.membership.active_member(peer, tenant) is None
                assert app.membership.active_member(app.review_identities["owner"].principal, tenant) is not None
            elif case == "jurisdiction-changed":
                # Ordinary synthetic host registry reconfiguration. The real
                # membership provider and validation guards remain intact;
                # this fixture does not model a public administration API.
                registry = app.gate._credverify._registry
                assert registry._jurisdiction == "global"
                registry._jurisdiction = "fictional-new-region"
                for receipt in approved.credential_receipts:
                    subject = app.gate._credverify._identity.resolve(receipt.subject_id, tenant)
                    assert subject is not None and subject.active
                    current = registry.lookup(receipt.subject_id, receipt.role)
                    assert current is not None and current.status == receipt.status == "active"
                    assert current.subject_id == receipt.subject_id and current.role == receipt.role
                    assert current.licence_type == receipt.licence_type
                    assert current.jurisdiction != receipt.jurisdiction
                    assert current.expires_at_us > app.clock.now_us()
            if case in ("membership-inactive", "jurisdiction-changed"):
                # The retained signed credential is still cryptographically
                # current; only the live fictional member state changed.
                for receipt in approved.credential_receipts:
                    assert app.gate._credverify.verify_receipt(
                        receipt, tenant=tenant, now_us=app.clock.now_us())
            prior_record_ids = {env.record.record_id for env in app.stores.recorder.entries(tenant)}
            outcome = app.finaliser.complete_review(session, document, app.clinician)
            if refusal:
                assert outcome.state == FINALISATION_FAILED, outcome.detail
                if case in ("membership-inactive", "jurisdiction-changed"):
                    assert "clinical reviewer membership changed since its retained receipt" in outcome.detail
                else:
                    matching = [
                        envelope.record for envelope in app.stores.recorder.entries(tenant)
                        if envelope.record.record_id not in prior_record_ids
                        and envelope.record.tenant_id == tenant
                        and envelope.record.correlation_id == approved.envelope.record.correlation_id
                        and envelope.record.action == approved.envelope.record.action
                    ]
                    assert matching, "expected new decision evidence bound to this attempt"
                    assert any(refusal in entry.decision.reason_codes for entry in matching)
            else:
                assert outcome.state == FINALISATION_COMMITTED, outcome.detail
                stored = app.store.get(session.session_id, app.clinician.owner_id).document(document.doc_id)
                assert stored.status == SIGNED and stored.signed_by == app.clinician.display_name
                files = list(app.records.rglob("*.docx"))
                assert len(files) == 1
                body = app.finaliser.committed_bytes(stored)
                assert sha256(body).hexdigest() == record.artifact_sha256
                assert files[0].read_bytes() == app.artifacts.get(app.finaliser._tenant, record.artifact_address) == body
                assert app.stores.permits.used(tenant, record.nonce)
                modified = files[0].stat().st_mtime_ns
                receipt = app.gate.reconcile_release(spec=app.spec, artifact_sha256=record.artifact_sha256,
                    out_path=str(files[0]), nonce=record.nonce,
                    context=app.finaliser._context(session, document, app.clinician, outcome))
                assert receipt.state == "committed" and receipt.evidence["target_holds"] is True
                assert app.finaliser.committed_bytes(stored) == body
                assert files[0].stat().st_mtime_ns == modified
        if refusal:
            assert not list(app.records.rglob("*.docx"))
            assert not app.stores.permits.used(tenant, record.nonce)
        assert app.review_attempts.get(record.nonce) == packet
        assert app.stores.recorder.verify_chain(tenant)
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
