"""Restricted local journal/session integration over actual guarded fixture grants.

The host route automatically captures generated material and explicit choices;
actual UI delivery and human reading are not claimed.
All identities, documents and signing keys are fictional local fixtures.
"""

from dataclasses import replace
import os

import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.approval_observations import ApprovalObservations, PURPOSE
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.observed_review import ObservedMaterialReview
from assurance_reference.review_material import MaterialReview, material_contract
from assurance_reference.session_credentials import SessionRefused
from regulated_core.canonical import digest_hex
from regulated_core.signing import Ed25519Signer, TrustDirectory


def test_durable_observations_audited_session_read_and_unchanged_guarded_release(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        app = build_education_fixture(roles, tmp_path)
        signer, observer = Ed25519Signer("fixture:observation-journal"), Ed25519Signer("fixture:observer")
        trust = TrustDirectory()
        trust.register_signer(signer)
        trust.register_signer(observer)
        journal = AlertJournal(roles.alerts, signer, trust)

        def service(sessions, store, cohorts=()):
            return ApprovalObservations(tenant=app.context.tenant, journal=store, sessions=sessions,
                observer_key_ids=(observer.key_id,), reader_principals=("head",), cohorts=cohorts)

        observations = service(app.sessions, journal)
        requester = app.gates["requester"]
        contract = material_contract(app.contract, prior_artifact=None,
            reversibility="Fictional local file; no recall claim", exposure="Fixture only",
            checker_findings=["Fixture source fidelity"], uncertainty="No human protection claim")
        opened = requester.open_review(spec=app.spec, contract=contract, context=app.context)
        common = dict(spec=app.spec, contract=contract, review_id=opened["review_id"], artifact=app.body)
        references = []
        for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
            route = ObservedMaterialReview(MaterialReview(app.gates[principal]),
                observations=observations, signer=observer, clock=app.clock,
                sessions=app.sessions, authenticated=app.identities[principal], synthetic=True)
            context = replace(app.context, actor_id=principal, now_us=app.clock.now_us())
            presented = route.present(**common, context=context)
            captured = route.finish(**common, context=context, role=role, outcome="approved",
                presentation_ticket=presented["presentation_ticket"],
                displayed_sha256=presented["view"]["display_sha256"])
            decided = app.clock.read()
            retained = requester.get_review(spec=app.spec, contract=contract,
                review_id=opened["review_id"], context=replace(app.context, now_us=decided.now_us))
            assert principal in retained["approver_ids"]
            reference = captured["observation_id"]
            event = journal.read(reference, tenant_id=app.context.tenant)["payload"]["event"]
            assert event["reviewer"] == principal and event["outcome"] == "approved"
            assert event["display_sha256"] == presented["view"]["display_sha256"]
            assert event["decision_sha256"] == presented["view"]["bound"]["decision_record_hash"]
            assert event["clock_domain"] == decided.domain and event["synthetic"] is True
            assert event["presented_us"] <= event["decided_us"] <= decided.now_us
            references.append(reference)
            # Observation retention does not bypass the original two-role quorum.
            if principal == "teacher":
                denied = requester.authorize_release(spec=app.spec, contract=contract,
                    context=replace(app.context, approval=opened["review_id"], now_us=app.clock.now_us()),
                    artifact=app.body, out_path=str(app.path))
                assert not denied.allowed and not app.path.exists()

        # Additional detached, explicitly synthetic workflow assertions exercise
        # the five-person cohort floor. They are NOT additional guarded grants.
        for index, status in enumerate(("refused", "escalated", "refused")):
            synthetic = {**event, "review_id": f"synthetic-review-{index}",
                         "reviewer": f"synthetic-reviewer-{index}", "outcome": status}
            references.append(observations.record(synthetic, observer.sign(synthetic)))
        cohorts = ({"cohort_id": "fixture-closed-period", "clock_domain": decided.domain,
                    "evidence_kind": "synthetic-fixture",
                    "start_us": 0, "end_us": decided.now_us + 1,
                    "observation_ids": tuple(references)},)
        # Reconstruct services over the same durable restricted pools.
        restarted_journal = AlertJournal(roles.alerts, signer, trust)
        restarted_sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer,
                                           clock=app.clock)
        restarted = service(restarted_sessions, restarted_journal, cohorts)
        before_ids = restarted_journal.list_ids(tenant_id=app.context.tenant)
        with pytest.raises(SessionRefused):
            restarted.report(authenticated=app.identities["teacher"], purpose=PURPOSE,
                             cohort_id="fixture-closed-period")
        assert restarted_journal.list_ids(tenant_id=app.context.tenant) == before_ids
        result = restarted.report(authenticated=app.identities["head"], purpose=PURPOSE,
                                  cohort_id="fixture-closed-period")
        assert result["outcome_counts"] == {"approved": 2, "refused": 2, "escalated": 1}
        assert result["synthetic_count"] == 5 and result["automatic_consequences"] == []
        after_ids = restarted_journal.list_ids(tenant_id=app.context.tenant)
        audit = [restarted_journal.read(i, tenant_id=app.context.tenant)["payload"]
                 for i in set(after_ids) - set(before_ids)]
        assert {row["stage"] for row in audit} == {"READ_REQUESTED", "REPORT_PREPARED"}
        assert {row["request_id"] for row in audit} == {result["request_id"]}
        assert next(row for row in audit if row["stage"] == "REPORT_PREPARED")[
            "report_sha256"] == digest_hex(result)

        release_context = replace(app.context, approval=opened["review_id"], now_us=app.clock.now_us())
        decision = requester.authorize_release(spec=app.spec, contract=contract,
            context=release_context, artifact=app.body, out_path=str(app.path))
        assert decision.allowed, decision.reason
        outcome = requester.commit_release(spec=app.spec, contract=contract, context=release_context,
            decision=decision, artifact=app.body, out_path=str(app.path))
        assert outcome.state == "committed" and app.path.read_bytes() == app.body

        restarted_sessions.revoke(app.identities["head"])
        with pytest.raises(SessionRefused):
            restarted.report(authenticated=app.identities["head"], purpose=PURPOSE,
                             cohort_id="fixture-closed-period")
        assert restarted_journal.list_ids(tenant_id=app.context.tenant) == after_ids
        # Observation access after revocation cannot invoke another release.
        assert app.path.read_bytes() == app.body
        assert app.stores.recorder.verify_chain(app.context.tenant)
    finally:
        for value in vars(roles).values():
            if callable(getattr(value, "close", None)):
                value.close()
