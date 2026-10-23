"""Prepare one authenticated delegated database draft under its root budget."""

from dataclasses import dataclass
import hashlib
import json

from regulated_core.budget import BudgetError
from regulated_core.canonical import digest_hex
from regulated_core.database_receiver_pg import PostgresTargetReceiver
from regulated_core.delegation import RELEASE_AUTHORITY_FIELD, release_authority_of
from regulated_core.delegation_chain_pg import resolve_stored_chain_on
from regulated_core.input_evidence_pg import record_with_inputs
from regulated_core.models import Decision
from regulated_core.permit import EmissionError
from regulated_core.reservation_subject import request_subject
from regulated_core.target import Outcome, effect_of


@dataclass(frozen=True)
class DraftAuthorization:
    status: str
    permit: object = None
    decision: object = None
    preparation: object = None
    alert_id: str | None = None
    detail: str = ""


class PreparedDelegatedDraft:
    """Host composition; final authority is still checked inside the receiver.

    Inputs already carry a host-signed admission and exact release-authority
    claim. The host's currentness verifier must authenticate executor membership,
    exact request scope and preflight. All configured authorities are pinned by
    the host, never selected from a request. Reservations remain retained after
    a later refusal or uncertain outcome; this class does not recycle capacity.
    It creates no effect and does not claim deployed identity or key isolation.
    """

    def __init__(self, *, pool, delegated, recorder, issuer, budget, alerts):
        self.pool, self.delegated = pool, delegated
        self.recorder, self.issuer, self.budget, self.alerts = recorder, issuer, budget, alerts

    def authorize_current(self, *, tenant: str, request_id: str, admit) -> DraftAuthorization:
        """Serialize this host's admissions before it assigns decision timestamps.

        ``admit`` is a trusted host callback, not request code. It authenticates
        the caller and returns freshly stamped inputs, admission and output.
        Stamping requests before they wait in a queue can make an earlier
        timestamp arrive after a later recorded decision; the recorder must
        refuse that ordering. This lane preserves the guard rather than changing
        old signed inputs. Other host writers must obey their own ordering;
        the recorder still rejects a conflicting writer outside this lane.
        """
        request_hash = digest_hex({"schema": "executable-assurance/delegated-intake/v1",
                                   "tenant": tenant, "request_id": request_id})
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SET LOCAL lock_timeout = '30s'")
                conn.execute("SET LOCAL statement_timeout = '30s'")
                conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                             ("reference-delegated-intake:" + tenant,))
                inputs, admission, output = admit()
                if inputs.context.tenant_id != tenant or admission.request_id != request_id:
                    raise EmissionError("host intake returned a different tenant or request")
                result = self.authorize(inputs, admission, output)
            return result
        except EmissionError as exc:
            status, code, detail = "refused", "ADMISSION_REFUSED", str(exc)
        except Exception as exc:
            status, code = "unknown", "AUTHORIZATION_UNCERTAIN"
            detail = f"Host intake was not confirmed ({type(exc).__name__}); reconcile the request."
        alert = self.alerts.append_refusal(tenant_id=tenant, request_hash=request_hash,
                                           decision_hash=None, code=code)
        return DraftAuthorization(status, alert_id=alert, detail=detail)

    def authorize(self, inputs, admission, output: bytes) -> DraftAuthorization:
        root = self.delegated.root
        tenant = inputs.context.tenant_id
        envelope = None
        request_hash = digest_hex({"schema": "executable-assurance/delegated-draft-request/v1",
                                   "inputs": inputs.digest(), "admission": admission.signed_body(),
                                   "output_sha256": hashlib.sha256(output).hexdigest()})
        try:
            if (self.issuer.delegated_verifier is not self.delegated
                    or self.issuer.input_verifier is not root.inputs
                    or self.issuer.evidence_verifier is not root.history):
                raise EmissionError("delegated issuer is not pinned to these input and history authorities")
            bound = effect_of(inputs.action.destination)
            claim = release_authority_of(json.loads(inputs.action.destination).get(RELEASE_AUTHORITY_FIELD))
            if bound is None or claim is None or hashlib.sha256(output).hexdigest() != bound.output_digest:
                raise EmissionError("delegated draft lacks exact output and authority bindings")
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
                conn.execute("SET LOCAL lock_timeout = '5s'")
                conn.execute("SET LOCAL statement_timeout = '10s'")
                root.inputs.verify_on(conn, inputs, admission, evidence_key_id=root.evidence_key_id,
                                      now_us=root.inputs.now_on(conn))
                epoch = conn.execute("SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 "
                                     "WHERE tenant=%s", (tenant,)).fetchone()[0]
                checked = resolve_stored_chain_on(conn, tenant, claim.grant_digest,
                                                  verifier=root, expected_epoch=int(epoch))
                chain = checked.chain
                if ((claim.chain_digest, claim.root_digest, claim.mission) !=
                        (chain.digest, chain.root.digest(), chain.root.root_mission)
                        or bound.mission != claim.mission
                        or chain.leaf.subject != inputs.context.actor.actor_id
                        or inputs.action.action_id not in chain.leaf.operations
                        or bound.target.digest() not in chain.leaf.targets):
                    raise EmissionError("authenticated draft exceeds its retained child authority")
                revision = self.delegated.executors.verify_on(conn, tenant, chain.leaf.subject)
                if not isinstance(revision, str) or not revision:
                    raise EmissionError("current host executor membership is unavailable")
            policy = self.delegated.policy
            decision = policy.evaluate(inputs.assertion, inputs.action, inputs.context)
            if not decision.is_allow_class:
                envelope = record_with_inputs(self.recorder, inputs, decision,
                                               admission=admission, verifier=root.inputs)
                raise EmissionError("delegated policy does not allow this draft")
            terms = policy.mission_budget(inputs.action.action_id)
            if not terms or terms["limit"] != chain.root.budget_limit:
                raise EmissionError("draft policy budget differs from its root ceiling")
            subject = request_subject(inputs.assertion, inputs.action, inputs.context, policy.ref,
                                      mission=claim.mission, nonce=admission.permit_nonce)
            try:
                reservation = self.budget.reserve(tenant, claim.mission, reservation_id=admission.permit_nonce,
                                    subject_digest=subject, **terms)
            except BudgetError:
                envelope = record_with_inputs(
                    self.recorder, inputs, Decision.deny("BUDGET_EXCEEDED", "The root mission limit is exhausted"),
                    admission=admission, verifier=root.inputs,
                )
                raise EmissionError("root mission budget refused the reservation")
            envelope = record_with_inputs(self.recorder, inputs, decision,
                                           admission=admission, verifier=root.inputs)
            deadline = min([chain.expires_at_us, admission.expires_at_us] +
                           [c.expires_at_us for c in inputs.context.actor.credentials])
            draft = self.issuer.draft(
                envelope, output, target=bound.target, operation=inputs.action.action_id,
                expected_target_state=bound.target_state, principal=chain.leaf.subject,
                approval_ref="", qualification_digests=(), ttl_us=root.inputs.max_age_us,
                nonce=admission.permit_nonce, not_after_us=deadline, mission=claim.mission,
                budget_reservation=reservation.reservation_id, budget_units=terms["units"],
                policy_version=self.issuer.expected_policy_version,
                grant_digest=claim.grant_digest, chain_digest=claim.chain_digest, root_digest=claim.root_digest,
            )
            preparation = self.recorder.prepare_target(
                draft, issuer_key_id=root.permit_key_id, policy=policy,
                evidence_verifier=root.history, max_decision_age_us=root.inputs.max_age_us,
                input_verifier=root.inputs, clock=root.inputs.clock,
                delegated_verifier=self.delegated,
            )
            signed = self.issuer.issue(draft)
            return DraftAuthorization("authorized", signed, envelope, preparation)
        except EmissionError as exc:
            status, code = "refused", "ADMISSION_REFUSED"
            detail = str(exc)
        except Exception as exc:
            status, code = "unknown", "AUTHORIZATION_UNCERTAIN"
            detail = (f"Authorization was not confirmed ({type(exc).__name__}); "
                      "reconcile the retained request and alert.")
        alert_id = self.alerts.append_refusal(
            tenant_id=tenant, request_hash=request_hash,
            decision_hash=None if envelope is None else envelope.record_hash, code=code,
        )
        return DraftAuthorization(status, decision=envelope, alert_id=alert_id, detail=detail)


class AuditedDelegatedReceiver(PostgresTargetReceiver):
    """Keep the core receiving transaction and retain uncertified outcomes.

    Alerts use a separate committed transaction after receiving returns or
    raises. An alert-write failure propagates; this is not an atomic outbox and
    cannot guarantee an alert if the process dies before the append. The exact
    receiving receipt remains the reconciliation authority. Status/observation
    stay read/reconciliation operations and do not deliver the draft.
    """

    def __init__(self, *, alerts, **parameters):
        super().__init__(**parameters)
        self.alerts = alerts

    def _uncertain(self, signed):
        self.alerts.append(
            tenant_id=self._effect.tenant_id,
            decision_hash=signed.permit.decision_record_hash,
            permit_hash=digest_hex(signed.permit.signed_body()),
            code="TARGET_UNKNOWN", outcome="unknown",
        )

    def commit(self, signed, output):
        try:
            result = super().commit(signed, output)
        except Exception:
            self._uncertain(signed)
            raise
        if result.outcome is Outcome.UNKNOWN:
            self._uncertain(signed)
        elif result.outcome in {Outcome.FAILED, Outcome.NOT_COMMITTED}:
            self.alerts.append_refusal(
                tenant_id=self._effect.tenant_id,
                request_hash=digest_hex(signed.permit.signed_body()),
                decision_hash=signed.permit.decision_record_hash,
                code="AUTHORIZATION_REFUSED",
            )
        return result
