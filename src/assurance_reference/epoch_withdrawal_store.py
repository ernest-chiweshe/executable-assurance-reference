"""Governed tenant-epoch writes with exact receipts in one owned transaction.

Staged reference adapter: provisioning and host composition are explicit.
Ordinary epoch reads inherit the original reader unchanged. Explicit governance
reads reuse their governance session or owned transaction. Legacy direct writes always refuse.
"""
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
from threading import RLock, local

from psycopg.pq import TransactionStatus

from assurance_reference.clock_floor import DurableClock
from regulated_core.canonical import canonical_bytes
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from regulated_core.governance_targets import FinalCheckRefused, GovernedChange
from regulated_core.governance_transaction import GovernanceTransactionCheck, run_governance_check
from regulated_core.persistence_pg import PersistenceError, PostgresGovernanceLog, PostgresRevocationLedger, _tenant, decode_envelope
from regulated_core.permit import EmissionError
from regulated_core.signing import Signature
from regulated_core.target import Outcome, SignedTargetPermit, TargetAuthority, TargetPermit, TargetRef, require_permit_clock

from assurance_reference.epoch_withdrawal_admission import KIND, OPERATION, checked_change, withdrawal_bytes, verify_supervisor_approval
from assurance_reference.epoch_withdrawal_review import EpochWithdrawalReviewLoader, _LockedRosterObservation, decode_review, encode_review
from regulated_core.clock import authority_write_committed

PROOF_SCHEMA = "reference/epoch-withdrawal-proof/v1"


def _decode_permit(raw):
    try:
        fields = dict(raw)
        permit = dict(fields.pop("permit"))
        signature = Signature(**fields.pop("signature"))
        if fields:
            raise ValueError("extra permit envelope fields")
        permit["qualification_digests"] = tuple(permit["qualification_digests"])
        signed = SignedTargetPermit(TargetPermit(**permit), signature)
        if canonical_bytes(signed) != canonical_bytes(raw):
            raise ValueError("noncanonical permit")
        return signed
    except (TypeError, ValueError, KeyError) as error:
        raise PersistenceError("invalid withdrawal permit evidence") from error


class GuardedPostgresRevocationLedger(PostgresRevocationLedger):
    def __init__(self, *, pool, clock, guard):
        if (not isinstance(clock, DurableClock) or not isinstance(guard, GovernanceGuard)
                or not callable(getattr(pool, "connection", None))):
            raise TypeError("guarded epoch ledger requires explicit pool, durable clock and governance guard")
        super().__init__(pool=pool)
        self.clock, self.governance_guard = clock, guard
        self._writers = {}
        self._writer_lock = RLock()
        self._epoch_reader = local()

    def revoke(self, tenant_id, *, actor, reason, now_us):
        raise GovernanceRefused("tenant epoch withdrawal requires the registered supervisor governance target")

    def bind_writer(self, *, loader, authority, log):
        if (not isinstance(loader, EpochWithdrawalReviewLoader)
                or not isinstance(authority, TargetAuthority)
                or not isinstance(log, PostgresGovernanceLog)
                or loader.clock is not self.clock or authority.clock is not self.clock
                or loader.roster._proof_verifier.authority is not authority):
            raise TypeError("epoch writer requires its exact review loader and target authority")
        configured = (loader, authority, log)
        tenant = loader.roster._proof_verifier.tenant
        with self._writer_lock:
            if tenant in self._writers and self._writers[tenant] != configured:
                raise TypeError("epoch writer cannot be rebound for this tenant")
            self._writers[tenant] = configured

    def _services(self, tenant):
        with self._writer_lock:
            configured = self._writers.get(tenant)
        if configured is None:
            raise GovernanceRefused("epoch receiving authority has not been composed for this tenant")
        return configured

    @contextmanager
    def _epoch_read_scope(self, connection, tenant):
        """Reuse only this tenant's owned transaction on this synchronous thread."""
        if getattr(self._epoch_reader, "active", None) is not None:
            raise GovernanceRefused("nested epoch transaction read scope")
        if (connection.info.transaction_status != TransactionStatus.INTRANS
                or connection.execute("SELECT current_setting('app.tenant', true)").fetchone()[0] != tenant):
            raise GovernanceRefused("epoch read scope requires its active tenant transaction")
        self._epoch_reader.active = (connection, tenant)
        try:
            yield
        finally:
            del self._epoch_reader.active

    def governance_epoch(self, tenant_id):
        """Explicit writer-authority reader; ordinary epoch() stays inherited."""
        active = getattr(self._epoch_reader, "active", None)
        if active is None:
            with self._writer_lock:
                configured = self._writers.get(tenant_id)
            if configured is None:
                return super().epoch(tenant_id)
            # Admission also reads the epoch before the owned effect starts.
            # Reuse a held governance session there too; otherwise waiting
            # workers can occupy all pool slots while its owner needs a read.
            with configured[2].connection() as connection, connection.transaction():
                _tenant(connection, tenant_id)
                return int(connection.execute(
                    "SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 WHERE tenant=%s",
                    (tenant_id,)).fetchone()[0])
        connection, tenant = active
        if (tenant_id != tenant or connection.info.transaction_status != TransactionStatus.INTRANS
                or connection.execute("SELECT current_setting('app.tenant', true)").fetchone()[0] != tenant):
            raise GovernanceRefused("epoch read differs from its owned tenant transaction")
        return int(connection.execute(
            "SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 WHERE tenant=%s",
            (tenant,)).fetchone()[0])

    @contextmanager
    def _effect_transaction(self, tenant, log):
        # The governance scope already owns this session. Each operation owns
        # its transaction; no outer transaction or additional governor checkout.
        with log.connection() as connection, connection.transaction():
            _tenant(connection, tenant)
            with self._epoch_read_scope(connection, tenant):
                yield connection

    @staticmethod
    def _target(tenant):
        return TargetRef("governance", KIND + ":" + tenant)

    def _authenticate(self, signed, *, tenant, nonce, digest, prior):
        _, authority, _ = self._services(tenant)
        if not isinstance(signed, SignedTargetPermit):
            raise EmissionError("epoch withdrawal requires original signed target authority")
        authority.authenticate(signed, tenant_id=tenant, target=self._target(tenant), operation=OPERATION)
        p = signed.permit
        if (p.nonce != nonce or p.output_digest != digest or p.expected_target_state != str(prior)
                or p.action_id != OPERATION or p.revocation_epoch != prior
                or not p.approval_ref or p.grant_digest or p.preparation_digest):
            raise EmissionError("epoch withdrawal signed authority binding differs")
        return p

    def _decision(self, signed, approved, envelope):
        loader, _, _ = self._services(signed.permit.tenant_id)
        p = signed.permit
        if (not loader.recorder.verify_entry(envelope)
                or envelope.record.record_id != p.decision_record_id
                or envelope.record_hash != p.decision_record_hash
                or envelope.record.actor_id != p.principal
                or approved.certificate.request_id != p.approval_ref):
            raise EmissionError("epoch withdrawal issuing decision binding differs")
        expected = replace(approved.envelope.record, record_id=envelope.record.record_id,
                           decided_at_us=envelope.record.decided_at_us)
        if envelope.record != expected:
            raise EmissionError("epoch withdrawal current decision differs from approved record")

    def apply(self, governed):
        loader, authority, log = self._services(getattr(governed, "tenant_id", None))
        if (not isinstance(governed, GovernedChange) or governed.first_state_only
                or governed.kind != KIND or governed.operation != OPERATION
                or governed.subject != governed.tenant_id
                or not isinstance(governed.final_check, GovernanceTransactionCheck)):
            raise FinalCheckRefused("epoch withdrawal requires exact governed transaction authority")
        tenant = governed.tenant_id
        self.governance_guard.require(KIND, tenant)
        change = checked_change(tenant, governed.change)
        prior = change["prior_epoch"]
        digest = sha256(withdrawal_bytes(tenant, prior_epoch=prior, reason=change["reason"])).hexdigest()
        if (governed.approved_prior != str(prior) or governed.expected_state != str(prior + 1)
                or governed.change_digest != digest):
            raise FinalCheckRefused("epoch withdrawal approved state or bytes differ")
        signed = governed.authority_proof
        try:
            p = self._authenticate(signed, tenant=tenant, nonce=governed.nonce, digest=digest, prior=prior)
        except EmissionError as error:
            raise FinalCheckRefused(str(error)) from error
        with self._effect_transaction(tenant, log) as connection:
            try:
                # Lock order: roster, review, tenant epoch, then budget. The final
                # loader call rereads under the same locks after budget contention.
                loader.load_on(connection, tenant_id=tenant, review_id=p.approval_ref,
                               change=change, requester_id=p.principal)
                connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                                   ("regulated-revocation:" + tenant,))
                current = int(connection.execute(
                    "SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 WHERE tenant=%s",
                    (tenant,)).fetchone()[0])
                if current != prior:
                    raise FinalCheckRefused("epoch changed since withdrawal approval; nothing written")
                entries = loader.recorder.entries(tenant)
                envelope = next((env for env in entries if env.record.record_id == p.decision_record_id), None)
                if envelope is None:
                    raise FinalCheckRefused("withdrawal issuing decision is absent")
                run_governance_check(governed.final_check, connection)
                admitted = loader.load_on(connection, tenant_id=tenant, review_id=p.approval_ref,
                                          change=change, requester_id=p.principal)
                self._decision(signed, admitted.approved, envelope)
                authority.current(signed, connection=connection, at_effect=True)
                reading = require_permit_clock(p, self.clock, connection=connection,
                                               effect_margin_us=authority.effect_margin_us)
                now = reading.now_us
                if (now >= admitted.approved.envelope.record.decided_at_us + 3_600_000_000
                        or any(now >= r.expires_at_us for r in admitted.approved.credential_receipts)):
                    raise FinalCheckRefused("supervisor approval expired before epoch append")
                proof = {"schema": PROOF_SCHEMA, "review": encode_review(tenant, change, admitted.approved),
                         "permit": json.loads(canonical_bytes(signed)),
                         "decision": json.loads(canonical_bytes(envelope)), "roster_digest": admitted.roster_digest,
                         "clock_domain": reading.domain, "at_us": now}
                body = canonical_bytes(proof).decode("utf-8")
                fingerprint = sha256(body.encode("utf-8")).hexdigest()
            except (EmissionError, PersistenceError) as error:
                # All checks precede the first epoch/receipt write. The owned
                # transaction also rolls back any consumed budget on refusal.
                raise FinalCheckRefused(str(error)) from error
            connection.execute(
                "INSERT INTO regulated_revocation_events_v1 (tenant,epoch,actor,reason,revoked_at_us)"
                " VALUES (%s,%s,%s,%s,%s)", (tenant, prior + 1, p.principal, change["reason"], now))
            connection.execute(
                "INSERT INTO reference_epoch_withdrawal_receipts_v1"
                " (tenant,epoch,operation,nonce,change_digest,proof_digest,proof)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (tenant, prior + 1, OPERATION, p.nonce, digest, fingerprint, body))
        authority_write_committed()  # after the commit: a later rollback past this epoch is detected

    def receipt(self, tenant_id, operation, nonce, change_digest):
        loader, _, log = self._services(tenant_id)
        if tenant_id != loader.roster._proof_verifier.tenant or operation != OPERATION:
            raise PersistenceError("withdrawal receipt scope differs")
        with log.connection() as connection, connection.transaction():
            _tenant(connection, tenant_id)
            row = connection.execute(
                "SELECT r.epoch,r.proof_digest,r.proof,e.actor,e.reason,e.revoked_at_us"
                " FROM reference_epoch_withdrawal_receipts_v1 r"
                " JOIN regulated_revocation_events_v1 e ON e.tenant=r.tenant AND e.epoch=r.epoch"
                " WHERE r.tenant=%s AND r.operation=%s AND r.nonce=%s AND r.change_digest=%s",
                (tenant_id, operation, nonce, change_digest)).fetchone()
            if row is None:
                return Outcome.UNKNOWN
            epoch, fingerprint, body, actor, reason, at_us = row
            if not isinstance(body, str) or sha256(body.encode("utf-8")).hexdigest() != fingerprint:
                raise PersistenceError("withdrawal receipt body integrity differs")
            proof = json.loads(body)
            if (set(proof) != {"schema", "review", "permit", "decision", "roster_digest", "clock_domain", "at_us"}
                    or proof["schema"] != PROOF_SCHEMA or proof["at_us"] != at_us
                    or proof["clock_domain"] != self.clock.domain):
                raise PersistenceError("withdrawal receipt proof or clock differs")
            change, approved = decode_review(tenant_id, proof["review"])
            if (change["prior_epoch"] + 1 != epoch or change["reason"] != reason
                    or sha256(withdrawal_bytes(tenant_id, prior_epoch=change["prior_epoch"],
                                              reason=reason)).hexdigest() != change_digest):
                raise PersistenceError("withdrawal event differs from approved change")
            signed = _decode_permit(proof["permit"])
            p = self._authenticate(signed, tenant=tenant_id, nonce=nonce,
                                   digest=change_digest, prior=change["prior_epoch"])
            if (actor != p.principal or p.clock_domain != proof["clock_domain"]
                    or not p.issued_at_us <= at_us < p.expires_at_us):
                raise PersistenceError("withdrawal event time or requester differs")
            self._decision(signed, approved, decode_envelope(proof["decision"]))
            history = loader.roster._verified_history(connection, loader.installation)
            roster = next((r for r, _ in history if r.digest() == proof["roster_digest"]), None)
            if roster is None:
                raise PersistenceError("withdrawal historical roster authority is absent")
            verify_supervisor_approval(approved, workflow=loader.workflow, recorder=loader.recorder,
                roster_store=_LockedRosterObservation(loader.installation, roster),
                installation=loader.installation, tenant_id=tenant_id, change=change,
                requester_id=actor, now_us=at_us)
            # Historical authentication deliberately ignores current revocation
            # and expiry: this exact committed effect already happened.
            return Outcome.COMMITTED
