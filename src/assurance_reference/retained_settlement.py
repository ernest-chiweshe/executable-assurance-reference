"""One retained settlement per approved review, resumable by re-entry and recoverable by observation (X-4).

Generic form of the frozen Studio owner chain (``studio_owner_settlement_pg.py@6bba989a``, re-entry and reuse of a
retained settlement) over the reference pack gate:

* ``settle`` turns an approved review into exactly one target authorization. Its first call writes a durable
  ``settling`` intent naming every binding (tenant, review, principal, contract, exact bytes, target and nonce),
  asks the inherited gate to authorize, and retains that exact authorization (decision envelope, signed permit
  with its live budget reservation, and the decision inputs). Each step holds the review's settlement lock.
* A nonce settles under one review only (``settlement_nonce_once``): naming it under another review refuses.
* Re-entering with the same bindings returns the SAME retained authorization, re-authenticated (permit signature,
  decision signature and their binding), so the live reservation is resumed rather than reserved again. Any changed
  binding refuses. An intent left without a retained authorization (a crash between the two named points) is
  UNKNOWN: it is never re-authorized, because a second permit could double-spend.
* ``commit`` releases through the inherited exact-session gate; the target's own single-use nonce refuses any second
  effect. ``observe`` answers from the target receipt only, never by resending.

Nothing here signs, reserves or releases by itself; the inherited gate and targets keep every guard.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json
from types import MappingProxyType
from typing import Any

from psycopg import errors, sql

from factory.projectos.regulated import EmissionDecision
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.engine import TargetAuthorization
from regulated_core.input_evidence import DecisionInputs
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import decode_envelope
from regulated_core.signing import Signature
from regulated_core.target import SignedTargetPermit, TargetPermit

TABLE = "reference_release_settlements_v1"
SETTLING, SETTLED = "settling", "settled"


class SettlementRefused(EmissionError):
    """A settlement request that cannot be served without a second authority or a changed binding."""


class SettlementUnknown(EmissionError):
    """A settlement intent exists without a retained authorization; reconcile by the authorised procedure."""


def migrate_settlements(owner: Any, writer_role: str) -> None:
    """Fresh isolated schema only. The writer may read, insert intents and complete them, never delete."""
    with owner.connection() as conn, conn.transaction():
        conn.execute(f"""CREATE TABLE {TABLE}(
            tenant text NOT NULL, review_id text NOT NULL, binding_digest text NOT NULL CHECK(length(binding_digest)=64),
            nonce text NOT NULL, state text NOT NULL CHECK(state IN ('settling','settled')),
            authorization_body jsonb, PRIMARY KEY(tenant, review_id),
            CONSTRAINT settlement_nonce_once UNIQUE(tenant, nonce),
            CHECK((state = 'settling') = (authorization_body IS NULL)))""")
        name = sql.Identifier(TABLE)
        conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("CREATE POLICY settlement_scope ON {} USING "
                             "(tenant=current_setting('app.tenant',true)) WITH CHECK "
                             "(tenant=current_setting('app.tenant',true))").format(name))
        conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
        conn.execute(sql.SQL("GRANT SELECT, INSERT ON {} TO {}").format(name, sql.Identifier(writer_role)))
        conn.execute(sql.SQL("GRANT UPDATE(state, authorization_body) ON {} TO {}")
                     .format(name, sql.Identifier(writer_role)))


def _encode(authorization: TargetAuthorization) -> dict[str, Any]:
    inputs = DecisionInputs(authorization.assertion, authorization.action, authorization.ctx, authorization.policy)
    body = {"schema": "reference/retained-settlement/v1", "authorized": authorization.authorized,
            "reason": authorization.reason, "decision_kind": authorization.decision_kind,
            "envelope": asdict(authorization.envelope), "permit": asdict(authorization.permit),
            "inputs": inputs.body()}
    encoded = json.loads(json.dumps(body, sort_keys=True, default=_default))
    if _decode(encoded) != authorization:
        raise SettlementRefused("the authorization does not round-trip exactly; it is not retained")
    return encoded


def _default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, MappingProxyType):
        return dict(value)
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"unretainable value {type(value).__name__}")


def _decode(raw: dict[str, Any]) -> TargetAuthorization:
    if not isinstance(raw, dict) or raw.get("schema") != "reference/retained-settlement/v1":
        raise SettlementRefused("retained settlement has an unknown schema")
    inputs = DecisionInputs.decode(raw["inputs"])
    permit = dict(raw["permit"])
    fields = dict(permit["permit"])
    fields["qualification_digests"] = tuple(fields["qualification_digests"])
    signed = SignedTargetPermit(TargetPermit(**fields), Signature(**permit["signature"]))
    return TargetAuthorization(raw["authorized"], raw["reason"], raw["decision_kind"],
                               decode_envelope(raw["envelope"]), signed, inputs.assertion, inputs.action,
                               inputs.context, inputs.policy)


class RetainedSettlements:
    """The settlement store over the dedicated settlement-writer login."""

    def __init__(self, *, pool: Any) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("retained settlements require the settlement writer pool")
        self.pool = pool

    def transaction(self, tenant: str, review_id: str):
        return _Locked(self.pool, tenant, review_id)


class _Locked:
    def __init__(self, pool: Any, tenant: str, review_id: str) -> None:
        self.pool, self.tenant, self.review_id = pool, tenant, review_id

    def __enter__(self):
        # Every context entered here is unwound, with the original exception, if any later step of entry fails.
        with ExitStack() as stack:
            self.conn = stack.enter_context(self.pool.connection())
            stack.enter_context(self.conn.transaction())
            self.conn.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant,))
            self.conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                              ("reference-settlement:" + digest_hex([self.tenant, self.review_id]),))
            self._stack = stack.pop_all()
        return self

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)

    def row(self):
        return self.conn.execute(f"SELECT binding_digest, nonce, state, authorization_body FROM {TABLE}"
                                 " WHERE tenant=%s AND review_id=%s", (self.tenant, self.review_id)).fetchone()

    def intend(self, binding: str, nonce: str) -> None:
        try:
            self.conn.execute(f"INSERT INTO {TABLE}(tenant, review_id, binding_digest, nonce, state)"
                              " VALUES(%s,%s,%s,%s,'settling')", (self.tenant, self.review_id, binding, nonce))
        except errors.UniqueViolation as taken:
            if taken.diag.constraint_name == "settlement_nonce_once":
                raise SettlementRefused("this nonce is already settled for another review") from taken
            raise

    def retain(self, binding: str, body: dict[str, Any]) -> None:
        row = self.conn.execute(f"UPDATE {TABLE} SET state='settled', authorization_body=%s::jsonb"
                                " WHERE tenant=%s AND review_id=%s AND state='settling' AND binding_digest=%s"
                                " RETURNING review_id", (json.dumps(body), self.tenant, self.review_id, binding)
                                ).fetchone()
        if row is None:
            raise SettlementRefused("the settlement intent changed before its authorization was retained")


class SettledReleaseGate:
    """A host pack gate whose permits are settled once per approved review and re-entered idempotently."""

    def __init__(self, gate: Any, settlements: RetainedSettlements) -> None:
        if not isinstance(settlements, RetainedSettlements) or not callable(getattr(gate, "authorize_release", None)):
            raise TypeError("settled release requires the host gate and the retained settlement store")
        self._gate, self._settlements = gate, settlements

    def __getattr__(self, name: str) -> Any:
        return getattr(self._gate, name)

    def _binding(self, contract: dict, artifact: bytes, out_path: str, context: Any) -> str:
        target = self._gate.target_for(out_path, context.tenant)
        return digest_hex({"schema": "reference/settlement-binding/v1", "tenant": context.tenant,
                           "review_id": context.approval, "principal": context.actor_id,
                           "contract": hashlib.sha256(canonical_bytes(dict(contract))).hexdigest(),
                           "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                           "target": target.target.digest(), "operation": target.operation,
                           "nonce": context.nonce, "action_id": context.action_id})

    def _authenticated(self, authorization: TargetAuthorization, out_path: str, context: Any) -> TargetAuthorization:
        engine = self._gate._engine
        target = self._gate.target_for(out_path, context.tenant)
        engine.targets.authenticate(authorization.permit, tenant_id=context.tenant, target=target.target,
                                    operation=target.operation)
        if (not engine._recorder.verify_entry(authorization.envelope)
                or authorization.permit.permit.decision_record_hash != authorization.envelope.record_hash
                or authorization.permit.permit.principal != context.actor_id
                # The signed nonce ties the permit to this review's row: another review's genuine authorization,
                # substituted at rest, verifies everywhere else but names its own nonce (X-4).
                or authorization.permit.permit.nonce != context.nonce
                or authorization.envelope.record.tenant_id != context.tenant):
            raise SettlementRefused("the retained settlement is not this review's authenticated authorization")
        return authorization

    def settle(self, *, spec: Any, contract: dict, artifact: bytes, out_path: str, context: Any) -> EmissionDecision:
        if not context.approval or not context.nonce:
            raise SettlementRefused("a settlement names its approved review and nonce")
        binding = self._binding(contract, artifact, out_path, context)
        with self._settlements.transaction(context.tenant, context.approval) as held:
            row = held.row()
            if row is not None:
                if row[0] != binding or row[1] != context.nonce:
                    raise SettlementRefused("this review is already settled with a different binding")
                if row[2] != SETTLED:
                    raise SettlementUnknown("settlement intent without a retained authorization; reconcile")
                retained = _decode(row[3] if isinstance(row[3], dict) else json.loads(row[3]))
                return EmissionDecision(True, "retained settlement", {"settlement": "re-entered"},
                                        self._authenticated(retained, out_path, context))
            held.intend(binding, context.nonce)
        # Named point "after-intent-before-authorization": the intent is durable before any authority is created.
        decision = self._gate.authorize_release(spec=spec, contract=contract, out_path=out_path, context=context,
                                                artifact=artifact)
        authorization = decision.permit
        if not decision.allowed or not isinstance(authorization, TargetAuthorization) or authorization.permit is None:
            return decision
        body = _encode(authorization)
        # Named point "after-authorization-before-retention": a crash here leaves the intent UNKNOWN.
        with self._settlements.transaction(context.tenant, context.approval) as held:
            held.retain(binding, body)
        return decision


__all__ = ["SETTLED", "SETTLING", "SettledReleaseGate", "RetainedSettlements", "SettlementRefused",
           "SettlementUnknown", "TABLE", "migrate_settlements"]
