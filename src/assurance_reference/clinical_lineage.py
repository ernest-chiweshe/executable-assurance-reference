"""Session-bound historical Health authorization evidence in application state.

The host selects a separate clinician namespace in the existing FORCE-RLS
project state table. Writes are insert-and-compare, never update or delete.
The application-state login still has its existing update privileges: this is
durable local evidence, not compliance WORM or administrator-resistant storage.
An authorization record never establishes that the receiving effect committed;
that answer remains with the unchanged target receipt and reconciliation path.
"""

from hashlib import sha256
import json

from assurance_reference.lineage_gate import LineageUnavailable
from assurance_reference.project_state import SessionProjectPool
from assurance_reference.qualified_engine import QualificationSet
from assurance_reference.session_credentials import AuthenticatedSession
from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockError
from regulated_core.engine import TargetAuthorization
from regulated_core.persistence_pg import PersistenceError, decode_envelope
from regulated_core.qualification import QualificationError
from regulated_core.signing import Signature
from regulated_core.target import SignedTargetPermit, TargetPermit


SCHEMA = "reference/clinical-authorization-lineage/v1"


def _identifier(tenant, principal, nonce):
    if any(not isinstance(value, str) or not value for value in (tenant, principal, nonce)):
        raise LineageUnavailable("explicit clinical lineage identity required")
    return sha256(canonical_bytes([SCHEMA, tenant, principal, nonce])).hexdigest()


def authorization_packet(decision, *, tenant, principal):
    """Bind the already verified gate answer to the authenticated recipient."""
    authorization = decision.permit
    if (not decision.allowed or not isinstance(authorization, TargetAuthorization)
            or not authorization.authorized or authorization.permit is None):
        raise LineageUnavailable("only a verified allowed authorization can be retained")
    permit = authorization.permit.permit
    if (permit.tenant_id, permit.principal) != (tenant, principal):
        raise LineageUnavailable("clinical lineage belongs to another authenticated identity")
    packet = json.loads(canonical_bytes({"schema": SCHEMA, "tenant": tenant,
        "principal": principal, "nonce": permit.nonce, "evidence": decision.evidence}))
    _validate(packet, tenant=tenant, principal=principal, nonce=permit.nonce)
    lineage = packet["evidence"]["qualification_lineage"]
    if (lineage["signed_target_permit"] != json.loads(canonical_bytes(authorization.permit))
            or packet["evidence"]["authorization_decision"] != json.loads(canonical_bytes(authorization.envelope))):
        raise LineageUnavailable("clinical lineage differs from the verified gate answer")
    return packet


def _validate(packet, *, tenant, principal, nonce):
    """Check stored integrity/bindings; this does not issue or refresh authority."""
    try:
        _identifier(tenant, principal, nonce)
        if (set(packet) != {"schema", "tenant", "principal", "nonce", "evidence"}
                or (packet["schema"], packet["tenant"], packet["principal"], packet["nonce"])
                != (SCHEMA, tenant, principal, nonce)):
            raise ValueError("record scope differs")
        lineage = packet["evidence"]["qualification_lineage"]
        permit = lineage["signed_target_permit"]["permit"]
        envelope = packet["evidence"]["authorization_decision"]
        record = envelope["record"]
        if ((permit["tenant_id"], permit["principal"], permit["nonce"]) != (tenant, principal, nonce)
                or (record["tenant_id"], record["actor_id"]) != (tenant, principal)
                or permit["assertion_id"] != record["assertion_id"]
                or permit["action_id"] != record["action"]["action_id"]
                or permit["clock_domain"] != envelope["domain"]
                or not (permit["decision_record_hash"] == lineage["decision_record_hash"] == envelope["record_hash"])
                or not (permit["decision_record_id"] == lineage["decision_record_id"] == record["record_id"])):
            raise ValueError("signed evidence scope differs")
    except (KeyError, TypeError, ValueError) as error:
        raise LineageUnavailable("clinical lineage failed integrity validation") from error


class RetainedClinicalLineage:
    """Host-owned store: session admission on every historical read and append."""

    def __init__(self, *, pool, sessions, authenticated, qualifications, recorder, permit_authority):
        if not isinstance(authenticated, AuthenticatedSession):
            raise ValueError("clinical lineage requires an authenticated session")
        if (not isinstance(qualifications, QualificationSet)
                or not callable(getattr(recorder, "verify_entry", None))
                or not isinstance(permit_authority, str) or not permit_authority):
            raise ValueError("clinical lineage requires host-pinned historical verification")
        self._qualifications, self._recorder = qualifications, recorder
        self._permit_authority = permit_authority
        # Hash the principal to make the namespace unambiguous; the tenant is
        # independently bound by SessionProjectPool and the existing RLS policy.
        namespace = "health-authorization-lineage-v1:" + sha256(
            canonical_bytes(authenticated.principal)).hexdigest()
        self._pool = SessionProjectPool(pool=pool, sessions=sessions,
            authenticated=authenticated, namespace=namespace)
        self._tenant, self._principal = authenticated.tenant, authenticated.principal

    def _decode(self, state, nonce):
        try:
            state = json.loads(state) if isinstance(state, str) else state
            if set(state) != {"packet", "digest"}:
                raise ValueError("unexpected stored fields")
            packet = state["packet"]
            if sha256(canonical_bytes(packet)).hexdigest() != state["digest"]:
                raise ValueError("stored digest differs")
            _validate(packet, tenant=self._tenant, principal=self._principal, nonce=nonce)
            evidence = packet["evidence"]
            envelope = decode_envelope(evidence["authorization_decision"])
            if not self._recorder.verify_entry(envelope):
                raise ValueError("retained decision signature is not trusted")
            signed = evidence["qualification_lineage"]["signed_target_permit"]
            body = dict(signed["permit"])
            body["qualification_digests"] = tuple(body["qualification_digests"])
            permit = SignedTargetPermit(TargetPermit(**body), Signature(**signed["signature"]))
            verified = self._qualifications.retained_lineage(permit, permit_authority=self._permit_authority)
            if canonical_bytes(verified) != canonical_bytes(evidence["qualification_lineage"]):
                raise ValueError("retained report lineage differs from host-pinned evidence")
            return json.loads(canonical_bytes(packet))
        except (KeyError, TypeError, ValueError, PersistenceError, QualificationError, ClockError) as error:
            raise LineageUnavailable("stored clinical lineage is inconsistent") from error

    def retain(self, decision):
        packet = authorization_packet(decision, tenant=self._tenant, principal=self._principal)
        nonce = packet["nonce"]
        identifier = _identifier(self._tenant, self._principal, nonce)
        encoded = canonical_bytes(packet)
        state = canonical_bytes({"packet": packet, "digest": sha256(encoded).hexdigest()}).decode()
        with self._pool.connection() as conn:
            conn.execute("INSERT INTO projectos_states (tenant_id,namespace,project_id,revision,state) "
                "VALUES (%s,%s,%s,1,%s::jsonb) ON CONFLICT DO NOTHING",
                (self._tenant, self._pool.namespace, identifier, state))
            row = conn.execute("SELECT state FROM projectos_states WHERE tenant_id=%s "
                "AND namespace=%s AND project_id=%s",
                (self._tenant, self._pool.namespace, identifier)).fetchone()
            if row is None or canonical_bytes(self._decode(row[0], nonce)) != encoded:
                raise LineageUnavailable("existing clinical lineage differs; nothing overwritten")

    def get(self, nonce):
        identifier = _identifier(self._tenant, self._principal, nonce)
        with self._pool.connection() as conn:
            row = conn.execute("SELECT state FROM projectos_states WHERE tenant_id=%s "
                "AND namespace=%s AND project_id=%s",
                (self._tenant, self._pool.namespace, identifier)).fetchone()
            return None if row is None else self._decode(row[0], nonce)
