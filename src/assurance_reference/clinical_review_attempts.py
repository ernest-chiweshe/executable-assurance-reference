"""Retain one clinical review preparation without issuing release authority.

This uses the existing session-bound application-state namespace. It is workflow
state, not a signature, approval, target receipt or administrator-resistant log.
The retained owner session and exact artifact remain inputs to the intact gate.
"""
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

from assurance_reference.project_state import SessionProjectPool
from assurance_reference.session_credentials import AuthenticatedSession
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import canonical_bytes
from regulated_core.target import ABSENT

SCHEMA = "reference/clinical-review-attempt/v1"


def _state_bytes(value):
    # This is ordinary application JSON, not signed evidence. Preserve the
    # original clinical session's finite float seconds without changing any
    # core canonicalization rule or rebinding the approved contract.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


class ClinicalReviewStateError(ValueError):
    """A retained preparation is missing, inconsistent or belongs elsewhere."""


def _key(tenant, principal, nonce):
    if any(not isinstance(v, str) or not v for v in (tenant, principal, nonce)):
        raise ClinicalReviewStateError("explicit clinical attempt identity required")
    return sha256(canonical_bytes([SCHEMA, tenant, principal, nonce])).hexdigest()


def prepare_packet(*, context, contract, artifact_address, artifact):
    """Copy exact pre-approval inputs; do not retain a caller's approval object."""
    if (not isinstance(context, EmissionContext) or context.approval is not None
            or context.actor_roles or context.is_producer or context.retained_state is not None):
        raise ClinicalReviewStateError("clinical preparation requires an unapproved human context")
    packet = {"schema": SCHEMA, "context": asdict(context), "contract": contract,
              "artifact_address": artifact_address, "artifact_sha256": sha256(artifact).hexdigest()}
    return validate_packet(packet, tenant=context.tenant, principal=context.actor_id, nonce=context.nonce)


def validate_packet(packet, *, tenant, principal, nonce):
    """Validate workflow bindings only; every release still needs fresh authority."""
    try:
        _key(tenant, principal, nonce)
        if set(packet) != {"schema", "context", "contract", "artifact_address", "artifact_sha256"}:
            raise ValueError("unexpected preparation fields")
        ctx = EmissionContext(**packet["context"])
        contract = packet["contract"]
        session = contract["clinical_session"]
        if (packet["schema"] != SCHEMA or (ctx.tenant, ctx.actor_id, ctx.nonce) != (tenant, principal, nonce)
                or ctx.approval is not None or ctx.actor_roles or ctx.is_producer
                or ctx.retained_state is not None or ctx.review_producer_id
                or ctx.vertical_name != "health" or not ctx.project_id or not ctx.action_id
                or not ctx.release_target or type(ctx.now_us) is not int or ctx.now_us <= 0
                or type(ctx.not_after_us) is not int or ctx.not_after_us <= ctx.now_us):
            raise ValueError("context scope or lifetime differs")
        digest = packet["artifact_sha256"]
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                or packet["artifact_address"] != digest
                or contract["prepared_release"]["artifact_sha256"] != digest
                or contract["release_target"]["expected_state"] != ABSENT
                or contract["release_target"]["kind"] != "filesystem"
                or contract["release_target"]["identity"] != str(Path(ctx.release_target).resolve())
                or ctx.project_id != contract["session_id"] + ":" + contract["doc_id"]
                or ctx.action_id != "finalise:" + contract["document_digest"]):
            raise ValueError("artifact or create-only target differs")
        if (set(session) != {"schema", "user_id", "username", "workspace_id", "reference", "expires_at"}
                or session["schema"] != "health/session-admission/v1"
                or (session["user_id"], session["workspace_id"]) != (principal, tenant)
                or any(not isinstance(session[k], str) or not session[k]
                       for k in ("username", "reference"))
                or type(session["expires_at"]) not in (int, float)
                or not 0 < session["expires_at"] < float("inf")):
            raise ValueError("retained clinical session differs")
        return json.loads(_state_bytes(packet))
    except (KeyError, TypeError, ValueError) as error:
        raise ClinicalReviewStateError("clinical review preparation failed validation") from error


class RetainedClinicalReviewAttempts:
    """Owner-admitted insert-and-compare preparations; no update/delete API."""

    def __init__(self, *, pool, sessions, authenticated):
        if not isinstance(authenticated, AuthenticatedSession):
            raise ValueError("clinical review preparation requires an authenticated session")
        namespace = "health-review-attempt-v1:" + sha256(
            canonical_bytes(authenticated.principal)).hexdigest()
        self._pool = SessionProjectPool(pool=pool, sessions=sessions,
            authenticated=authenticated, namespace=namespace)
        self._tenant, self._principal = authenticated.tenant, authenticated.principal

    def _decode(self, state, nonce):
        try:
            state = json.loads(state) if isinstance(state, str) else state
            # JSONB retains this as a string, so database numeric rendering
            # cannot change the original finite float seconds in the contract.
            if (set(state) != {"packet_json", "digest"}
                    or not isinstance(state["packet_json"], str)
                    or sha256(state["packet_json"].encode("utf-8")).hexdigest() != state["digest"]):
                raise ValueError("preparation digest differs")
            packet = json.loads(state["packet_json"])
            if _state_bytes(packet).decode("utf-8") != state["packet_json"]:
                raise ValueError("preparation encoding differs")
            return validate_packet(packet, tenant=self._tenant,
                                   principal=self._principal, nonce=nonce)
        except (KeyError, TypeError, ValueError) as error:
            raise ClinicalReviewStateError("stored clinical review preparation is inconsistent") from error

    def retain(self, packet):
        try:
            nonce = packet["context"]["nonce"]
        except (KeyError, TypeError) as error:
            raise ClinicalReviewStateError("clinical attempt identity is missing") from error
        packet = validate_packet(packet, tenant=self._tenant, principal=self._principal, nonce=nonce)
        identifier = _key(self._tenant, self._principal, nonce)
        encoded = _state_bytes(packet)
        state = _state_bytes({"packet_json": encoded.decode("utf-8"), "digest": sha256(encoded).hexdigest()}).decode()
        with self._pool.connection() as conn:
            conn.execute("INSERT INTO projectos_states (tenant_id,namespace,project_id,revision,state) "
                "VALUES (%s,%s,%s,1,%s::jsonb) ON CONFLICT DO NOTHING",
                (self._tenant, self._pool.namespace, identifier, state))
            row = conn.execute("SELECT state FROM projectos_states WHERE tenant_id=%s "
                "AND namespace=%s AND project_id=%s",
                (self._tenant, self._pool.namespace, identifier)).fetchone()
            if row is None or _state_bytes(self._decode(row[0], nonce)) != encoded:
                raise ClinicalReviewStateError("existing preparation differs; nothing overwritten")

    def get(self, nonce):
        identifier = _key(self._tenant, self._principal, nonce)
        with self._pool.connection() as conn:
            row = conn.execute("SELECT state FROM projectos_states WHERE tenant_id=%s "
                "AND namespace=%s AND project_id=%s",
                (self._tenant, self._pool.namespace, identifier)).fetchone()
            return None if row is None else self._decode(row[0], nonce)
