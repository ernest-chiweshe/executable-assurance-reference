"""Current D5 source custody on the managed review store, with explicit issuer trust.

The caller supplies a signed source attestation; this adapter never signs or
asserts that a source issuer is professionally qualified. Provisioning the issuer,
its review process and domain credentials remains a host responsibility. There is
no customer-facing source mutation endpoint in this module.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, replace
from typing import Any

from factory.pg_session import SessionBoundPool
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.review_store import PostgresReviewStore
from regulated_core.signing import Signature, TrustDirectory

from .demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from .demonstration_surfaces import EvidenceUnavailable
from .demonstrations import USES

SCHEMA = "d5/reviewed-source/v1"


def source_payload(snapshot: EvidenceSnapshot, use: str, sequence: int, *, withdrawn: bool = False) -> dict[str, Any]:
    """Construct data for an independently authorized source reviewer to sign."""
    if use not in USES or type(sequence) is not int or sequence < 1 or type(withdrawn) is not bool:
        raise EvidenceUnavailable("Invalid source domain, sequence or withdrawal state")
    return {"schema": SCHEMA, "use": use, "sequence": sequence, "withdrawn": withdrawn,
            "snapshot": asdict(snapshot)}


def _decode(payload: Mapping[str, Any]) -> EvidenceSnapshot:
    if set(payload) != {"schema", "use", "sequence", "withdrawn", "snapshot"} or payload["schema"] != SCHEMA:
        raise EvidenceUnavailable("Invalid signed source envelope")
    raw = payload["snapshot"]
    if not isinstance(raw, dict) or set(raw) != set(EvidenceSnapshot.__dataclass_fields__):
        raise EvidenceUnavailable("Invalid signed evidence snapshot")
    data = dict(raw)
    for field in ("sources", "statements"):
        data[field] = tuple(tuple(row) for row in data[field])
    for field in ("disclosures", "conflicts"):
        data[field] = tuple(data[field])
    snapshot = EvidenceSnapshot(**data)
    if canonical_bytes(payload) != canonical_bytes(source_payload(
            snapshot, payload["use"], payload["sequence"], withdrawn=payload["withdrawn"])):
        raise EvidenceUnavailable("Noncanonical source representation")
    return snapshot


class RetainedEvidence:
    """Tenant/domain/case-bound signed source revisions; construction performs no I/O."""
    def __init__(self, *, pool: SessionBoundPool, trust: TrustDirectory,
                 authorities: Mapping[str, frozenset[str]]) -> None:
        if not isinstance(pool, SessionBoundPool):
            raise ValueError("Source custody requires the managed bounded session")
        self.authorities = {use: frozenset(keys) for use, keys in authorities.items()}
        if (not self.authorities or any(use not in USES or not keys or
                any(not trust.is_known(key) for key in keys) for use, keys in self.authorities.items())):
            raise ValueError("Every source domain needs explicit trusted source-review authorities")
        self.pool, self.trust = pool, trust
        self.store = PostgresReviewStore(pool=pool)

    @staticmethod
    def _id(tenant: str, use: str, case_id: str) -> str:
        if not tenant or use not in USES or not isinstance(case_id, str) or not case_id.strip():
            raise EvidenceUnavailable("Tenant, source domain and case are required")
        return "d5-source:" + digest_hex([tenant, use, case_id])

    @contextmanager
    def guard(self, tenant: str, use: str, case_id: str) -> Iterator[None]:
        # Both readers during a release and writers take this exact session lock.
        # Independent evidence/permit transactions still commit before an effect.
        key = int.from_bytes(bytes.fromhex(digest_hex([SCHEMA, tenant, use, case_id]))[:8], "big", signed=True)
        self._id(tenant, use, case_id)
        with self.pool.reuse_or_open_session() as conn:
            try:
                conn.execute("SELECT pg_advisory_lock(%s)", (key,))
            except BaseException:
                conn.close()  # A lost reply may hide a successful acquisition.
                raise
            try:
                yield
            finally:
                if not conn.closed:
                    try:
                        if conn.execute("SELECT pg_advisory_unlock(%s)", (key,)).fetchone() != (True,):
                            raise RuntimeError("Source custody lock release was not confirmed")
                    except BaseException:
                        conn.close()
                        raise

    def _verified(self, value: Any, tenant: str, use: str, case_id: str) -> tuple[EvidenceSnapshot, dict[str, Any]]:
        try:
            if not isinstance(value, dict) or set(value) != {"payload", "signature"}:
                raise ValueError("source envelope required")
            payload = value["payload"]
            signature = Signature(**value["signature"])
            if signature.key_id not in self.authorities.get(use, ()) or not self.trust.verify(payload, signature):
                raise ValueError("wrong or invalid source authority")
            snapshot = _decode(payload)
            if (snapshot.tenant, payload["use"], snapshot.case_id) != (tenant, use, case_id):
                raise ValueError("source scope mismatch")
            return snapshot, payload
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            raise EvidenceUnavailable("Current source custody failed identity or signature verification") from exc

    def retain(self, payload: dict[str, Any], signature: Signature, *, expected_sequence: int) -> None:
        # Freeze the caller-owned containers before verification/storage.
        import json
        value: dict[str, Any] = json.loads(canonical_bytes({"payload": payload, "signature": asdict(signature)}))
        snapshot = _decode(value["payload"])
        tenant, use, case_id = snapshot.tenant, value["payload"]["use"], snapshot.case_id
        self._verified(value, tenant, use, case_id)
        if type(expected_sequence) is not int or expected_sequence < 0:
            raise EvidenceUnavailable("Expected source sequence is required")
        with self.guard(tenant, use, case_id):
            def replace(prior: dict[str, Any] | None) -> dict[str, Any]:
                sequence = 0 if prior is None else self._verified(prior, tenant, use, case_id)[1]["sequence"]
                if sequence != expected_sequence or value["payload"]["sequence"] != sequence + 1:
                    raise EvidenceUnavailable("Source changed; reread and obtain a new source attestation")
                return value
            self.store.transact(tenant, self._id(tenant, use, case_id), replace)

    def current(self, tenant: str, use: str, case_id: str) -> EvidenceSnapshot:
        value = self.store.get(tenant, self._id(tenant, use, case_id))
        snapshot, payload = self._verified(value, tenant, use, case_id)
        if payload["withdrawn"]:
            raise EvidenceUnavailable("The source reviewer withdrew this case")
        return snapshot


class SourceReleaseGuard:
    """Compose as the pack's review extension: lifecycle first, then source custody.

    The same current snapshot is held through the enclosing gate operation. This
    supplies no new approver roles and is not itself a professional source review.
    """
    def __init__(self, source: RetainedEvidence, pack: Any, registry: Any, clock_us: Any) -> None:
        self.source, self.pack, self.registry, self.clock_us = source, pack, registry, clock_us

    @contextmanager
    def release_guard(self, contract: dict[str, Any], context: EmissionContext, *, writer: bool = False) -> Iterator[None]:
        case_id = contract.get("case_id")
        if not isinstance(case_id, str):
            raise EvidenceUnavailable("Source case required for governed release")
        with self.registry.resolution_guard(context.tenant, self.pack.manifest.id,
                now_us=self.clock_us(), expected_reference=self.pack.reference):
            with self.source.guard(context.tenant, self.pack.manifest.capability, case_id):
                snapshot = self.source.current(context.tenant, self.pack.manifest.capability, case_id)
                result, _ = SnapshotVerifier((snapshot,)).verify_context(
                    str(contract.get("body", "")), contract, replace(context, now_us=self.clock_us()))
                if result.value != "pass":
                    raise EvidenceUnavailable("The approved packet no longer matches current reviewed evidence")
                yield

    def view(self, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        # The existing Education confirmation widget is not a D5 source issuer.
        # Expose verified provenance without asserting a customer reviewed it.
        snapshot = self.source.current(context.tenant, self.pack.manifest.capability, str(contract.get("case_id", "")))
        return {"required": False, "can_confirm": False, "source_attestation": {
            "case_id": snapshot.case_id, "revision": snapshot.revision, "evidence_digest": snapshot.digest,
            "valid_until_us": snapshot.valid_until_us,
            "meaning": "Configured source authority attestation; not a customer confirmation or professional qualification",
        }}

    def confirm_from_context(self, **kwargs: Any) -> dict[str, Any]:
        raise EvidenceUnavailable("Source attestations must come from the configured source-review authority")
