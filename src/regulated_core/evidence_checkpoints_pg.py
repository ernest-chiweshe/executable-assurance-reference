"""Bounded verification of recorder checkpoints using externally pinned history.

Pins and the monotonic head come from trusted host configuration or a protected
publication service, never from the request or the evidence database. This
module does not provide that service or claim external custody. Publishing a
pin happens only after the checkpoint transaction commits.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, digest_hex
from .evidence import GENESIS, SignedDecisionEnvelope, verify_envelope
from .persistence_pg import PersistenceError, _entry_hash, decode_envelope
from .signing import Signature, Signer, TrustDirectory

SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_evidence_checkpoints_v1 (
 tenant TEXT NOT NULL, to_seq BIGINT NOT NULL CHECK(to_seq>=0),
 checkpoint_digest TEXT NOT NULL, payload JSONB NOT NULL,
 PRIMARY KEY(tenant,to_seq), UNIQUE(tenant,checkpoint_digest));
ALTER TABLE regulated_evidence_checkpoints_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_checkpoints_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS checkpoint_tenant_v1 ON regulated_evidence_checkpoints_v1;
CREATE POLICY checkpoint_tenant_v1 ON regulated_evidence_checkpoints_v1
 USING(tenant=current_setting('app.tenant',true))
 WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS checkpoint_immutable_v1 ON regulated_evidence_checkpoints_v1;
CREATE TRIGGER checkpoint_immutable_v1 BEFORE UPDATE OR DELETE
 ON regulated_evidence_checkpoints_v1 FOR EACH ROW
 EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS checkpoint_no_truncate_v1 ON regulated_evidence_checkpoints_v1;
CREATE TRIGGER checkpoint_no_truncate_v1 BEFORE TRUNCATE
 ON regulated_evidence_checkpoints_v1 FOR EACH STATEMENT
 EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


@dataclass(frozen=True)
class Checkpoint:
    """A signed verification result for a contiguous interval."""

    tenant: str
    from_seq: int
    to_seq: int
    previous_digest: str
    last_entry_hash: str
    profile: str
    signature: Signature

    def body(self) -> dict[str, object]:
        return {
            "schema": "regulated/evidence-checkpoint/v1",
            "tenant": self.tenant, "from_seq": self.from_seq, "to_seq": self.to_seq,
            "previous_digest": self.previous_digest,
            "last_entry_hash": self.last_entry_hash, "profile": self.profile,
        }

    def digest(self) -> str:
        return digest_hex({"body": self.body(), "signature": self.signature})


@dataclass(frozen=True)
class PinnedHistory:
    """Trusted, ordered checkpoint history plus an independently held head.

    Construct only at the trusted configuration boundary. These values must
    survive receiver restarts outside the mutable evidence database.
    """

    tenant: str
    profile: str
    checkpoints: tuple[Checkpoint, ...]
    head_digest: str

    def validate(self, trust: TrustDirectory, evidence_key_ids: frozenset[str]) -> None:
        if (not isinstance(evidence_key_ids, frozenset) or not evidence_key_ids
                or any(not trust.is_known(key) for key in evidence_key_ids)):
            raise PersistenceError("explicit trusted evidence key identities are required")
        previous, next_seq = GENESIS, 0
        for pin in self.checkpoints:
            if pin.signature.key_id not in evidence_key_ids:
                raise PersistenceError("checkpoint signer is outside the evidence key domain")
            if (pin.tenant != self.tenant or pin.profile != self.profile
                    or type(pin.from_seq) is not int or type(pin.to_seq) is not int
                    or pin.from_seq != next_seq or pin.to_seq < next_seq
                    or pin.previous_digest != previous
                    or not trust.verify(pin.body(), pin.signature)):
                raise PersistenceError("invalid pinned checkpoint history")
            previous, next_seq = pin.digest(), pin.to_seq + 1
        if not self.tenant or not self.profile or previous != self.head_digest:
            raise PersistenceError("checkpoint history does not match protected head")


def _transaction(conn: Any, tenant: str) -> None:
    from psycopg.pq import TransactionStatus
    if conn.info.transaction_status != TransactionStatus.INTRANS:
        raise PersistenceError("checkpoint operation requires an active transaction")
    actual, isolation = conn.execute(
        "SELECT current_setting('app.tenant',true),current_setting('transaction_isolation')"
    ).fetchone()
    if actual != tenant or isolation != "read committed":
        raise PersistenceError("checkpoint operation requires matching READ COMMITTED tenant")


def _load_pin(conn: Any, pin: Checkpoint) -> None:
    row = conn.execute(
        "SELECT checkpoint_digest,payload FROM regulated_evidence_checkpoints_v1"
        " WHERE tenant=%s AND to_seq=%s", (pin.tenant, pin.to_seq),
    ).fetchone()
    expected = {"body": pin.body(), "signature": pin.signature}
    if row is None or row[0] != pin.digest() or canonical_bytes(row[1]) != canonical_bytes(expected):
        raise PersistenceError("published checkpoint missing or altered")


def _range(
    conn: Any, *, tenant: str, start: int, end: int, previous: str,
    trust: TrustDirectory, allowed_keys: frozenset[str], bound: int,
) -> tuple[SignedDecisionEnvelope, ...]:
    if type(bound) is not int or bound <= 0 or end < start or end - start + 1 > bound:
        raise PersistenceError("evidence interval exceeds configured verification bound")
    rows = conn.execute(
        "SELECT seq,entry_hash,envelope FROM regulated_decision_evidence_v1"
        " WHERE tenant=%s AND seq>=%s AND seq<=%s ORDER BY seq LIMIT %s",
        (tenant, start, end, bound),
    ).fetchall()
    if len(rows) != end - start + 1:
        raise PersistenceError("evidence interval has a gap")
    entries = []
    for offset, (seq, entry_hash, raw) in enumerate(rows):
        entry = decode_envelope(raw)
        if (seq != start + offset or entry.seq != seq or entry.prev_hash != previous
                or entry.record.tenant_id != tenant or _entry_hash(entry) != entry_hash
                or entry.signature.key_id not in allowed_keys
                or not verify_envelope(entry, trust)):
            raise PersistenceError("evidence interval failed verification")
        entries.append(entry)
        previous = entry_hash
    return tuple(entries)


def checkpoint_on(
    conn: Any, *, tenant: str, through_seq: int, previous: Checkpoint | None,
    expected_previous_digest: str, profile: str, signer: Signer,
    trust: TrustDirectory, allowed_keys: frozenset[str], max_entries: int,
) -> Checkpoint:
    """Verify a bounded interval under the recorder lock and retain its signature.

    The expected previous digest is a protected publication pin. A valid old-key
    signature alone cannot replace that pin. Retry after a lost acknowledgement
    returns exactly the retained checkpoint rather than signing different bytes.
    """
    _transaction(conn, tenant)
    if (not profile or type(through_seq) is not int or signer.key_id not in allowed_keys
            or type(max_entries) is not int or max_entries <= 0):
        raise PersistenceError("invalid checkpoint configuration")
    start, previous_hash = 0, GENESIS
    if previous is not None:
        if previous.signature.key_id not in allowed_keys:
            raise PersistenceError("previous checkpoint signer is outside the evidence key domain")
        if (previous.tenant != tenant or previous.profile != profile or previous.digest() != expected_previous_digest
                or not trust.verify(previous.body(), previous.signature)):
            raise PersistenceError("previous checkpoint does not match protected pin")
        start, previous_hash = previous.to_seq + 1, previous.last_entry_hash
    elif expected_previous_digest != GENESIS:
        raise PersistenceError("missing previously published checkpoint")
    if through_seq < start or through_seq - start + 1 > max_entries:
        raise PersistenceError("checkpoint range is not bounded")
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                 ("regulated-evidence-v1:" + tenant,))
    if previous is not None:
        _load_pin(conn, previous)
    latest = conn.execute(
        "SELECT to_seq,checkpoint_digest,payload FROM regulated_evidence_checkpoints_v1"
        " WHERE tenant=%s ORDER BY to_seq DESC LIMIT 1", (tenant,),
    ).fetchone()
    if latest and latest[0] > through_seq:
        raise PersistenceError("checkpoint head already advanced")
    if latest and latest[0] != through_seq and latest[1] != expected_previous_digest:
        raise PersistenceError("checkpoint head differs from protected publication head")
    entries = _range(conn, tenant=tenant, start=start, end=through_seq,
                     previous=previous_hash, trust=trust, allowed_keys=allowed_keys, bound=max_entries)
    body = {
        "schema": "regulated/evidence-checkpoint/v1", "tenant": tenant,
        "from_seq": start, "to_seq": through_seq,
        "previous_digest": expected_previous_digest, "last_entry_hash": _entry_hash(entries[-1]),
        "profile": profile,
    }
    if latest and latest[0] == through_seq:
        raw = latest[2]
        signature = Signature(**raw["signature"])
        result = Checkpoint(tenant, start, through_seq, expected_previous_digest,
                            str(body["last_entry_hash"]), profile, signature)
        if (raw["body"] != body or latest[1] != result.digest()
                or signature.key_id != signer.key_id or not trust.verify(body, signature)):
            raise PersistenceError("stored checkpoint retry differs from verified interval")
        return result
    signature = signer.sign(body)
    if signature.key_id != signer.key_id or not trust.verify(body, signature):
        raise PersistenceError("checkpoint signer failed verification")
    result = Checkpoint(tenant, start, through_seq, expected_previous_digest,
                        str(body["last_entry_hash"]), profile, signature)
    conn.execute(
        "INSERT INTO regulated_evidence_checkpoints_v1 VALUES (%s,%s,%s,%s::jsonb)",
        (tenant, through_seq, result.digest(),
         canonical_bytes({"body": body, "signature": signature}).decode()),
    )
    return result


class PinnedVerifier:
    """Validate configuration once, then verify at most one bounded interval.

    Old entries covered by a pinned checkpoint must still match that checkpoint.
    Uncheckpointed tail entries must carry the current key; retired keys cannot
    append backdated authority. The current decision must always use the current
    key. Policy, age, approvals, replay, revocation and budget remain separate.
    """

    def __init__(self, history: PinnedHistory, *, trust: TrustDirectory,
                 current_key: str, max_entries: int,
                 evidence_key_ids: frozenset[str]) -> None:
        history.validate(trust, evidence_key_ids)
        if current_key not in evidence_key_ids or not trust.is_known(current_key) or type(max_entries) is not int or max_entries <= 0:
            raise PersistenceError("invalid bounded verifier configuration")
        self.history, self.trust = history, trust
        self.current_key, self.max_entries = current_key, max_entries
        self.evidence_key_ids = evidence_key_ids
        self._ends = tuple(pin.to_seq for pin in history.checkpoints)
        self._history_keys = evidence_key_ids

    def verify(self, conn: Any, selected_seq: int, *, require_current: bool = True) -> SignedDecisionEnvelope:
        _transaction(conn, self.history.tenant)
        if type(selected_seq) is not int or selected_seq < 0:
            raise PersistenceError("invalid selected sequence")
        pins = self.history.checkpoints
        if pins:
            _load_pin(conn, pins[-1])
        index = bisect_left(self._ends, selected_seq)
        previous = pins[index - 1] if index else None
        start = previous.to_seq + 1 if previous else 0
        prev_hash = previous.last_entry_hash if previous else GENESIS
        covering = pins[index] if index < len(pins) else None
        end = covering.to_seq if covering else selected_seq
        keys = self._history_keys
        # Historical entry keys are not inferred from timestamps or DB metadata.
        # A covered interval is pinned byte-for-byte by its signed final link.
        if not covering:
            keys = frozenset({self.current_key})
        entries = _range(conn, tenant=self.history.tenant, start=start, end=end, previous=prev_hash,
                         trust=self.trust, allowed_keys=keys, bound=self.max_entries)
        if covering:
            _load_pin(conn, covering)
            if _entry_hash(entries[-1]) != covering.last_entry_hash:
                raise PersistenceError("evidence interval differs from published checkpoint")
        selected = entries[selected_seq - start]
        if require_current and selected.signature.key_id != self.current_key:
            raise PersistenceError("historical evidence cannot authorize a new effect")
        return selected

    def configuration_digest(self) -> str:
        """Identify the trusted configuration used for one composed verification."""
        return digest_hex({
            "tenant": self.history.tenant, "profile": self.history.profile,
            "head": self.history.head_digest, "current": self.current_key,
            "keys": sorted(self.evidence_key_ids), "bound": self.max_entries,
        })

    def recheck(self, conn: Any, verified: SignedDecisionEnvelope) -> SignedDecisionEnvelope:
        """Rebind verified bytes to retained rows without repeating interval crypto.

        The caller must have produced this value internally with verify() and
        retained the same trusted configuration. This is not an authentication
        API for a client-supplied envelope. Append-only database privileges are
        required; this detects selected-row and checkpoint tampering but does
        not rescan every historical ancestor after verification.
        """
        _transaction(conn, self.history.tenant)
        if verified.record.tenant_id != self.history.tenant:
            raise PersistenceError("verified record belongs to another tenant")
        pins = self.history.checkpoints
        if pins:
            _load_pin(conn, pins[-1])
        index = bisect_left(self._ends, verified.seq)
        if index < len(pins) and pins[index] != pins[-1]:
            _load_pin(conn, pins[index])
        row = conn.execute(
            "SELECT entry_hash,envelope FROM regulated_decision_evidence_v1"
            " WHERE tenant=%s AND seq=%s", (self.history.tenant, verified.seq),
        ).fetchone()
        if (row is None or row[0] != _entry_hash(verified)
                or canonical_bytes(row[1]) != canonical_bytes(verified)):
            raise PersistenceError("retained decision changed after interval verification")
        return verified
