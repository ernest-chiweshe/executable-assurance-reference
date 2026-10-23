"""Shared evidence formats and verification contracts (Phase 1 core).

These objects attest evidence, never permission. Existing recorder/caller policy,
locks and time checks remain mandatory. No caller uses this module yet.
A delta carries full unchanged envelope bytes and their individual inclusion
paths, so consistency of two heads cannot disguise substituted delta bodies.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any

from .canonical import digest_hex
from .evidence_encoding import canonical_bytes, loads as evidence_loads
from .clock import TrustedClock, read_clock
from .evidence import GENESIS, SignedDecisionEnvelope, verify_envelope
from .evidence_map import EMPTY as EMPTY_MAP
from .merkle import EMPTY_ROOT, MAX_SIZE, verify_consistency, verify_inclusion
from .signing import Signature, Signer, TrustDirectory
from .evidence_key_policy import key_allowed, valid_policy, copy_retirements


class EvidenceError(ValueError):
    pass


def _natural(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_SIZE


def _hex(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


@dataclass(frozen=True)
class TreeHead:
    tenant: str
    tree_size: int
    tree_root: str
    map_root: str
    last_entry_hash: str
    key_id: str
    clock_domain: str
    issued_at_us: int
    previous_sth_digest: str
    signature: Signature

    def body(self) -> dict[str, Any]:
        return {"schema": "regulated/evidence-sth/v2", "map_schema": "regulated/evidence-map/v2", "tenant": self.tenant,
                "tree_size": self.tree_size, "tree_root": self.tree_root,
                "map_root": self.map_root, "last_entry_hash": self.last_entry_hash,
                "key_id": self.key_id, "clock_domain": self.clock_domain,
                "issued_at_us": self.issued_at_us, "previous_sth_digest": self.previous_sth_digest}

    def document(self) -> dict[str, Any]:
        return {"body": self.body(), "signature": self.signature}

    def digest(self) -> str:
        return digest_hex(self.document())

    @classmethod
    def from_document(cls, value: dict[str, Any]) -> TreeHead:
        try:
            if type(value) is not dict or set(value) != {"body", "signature"}:
                raise ValueError("unexpected head document fields")
            body = dict(value["body"])
            if body.pop("map_schema") != "regulated/evidence-map/v2":
                raise ValueError("wrong map schema")
            if body.pop("schema") != "regulated/evidence-sth/v2":
                raise ValueError("unexpected head schema")
            signature = Signature(**value["signature"])
            result = cls(**body, signature=signature)
            if canonical_bytes(result.document()) != canonical_bytes(value):
                raise ValueError("head is not canonical typed data")
            return result
        except (TypeError, KeyError, ValueError, RecursionError) as exc:
            raise EvidenceError("invalid head document") from exc


def verify_head(head: TreeHead, *, tenant: str, clock_domain: str,
                trust: TrustDirectory, allowed_keys: frozenset[str],
                historical_keys: dict | None = None) -> bool:
    if (type(head) is not TreeHead or not tenant or not clock_domain
            or head.tenant != tenant or head.clock_domain != clock_domain
            or type(head.signature) is not Signature or type(head.key_id) is not str
            or head.key_id != head.signature.key_id
            or not key_allowed(head.key_id, head.tree_size, allowed_keys, historical_keys) or not _natural(head.tree_size)
            or not _natural(head.issued_at_us)
            or not all(_hex(v) for v in (head.tree_root, head.map_root, head.last_entry_hash,
                                         head.previous_sth_digest))):
        return False
    if head.tree_size == 0 and (head.tree_root != EMPTY_ROOT.hex()
                               or head.map_root != EMPTY_MAP[0].hex()
                               or head.last_entry_hash != GENESIS
                               or head.previous_sth_digest != GENESIS):
        return False
    return trust.verify(head.body(), head.signature)


def sign_head(*, tenant: str, tree_size: int, tree_root: bytes, map_root: bytes,
              last_entry_hash: str, previous: TreeHead | None, signer: Signer,
              clock: TrustedClock, trust: TrustDirectory,
              signing_keys: frozenset[str], historical_keys: dict) -> TreeHead:
    """Take a fresh clock reading for this signature; never cache an action time."""
    if (type(signing_keys) is not frozenset or signer.key_id not in signing_keys
            or not valid_policy(signing_keys, historical_keys) or not trust.matches_signer(signer)
            or type(tree_root) is not bytes or len(tree_root) != 32
            or type(map_root) is not bytes or len(map_root) != 32):
        raise EvidenceError("unqualified evidence signing configuration")
    if previous is not None:
        if (not verify_head(previous, tenant=tenant, clock_domain=clock.domain, trust=trust,
                            allowed_keys=signing_keys, historical_keys=historical_keys)
                or tree_size != previous.tree_size + 1):
            raise EvidenceError("head does not extend the previous signed size")
    elif tree_size not in (0, 1):
        raise EvidenceError("missing previous signed head")
    reading = read_clock(clock)
    if previous is not None and reading.now_us < previous.issued_at_us:
        raise EvidenceError("head time regressed")
    draft = TreeHead(tenant, tree_size, tree_root.hex(), map_root.hex(), last_entry_hash,
                     signer.key_id, reading.domain, reading.now_us,
                     GENESIS if previous is None else previous.digest(),
                     Signature(signer.key_id, "", signer.alg))
    # Validate structural fields before asking the signer to sign arbitrary data.
    if (not _natural(tree_size) or not tenant or not _hex(last_entry_hash)
            or (tree_size == 0 and (tree_root != EMPTY_ROOT or map_root != EMPTY_MAP[0]
                                   or last_entry_hash != GENESIS))):
        raise EvidenceError("invalid new head fields")
    result = replace(draft, signature=signer.sign(draft.body()))
    if not verify_head(result, tenant=tenant, clock_domain=clock.domain, trust=trust,
                       allowed_keys=signing_keys):
        raise EvidenceError("new head signature verification failed")
    return result


def verify_head_extension(previous: TreeHead | None, new: TreeHead,
                          consistency: tuple[bytes, ...], *, tenant: str, clock_domain: str,
                          trust: TrustDirectory, allowed_keys: frozenset[str],
                historical_keys: dict | None = None) -> bool:
    if not verify_head(new, tenant=tenant, clock_domain=clock_domain, trust=trust, allowed_keys=allowed_keys, historical_keys=historical_keys):
        return False
    if previous is None:
        return verify_consistency(0, new.tree_size, EMPTY_ROOT, bytes.fromhex(new.tree_root), consistency)
    if not verify_head(previous, tenant=tenant, clock_domain=clock_domain,
                       trust=trust, allowed_keys=allowed_keys, historical_keys=historical_keys):
        return False
    if new.issued_at_us < previous.issued_at_us:
        return False
    if new.tree_size == previous.tree_size:
        return new == previous and not consistency
    if new.tree_size == previous.tree_size + 1 and new.previous_sth_digest != previous.digest():
        return False
    return verify_consistency(previous.tree_size, new.tree_size, bytes.fromhex(previous.tree_root),
                              bytes.fromhex(new.tree_root), consistency)


@dataclass(frozen=True)
class EvidenceDelta:
    tenant: str
    from_seq: int
    to_seq: int
    envelopes: tuple[bytes, ...]
    previous: TreeHead | None
    head: TreeHead
    consistency: tuple[bytes, ...]
    inclusion_paths: tuple[tuple[bytes, ...], ...]

    def document(self) -> dict[str, Any]:
        return {"schema": "regulated/evidence-delta/v1", "tenant": self.tenant,
                "from_seq": self.from_seq, "to_seq": self.to_seq,
                "envelopes": tuple(raw.hex() for raw in self.envelopes),
                "previous": None if self.previous is None else self.previous.document(),
                "head": self.head.document(),
                "consistency": tuple(h.hex() for h in self.consistency),
                "inclusion_paths": tuple(tuple(h.hex() for h in path) for path in self.inclusion_paths)}

    def bytes(self) -> bytes:
        return canonical_bytes(self.document())

    @classmethod
    def from_bytes(cls, raw: bytes, *, max_bytes: int, max_entries: int,
                   max_envelope_bytes: int) -> EvidenceDelta:
        """Decode a bounded canonical object, without asserting its authenticity.

        Transport/storage must bound its own read before calling this method.
        verify_delta must still check trusted pins, signatures, chain and proofs.
        Limits are explicit host configuration, never taken from the object.
        """
        if (type(raw) is not bytes or not all(_natural(n) and n > 0 for n in
                                             (max_bytes, max_entries, max_envelope_bytes))
                or len(raw) > max_bytes):
            raise EvidenceError("delta byte bound or decoder configuration failed")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON member")
                result[key] = value
            return result

        def reject_constant(value):
            raise ValueError("non-finite JSON number")

        def hashes(value, limit):
            if type(value) is not list or len(value) > limit or not all(_hex(h) for h in value):
                raise ValueError("invalid proof hashes")
            return tuple(bytes.fromhex(h) for h in value)

        try:
            value = evidence_loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
            if (type(value) is not dict or set(value) != {"schema", "tenant", "from_seq", "to_seq",
                    "envelopes", "previous", "head", "consistency", "inclusion_paths"}
                    or value["schema"] != "regulated/evidence-delta/v1"
                    or type(value["tenant"]) is not str or not value["tenant"]
                    or not _natural(value["from_seq"]) or not _natural(value["to_seq"])
                    or type(value["envelopes"]) is not list
                    or not 0 < len(value["envelopes"]) <= max_entries
                    or type(value["inclusion_paths"]) is not list
                    or len(value["inclusion_paths"]) != len(value["envelopes"])):
                raise ValueError("invalid delta fields")
            envelopes = []
            for encoded in value["envelopes"]:
                if (type(encoded) is not str or not encoded or len(encoded) % 2
                        or len(encoded) > 2 * max_envelope_bytes
                        or any(c not in "0123456789abcdef" for c in encoded)):
                    raise ValueError("invalid or oversized envelope encoding")
                envelopes.append(bytes.fromhex(encoded))
            previous = None if value["previous"] is None else TreeHead.from_document(value["previous"])
            head = TreeHead.from_document(value["head"])
            start = 0 if previous is None else previous.tree_size
            if (not _natural(start) or not _natural(head.tree_size)
                    or value["from_seq"] != start
                    or value["to_seq"] != start + len(envelopes) - 1
                    or head.tree_size != value["to_seq"] + 1):
                raise ValueError("invalid delta contiguous range")
            result = cls(value["tenant"], value["from_seq"], value["to_seq"], tuple(envelopes),
                         previous, head, hashes(value["consistency"], 65),
                         tuple(hashes(path, 64) for path in value["inclusion_paths"]))
            if result.bytes() != raw:
                raise ValueError("noncanonical delta bytes")
            return result
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
            raise EvidenceError("invalid retained delta encoding") from exc


def verify_delta(delta: EvidenceDelta, *, expected_previous: TreeHead | None,
                 expected_head: TreeHead, tenant: str, clock_domain: str,
                 trust: TrustDirectory, allowed_head_keys: frozenset[str],
                 allowed_envelope_keys: frozenset[str],
                 allowed_envelope_domains: frozenset[str], max_entries: int,
                 historical_head_keys: dict | None = None) -> tuple[SignedDecisionEnvelope, ...]:
    """Verify a bounded retained object; receipt/custody and audit gate are Phase 2."""
    from .persistence_pg import PersistenceError, decode_envelope

    if (type(delta) is not EvidenceDelta or delta.tenant != tenant
            or not _natural(max_entries) or max_entries == 0
            or type(delta.envelopes) is not tuple or type(delta.inclusion_paths) is not tuple
            or not 0 < len(delta.envelopes) <= max_entries
            or len(delta.inclusion_paths) != len(delta.envelopes)
            or delta.previous != expected_previous or delta.head != expected_head
            or type(allowed_envelope_keys) is not frozenset or not allowed_envelope_keys
            or type(allowed_envelope_domains) is not frozenset or not allowed_envelope_domains):
        raise EvidenceError("delta scope, pins or range bound failed")
    start = 0 if expected_previous is None else expected_previous.tree_size
    if (not _natural(delta.from_seq) or not _natural(delta.to_seq) or delta.from_seq != start
            or delta.to_seq != start + len(delta.envelopes) - 1
            or delta.head.tree_size != delta.to_seq + 1
            or not verify_head_extension(expected_previous, expected_head, delta.consistency,
                                         tenant=tenant, clock_domain=clock_domain, trust=trust,
                                         allowed_keys=allowed_head_keys, historical_keys=historical_head_keys)):
        raise EvidenceError("delta head or completeness check failed")
    previous_hash = GENESIS if expected_previous is None else expected_previous.last_entry_hash
    verified = []
    for offset, raw in enumerate(delta.envelopes):
        seq = start + offset
        if type(raw) is not bytes:
            raise EvidenceError("delta envelopes must preserve exact bytes")
        try:
            value = evidence_loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("noncanonical retained bytes")
            envelope = decode_envelope(value)
        except (TypeError, ValueError, KeyError, PersistenceError, RecursionError) as exc:
            raise EvidenceError("invalid retained envelope") from exc
        if (envelope.record.tenant_id != tenant or type(envelope.seq) is not int or envelope.seq != seq
                or envelope.prev_hash != previous_hash or envelope.signature.key_id not in allowed_envelope_keys
                or envelope.clock_domain not in allowed_envelope_domains or not verify_envelope(envelope, trust)
                or not verify_inclusion(raw, seq, delta.head.tree_size, delta.inclusion_paths[offset],
                                        bytes.fromhex(delta.head.tree_root))):
            raise EvidenceError("retained envelope verification failed")
        previous_hash = envelope.chain_hash()
        verified.append(envelope)
    if previous_hash != delta.head.last_entry_hash:
        raise EvidenceError("retained final entry differs from signed head")
    return tuple(verified)


@dataclass(frozen=True)
class KeySummary:
    count: int
    first_seq: int
    last_seq: int
    key_root: str

    def bytes(self) -> bytes:
        return canonical_bytes({"schema": "regulated/evidence-key-value/v1", "count": self.count,
                                "first_seq": self.first_seq, "last_seq": self.last_seq,
                                "key_root": self.key_root})

    @classmethod
    def decode(cls, raw: bytes, tree_size: int) -> KeySummary:
        try:
            value = evidence_loads(raw)
            if value.pop("schema") != "regulated/evidence-key-value/v1":
                raise ValueError("wrong key value schema")
            result = cls(**value)
            if (not all(_natural(n) for n in (result.count, result.first_seq, result.last_seq))
                    or not 0 < result.count <= tree_size
                    or not result.first_seq <= result.last_seq < tree_size
                    or result.count > result.last_seq - result.first_seq + 1
                    or (result.count == 1) != (result.first_seq == result.last_seq)
                    or not _hex(result.key_root) or result.bytes() != raw):
                raise ValueError("invalid occurrence summary")
            return result
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
            raise EvidenceError("invalid authenticated key summary") from exc


def occurrence_bytes(seq: int) -> bytes:
    if not _natural(seq):
        raise EvidenceError("invalid occurrence sequence")
    return canonical_bytes({"schema": "regulated/evidence-key-occurrence/v1", "seq": seq})


def lookup_key(tenant: str, key_type: str, key: Any) -> bytes:
    """Exact decoded-JSON question; caller qualification is a separate gate."""
    from .evidence_map import key_digest
    from .evidence_questions import normalize_json_key, QuestionRefused
    if type(tenant) is not str or not tenant:
        raise EvidenceError("invalid lookup tenant")
    if type(key_type) is not str or key_type not in ("record_id", "record_hash", "record_id_hash", "outcome_of",
                                                                 "release_decision_eligible", "release_outcome_eligible"):
        raise EvidenceError("unknown evidence lookup type")
    if key_type == "record_id_hash":
        if type(key) is not tuple or len(key) != 2:
            raise EvidenceError("invalid composite lookup key")
        key = list(key)  # API pair wrapper, not a caller's tuple-valued record ID.
    if key_type in ("release_decision_eligible", "release_outcome_eligible"):
        length = 3 if key_type == "release_decision_eligible" else 5
        if (type(key) is not list or len(key) != length
                or type(key[-2]) is not str or not key[-2] or type(key[-1]) is not str
                or (length == 5 and (type(key[2]) is not list or len(key[2]) != 3))):
            raise EvidenceError("invalid eligibility question shape")
    try:
        normalized = normalize_json_key(key)
    except QuestionRefused as exc:
        raise EvidenceError("lookup requires decoded JSON values") from exc
    return key_digest(tenant, key_type, normalized)


def envelope_keys(envelope: SignedDecisionEnvelope) -> dict[bytes, str]:
    """Work depends on this record's annotations, never on stored history."""
    tenant = envelope.record.tenant_id
    pairs = [("record_id", envelope.record.record_id), ("record_hash", envelope.record_hash),
             ("record_id_hash", (envelope.record.record_id, envelope.record_hash))]
    pairs.extend(("outcome_of", item.message) for item in envelope.record.decision.annotations
                 if item.kind == "outcome-of-decision")
    # Writers and proof verification call this only after verify_envelope.
    from .evidence_eligibility import stored_eligibility_pairs
    pairs.extend(stored_eligibility_pairs(envelope))
    # Repeated identical annotations contribute one occurrence for this envelope.
    return {lookup_key(tenant, kind, key): kind for kind, key in pairs}


@dataclass(frozen=True)
class UnhashableIdFlag:
    first_seq: int

    def bytes(self) -> bytes:
        return canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": self.first_seq})

    @classmethod
    def decode(cls, raw: bytes, tree_size: int) -> "UnhashableIdFlag":
        try:
            value = evidence_loads(raw)
            if (type(value) is not dict or set(value) != {"schema", "first_seq"}
                    or value["schema"] != "regulated/evidence-flag/v1"
                    or not _natural(value["first_seq"]) or value["first_seq"] >= tree_size
                    or canonical_bytes(value) != raw):
                raise ValueError("invalid flag body")
            return cls(value["first_seq"])
        except (TypeError, ValueError, KeyError, RecursionError) as exc:
            raise EvidenceError("invalid authenticated history flag") from exc


def unhashable_id_key(tenant: str) -> bytes:
    from .evidence_map import key_digest
    return key_digest(tenant, "flag", "unhashable-record-id")


@dataclass(frozen=True)
class HistoryFlagProof:
    head: TreeHead
    map_proof: Any


def verify_history_flag(proof: HistoryFlagProof, *, expected_head: TreeHead,
                        tenant: str, clock_domain: str, trust: TrustDirectory,
                        allowed_head_keys: frozenset[str],
                        historical_head_keys: dict | None = None) -> UnhashableIdFlag | None:
    from .evidence_map import verify_map_proof
    if (type(proof) is not HistoryFlagProof or proof.head != expected_head
            or not verify_head(expected_head, tenant=tenant, clock_domain=clock_domain,
                               trust=trust, allowed_keys=allowed_head_keys, historical_keys=historical_head_keys)
            or not verify_map_proof(bytes.fromhex(expected_head.map_root), unhashable_id_key(tenant), proof.map_proof)):
        raise EvidenceError("history flag head or proof failed")
    return (None if proof.map_proof.value is None else
            UnhashableIdFlag.decode(proof.map_proof.value, expected_head.tree_size))


def require_hashable_history(proof: HistoryFlagProof, **verification: Any) -> None:
    """Preserve H5's failure class; activation remains a separate caller change."""
    if verify_history_flag(proof, **verification) is not None:
        raise TypeError("unhashable record_id in authenticated history")


@dataclass(frozen=True)
class OccurrenceProof:
    ordinal: int
    seq: int
    envelope: bytes
    key_path: tuple[bytes, ...]
    evidence_path: tuple[bytes, ...]


@dataclass(frozen=True)
class LookupProof:
    head: TreeHead
    map_proof: Any  # validated as MapProof by verify_map_proof
    occurrence: OccurrenceProof | None = None


@dataclass(frozen=True)
class LookupResult:
    summary: KeySummary | None
    envelope: SignedDecisionEnvelope | None


def verify_lookup(proof: LookupProof, *, expected_head: TreeHead, tenant: str,
                  key_type: str, key: Any, selection: str, ordinal: int | None = None,
                  clock_domain: str, trust: TrustDirectory, allowed_head_keys: frozenset[str],
                  allowed_envelope_keys: frozenset[str],
                  allowed_envelope_domains: frozenset[str],
                  historical_head_keys: dict | None = None) -> LookupResult:
    """Authenticate absence/count or one requested occurrence at a pinned head.

    This is an evidence answer, not authorization or a freshness decision. Caller
    gates must independently qualify the pinned head and their own time/lock rules.
    """
    from .evidence_map import verify_map_proof
    from .persistence_pg import PersistenceError, decode_envelope
    expected_key = lookup_key(tenant, key_type, key)
    if (selection not in ("count", "absent", "first", "latest", "ordinal")
            or (selection == "ordinal" and not _natural(ordinal))
            or (selection != "ordinal" and ordinal is not None)
            or type(proof) is not LookupProof or proof.head != expected_head
            or not verify_head(expected_head, tenant=tenant, clock_domain=clock_domain,
                               trust=trust, allowed_keys=allowed_head_keys, historical_keys=historical_head_keys)
            or not verify_map_proof(bytes.fromhex(expected_head.map_root), expected_key, proof.map_proof)):
        raise EvidenceError("lookup question, head or map proof failed")
    if proof.map_proof.value is None:
        if proof.occurrence is not None:
            raise EvidenceError("absent key has an occurrence")
        return LookupResult(None, None)
    summary = KeySummary.decode(proof.map_proof.value, expected_head.tree_size)
    if selection in ("count", "absent"):
        if proof.occurrence is not None:
            raise EvidenceError("unexpected occurrence for summary query")
        return LookupResult(summary, None)
    wanted = 0 if selection == "first" else summary.count - 1 if selection == "latest" else ordinal
    if wanted >= summary.count:
        if proof.occurrence is not None:
            raise EvidenceError("out-of-range occurrence supplied")
        return LookupResult(summary, None)
    item = proof.occurrence
    if (type(item) is not OccurrenceProof or not _natural(item.ordinal) or item.ordinal != wanted
            or not _natural(item.seq) or not summary.first_seq <= item.seq <= summary.last_seq
            or (wanted == 0 and item.seq != summary.first_seq)
            or (wanted == summary.count - 1 and item.seq != summary.last_seq)
            or type(item.envelope) is not bytes
            or not verify_inclusion(occurrence_bytes(item.seq), wanted, summary.count,
                                    item.key_path, bytes.fromhex(summary.key_root))
            or not verify_inclusion(item.envelope, item.seq, expected_head.tree_size,
                                    item.evidence_path, bytes.fromhex(expected_head.tree_root))):
        raise EvidenceError("lookup occurrence inclusion failed")
    try:
        value = evidence_loads(item.envelope)
        if canonical_bytes(value) != item.envelope:
            raise ValueError("noncanonical envelope")
        envelope = decode_envelope(value)
        if (type(allowed_envelope_keys) is not frozenset or not allowed_envelope_keys
                or type(allowed_envelope_domains) is not frozenset or not allowed_envelope_domains
                or envelope.record.tenant_id != tenant or type(envelope.seq) is not int
                or envelope.seq != item.seq or envelope.signature.key_id not in allowed_envelope_keys
                or envelope.clock_domain not in allowed_envelope_domains
                or not verify_envelope(envelope, trust) or expected_key not in envelope_keys(envelope)):
            raise ValueError("envelope is not qualified for the requested key")
    except (TypeError, ValueError, KeyError, AttributeError, PersistenceError, RecursionError) as exc:
        raise EvidenceError("lookup envelope qualification failed") from exc
    return LookupResult(summary, envelope)


class MemoryEvidenceService:
    """Tenant-scoped core store; no permit, retention or caller migration.

    Appends stage only newly created nodes using read-through overlays. Signing
    failure leaves all published state unchanged. Work is O(256*q + q*log n)
    for q distinct keys derived from the new record, plus its body-byte cost,
    using amortized hash-table operations (not a hard real-time wall-clock bound).
    There is no history copy or implicit full-history fallback.
    """

    def __init__(self, *, tenant: str, signer: Signer, clock: TrustedClock,
                 trust: TrustDirectory, signing_keys: frozenset[str],
                 historical_head_keys: dict, envelope_keys_allowed: frozenset[str],
                 envelope_domains: frozenset[str]) -> None:
        from threading import RLock
        from .merkle import MemoryMerkleLog
        from .evidence_map import MemorySparseMap
        if (type(tenant) is not str or not tenant or not envelope_keys_allowed
                or type(envelope_keys_allowed) is not frozenset
                or not envelope_domains or type(envelope_domains) is not frozenset):
            raise EvidenceError("invalid evidence service scope")
        self.tenant, self.signer, self.clock, self.trust = tenant, signer, clock, trust
        try:
            retired = copy_retirements(signing_keys, historical_head_keys)
        except ValueError as exc:
            raise EvidenceError("invalid evidence key retirement policy") from exc
        self.signing_keys, self.historical_head_keys = signing_keys, retired
        self.envelope_keys_allowed, self.envelope_domains = envelope_keys_allowed, envelope_domains
        self._lock = RLock()
        self._tree, self._map = MemoryMerkleLog(), MemorySparseMap()
        self._key_trees: dict[bytes, Any] = {}
        self._occurrences: dict[tuple[bytes, int], int] = {}
        self._envelopes: dict[int, bytes] = {}
        self._heads: dict[int, TreeHead] = {}
        self._head: TreeHead | None = None
        self.last_append_work: dict[str, int] = {}

    @property
    def head(self) -> TreeHead | None:
        with self._lock:
            return self._head

    def append(self, envelope: SignedDecisionEnvelope) -> TreeHead:
        from collections import ChainMap
        from .merkle import MemoryMerkleLog
        from .evidence_map import MemorySparseMap
        from .persistence_pg import PersistenceError, decode_envelope
        with self._lock:
            seq = self._tree.frontier.size
            prev = GENESIS if self._head is None else self._head.last_entry_hash
            if self._head is None:
                if seq != 0 or self._tree.root() != EMPTY_ROOT or self._map.root != EMPTY_MAP[0]:
                    raise EvidenceError("unpublished initial state")
            elif (not verify_head(self._head, tenant=self.tenant, clock_domain=self.clock.domain,
                                  trust=self.trust, allowed_keys=self.signing_keys, historical_keys=self.historical_head_keys)
                  or seq != self._head.tree_size or self._tree.root().hex() != self._head.tree_root
                  or self._map.root.hex() != self._head.map_root):
                raise EvidenceError("stored append state differs from signed head")
            # Freeze exact typed bytes before deriving indexes; caller-owned nested
            # values cannot mutate the stored object after signature verification.
            try:
                raw = canonical_bytes(envelope)
                decoded = evidence_loads(raw)
                from .evidence_encoding import reject_nul
                reject_nul(decoded)
                envelope = decode_envelope(decoded)
            except (TypeError, ValueError, KeyError, PersistenceError, RecursionError) as exc:
                raise EvidenceError("invalid appended envelope") from exc
            if (type(envelope.seq) is not int or envelope.seq != seq or envelope.prev_hash != prev
                    or envelope.record.tenant_id != self.tenant
                    or envelope.signature.key_id not in self.envelope_keys_allowed
                    or envelope.clock_domain not in self.envelope_domains
                    or not verify_envelope(envelope, self.trust)):
                raise EvidenceError("append scope, chain or signature failed")
            keys = envelope_keys(envelope)
            staged_tree = MemoryMerkleLog()
            staged_tree.frontier = self._tree.frontier
            staged_tree._nodes = ChainMap({}, self._tree._nodes)
            staged_tree.append(raw)
            staged_map = MemorySparseMap()
            staged_map.root = self._map.root
            staged_map._nodes = ChainMap({}, self._map._nodes)
            pending = []
            for digest in keys:
                base = self._key_trees.get(digest)
                tree = MemoryMerkleLog()
                if base is not None:
                    tree.frontier = base.frontier
                    tree._nodes = ChainMap({}, base._nodes)
                else:
                    tree._nodes = ChainMap({})
                old_value = self._map.prove(digest).value
                old = None if old_value is None else KeySummary.decode(old_value, seq)
                if ((base is None) != (old is None)
                        or (old is not None and (old.count != tree.frontier.size
                                                or old.key_root != tree.root().hex()))):
                    raise EvidenceError("stored occurrence tree and map disagree")
                ordinal = tree.append(occurrence_bytes(seq))
                summary = KeySummary(ordinal + 1, seq if old is None else old.first_seq,
                                     seq, tree.root().hex())
                staged_map.update(digest, summary.bytes())
                pending.append((digest, base, tree, ordinal))
            if (type(envelope.record.record_id) is list or type(envelope.record.record_id) is dict):
                flag_key = unhashable_id_key(self.tenant)
                old_flag = self._map.prove(flag_key).value
                if old_flag is None:
                    staged_map.update(flag_key, UnhashableIdFlag(seq).bytes())
                else:
                    UnhashableIdFlag.decode(old_flag, seq)
            head = sign_head(tenant=self.tenant, tree_size=seq + 1, tree_root=staged_tree.root(),
                             map_root=staged_map.root, last_entry_hash=envelope.chain_hash(),
                             previous=self._head, signer=self.signer, clock=self.clock, trust=self.trust,
                             signing_keys=self.signing_keys, historical_keys=self.historical_head_keys)
            # No callback or I/O after signing succeeds; only bounded staged data
            # is committed under the service lock. Process failure is outside this
            # volatile adapter's durability contract; PG owns durable transactions.
            work = {"keys": len(keys), "tree_nodes": len(staged_tree._nodes.maps[0]),
                    "map_nodes": len(staged_map._nodes.maps[0]), "key_nodes": 0}
            self._tree._nodes.update(staged_tree._nodes.maps[0])
            self._tree.frontier = staged_tree.frontier
            self._map._nodes.update(staged_map._nodes.maps[0])
            self._map.root = staged_map.root
            for digest, base, tree, ordinal in pending:
                work["key_nodes"] += len(tree._nodes.maps[0])
                if base is None:
                    base = MemoryMerkleLog()
                    self._key_trees[digest] = base
                base._nodes.update(tree._nodes.maps[0])
                base.frontier = tree.frontier
                self._occurrences[digest, ordinal] = seq
            self._envelopes[seq] = raw
            self._heads[seq + 1] = self._head = head
            self.last_append_work = work
            return head

    def history_flag(self, *, head: TreeHead) -> HistoryFlagProof:
        with self._lock:
            if type(head) is not TreeHead or self._heads.get(head.tree_size) != head:
                raise EvidenceError("head is not stored in this tenant service")
            proof = HistoryFlagProof(head, self._map.prove(unhashable_id_key(self.tenant), bytes.fromhex(head.map_root)))
            verify_history_flag(proof, expected_head=head, tenant=self.tenant, clock_domain=self.clock.domain,
                                trust=self.trust, allowed_head_keys=self.signing_keys, historical_head_keys=self.historical_head_keys)
            return proof

    def lookup(self, *, head: TreeHead, key_type: str, key: Any,
               selection: str, ordinal: int | None = None) -> LookupProof:
        digest = lookup_key(self.tenant, key_type, key)
        if (selection not in ("count", "absent", "first", "latest", "ordinal")
                or (selection == "ordinal" and not _natural(ordinal))
                or (selection != "ordinal" and ordinal is not None)):
            raise EvidenceError("invalid lookup selection")
        with self._lock:
            if type(head) is not TreeHead or self._heads.get(head.tree_size) != head:
                raise EvidenceError("head is not stored in this tenant service")
            proof = self._map.prove(digest, bytes.fromhex(head.map_root))
            if proof.value is None or selection in ("count", "absent"):
                return LookupProof(head, proof)
            summary = KeySummary.decode(proof.value, head.tree_size)
            wanted = 0 if selection == "first" else summary.count - 1 if selection == "latest" else ordinal
            if wanted >= summary.count:
                return LookupProof(head, proof)
            seq = self._occurrences[digest, wanted]
            item = OccurrenceProof(wanted, seq, self._envelopes[seq],
                                   self._key_trees[digest].inclusion(wanted, summary.count),
                                   self._tree.inclusion(seq, head.tree_size))
            return LookupProof(head, proof, item)
