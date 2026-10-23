"""Pure witness verification contracts, SPEC032-034.

These checks neither persist witness state nor issue permits. A server must
serialize decisions and durably store an accepted head/ack before replying.
Transport, durable witness storage, retention and permit integration are separate
Phase 2 work. Existing head bytes and signatures are never changed here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .canonical import digest_hex
from .evidence_namespace import NamespaceHead, valid_scope, verify_namespace_head
from .evidence_service import EvidenceError, TreeHead, _hex, _natural, verify_head
from .merkle import EMPTY_ROOT, verify_consistency
from .signing import ALG_ED25519, Signature, TrustDirectory

Head = TreeHead | NamespaceHead
GENESIS_ACK = "0" * 64


def _nonce(value: object) -> bool:
    return type(value) is str and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class WitnessScope:
    scope_type: str
    scope_id: str
    namespace: str

    def __post_init__(self):
        evidence = (type(self.scope_type) is str and self.scope_type == "tenant"
                    and type(self.scope_id) is str and bool(self.scope_id)
                    and type(self.namespace) is str and self.namespace == "evidence")
        if not evidence and not valid_scope(self.scope_type, self.scope_id, self.namespace):
            raise EvidenceError("invalid witness scope")

    def fields(self) -> dict:
        return dict(scope_type=self.scope_type, scope_id=self.scope_id, namespace=self.namespace)


@dataclass(frozen=True)
class HeadPolicy:
    scope: WitnessScope
    clock_domain: str
    allowed_keys: frozenset[str]
    trust: TrustDirectory
    historical_keys: dict = field(default_factory=dict)

    def verify(self, head: Head, *, current_only=False) -> bool:
        if type(self.scope) is not WitnessScope:
            return False
        if self.scope.namespace == "evidence":
            return verify_head(head, tenant=self.scope.scope_id, clock_domain=self.clock_domain,
                               allowed_keys=self.allowed_keys, trust=self.trust,
                               historical_keys={} if current_only else self.historical_keys)
        return verify_namespace_head(head, **self.scope.fields(), clock_domain=self.clock_domain,
                                     allowed_keys=self.allowed_keys, trust=self.trust,
                               historical_keys={} if current_only else self.historical_keys)


@dataclass(frozen=True)
class Checkpoint:
    size: int
    root: str
    head_digest: str

    def __post_init__(self):
        if not _natural(self.size) or not _hex(self.root) or not _hex(self.head_digest):
            raise EvidenceError("invalid witness checkpoint")

    @classmethod
    def from_head(cls, head: Head, policy: HeadPolicy) -> Checkpoint:
        if not policy.verify(head):
            raise EvidenceError("unverified witness head")
        return cls(head.tree_size, head.tree_root, head.digest())

    def fields(self) -> dict:
        return dict(size=self.size, root=self.root, head_digest=self.head_digest)


@dataclass(frozen=True)
class WitnessRequest:
    request_id: str
    scope: WitnessScope
    previous: Checkpoint | None
    head: Head
    consistency: tuple[bytes, ...]

    def checkpoint(self, policy: HeadPolicy) -> Checkpoint:
        if (not _nonce(self.request_id) or type(self.scope) is not WitnessScope or self.scope != policy.scope
                or (self.previous is not None and type(self.previous) is not Checkpoint)
                or type(self.consistency) is not tuple or len(self.consistency) > 65
                or any(type(h) is not bytes or len(h) != 32 for h in self.consistency)):
            raise EvidenceError("invalid witness request")
        if not policy.verify(self.head, current_only=True):
            raise EvidenceError("witness requests require current signing key")
        return Checkpoint.from_head(self.head, policy)

    def document(self, policy: HeadPolicy) -> dict:
        checkpoint = self.checkpoint(policy)
        return {"schema": "regulated/witness-request/v1", "request_id": self.request_id,
                **self.scope.fields(), "previous": None if self.previous is None else self.previous.fields(),
                "checkpoint": {**checkpoint.fields(), "head": self.head.document()},
                "consistency": [h.hex() for h in self.consistency]}


def decide_request(request: WitnessRequest, current: Head | None,
                   policy: HeadPolicy) -> Literal["ACK", "REACK", "STALE", "CONFLICT"]:
    """Decide against a caller-held serialized durable snapshot; performs no write.

    Only CURRENT is re-acknowledged. An old accepted head still returns STALE.
    Invalid input/proof raises; STALE/CONFLICT must become signed refusals.
    """
    if type(request) is not WitnessRequest:
        raise EvidenceError("invalid witness request type")
    target = request.checkpoint(policy)
    latest = None if current is None else Checkpoint.from_head(current, policy)
    if latest is not None:
        if target.size < latest.size:
            return "STALE"
        if target.size == latest.size:
            return "REACK" if target == latest else "CONFLICT"
    if request.previous != latest:
        return "STALE"
    old_size, old_root = (0, EMPTY_ROOT) if latest is None else (latest.size, bytes.fromhex(latest.root))
    predecessor = (request.head.previous_sth_digest if type(request.head) is TreeHead
                   else request.head.previous_head_digest)
    if (current is not None and (request.head.issued_at_us < current.issued_at_us
            or (target.size == latest.size + 1 and predecessor != latest.head_digest))
            or not verify_consistency(old_size, target.size, old_root, bytes.fromhex(target.root), request.consistency)):
        raise EvidenceError("invalid witness extension")
    return "ACK"


@dataclass(frozen=True)
class WitnessAck:
    witness_id: str
    request_id: str
    scope: WitnessScope
    checkpoint: Checkpoint
    previous_ack_digest: str
    issued_at_us: int
    signature: Signature

    def body(self) -> dict:
        return {"schema": "regulated/witness-ack/v1", "witness_id": self.witness_id,
                "request_id": self.request_id, **self.scope.fields(), **self.checkpoint.fields(),
                "previous_ack_digest": self.previous_ack_digest, "issued_at_us": self.issued_at_us}

    def document(self) -> dict:
        return {"body": self.body(), "signature": self.signature}

    def digest(self) -> str:
        return digest_hex(self.document())


@dataclass(frozen=True)
class WitnessReack:
    witness_id: str
    request_id: str
    ack: WitnessAck
    signature: Signature

    def body(self) -> dict:
        return {"schema": "regulated/witness-reack/v1", "witness_id": self.witness_id,
                "request_id": self.request_id, "ack": self.ack.document()}


@dataclass(frozen=True)
class HistoricalAck:
    """Evidence-only envelope; never accepted by permit quorum verification."""
    ack: WitnessAck


@dataclass(frozen=True)
class WitnessSet:
    # Tuple of (witness_id, key_id). Identity aliases cannot multiply quorum votes.
    members: tuple[tuple[str, str], ...]
    unavailable: int
    malicious: int
    quorum: int

    def validate(self, trust: TrustDirectory) -> None:
        if (type(self.members) is not tuple or not self.members or len(self.members) > 64
                or any(type(p) is not tuple or len(p) != 2
                       or any(type(x) is not str or not x for x in p) for p in self.members)):
            raise EvidenceError("invalid witness membership")
        n = len(self.members)
        ids, keys = zip(*self.members)
        if (len(set(ids)) != n or len(set(keys)) != n or not trust.distinct_keys(keys)
                or any(type(x) is not int for x in (self.unavailable, self.malicious, self.quorum))
                or not 0 <= self.unavailable < n or not 0 <= self.malicious < n
                or not 1 <= self.quorum <= n - self.unavailable
                or 2 * self.quorum - n < self.malicious + 1):
            raise EvidenceError("unsafe witness quorum configuration")


def _signed(body: dict, signature: Signature, key_id: str, trust: TrustDirectory) -> bool:
    return (type(signature) is Signature and signature.key_id == key_id
            and signature.alg == ALG_ED25519 and trust.verify(body, signature))


def _ack_valid(ack: WitnessAck, witness_id: str, key_id: str, scope: WitnessScope,
               checkpoint: Checkpoint, trust: TrustDirectory) -> bool:
    return (type(ack) is WitnessAck and type(ack.scope) is WitnessScope
            and type(ack.checkpoint) is Checkpoint and ack.witness_id == witness_id
            and ack.scope == scope and ack.checkpoint == checkpoint
            and _nonce(ack.request_id) and _hex(ack.previous_ack_digest) and _natural(ack.issued_at_us)
            and _signed(ack.body(), ack.signature, key_id, trust))


def verify_quorum(responses: tuple[WitnessAck | WitnessReack, ...], *,
                  requests: dict[str, str], checkpoint: Checkpoint, scope: WitnessScope,
                  previous_acks: dict[str, str], members: WitnessSet,
                  trust: TrustDirectory) -> tuple[WitnessAck, ...]:
    """Verify one batch; previous_acks must come from verified durable local state.

    A refusal, missing response, or historical object cannot be converted to an
    ACK. Network timeout/conflict/audit failures must stop the orchestrator before
    this function. This function alone does not authorize a permit.
    """
    members.validate(trust)
    keys = dict(members.members)
    if (type(responses) is not tuple or len(responses) > len(keys)
            or type(checkpoint) is not Checkpoint or type(scope) is not WitnessScope
            or type(requests) is not dict or set(requests) != set(keys)
            or any(not _nonce(v) for v in requests.values())
            or len(set(requests.values())) != len(requests)
            or type(previous_acks) is not dict or set(previous_acks) != set(keys)
            or any(not _hex(v) for v in previous_acks.values())):
        raise EvidenceError("invalid witness quorum inputs")
    verified, seen = [], set()
    for response in responses:
        if type(response) is not WitnessAck and type(response) is not WitnessReack:
            raise EvidenceError("non-qualifying witness response")
        identity = response.witness_id
        if type(identity) is not str or identity not in keys or identity in seen:
            raise EvidenceError("unknown or duplicate witness")
        seen.add(identity)
        if response.request_id != requests[identity]:
            raise EvidenceError("witness response replay")
        ack = response.ack if type(response) is WitnessReack else response
        if not _ack_valid(ack, identity, keys[identity], scope, checkpoint, trust):
            raise EvidenceError("invalid witness acknowledgement")
        if type(response) is WitnessReack and not _signed(response.body(), response.signature, keys[identity], trust):
            raise EvidenceError("invalid witness re-acknowledgement")
        # A lost reply's old ACK may either already be pinned or directly extend
        # the pin. Larger gaps must be recovered/verified through bounded ack-range.
        pin = previous_acks[identity]
        if ack.previous_ack_digest != pin and not (type(response) is WitnessReack and ack.digest() == pin):
            raise EvidenceError("unreconciled witness acknowledgement chain")
        verified.append(ack)
    if len(verified) < members.quorum:
        raise EvidenceError("insufficient witness quorum")
    return tuple(verified)
