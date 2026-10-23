"""SPEC020 namespace wire formats; no writer gains sealing authority here.

The separate sealer must validate source signatures, transitions, full retained
history and coherent snapshots before signing. These pure contracts do not
perform that protocol or authorize any caller.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Any

from .canonical import digest_hex
from .evidence_encoding import canonical_bytes, loads as evidence_loads
from .clock import TrustedClock, read_clock
from .evidence import GENESIS
from .evidence_map import EMPTY as EMPTY_MAP
from .evidence_service import EvidenceError, _hex, _natural
from .merkle import EMPTY_ROOT, leaf_hash, verify_consistency
from .signing import Signature, Signer, TrustDirectory
from .evidence_key_policy import key_allowed, valid_policy

SCOPES = frozenset({"tenant", "installation", "verification_class"})
NAMESPACES = frozenset({"scope", "collaboration", "budget", "governance", "roster",
                        "qualification", "delegation", "release", "lifecycle"})


def valid_scope(scope_type: str, scope_id: str, namespace: str) -> bool:
    return (type(scope_type) is str and scope_type in SCOPES
            and type(scope_id) is str and bool(scope_id)
            and type(namespace) is str and namespace in NAMESPACES)


def state_key(scope_type: str, scope_id: str, namespace: str, kind: str, identifier: Any) -> bytes:
    if (not valid_scope(scope_type, scope_id, namespace) or type(kind) is not str or not kind
            or (type(identifier) is not str and type(identifier) is not list)):
        raise EvidenceError("invalid namespace state key")
    try:
        # Reject non-JSON objects/non-finite numbers before the shared canonical
        # encoder; a composite identifier is a JSON array, not a custom object.
        encoded = json.dumps(identifier, allow_nan=False)
        if evidence_loads(encoded) != identifier:
            raise ValueError("not a JSON identifier")
        return sha256(canonical_bytes({"schema": "regulated/ns-state-key/v1", "scope_type": scope_type,
                                       "scope_id": scope_id, "namespace": namespace, "kind": kind,
                                       "id": identifier})).digest()
    except (TypeError, ValueError, RecursionError) as exc:
        raise EvidenceError("invalid namespace identifier encoding") from exc


@dataclass(frozen=True)
class StateValue:
    sequence: int
    history_head: str
    content_digest: str

    def bytes(self) -> bytes:
        if not _natural(self.sequence) or not _hex(self.history_head) or not _hex(self.content_digest):
            raise EvidenceError("invalid namespace state value")
        return canonical_bytes({"schema": "regulated/ns-state-value/v1", "sequence": self.sequence,
                                "history_head": self.history_head, "content_digest": self.content_digest})

    @classmethod
    def from_bytes(cls, raw: bytes) -> StateValue:
        try:
            if type(raw) is not bytes:
                raise ValueError("state value must be bytes")
            value = evidence_loads(raw)
            if value.pop("schema") != "regulated/ns-state-value/v1":
                raise ValueError("wrong state value schema")
            result = cls(**value)
            if result.bytes() != raw:
                raise ValueError("noncanonical state value")
            return result
        except (TypeError, ValueError, AttributeError, KeyError, RecursionError) as exc:
            raise EvidenceError("invalid namespace state representation") from exc


@dataclass(frozen=True)
class Transition:
    scope_type: str
    scope_id: str
    namespace: str
    key: str
    history_sequence: int
    history_head: str
    content_digest: str

    def bytes(self) -> bytes:
        if (not valid_scope(self.scope_type, self.scope_id, self.namespace) or not _hex(self.key)
                or not _natural(self.history_sequence) or not _hex(self.history_head)
                or not _hex(self.content_digest)):
            raise EvidenceError("invalid namespace transition")
        return canonical_bytes({"schema": "regulated/ns-transition/v1", "scope_type": self.scope_type,
                                "scope_id": self.scope_id, "namespace": self.namespace, "key": self.key,
                                "history_sequence": self.history_sequence, "history_head": self.history_head,
                                "content_digest": self.content_digest})

    def state_value(self) -> StateValue:
        self.bytes()  # qualify all scope/key/sequence fields before projection
        return StateValue(self.history_sequence, self.history_head, self.content_digest)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Transition:
        try:
            if type(raw) is not bytes:
                raise ValueError("transition must be bytes")
            value = evidence_loads(raw)
            if value.pop("schema") != "regulated/ns-transition/v1":
                raise ValueError("wrong transition schema")
            result = cls(**value)
            if result.bytes() != raw:
                raise ValueError("noncanonical transition")
            return result
        except (TypeError, ValueError, AttributeError, KeyError, RecursionError) as exc:
            raise EvidenceError("invalid namespace transition representation") from exc


def advance_chain(previous: str, transition: Transition) -> str:
    if not _hex(previous) or type(transition) is not Transition:
        raise EvidenceError("invalid namespace chain input")
    return sha256(bytes.fromhex(previous) + leaf_hash(transition.bytes())).hexdigest()


@dataclass(frozen=True)
class NamespaceHead:
    scope_type: str
    scope_id: str
    namespace: str
    version: int
    tree_root: str
    map_root: str
    chain: str
    previous_head_digest: str
    key_id: str
    clock_domain: str
    issued_at_us: int
    signature: Signature

    @property
    def tree_size(self) -> int:
        """Shared publication adapter's size interface; wire field stays version."""
        return self.version

    def body(self) -> dict[str, Any]:
        return {"schema": "regulated/ns-head/v2", "map_schema": "regulated/evidence-map/v2", "scope_type": self.scope_type, "scope_id": self.scope_id,
                "namespace": self.namespace, "version": self.version, "tree_root": self.tree_root,
                "map_root": self.map_root, "chain": self.chain, "previous_head_digest": self.previous_head_digest,
                "key_id": self.key_id, "clock_domain": self.clock_domain, "issued_at_us": self.issued_at_us}

    def document(self) -> dict[str, Any]:
        return {"body": self.body(), "signature": self.signature}

    def digest(self) -> str:
        return digest_hex(self.document())

    @classmethod
    def from_document(cls, value: dict[str, Any]) -> NamespaceHead:
        try:
            if type(value) is not dict or set(value) != {"body", "signature"}:
                raise ValueError("invalid head document fields")
            body = dict(value["body"])
            if body.pop("map_schema") != "regulated/evidence-map/v2":
                raise ValueError("wrong map schema")
            if body.pop("schema") != "regulated/ns-head/v2":
                raise ValueError("wrong namespace head schema")
            result = cls(**body, signature=Signature(**value["signature"]))
            if canonical_bytes(result.document()) != canonical_bytes(value):
                raise ValueError("noncanonical typed head")
            return result
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
            raise EvidenceError("invalid namespace head representation") from exc


def _head_shape(head: NamespaceHead) -> bool:
    if (type(head) is not NamespaceHead or not valid_scope(head.scope_type, head.scope_id, head.namespace)
            or not _natural(head.version) or not _natural(head.issued_at_us)
            or not all(_hex(x) for x in (head.tree_root, head.map_root, head.chain, head.previous_head_digest))
            or type(head.signature) is not Signature or type(head.key_id) is not str or not head.key_id
            or type(head.clock_domain) is not str or not head.clock_domain or head.signature.key_id != head.key_id):
        return False
    return head.version != 0 or (head.tree_root == EMPTY_ROOT.hex() and head.map_root == EMPTY_MAP[0].hex()
                                 and head.chain == GENESIS and head.previous_head_digest == GENESIS)


def verify_namespace_head(head: NamespaceHead, *, scope_type: str, scope_id: str, namespace: str,
                          clock_domain: str, trust: TrustDirectory, allowed_keys: frozenset[str],
                          historical_keys: dict | None = None) -> bool:
    return (_head_shape(head)
            and (head.scope_type, head.scope_id, head.namespace) == (scope_type, scope_id, namespace)
            and head.clock_domain == clock_domain and key_allowed(head.key_id, head.version, allowed_keys, historical_keys)
            and trust.verify(head.body(), head.signature))


def verify_namespace_extension(previous: NamespaceHead | None, new: NamespaceHead,
                               consistency: tuple[bytes, ...], **verification: Any) -> bool:
    if not verify_namespace_head(new, **verification):
        return False
    if previous is None:
        return (new.previous_head_digest == GENESIS
                and verify_consistency(0, new.version, EMPTY_ROOT, bytes.fromhex(new.tree_root), consistency))
    if not verify_namespace_head(previous, **verification) or new.issued_at_us < previous.issued_at_us:
        return False
    if new.version == previous.version:
        return new == previous and not consistency
    return (new.previous_head_digest == previous.digest()
            and verify_consistency(previous.version, new.version, bytes.fromhex(previous.tree_root),
                                   bytes.fromhex(new.tree_root), consistency))


def sign_namespace_head(*, scope_type: str, scope_id: str, namespace: str, version: int,
                        tree_root: bytes, map_root: bytes, chain: str, previous: NamespaceHead | None,
                        consistency: tuple[bytes, ...], signer: Signer, clock: TrustedClock,
                        trust: TrustDirectory, signing_keys: frozenset[str],
                        historical_keys: dict) -> NamespaceHead:
    """Sealer-only composition primitive; this grants no capability to writers."""
    if (not _natural(version) or not valid_scope(scope_type, scope_id, namespace)
            or type(signing_keys) is not frozenset or signer.key_id not in signing_keys
            or not valid_policy(signing_keys, historical_keys) or not trust.matches_signer(signer)
            or type(tree_root) is not bytes or len(tree_root) != 32
            or type(map_root) is not bytes or len(map_root) != 32):
        raise EvidenceError("unqualified namespace signing configuration")
    verify = dict(scope_type=scope_type, scope_id=scope_id, namespace=namespace,
                  clock_domain=clock.domain, trust=trust, allowed_keys=signing_keys, historical_keys=historical_keys)
    if previous is not None and (not verify_namespace_head(previous, **verify) or version <= previous.version):
        raise EvidenceError("namespace seal must advance a qualified previous head")
    reading = read_clock(clock)
    draft = NamespaceHead(scope_type, scope_id, namespace, version, tree_root.hex(), map_root.hex(), chain,
                          GENESIS if previous is None else previous.digest(), signer.key_id, reading.domain,
                          reading.now_us, Signature(signer.key_id, "", signer.alg))
    if (not _head_shape(draft) or (previous is not None and reading.now_us < previous.issued_at_us)
            or not verify_consistency(0 if previous is None else previous.version, version,
                                      EMPTY_ROOT if previous is None else bytes.fromhex(previous.tree_root),
                                      tree_root, consistency)):
        raise EvidenceError("invalid namespace seal fields, time or consistency")
    result = replace(draft, signature=signer.sign(draft.body()))
    if not verify_namespace_extension(previous, result, consistency, **verify):
        raise EvidenceError("new namespace signature or extension failed")
    return result
