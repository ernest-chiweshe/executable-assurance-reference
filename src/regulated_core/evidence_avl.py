"""Immutable AVL nodes with authenticated child heights and aggregates.

Qualification keys are (expiry, sequence), ranked by (qualification time, -seq).
Candidate keys are activation ordinals; aggregates retain the top three
(ordinal, version) entries. The service enforces one candidate per version.
Updates path-copy O(log n) nodes. Historical root objects remain immutable.
Proofs authenticate the query answer, not caller authority or source signatures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Literal

from .canonical import canonical_bytes

Mode = Literal["qualification", "candidate"]
MAX_PROOF_NODES = 128  # exceeds AVL height for a uint64-sized history
EMPTY_ROOT = sha256(b"regulated/evidence-avl/v1:empty").digest()


def _integer(value: int) -> bool:
    return type(value) is int and 0 <= value < 1 << 64


@dataclass(frozen=True)
class Report:
    seq: int
    qualified_at_us: int
    expires_at_us: int
    content_digest: str

    def __post_init__(self) -> None:
        if not all(_integer(x) for x in (self.seq, self.qualified_at_us, self.expires_at_us)):
            raise ValueError("invalid report integers")
        if (type(self.content_digest) is not str or len(self.content_digest) != 64
                or any(x not in "0123456789abcdef" for x in self.content_digest)):
            raise ValueError("invalid report content digest")


@dataclass(frozen=True)
class Candidate:
    ordinal: int
    version: str

    def __post_init__(self) -> None:
        if not _integer(self.ordinal) or type(self.version) is not str or not self.version:
            raise ValueError("invalid candidate")


Record = Report | Candidate
Aggregate = tuple[tuple[int, int | str], ...]


def _mode(record: Record) -> Mode:
    if type(record) is Report:
        return "qualification"
    if type(record) is Candidate:
        return "candidate"
    raise ValueError("invalid AVL record")


def _key(record: Record) -> tuple[int, ...]:
    return (record.expires_at_us, record.seq) if type(record) is Report else (record.ordinal,)


def _score(record: Record) -> tuple[int, int | str]:
    return ((record.qualified_at_us, -record.seq) if type(record) is Report
            else (record.ordinal, record.version))


def _aggregate(record: Record, left: Descriptor | None, right: Descriptor | None) -> Aggregate:
    values = [_score(record)]
    if left is not None:
        values.extend(left.best)
    if right is not None:
        values.extend(right.best)
    return tuple(sorted(values, reverse=True)[:1 if type(record) is Report else 3])


@dataclass(frozen=True)
class Descriptor:
    hash: bytes
    best: Aggregate
    height: int

    def body(self) -> dict:
        return {"hash": self.hash.hex(), "best": self.best, "height": self.height}


def _descriptor_valid(value: Descriptor | None, mode: Mode) -> bool:
    if value is None:
        return True
    if (type(value) is not Descriptor or type(value.hash) is not bytes or len(value.hash) != 32
            or type(value.height) is not int or not 1 <= value.height <= MAX_PROOF_NODES
            or type(value.best) is not tuple or not 1 <= len(value.best) <= (1 if mode == "qualification" else 3)):
        return False
    for pair in value.best:
        if type(pair) is not tuple or len(pair) != 2 or not _integer(pair[0]):
            return False
        if mode == "qualification":
            if type(pair[1]) is not int or not -(1 << 64) < pair[1] <= 0:
                return False
        elif type(pair[1]) is not str or not pair[1]:
            return False
    return (tuple(sorted(value.best, reverse=True)) == value.best
            and len({x[0] for x in value.best}) == len(value.best))


@dataclass(frozen=True)
class Header:
    record: Record
    height: int
    left: Descriptor | None
    right: Descriptor | None

    def body(self) -> dict:
        return {"record": self.record, "height": self.height,
                "left": None if self.left is None else self.left.body(),
                "right": None if self.right is None else self.right.body()}

    def descriptor(self) -> Descriptor:
        mode = _mode(self.record)
        if not _descriptor_valid(self.left, mode) or not _descriptor_valid(self.right, mode):
            raise ValueError("invalid child descriptor")
        left = 0 if self.left is None else self.left.height
        right = 0 if self.right is None else self.right.height
        if type(self.height) is not int or self.height != 1 + max(left, right) or abs(left - right) > 1:
            raise ValueError("invalid AVL height or balance")
        return Descriptor(sha256(b"\x02" + canonical_bytes(self.body())).digest(),
                          _aggregate(self.record, self.left, self.right), self.height)


@dataclass(frozen=True)
class Node:
    record: Record
    left: Node | None = None
    right: Node | None = None
    header: Header = field(init=False)
    descriptor: Descriptor = field(init=False)

    def __post_init__(self) -> None:
        mode = _mode(self.record)
        if any(x is not None and _mode(x.record) != mode for x in (self.left, self.right)):
            raise ValueError("mixed AVL record kinds")
        left = None if self.left is None else self.left.descriptor
        right = None if self.right is None else self.right.descriptor
        header = Header(self.record, 1 + max(_height(self.left), _height(self.right)), left, right)
        # Intermediate unbalanced nodes exist only during a rotation. They never
        # become roots or proof headers; descriptor hashing still binds heights.
        descriptor = Descriptor(sha256(b"\x02" + canonical_bytes(header.body())).digest(),
                                _aggregate(self.record, left, right), header.height)
        object.__setattr__(self, "header", header)
        object.__setattr__(self, "descriptor", descriptor)


def _height(node: Node | None) -> int:
    return 0 if node is None else node.descriptor.height


def _rotate_left(node: Node) -> Node:
    pivot = node.right
    assert pivot is not None
    return Node(pivot.record, Node(node.record, node.left, pivot.left), pivot.right)


def _rotate_right(node: Node) -> Node:
    pivot = node.left
    assert pivot is not None
    return Node(pivot.record, pivot.left, Node(node.record, pivot.right, node.right))


def _balance(node: Node) -> Node:
    if _height(node.left) - _height(node.right) > 1:
        left = node.left
        assert left is not None
        if _height(left.left) < _height(left.right):
            node = Node(node.record, _rotate_left(left), node.right)
        return _rotate_right(node)
    if _height(node.right) - _height(node.left) > 1:
        right = node.right
        assert right is not None
        if _height(right.right) < _height(right.left):
            node = Node(node.record, node.left, _rotate_right(right))
        return _rotate_left(node)
    return node


def _insert(node: Node | None, record: Record) -> Node:
    if node is None:
        return Node(record)
    if _key(record) == _key(node.record):
        if record != node.record:
            raise ValueError("AVL key already bound to a different record")
        return node
    if _key(record) < _key(node.record):
        return _balance(Node(node.record, _insert(node.left, record), node.right))
    return _balance(Node(node.record, node.left, _insert(node.right, record)))


def _remove(node: Node | None, key: tuple[int, ...]) -> Node | None:
    if node is None:
        raise KeyError(key)
    if key < _key(node.record):
        return _balance(Node(node.record, _remove(node.left, key), node.right))
    if key > _key(node.record):
        return _balance(Node(node.record, node.left, _remove(node.right, key)))
    if node.left is None:
        return node.right
    if node.right is None:
        return node.left
    successor = node.right
    while successor.left is not None:
        successor = successor.left
    return _balance(Node(successor.record, node.left, _remove(node.right, _key(successor.record))))


@dataclass(frozen=True)
class EvidenceAVL:
    mode: Mode
    node: Node | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("qualification", "candidate"):
            raise ValueError("invalid AVL mode")
        if self.node is not None and _mode(self.node.record) != self.mode:
            raise ValueError("AVL mode mismatch")

    @property
    def root(self) -> bytes:
        return EMPTY_ROOT if self.node is None else self.node.descriptor.hash

    @property
    def height(self) -> int:
        return _height(self.node)

    def insert(self, record: Record) -> EvidenceAVL:
        if _mode(record) != self.mode:
            raise ValueError("AVL mode mismatch")
        return EvidenceAVL(self.mode, _insert(self.node, record))

    def remove_candidate(self, ordinal: int) -> EvidenceAVL:
        if self.mode != "candidate" or not _integer(ordinal):
            raise ValueError("invalid candidate removal")
        return EvidenceAVL(self.mode, _remove(self.node, (ordinal,)))

    def current_proof(self, now_us: int) -> tuple[Header, ...]:
        if self.mode != "qualification" or not _integer(now_us):
            raise ValueError("invalid qualification query")
        proof = []
        node = self.node
        while node is not None:
            proof.append(node.header)
            node = node.left if node.record.expires_at_us > now_us else node.right
        return tuple(proof)

    def candidates_proof(self) -> tuple[Header, ...]:
        if self.mode != "candidate":
            raise ValueError("not a candidate tree")
        return () if self.node is None else (self.node.header,)


def verify_current(root: bytes, now_us: int, proof: tuple[Header, ...]) -> int | None:
    """Return the proven winning seq (or absence); malformed proofs raise ValueError."""
    if (type(root) is not bytes or len(root) != 32 or not _integer(now_us)
            or type(proof) is not tuple or len(proof) > MAX_PROOF_NODES):
        raise ValueError("invalid qualification proof")
    if root == EMPTY_ROOT:
        if proof:
            raise ValueError("nonempty proof for empty tree")
        return None
    expected = None
    best = None
    lower = upper = None
    for position, header in enumerate(proof):
        if type(header) is not Header or type(header.record) is not Report:
            raise ValueError("invalid report proof header")
        descriptor = header.descriptor()
        if (position == 0 and descriptor.hash != root) or (position > 0 and descriptor != expected):
            raise ValueError("proof child/root commitment mismatch")
        key = _key(header.record)
        if (lower is not None and key <= lower) or (upper is not None and key >= upper):
            raise ValueError("invalid proof key order")
        if header.record.expires_at_us > now_us:
            values = [_score(header.record)]
            if header.right is not None:
                values.extend(header.right.best)
            best = max(values + ([] if best is None else [best]))
            expected = header.left
            upper = key
        else:
            expected = header.right
            lower = key
        if expected is None and position + 1 != len(proof):
            raise ValueError("extra proof nodes")
    if not proof or expected is not None:
        raise ValueError("incomplete proof")
    return None if best is None else -best[1]


def verify_candidates(root: bytes, proof: tuple[Header, ...]) -> tuple[tuple[int, str], ...]:
    """Top-three authenticated ordinals/versions; selected row inclusion is separate."""
    if type(root) is not bytes or len(root) != 32 or type(proof) is not tuple:
        raise ValueError("invalid candidate proof")
    if root == EMPTY_ROOT and not proof:
        return ()
    if len(proof) != 1 or type(proof[0]) is not Header or type(proof[0].record) is not Candidate:
        raise ValueError("invalid candidate header")
    descriptor = proof[0].descriptor()
    if descriptor.hash != root:
        raise ValueError("candidate root mismatch")
    return descriptor.best
