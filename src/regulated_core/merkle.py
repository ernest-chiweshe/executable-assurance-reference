"""SHA-256 RFC 9162 trees, immutable compact frontiers and bounded proofs.

Only completed subtrees are stored: (level, index) addresses 2**level leaves.
Proof generation reads those nodes; it never loads or rehashes historical leaves.
Sizes and proof lengths are bounded by the RFC uint64 tree-size representation.
No signed-envelope normalization happens here: leaf inputs are exact bytes.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256

MAX_SIZE = (1 << 64) - 1
EMPTY_ROOT = sha256(b"").digest()
NodeReader = Callable[[int, int], bytes]


def _size(value: int) -> bool:
    return type(value) is int and 0 <= value <= MAX_SIZE


def _hash(value: bytes) -> bool:
    return type(value) is bytes and len(value) == 32


def leaf_hash(data: bytes) -> bytes:
    if type(data) is not bytes:
        raise ValueError("leaf input must be bytes")
    return sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if not _hash(left) or not _hash(right):
        raise ValueError("subtree hash must be 32 bytes")
    return sha256(b"\x01" + left + right).digest()


@dataclass(frozen=True)
class CompletedNode:
    level: int
    index: int
    digest: bytes


@dataclass(frozen=True)
class Frontier:
    """Low-level-first slots; a slot is occupied exactly when its size bit is set."""

    size: int = 0
    slots: tuple[bytes | None, ...] = ()

    def __post_init__(self) -> None:
        if not _size(self.size) or type(self.slots) is not tuple:
            raise ValueError("invalid frontier")
        if len(self.slots) != self.size.bit_length():
            raise ValueError("noncanonical frontier length")
        for level, digest in enumerate(self.slots):
            occupied = bool(self.size & (1 << level))
            if (occupied and not _hash(digest)) or (not occupied and digest is not None):
                raise ValueError("frontier occupancy mismatch")

    def append(self, data: bytes) -> tuple[Frontier, tuple[CompletedNode, ...]]:
        if self.size == MAX_SIZE:
            raise ValueError("tree size exhausted")
        value = leaf_hash(data)
        completed = [CompletedNode(0, self.size, value)]
        slots = list(self.slots)
        level = 0
        while self.size & (1 << level):
            value = node_hash(slots[level], value)
            slots[level] = None
            level += 1
            completed.append(CompletedNode(level, self.size >> level, value))
        if level == len(slots):
            slots.append(value)
        else:
            slots[level] = value
        return Frontier(self.size + 1, tuple(slots)), tuple(completed)

    @property
    def root(self) -> bytes:
        return root_from_frontier(self)


def root_from_frontier(frontier: Frontier) -> bytes:
    right = None
    for value in frontier.slots:
        if value is not None:
            right = value if right is None else node_hash(value, right)
    return EMPTY_ROOT if right is None else right


def _range_root(read: NodeReader, start: int, size: int) -> bytes:
    if not size:
        return EMPTY_ROOT
    if size & (size - 1) == 0:
        result = read(size.bit_length() - 1, start // size)
        if not _hash(result):
            raise ValueError("invalid stored subtree hash")
        return result
    split = 1 << (size.bit_length() - 1)
    return node_hash(_range_root(read, start, split),
                     _range_root(read, start + split, size - split))


def tree_root(read: NodeReader, size: int) -> bytes:
    if not _size(size):
        raise ValueError("invalid tree size")
    return _range_root(read, 0, size)


def inclusion_proof(read: NodeReader, index: int, size: int) -> tuple[bytes, ...]:
    if not _size(size) or type(index) is not int or not 0 <= index < size:
        raise ValueError("leaf outside tree")
    path = []

    def descend(start: int, count: int, offset: int) -> None:
        if count == 1:
            return
        split = 1 << ((count - 1).bit_length() - 1)
        if offset < split:
            descend(start, split, offset)
            path.append(_range_root(read, start + split, count - split))
        else:
            descend(start + split, count - split, offset - split)
            path.append(_range_root(read, start, split))

    descend(0, size, index)
    return tuple(path)


def _proof(path: Sequence[bytes], limit: int) -> bool:
    return ((type(path) is list or type(path) is tuple) and len(path) <= limit
            and all(_hash(value) for value in path))


def verify_inclusion(data: bytes, index: int, size: int,
                     path: Sequence[bytes], root: bytes) -> bool:
    if (not _size(size) or type(index) is not int or not 0 <= index < size
            or type(data) is not bytes or not _hash(root) or not _proof(path, 64)):
        return False
    position, last = index, size - 1
    value = leaf_hash(data)
    for sibling in path:
        if last == 0:
            return False
        if position & 1 or position == last:
            value = node_hash(sibling, value)
            while position and position & 1 == 0:
                position >>= 1
                last >>= 1
        else:
            value = node_hash(value, sibling)
        position >>= 1
        last >>= 1
    return last == 0 and value == root


def consistency_proof(read: NodeReader, first: int, second: int) -> tuple[bytes, ...]:
    if not _size(first) or not _size(second) or first > second:
        raise ValueError("invalid consistency sizes")
    if first == 0 or first == second:
        return ()
    path = []

    def descend(start: int, old: int, new: int, known: bool) -> None:
        if old == new:
            if not known:
                path.append(_range_root(read, start, new))
            return
        split = 1 << ((new - 1).bit_length() - 1)
        if old <= split:
            descend(start, old, split, known)
            path.append(_range_root(read, start + split, new - split))
        else:
            descend(start + split, old - split, new - split, False)
            path.append(_range_root(read, start, split))

    descend(0, first, second, True)
    return tuple(path)


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       path: Sequence[bytes]) -> bool:
    if (not _size(first) or not _size(second) or first > second
            or not _hash(first_root) or not _hash(second_root) or not _proof(path, 65)):
        return False
    if first == second:
        return not path and first_root == second_root and (first != 0 or first_root == EMPTY_ROOT)
    if first == 0:
        return not path and first_root == EMPTY_ROOT
    if not path:
        return False
    old, new = first - 1, second - 1
    while old & 1:
        old >>= 1
        new >>= 1
    if first & (first - 1) == 0:
        old_value = new_value = first_root
        offset = 0
    else:
        old_value = new_value = path[0]
        offset = 1
    for sibling in path[offset:]:
        if new == 0:
            return False
        if old & 1 or old == new:
            old_value = node_hash(sibling, old_value)
            new_value = node_hash(sibling, new_value)
            while old and old & 1 == 0:
                old >>= 1
                new >>= 1
        else:
            new_value = node_hash(new_value, sibling)
        old >>= 1
        new >>= 1
    return new == 0 and old_value == first_root and new_value == second_root


class MemoryMerkleLog:
    """In-memory append-only completed-node store; the service supplies synchronization."""

    def __init__(self) -> None:
        self.frontier = Frontier()
        self._nodes: dict[tuple[int, int], bytes] = {}

    def append(self, data: bytes) -> int:
        frontier, nodes = self.frontier.append(data)
        for node in nodes:
            self._nodes[node.level, node.index] = node.digest
        index = self.frontier.size
        self.frontier = frontier
        return index

    def read_node(self, level: int, index: int) -> bytes:
        return self._nodes[level, index]

    def root(self, size: int | None = None) -> bytes:
        if size is None:
            return self.frontier.root
        self._check_size(size)
        return tree_root(self.read_node, size)

    def inclusion(self, index: int, size: int | None = None) -> tuple[bytes, ...]:
        size = self.frontier.size if size is None else size
        self._check_size(size)
        return inclusion_proof(self.read_node, index, size)

    def consistency(self, first: int, second: int | None = None) -> tuple[bytes, ...]:
        second = self.frontier.size if second is None else second
        self._check_size(second)
        return consistency_proof(self.read_node, first, second)

    def _check_size(self, size: int) -> None:
        if not _size(size) or size > self.frontier.size:
            raise ValueError("tree size not stored")
