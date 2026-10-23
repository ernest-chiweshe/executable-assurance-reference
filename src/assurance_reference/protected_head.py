"""Local decision-head publication adapter, SPEC-006/017.

This is local crash/replay protection, not administrator-resistant custody.
Rewinding CURRENT with newer head files present rolls forward. Deleting newer
head files and rewinding CURRENT (and optionally the database) is NOT detected.
External monotonic custody is required for that threat; none is claimed here.
No directories are enumerated on read or publication. Each instance handles one
scope. Decision and namespace stores share the same publication protocol.
"""
from __future__ import annotations

import errno
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from regulated_core.evidence_encoding import canonical_bytes, loads as evidence_loads
from regulated_core.evidence_service import (
    EvidenceError, TreeHead, verify_head, verify_head_extension,
)
from regulated_core.merkle import MAX_SIZE
from regulated_core.signing import TrustDirectory
from regulated_core.evidence_key_policy import valid_policy, copy_retirements


@dataclass(frozen=True)
class Publication:
    counter: int
    head: TreeHead
    consistency: tuple[bytes, ...]
    digest: str


class FileProtectedHeadStore:
    """Reference file store for the tenant decision namespace only.

    Call only after database locks have been released. advance() verifies a
    consistency proof and compare-and-set pin, but does not itself perform
    retention or grant a permit; those are the later pre-permit protocol.
    A persisted LATCH refuses all subsequent calls until explicit maintenance.
    """

    def __init__(self, base: Path, *, tenant: str, clock_domain: str,
                 trust: TrustDirectory, existing_heads: dict, advancing_heads: frozenset[str],
                 max_roll_forward: int = 8, max_head_bytes: int = 65536) -> None:
        if (type(tenant) is not str or not tenant or type(clock_domain) is not str or not clock_domain
                or not valid_policy(advancing_heads, existing_heads)
                or not advancing_heads
                or any(not trust.is_known(key) for key in advancing_heads | existing_heads.keys())
                or type(max_roll_forward) is not int or not 1 <= max_roll_forward <= 64
                or type(max_head_bytes) is not int or not 1024 <= max_head_bytes <= 1048576):
            raise EvidenceError("invalid protected-head configuration")
        self.directory = Path(base) / "heads" / "tenant" / sha256(tenant.encode()).hexdigest() / "evidence"
        self.tenant, self.clock_domain = tenant, clock_domain
        self.trust = trust
        self.advancing_heads = advancing_heads
        self.existing_heads = copy_retirements(advancing_heads, existing_heads)
        self.max_roll_forward, self.max_head_bytes = max_roll_forward, max_head_bytes

    def _arguments(self, *, advancing=False) -> dict:
        return dict(tenant=self.tenant, clock_domain=self.clock_domain,
                    trust=self.trust, allowed_keys=self.advancing_heads,
                    historical_keys={} if advancing else self.existing_heads)

    def _decode_head(self, document):
        return TreeHead.from_document(document)

    def _verify_head(self, head, *, advancing=False):
        return verify_head(head, **self._arguments(advancing=advancing))

    def _verify_extension(self, previous, new, consistency):
        return verify_head_extension(previous, new, consistency, **self._arguments())

    @contextmanager
    def _locked(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / "LOCK").open("a+b") as lock:
            lock.seek(0, os.SEEK_END)
            if lock.tell() == 0:
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                lock.seek(0)
                if os.name == "nt":
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _sync_directory(self) -> None:
        if os.name == "nt":
            # Windows does not expose directory fsync through Python's os API.
            return
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                    raise
        finally:
            os.close(descriptor)

    def _read_file(self, path: Path, limit: int) -> bytes:
        with path.open("rb") as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise EvidenceError("protected-head object exceeds configured bound")
        return data

    def _latch(self) -> None:
        try:
            with (self.directory / "LATCH").open("xb") as target:
                target.write(b"integrity or recovery bound failure; explicit maintenance required\n")
                target.flush()
                os.fsync(target.fileno())
            self._sync_directory()
        except FileExistsError:
            pass

    def _path(self, counter: int) -> Path:
        if type(counter) is not int or not 1 <= counter <= MAX_SIZE:
            raise EvidenceError("invalid publication counter")
        return self.directory / f"{counter:020d}.json"

    def _load(self, counter: int) -> Publication:
        data = self._read_file(self._path(counter), self.max_head_bytes)
        try:
            value = evidence_loads(data)
            if (type(value) is not dict or set(value) != {"schema", "counter", "head", "consistency"}
                    or value["schema"] != "regulated/head-publication/v1"
                    or type(value["counter"]) is not int or value["counter"] != counter
                    or type(value["consistency"]) is not list or len(value["consistency"]) > 65
                    or canonical_bytes(value) != data):
                raise ValueError("invalid publication representation")
            head = self._decode_head(value["head"])
            proof = tuple(bytes.fromhex(h) for h in value["consistency"])
            if any(len(h) != 32 for h in proof) or not self._verify_head(head):
                raise ValueError("invalid publication signature or proof encoding")
            return Publication(counter, head, proof, sha256(data).hexdigest())
        except (TypeError, KeyError, ValueError, RecursionError) as exc:
            raise EvidenceError("invalid protected-head publication") from exc

    def _replace_current(self, publication: Publication) -> None:
        data = canonical_bytes({"counter": publication.counter, "hash": publication.digest})
        temporary = self.directory / "CURRENT.tmp"
        with temporary.open("wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, self.directory / "CURRENT")
        self._sync_directory()

    def _read_locked(self) -> Publication | None:
        if (self.directory / "LATCH").exists():
            raise EvidenceError("protected-head store is latched")
        try:
            try:
                raw = self._read_file(self.directory / "CURRENT", 1024)
            except FileNotFoundError:
                current = None
            else:
                value = evidence_loads(raw)
                if (type(value) is not dict or set(value) != {"counter", "hash"}
                        or canonical_bytes(value) != raw):
                    raise EvidenceError("invalid CURRENT pointer")
                current = self._load(value["counter"])
                if current.digest != value["hash"]:
                    raise EvidenceError("CURRENT digest mismatch")
            steps = 0
            while True:
                counter = 1 if current is None else current.counter + 1
                if counter > MAX_SIZE:
                    return current
                try:
                    following = self._load(counter)
                except FileNotFoundError:
                    return current
                if steps >= self.max_roll_forward:
                    raise EvidenceError("protected-head recovery bound exceeded")
                if (not self._verify_head(following.head, advancing=True)
                        or current is not None and following.head.tree_size <= current.head.tree_size
                        or not self._verify_extension(None if current is None else current.head,
                                                      following.head, following.consistency)):
                    raise EvidenceError("publication chain is inconsistent")
                self._replace_current(following)
                current = following
                steps += 1
        except (EvidenceError, ValueError, KeyError, TypeError, OSError, RecursionError) as exc:
            self._latch()
            raise EvidenceError("protected-head integrity/recovery refused") from exc

    def read(self) -> TreeHead | None:
        with self._locked():
            publication = self._read_locked()
            return None if publication is None else publication.head

    def advance(self, expected: TreeHead | None, new: TreeHead,
                consistency: tuple[bytes, ...]) -> TreeHead:
        if not self._verify_head(new, advancing=True) or not self._verify_extension(expected, new, consistency):
            raise EvidenceError("unverified protected-head extension")
        with self._locked():
            current = self._read_locked()
            actual = None if current is None else current.head
            if actual == new:
                return new  # acknowledgement retry, never a second publication
            if actual != expected:
                raise EvidenceError("protected-head compare-and-set lost")
            if actual is not None and new.tree_size <= actual.tree_size:
                raise EvidenceError("protected-head size must advance")
            counter = 1 if current is None else current.counter + 1
            data = canonical_bytes({"schema": "regulated/head-publication/v1", "counter": counter,
                                    "head": new.document(), "consistency": tuple(h.hex() for h in consistency)})
            if len(data) > self.max_head_bytes:
                raise EvidenceError("protected-head object exceeds configured bound")
            with self._path(counter).open("xb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            self._sync_directory()
            publication = self._load(counter)  # read-back before pointer publication
            self._replace_current(publication)
            return new


class FileNamespaceHeadStore(FileProtectedHeadStore):
    """The same counter/CAS/recovery protocol, bound to one SPEC020 namespace.

    This adapter accepts sealed heads only. It neither seals unsigned writer
    state nor claims that source-history retention has already been performed.
    """

    def __init__(self, base: Path, *, scope_type: str, scope_id: str, namespace: str,
                 clock_domain: str, trust: TrustDirectory, existing_heads: dict, advancing_heads: frozenset[str],
                 max_roll_forward: int = 8, max_head_bytes: int = 65536) -> None:
        from regulated_core.evidence_namespace import valid_scope
        if not valid_scope(scope_type, scope_id, namespace):
            raise EvidenceError("invalid namespace publication scope")
        self.scope_type, self.scope_id, self.namespace = scope_type, scope_id, namespace
        super().__init__(base, tenant=scope_id, clock_domain=clock_domain, trust=trust,
                         existing_heads=existing_heads, advancing_heads=advancing_heads, max_roll_forward=max_roll_forward, max_head_bytes=max_head_bytes)
        self.directory = Path(base) / "heads" / scope_type / sha256(scope_id.encode()).hexdigest() / namespace

    def _arguments(self, *, advancing=False) -> dict:
        return dict(scope_type=self.scope_type, scope_id=self.scope_id, namespace=self.namespace,
                    clock_domain=self.clock_domain, trust=self.trust, allowed_keys=self.advancing_heads,
                    historical_keys={} if advancing else self.existing_heads)

    def _decode_head(self, document):
        from regulated_core.evidence_namespace import NamespaceHead
        return NamespaceHead.from_document(document)

    def _verify_head(self, head, *, advancing=False):
        from regulated_core.evidence_namespace import verify_namespace_head
        return verify_namespace_head(head, **self._arguments(advancing=advancing))

    def _verify_extension(self, previous, new, consistency):
        from regulated_core.evidence_namespace import verify_namespace_extension
        return verify_namespace_extension(previous, new, consistency, **self._arguments())
