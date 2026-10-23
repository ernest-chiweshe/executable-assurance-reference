"""The case store: one protocol, a memory twin, and (in pg_store) the Postgres authority.

Laws every implementation keeps (deliberation A2, review 10.A and 10.C):

- `open_case` writes the case, its first event and the idempotency row atomically; a second call
  with the same (workspace, action_id) and the same request digest returns the existing case
  (REPLAY); the same key with a different digest raises CareConflict (CONFLICT);
- `append` writes the updated case and one new event atomically and only when the caller's
  expected revision is the stored one; the new revision is expected + 1; the event's seq is the
  next in the case's chain and its prior_digest is the current head; anything else conflicts;
- `append_command` is `append` for a customer command: the (workspace, action_id) key is checked
  FIRST, so an exact retry after success returns the stored case (REPLAY, appended False) even
  though its expected revision is by then stale; the same key with a different request digest (or
  another case) raises CareConflict; otherwise the append law applies and the key is recorded with
  the event it produced, in the same transaction;
- reads are scoped: a case id that is not in the caller's workspace is simply absent (the router
  turns that into a non-disclosing not-found);
- events come back in seq order and the chain verifies.
"""
from __future__ import annotations

import threading
from dataclasses import replace
from typing import Protocol, runtime_checkable

from factory.care.contracts import Case, CaseEvent, CareConflict, CareContractError, verify_chain


@runtime_checkable
class CaseStore(Protocol):
    def open_case(self, case: Case, first_event: CaseEvent, *, request_digest: str) -> tuple[Case, bool]:
        """Create atomically. Returns (stored case, created). `created` is False on an exact replay."""
        ...

    def append(self, case: Case, event: CaseEvent, *, expected_revision: int) -> Case:
        """Store the updated case (revision expected+1) and its new event atomically, or conflict."""
        ...

    def append_command(self, case: Case, event: CaseEvent, *, expected_revision: int, action_id: str,
                       request_digest: str) -> tuple[Case, bool]:
        """`append` under an idempotency key: (stored case, appended); appended is False on an exact replay."""
        ...

    def case(self, workspace_id: str, case_id: str) -> Case | None: ...

    def cases_for(self, workspace_id: str) -> tuple[Case, ...]:
        """Newest first."""
        ...

    def all_cases(self, *, open_only: bool = True) -> tuple[Case, ...]:
        """Operator view across workspaces, newest first."""
        ...

    def events(self, case_id: str) -> tuple[CaseEvent, ...]: ...


def check_append(stored: Case | None, case: Case, event: CaseEvent, head: CaseEvent | None, expected_revision: int) -> None:
    """The append law, shared by both stores so they cannot drift."""
    if stored is None:
        raise CareConflict(f"case {case.case_id} does not exist")
    if stored.revision != expected_revision:
        raise CareConflict(f"case {case.case_id} changed underneath (revision {stored.revision}); re-read and retry")
    if case.revision != expected_revision + 1:
        raise CareConflict(f"case {case.case_id} must advance to revision {expected_revision + 1}")
    if case.case_id != stored.case_id or case.workspace_id != stored.workspace_id:
        raise CareConflict("a case keeps its id and workspace")
    next_seq = 1 if head is None else head.seq + 1
    if event.case_id != case.case_id or event.seq != next_seq:
        raise CareConflict(f"event seq must be {next_seq} for case {case.case_id}")
    if event.prior_digest != (head.digest if head is not None else ""):
        raise CareConflict("event prior_digest must be the current chain head")
    if not event.digest or not event.verify():
        raise CareContractError("an event is stored sealed: its digest must match its payload")
    if case.head_digest != event.digest:
        raise CareConflict("the case's head_digest must be the new event's digest")


def check_open(case: Case, first_event: CaseEvent) -> None:
    if case.revision != 1:
        raise CareConflict("a new case starts at revision 1")
    if first_event.seq != 1 or first_event.prior_digest != "" or first_event.case_id != case.case_id:
        raise CareConflict("the first event is seq 1 with no prior digest")
    if not first_event.digest or not first_event.verify() or case.head_digest != first_event.digest:
        raise CareContractError("the first event must be sealed and be the case's head")


class InMemoryCaseStore:
    """The twin: same laws, one process, for tests and the offline Hub."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cases: dict[str, Case] = {}
        self._events: dict[str, list[CaseEvent]] = {}
        # (workspace, action_id) -> (case_id, request digest, the event the command produced)
        self._idempotency: dict[tuple[str, str], tuple[str, str, str]] = {}

    def open_case(self, case: Case, first_event: CaseEvent, *, request_digest: str) -> tuple[Case, bool]:
        with self._lock:
            key = (case.workspace_id, case.action_id)
            prior = self._idempotency.get(key)
            if prior is not None:
                case_id, digest, _event_id = prior
                if digest != request_digest:
                    raise CareConflict(f"action_id {case.action_id!r} was already used for a different request")
                return self._cases[case_id], False
            if case.case_id in self._cases:
                raise CareConflict(f"case {case.case_id} already exists")
            check_open(case, first_event)
            self._cases[case.case_id] = case
            self._events[case.case_id] = [first_event]
            self._idempotency[key] = (case.case_id, request_digest, first_event.event_id)
            return case, True

    def append(self, case: Case, event: CaseEvent, *, expected_revision: int) -> Case:
        with self._lock:
            stored = self._cases.get(case.case_id)
            chain = self._events.get(case.case_id, [])
            check_append(stored, case, event, chain[-1] if chain else None, expected_revision)
            self._cases[case.case_id] = case
            chain.append(event)
            return case

    def append_command(self, case: Case, event: CaseEvent, *, expected_revision: int, action_id: str,
                       request_digest: str) -> tuple[Case, bool]:
        with self._lock:
            key = (case.workspace_id, action_id)
            prior = self._idempotency.get(key)
            if prior is not None:
                case_id, digest, _event_id = prior
                if digest != request_digest or case_id != case.case_id:
                    raise CareConflict(f"action_id {action_id!r} was already used for a different request")
                return self._cases[case_id], False
            stored = self.append(case, event, expected_revision=expected_revision)
            self._idempotency[key] = (case.case_id, request_digest, event.event_id)
            return stored, True

    def case(self, workspace_id: str, case_id: str) -> Case | None:
        with self._lock:
            found = self._cases.get(case_id)
            return found if found is not None and found.workspace_id == workspace_id else None

    def cases_for(self, workspace_id: str) -> tuple[Case, ...]:
        with self._lock:
            rows = [c for c in self._cases.values() if c.workspace_id == workspace_id]
            return tuple(sorted(rows, key=lambda c: (c.created_at, c.case_id), reverse=True))

    def all_cases(self, *, open_only: bool = True) -> tuple[Case, ...]:
        with self._lock:
            rows = [c for c in self._cases.values() if c.open or not open_only]
            return tuple(sorted(rows, key=lambda c: (c.created_at, c.case_id), reverse=True))

    def events(self, case_id: str) -> tuple[CaseEvent, ...]:
        with self._lock:
            chain = tuple(self._events.get(case_id, ()))
            problems = verify_chain(chain)
            if problems:
                raise CareContractError("event chain is broken: " + "; ".join(problems))
            return chain

    # test helper: tamper to prove the chain check
    def _replace_event(self, case_id: str, seq: int, event: CaseEvent) -> None:
        with self._lock:
            chain = self._events[case_id]
            chain[seq - 1] = replace(event)


__all__ = ["CaseStore", "InMemoryCaseStore", "check_append", "check_open"]
