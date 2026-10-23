"""The one participant seam: every collaborator faces the same six operations.

Local managed workers, future remote A2A agents, and test fakes all implement
this Protocol. No adapter is privileged by who made it; nothing in the seam
can name a maker. The Protocol module imports no provider, no SDK, and no
platform machinery — only the domain records it speaks in.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from factory.collaboration.contracts import (
    DispatchReceipt,
    ParticipantCard,
    RemoteTaskProjection,
    WakeSignal,
    WorkTicket,
)


@runtime_checkable
class ParticipantTransport(Protocol):
    """Six operations, typed receipts, no side doors.

    ``send`` carries a content-addressed note digest, never raw content —
    content moves through governed channels, not the transport seam. ``subscribe``
    yields signal-only wakes; state truth comes from ``status`` reconciliation.
    """

    def discover(self) -> ParticipantCard:
        """Return the participant's card: capabilities + qualification proof."""
        ...

    def dispatch(self, ticket: WorkTicket) -> DispatchReceipt:
        """Deliver a ticket. Idempotent per ticket idempotency_key; delivery is a hint."""
        ...

    def status(self, ticket_id: str) -> RemoteTaskProjection:
        """Reconcile the remote lifecycle for one ticket (authoritative read)."""
        ...

    def cancel(self, ticket_id: str) -> DispatchReceipt:
        """Request cancellation. The receipt reports delivery, not success."""
        ...

    def send(self, ticket_id: str, note_digest: str) -> DispatchReceipt:
        """Deliver a content-addressed note reference for an in-flight ticket."""
        ...

    def subscribe(self, ticket_id: str) -> Iterable[WakeSignal]:
        """Yield signal-only wakes for one ticket. Never content."""
        ...
