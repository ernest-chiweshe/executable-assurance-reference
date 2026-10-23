"""Construct the durable regulated stores over one explicitly scoped host pool.

No database connection, migration, activation or signing occurs here. The host
owns the underlying pool and must inject this same session adapter into any
additional authority store invoked while a lifecycle guard is held.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from factory.packs.lifecycle_pg import PostgresActivationLedger
from factory.pg_session import SessionBoundPool

from .governance_guard import GovernanceGuard
from .persistence_pg import (PostgresClearanceStore, PostgresDecisionRecorder, PostgresGovernanceLog, PostgresGrantStore,
                             PostgresHeartbeatStore, PostgresMissionBudget, PostgresPermitUseStore,
                             PostgresRevocationLedger)
from .review_store import PostgresReviewStore
from .signing import Signer, TrustDirectory


@dataclass(frozen=True)
class RegulatedPostgresStores:
    pool: SessionBoundPool
    activation: PostgresActivationLedger
    recorder: PostgresDecisionRecorder
    permits: PostgresPermitUseStore
    reviews: PostgresReviewStore
    # One durable budget ledger for every host engine over this pool: two hosts, or a host after a restart,
    # see the same reservations, so authority spread across workers cannot exceed a mission's limit (review 2976).
    budget: PostgresMissionBudget
    # One revocation epoch per tenant across every host and restart, so revoking reaches outstanding permits
    # wherever they are held (Paper A 5.3).
    revocation: PostgresRevocationLedger
    # Delegation grants and their revocations (A08), shared the same way: a chain issued on one host verifies on every
    # other, and revoking an ancestor reaches them all.
    grants: PostgresGrantStore
    # Tier-4 monitor clearances (A03), shared so a clearance recorded on one host counts on every other.
    clearances: PostgresClearanceStore
    # Governance attempts and outcomes (A09), the receiving record every governance target and review reads.
    governance: PostgresGovernanceLog | None = None
    # Monitor heartbeats (A17), shared so a heartbeat received by one host keeps every host's high-tier authority open.
    heartbeats: PostgresHeartbeatStore | None = None


def compose_regulated_stores(pool: Any, *, evidence_signer: Signer, trust: TrustDirectory,
                             guard: GovernanceGuard | None = None,
                             budget_allocator_pool: Any = None,
                             recorder_pool: Any = None,
                             historical_evidence_key_ids: frozenset[str] = frozenset()) -> RegulatedPostgresStores:
    """With `guard`, the activation ledger refuses every lifecycle write that is not a governance target applying an
    approved change (A09); a deployment passes one, so its pack lifecycle can change only through the door.

    Pass a separately authenticated ``budget_allocator_pool`` for reservation
    and release writes when the ledger enforces writer roles. The host owns
    its lifetime and must bind it to the same database and schema as ``pool``.
    It must not reuse the receiver session adapter: a lifecycle guard pins that
    adapter to the receiver login. Omission retains single-pool behavior and
    does not grant allocation privileges. This is connection routing, not
    separate-process custody.

    An explicit recorder pool authenticates evidence writes independently of
    the receiver. The caller owns it; absence preserves the shared session.
    """
    session = SessionBoundPool(pool)
    evidence_session = session if recorder_pool is None else SessionBoundPool(recorder_pool)
    return RegulatedPostgresStores(
        session, PostgresActivationLedger("", pool=session, guard=guard),
        PostgresDecisionRecorder(evidence_signer, trust, pool=evidence_session,
                                 historical_evidence_key_ids=historical_evidence_key_ids),
        PostgresPermitUseStore(pool=session), PostgresReviewStore(pool=session),
        PostgresMissionBudget(pool=session, allocator_pool=budget_allocator_pool),
        PostgresRevocationLedger(pool=session),
        PostgresGrantStore(pool=session), PostgresClearanceStore(pool=session),
        PostgresGovernanceLog(pool=session), PostgresHeartbeatStore(pool=session),
    )
