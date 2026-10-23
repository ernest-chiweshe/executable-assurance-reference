"""Offline recorder read contracts using signed synthetic storage observations.

The real decoder, signature checks and chain verifier run unchanged. This does
not exercise PostgreSQL storage, privileges or transaction durability.
"""

from contextlib import nullcontext
import json

import pytest

from regulated_core import (
    Action, ActionEffect, Actor, Assertion, Decision, Ed25519Signer,
    PolicyContext, PolicyRef, TrustDirectory,
)
from regulated_core.evidence import DecisionRecorder
from regulated_core.persistence_pg import PostgresDecisionRecorder
from regulated_core.signing import canonical_bytes


class SyntheticReadPool:
    def __init__(self, rows):
        self.rows = rows
        self.tenant = None
        self.reads = 0

    def connection(self):
        return nullcontext(self)

    def transaction(self):
        return nullcontext(self)

    def execute(self, query, parameters):
        if query == "SELECT set_config('app.tenant', %s, true)":
            self.tenant = parameters[0]
        else:
            assert query == (
                "SELECT seq, entry_hash, envelope FROM regulated_decision_evidence_v1"
                " WHERE tenant = %s ORDER BY seq"
            )
            assert parameters == (self.tenant,) == ("synthetic-read",)
            self.reads += 1
        return self

    def fetchall(self):
        return list(self.rows)


@pytest.mark.parametrize("order", [(2, 1, 0), (0, 2, 1)], ids=["reversed", "adjacent-swap"])
def test_postgres_recorder_refuses_reordered_signed_storage_observations(order):
    signer = Ed25519Signer("fixture:read-evidence")
    trust = TrustDirectory()
    trust.register_signer(signer)
    source = DecisionRecorder(signer, trust)
    tenant = "synthetic-read"
    for index in range(3):
        source.record(
            Assertion("fixture", tenant, "course:lesson", "a" * 64),
            Action("course:review", ActionEffect.REVERSIBLE),
            PolicyContext(tenant, Actor("reviewer", tenant, frozenset()),
                          "synthetic-review", str(index), index),
            PolicyRef("course", "fixture", "1"),
            Decision.deny("REVIEW_PENDING", "Synthetic read contract; no target effect"),
        )
    entries = source.entries(tenant)
    rows = tuple((entry.seq, entry.chain_hash(), json.loads(canonical_bytes(entry))) for entry in entries)
    pool = SyntheticReadPool(rows)
    recorder = PostgresDecisionRecorder(signer, trust, pool=pool)
    assert recorder.entries(tenant) == entries
    assert recorder.verify_chain(tenant) is True
    pool.rows = tuple(rows[index] for index in order)
    # Every stored entry still decodes and verifies individually. The chain's
    # ordering check must independently reject the synthetic read observation.
    assert recorder.entries(tenant) == tuple(entries[index] for index in order)
    assert recorder.verify_chain(tenant) is False
    assert pool.reads == 4
    pool.rows = rows
    assert recorder.verify_chain(tenant) is True
