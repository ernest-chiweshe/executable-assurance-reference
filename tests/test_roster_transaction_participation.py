"""Intact synthetic roster transaction observations; not a PostgreSQL rollback proof."""
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from regulated_core.governance_roster import GovernanceRoster, RosterMember, roster_change_bytes
from regulated_core.governance_targets import FinalCheckRefused, GOVERNANCE_ROLE, issue_bootstrap
from regulated_core.governance_transaction import GovernanceTransactionCheck
from regulated_core.persistence_pg import PostgresRosterStore
from roster_verifier_fixture import verified_store


class Connection:
    def __init__(self):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.events, self.rows = [], []

    @contextmanager
    def transaction(self):
        self.info.transaction_status = TransactionStatus.INTRANS
        self.events.append("begin")
        try:
            yield self
        except BaseException:
            self.rows.clear()
            self.events.append("rollback")
            raise
        else:
            self.events.append("commit")
        finally:
            self.info.transaction_status = TransactionStatus.IDLE

    def execute(self, sql, params=()):
        assert self.info.transaction_status == TransactionStatus.INTRANS
        if sql.startswith("SELECT pg_advisory"):
            self.events.append("lock")
        elif sql.startswith("SELECT version, roster_digest"):
            self.events.append("read-prior")
        elif sql.startswith("INSERT INTO regulated_governance_rosters_v1"):
            self.events.append("effect-and-receipt")
            self.rows.append(params)
        else:
            raise AssertionError(sql)
        return SimpleNamespace(fetchone=lambda: None, fetchall=lambda: [])


@pytest.mark.parametrize("failure", [None, "consume", "final"])
def test_roster_dispatches_participant_on_owned_connection_before_effect(failure):
    conn = Connection()
    configured, signer = verified_store(installation="fixture-installation")
    store = PostgresRosterStore(pool=SimpleNamespace(connection=lambda: nullcontext(conn)),
                                proof_verifier=configured._proof_verifier)
    roster = GovernanceRoster("fixture-installation", 1,
        (RosterMember("synthetic-reviewer", frozenset({GOVERNANCE_ROLE}), "fixture-line"),),
        frozenset(), True)

    def consume(actual):
        assert actual is conn
        conn.events.append("consume")
        if failure == "consume":
            raise FinalCheckRefused("ordinary reservation unavailable")

    def final():
        assert conn.info.transaction_status == TransactionStatus.INTRANS
        conn.events.append("final")
        if failure == "final":
            raise FinalCheckRefused("ordinary approval expired")

    proof = issue_bootstrap(signer, tenant_id="fixture", kind="governance-roster",
                            subject=roster.installation, output=roster_change_bytes(roster))
    change = SimpleNamespace(change={"roster": roster.as_fields()}, subject=roster.installation,
        approved_prior="absent", tenant_id="fixture", operation="governance:change-roster",
        nonce="bootstrap:" + proof.change_digest, change_digest=proof.change_digest, authority_proof=proof,
        final_check=GovernanceTransactionCheck(consume, final))
    if failure:
        with pytest.raises(FinalCheckRefused):
            store.apply(change)
        assert not conn.rows and "effect-and-receipt" not in conn.events
        assert conn.events[-1] == "rollback"
    else:
        store.apply(change)
        assert conn.events == ["begin", "lock", "read-prior", "read-prior", "read-prior", "consume", "final", "effect-and-receipt", "commit"]
        assert conn.rows[0][-4:] == ("fixture", "governance:change-roster", "bootstrap:" + proof.change_digest, proof.change_digest)
