"""Synthetic read observations and guarded refusals, not SQL isolation evidence."""
from copy import deepcopy

import pytest

from assurance_reference.lifecycle_migration import private_digest
from assurance_reference.lifecycle_partition import partition_snapshot
from assurance_reference.lifecycle_runtime import PartitionedActivationLedger, _LegacyReadView, _load, _merge_scoped_views
from factory.packs.lifecycle import LifecycleError
from factory.packs.lifecycle_pg import PostgresActivationLedger, _canonical, _digest, _restore, _snapshot
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from test_lifecycle_partition import legacy_snapshot


class SyntheticReads:
    """Fixed observations; deliberately cannot execute writes or model RLS."""
    def __init__(self, partition=None):
        self.partition = partition_snapshot("education", legacy_snapshot()) if partition is None else partition
        self.queries = []
        self.tenant = None
        self.private_revision = 6

    def execute(self, query, params):
        self.queries.append((query, params))
        if query.startswith("SELECT set_config"):
            self.tenant = params[0]
            value = (self.tenant,)
        elif query.startswith("SELECT revision,payload,state_digest FROM reference_pack_shared_v1"):
            value = None if params[0] != "education" else (
                6, self.partition["shared"], _digest("education", 6, self.partition["shared"]))
        elif query.startswith("SELECT revision,payload,state_digest FROM reference_pack_tenants_v1"):
            pack, tenant = params
            assert tenant == self.tenant
            scope = self.partition["scopes"].get(tenant)
            value = None if scope is None else (
                self.private_revision, scope, private_digest(pack, tenant, self.private_revision, scope))
        elif query.startswith("SELECT revision,requests,state_digest FROM reference_pack_installation_retries_v1"):
            requests = self.partition["scopes"][None]["requests"]
            value = (6, requests, private_digest(params[0], None, 6, requests))
        else:
            raise AssertionError("unexpected SQL in read-only synthetic observation")

        class Row:
            def fetchone(self):
                return deepcopy(value)

        return Row()


@pytest.mark.parametrize("tenant,version", [("school-a", "1"), ("school-b", None), ("new-school", "1")])
def test_scoped_view_preserves_original_revoked_pin_and_global_fallback(tenant, version):
    conn = SyntheticReads()
    revision, payload = _load(conn, "education", tenant)
    assert revision == 6
    assert _restore("education", payload).resolve(tenant, "education") == version
    foreign = "school-b" if tenant == "school-a" else "school-a"
    assert foreign not in _canonical(payload)
    assert "reference_pack_installation_retries_v1" not in repr(conn.queries)
    assert len([q for q, _ in conn.queries if "FROM reference_pack_tenants_v1" in q]) == 1


def test_global_read_excludes_all_private_rows_but_preserves_full_history():
    conn = SyntheticReads()
    _, payload = _load(conn, "education", None)
    ledger = _restore("education", payload)
    assert len(ledger.history("education")) == 3
    assert ledger.active("education").version == "1"
    assert ledger.is_revoked("education", "2")
    assert payload["pins"] == payload["requests"] == {}
    assert payload["governance_receipts"] == []
    assert len(conn.queries) == 1


def test_installation_retry_view_preserves_exact_old_replies_without_tenant_reads():
    conn = SyntheticReads()
    _, payload = _load(conn, "education", None, installation_retries=True)
    assert payload["requests"] == conn.partition["scopes"][None]["requests"]
    assert "school-a" not in _canonical(payload) and "school-b" not in _canonical(payload)
    assert len(conn.queries) == 2


def test_first_pack_read_establishes_tenant_scope_before_returning_empty_state():
    conn = SyntheticReads()
    revision, payload = _load(conn, "not-yet-installed", "school-a")
    assert revision == 0 and payload["records"] == []
    assert conn.queries[0][1] == ("school-a",)


@pytest.mark.parametrize("problem", ["private-ahead", "foreign-pin-receipt", "foreign-retry", "private-in-shared"])
def test_consistent_checksums_do_not_replace_structural_or_scope_validation(problem):
    conn = SyntheticReads()
    if problem == "private-ahead":
        conn.private_revision = 7
    elif problem == "foreign-pin-receipt":
        conn.partition["scopes"]["school-a"]["governance_receipts"] = [
            ["school-b", "pin", "foreign-nonce", "a" * 64]]
    elif problem == "foreign-retry":
        conn.partition["scopes"]["school-a"]["requests"]["foreign"] = (
            conn.partition["scopes"]["school-b"]["requests"]["private-b"])
    else:
        conn.partition["shared"]["pins"]["school-b"] = "2"
    with pytest.raises(LifecycleError):
        _load(conn, "education", "school-a")


def test_original_base_and_dependency_validators_use_shared_authority_and_scoped_pins():
    adapter = PartitionedActivationLedger
    conn = SyntheticReads()
    assert adapter._stored_base_matches(conn, "education#1")
    assert not adapter._stored_base_matches(conn, "education#2")
    assert adapter._stored_dependencies_match(conn, (("education#1", "a" * 64),))
    assert adapter._stored_dependencies_match(conn, (("education#1", "a" * 64),), "school-a")
    assert not adapter._stored_dependencies_match(conn, (("education#1", "a" * 64),), "school-b")
    assert not adapter._stored_dependencies_match(conn, (("education#1", "c" * 64),))
    assert not adapter._stored_dependencies_match(conn, (("missing#1", "a" * 64),))


def test_legacy_read_facade_refuses_unexpected_query():
    with pytest.raises(LifecycleError, match="unexpected legacy validator query"):
        _LegacyReadView(SyntheticReads(), None).execute("SELECT unrelated", ())


def test_governed_two_scope_view_preserves_other_private_state_during_target_pin():
    conn = SyntheticReads()
    _, governance = _load(conn, "education", "school-a")
    _, target = _load(conn, "education", "school-b")
    combined = _merge_scoped_views("education", governance, target)
    ledger = _restore("education", combined)
    receipt = ("school-a", "pin", "governance-for-b", "f" * 64)
    # Original memory validator on a synthetic observation; no DB/guard override.
    ledger.pin("school-b", "education", "1", receipt=receipt)
    partition = partition_snapshot("education", _snapshot(ledger, "education", combined["requests"]))
    assert partition["scopes"]["school-a"]["requests"] == conn.partition["scopes"]["school-a"]["requests"]
    assert receipt in partition["scopes"]["school-a"]["governance_receipts"]
    assert partition["scopes"]["school-b"]["pin"] == "1"
    assert partition["scopes"]["school-b"]["requests"] == conn.partition["scopes"]["school-b"]["requests"]
    assert partition["scopes"]["school-b"]["governance_receipts"] == conn.partition["scopes"]["school-b"]["governance_receipts"]


@pytest.mark.parametrize("problem", ["overlap", "shared-changed"])
def test_two_scope_transition_refuses_inconsistent_locked_views(problem):
    conn = SyntheticReads()
    _, first = _load(conn, "education", "school-a")
    _, second = _load(conn, "education", "school-a" if problem == "overlap" else "school-b")
    if problem == "shared-changed":
        second["records"][0]["reason"] = "changed shared observation"
    with pytest.raises(LifecycleError):
        _merge_scoped_views("education", first, second)


def test_public_operations_and_resolution_lock_cleanup_are_inherited_unchanged():
    for name in ("activate", "rollback", "revoke", "pin", "unpin", "active", "history", "pinned",
                 "resolve", "resolve_record", "is_revoked", "governance_receipt", "resolution_guard"):
        assert getattr(PartitionedActivationLedger, name) is getattr(PostgresActivationLedger, name)


@pytest.mark.parametrize("method,args,kwargs", [
    ("activate", ("education", "3", "a" * 64), {"at": "5"}),
    ("rollback", ("education",), {"at": "5", "reason": "synthetic"}),
    ("revoke", ("education", "1"), {"at": "5", "reason": "synthetic"}),
    ("pin", ("school-a", "education", "1"), {}),
    ("unpin", ("school-a", "education"), {}),
])
def test_every_public_write_requires_original_guard_before_opening_database(method, args, kwargs):
    class NoConnection:
        def connection(self):
            raise AssertionError("unadmitted operation must not reach storage")
    adapter = PartitionedActivationLedger("", pool=NoConnection(), guard=GovernanceGuard())
    with pytest.raises(GovernanceRefused):
        getattr(adapter, method)(*args, **kwargs)


def test_runtime_cannot_trigger_automatic_migration():
    adapter = PartitionedActivationLedger("", pool=object(), guard=GovernanceGuard())
    with pytest.raises(LifecycleError, match="explicit owner migration"):
        adapter.migrate()


@pytest.mark.parametrize("guard", [None, object()])
def test_runtime_refuses_missing_or_substitute_governance_guard(guard):
    with pytest.raises(TypeError, match="requires GovernanceGuard"):
        PartitionedActivationLedger("", pool=object(), guard=guard)
