"""Queued restricted-role reads after migration; not yet application wiring."""
import pytest

from assurance_reference.lifecycle_migration import migrate_reference_lifecycle
from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
from factory.pg_session import SessionBoundPool
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from test_lifecycle_migration import legacy as legacy  # shared explicit owned-schema fixture


@pytest.mark.parametrize("kind", ["receiver", "governor"])
def test_migrated_runtime_preserves_shared_authority_and_private_resolution(legacy, kind):
    owner, roles, names, _, _ = legacy
    migrate_reference_lifecycle(owner, runtime_roles=names)
    adapter = PartitionedActivationLedger("", pool=getattr(roles, kind), guard=GovernanceGuard())
    assert adapter.pack_ids() == ("education",)
    assert len(adapter.history("education")) == 3
    assert adapter.active("education").version == "1"
    assert adapter.is_revoked("education", "2")
    assert adapter.pinned("school-a", "education") == "1"
    assert adapter.pinned("school-b", "education") == "2"
    assert adapter.resolve("school-a", "education") == "1"
    assert adapter.resolve("school-b", "education") is None
    assert adapter.resolve("school-c", "education") == "1"
    assert adapter.governance_receipt("education", ("school-a", "pin", "nonce-a", "c" * 64))
    assert not adapter.governance_receipt("education", ("school-b", "pin", "nonce-a", "c" * 64))
    with pytest.raises(GovernanceRefused):
        adapter.unpin("school-a", "education")
    assert adapter.pinned("school-a", "education") == "1"


def test_inherited_session_resolution_guard_clears_scope_and_locks_after_failure(legacy):
    owner, roles, names, _, _ = legacy
    migrate_reference_lifecycle(owner, runtime_roles=names)
    pool = SessionBoundPool(roles.receiver)
    adapter = PartitionedActivationLedger("", pool=pool, guard=GovernanceGuard())
    with pytest.raises(RuntimeError, match="synthetic consumer failure"):
        with adapter.resolution_guard("school-a", "education") as record:
            assert record.version == "1"
            with pool.connection() as conn:
                # The guard's transaction has committed; no tenant setting escapes it.
                assert conn.execute("SELECT count(*) FROM reference_pack_tenants_v1").fetchone() == (0,)
                assert conn.execute("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() "
                                    "AND locktype='advisory'").fetchone()[0] > 0
            raise RuntimeError("synthetic consumer failure")
    with roles.governor.connection() as conn, conn.transaction():
        assert conn.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0))",
                            ("pack-lifecycle:education",)).fetchone() == (True,)
    with adapter.resolution_guard("school-b", "education") as record:
        assert record is None
