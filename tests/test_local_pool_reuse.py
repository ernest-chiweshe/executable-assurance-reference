"""Real restricted-login reuse contracts; authority guards remain unchanged."""

from contextlib import ExitStack
import os

from psycopg.pq import TransactionStatus
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from assurance_reference.local_roles import LocalPool, provision_local_roles


@pytest.fixture(scope="module")
def roles():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "explicit isolated factory_test is required"
    roles = provision_local_roles(dsn)
    yield roles
    for pool in vars(roles).values():
        if isinstance(pool, LocalPool):
            pool.close()


@pytest.mark.parametrize("interrupted", [False, True])
def test_same_physical_login_has_no_scope_or_timeout_residue(roles, interrupted):
    pool = roles.project_state
    settings = ("app.tenant", "app.education_tenant", "app.alert_tenant",
                "app.clinician", "app.project_namespace")
    with pool.connection() as conn:
        backend = conn.info.backend_pid
        defaults = conn.execute(
            "SELECT current_setting('lock_timeout'),current_setting('statement_timeout'),"
            "current_setting('idle_in_transaction_session_timeout')"
        ).fetchone()
    try:
        with pool.connection() as conn:
            assert conn.info.backend_pid == backend
            for key in settings:
                conn.execute("SELECT set_config(%s,%s,false)", (key, "fictional-first-scope"))
            conn.execute("SET lock_timeout='1234ms'")
            conn.execute("SET statement_timeout='5678ms'")
            conn.execute("SET idle_in_transaction_session_timeout='9s'")
            if interrupted:
                conn.execute("BEGIN")
                raise RuntimeError("fictional interrupted caller")
    except RuntimeError as exc:
        assert interrupted and str(exc) == "fictional interrupted caller"
    with pool.connection() as conn:
        assert conn.info.backend_pid == backend
        assert conn.info.transaction_status == TransactionStatus.IDLE
        assert conn.execute("SELECT session_user,current_user,current_schema()").fetchone() == (
            pool.role, pool.role, pool.schema)
        assert conn.prepare_threshold is None
        for key in settings:
            assert conn.execute("SELECT current_setting(%s,true)", (key,)).fetchone()[0] in (None, "")
        assert conn.execute(
            "SELECT current_setting('lock_timeout'),current_setting('statement_timeout'),"
            "current_setting('idle_in_transaction_session_timeout')"
        ).fetchone() == defaults
        assert conn.execute("SELECT count(*) FROM projectos_states").fetchone() == (0,)


def test_pool_capacity_and_physical_login_separation(roles):
    pool = roles.receiver
    with ExitStack() as stack:
        connections = [stack.enter_context(pool.connection()) for _ in range(3)]
        assert len({conn.info.backend_pid for conn in connections}) == 3
        assert all(conn.execute("SELECT session_user").fetchone() == (pool.role,)
                   for conn in connections)
        with pytest.raises(TimeoutError, match="capacity exhausted"):
            with pool.connection():
                pytest.fail("fourth simultaneous checkout was admitted")
        with roles.recorder.connection() as other:
            assert other.info.backend_pid not in {conn.info.backend_pid for conn in connections}
            assert other.execute("SELECT session_user").fetchone() == (roles.recorder.role,)
    with pool.connection() as conn:
        assert conn.info.backend_pid in {c.info.backend_pid for c in connections}
    pool.retarget(pool._dsn)  # the refused fourth checkout must not retain a lease


def test_failed_reset_discards_connection_before_next_checkout(roles, monkeypatch):
    pool = roles.allocator
    def failed_reset(connection):
        raise RuntimeError("synthetic cleanup failure")
    with monkeypatch.context() as patch:
        patch.setattr(pool, "_reset", failed_reset)
        with pool.connection() as conn:
            backend = conn.info.backend_pid
            conn.execute("SELECT set_config('app.tenant','fictional-old-scope',false)")
        assert conn.closed
    with pool.connection() as fresh:
        assert fresh.info.backend_pid != backend
        assert fresh.execute("SELECT current_setting('app.tenant',true)").fetchone()[0] in (None, "")
        assert fresh.execute("SELECT session_user").fetchone() == (pool.role,)


def test_closed_pool_does_not_reopen(roles):
    pool = LocalPool(roles.clock._dsn, roles.schema, roles.clock.role)
    with pool.connection() as conn:
        assert conn.execute("SELECT session_user").fetchone() == (roles.clock.role,)
    pool.close()
    pool.close()
    with pytest.raises(RuntimeError, match="pool is closed"):
        with pool.connection():
            pytest.fail("closed pool reopened")
    with pytest.raises(RuntimeError, match="pool is closed"):
        pool.retarget(pool._dsn)


def test_retarget_retires_all_cached_connections_and_preserves_identity(roles):
    pool = roles.education_reader
    with ExitStack() as stack:
        old = [stack.enter_context(pool.connection()) for _ in range(3)]
        old_pids = {conn.info.backend_pid for conn in old}
        identity = old[0].execute("SELECT session_user,current_schema(),inet_server_port()").fetchone()
    pool.retarget(pool._dsn)
    assert all(conn.closed for conn in old)
    with ExitStack() as stack:
        fresh = [stack.enter_context(pool.connection()) for _ in range(3)]
        assert old_pids.isdisjoint({conn.info.backend_pid for conn in fresh})
        assert all(conn.execute("SELECT session_user,current_schema(),inet_server_port()").fetchone()
                   == identity for conn in fresh)


def test_retarget_refuses_active_checkout_and_different_login_without_changing_pool(roles):
    pool = roles.education_governor
    original = pool._dsn
    with pool.connection() as conn:
        backend = conn.info.backend_pid
        with pytest.raises(RuntimeError, match="active checkouts"):
            pool.retarget(original)
        assert conn.execute("SELECT session_user").fetchone() == (pool.role,)
    config = conninfo_to_dict(original)
    for change in ({"user": "different-login"}, {"dbname": "different-database"},
                   {"host": "192.0.2.1"}):
        with pytest.raises(ValueError, match="only the local endpoint"):
            pool.retarget(make_conninfo(**{**config, **change}))
        assert pool._dsn == original
    with pool.connection() as conn:
        assert conn.info.backend_pid == backend
