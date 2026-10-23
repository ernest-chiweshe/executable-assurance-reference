"""Group E: existing privileged recovery writer, restricted runtime readers.

Real reviewed roots are revoked by the existing signed recovery ceremony.
Recovery BYPASSRLS is intentional and asserted, never called tenant-restricted.
The reused recovery harness witnesses a synthetic tenant-a empty head; this test
qualifies E read isolation only, not complete R-2b witness coverage or recovery.
"""
import os
import psycopg
import pytest
from psycopg import sql
from regulated_core.persistence_pg import PostgresGrantStore
from assurance_reference.recovery_ceremony import CeremonyRefused
from restricted_root_pg_fixture import TENANTS,root_environment,request_root,approve,admit
import test_recovery_ceremony as recovery_fixture


def test_recovery_revokes_two_reviewed_roots_and_runtime_reads_remain_isolated(tmp_path,monkeypatch):
    env=root_environment(tmp_path)
    grants={}
    for tenant in TENANTS:
        f=request_root(env,tenant)
        approve(f,'instructor');approve(f,'supervisor',finalize=True)
        result=admit(f)
        assert result.status=='admitted' and result.grant is not None,result
        grants[tenant]=result.grant
    # Reuse the existing fixture's rollback detection, signed witness and quarantine.
    # Only its test factory is replaced; no product authorization or guard is patched.
    def provision_existing(dsn):
        assert dsn==os.environ['FACTORY_TEST_DB_URL']
        return env.roles
    monkeypatch.setattr(recovery_fixture,'provision_local_roles',provision_existing)
    state,pools=recovery_fixture.make_held(tmp_path)
    roles,clock,authority,signer,arming,hold_at,witnessed,head_at=state
    recovery,owner=pools
    try:
        with recovery.connection() as conn:
            attrs=conn.execute('SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user').fetchone()
            assert attrs==(False,True,False,False),attrs
        recovery_fixture._wait_out_quarantine(hold_at,clock)
        ceremony=recovery_fixture._ceremony(signer,roles,hold_at,witnessed)
        result=authority.resume(ceremony)
        assert set(TENANTS)<=set(result['tenants'])
        with pytest.raises(CeremonyRefused):
            authority.resume(ceremony)
        for tenant in TENANTS:
            for kind in ('receiver','delegation_issuer','release_linker'):
                pool=getattr(roles,kind)
                with pool.connection() as conn,conn.transaction():
                    conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
                    assert conn.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()==(False,False)
                    rows=conn.execute('SELECT tenant,grant_digest FROM regulated_delegation_revocations_v1 ORDER BY tenant,grant_digest').fetchall()
                    assert rows==[(tenant,grants[tenant].digest)],('regulated_delegation_revocations_v1',kind,tenant,rows)
                assert PostgresGrantStore(pool=pool).revoked(tenant,[grants[tenant].digest])==frozenset({grants[tenant].digest})
        for kind in ('receiver','delegation_issuer','recorder','reviewer','issuer'):
            with getattr(roles,kind).connection() as conn:
                assert conn.execute("SELECT has_table_privilege(current_user,'regulated_delegation_revocations_v1','INSERT')").fetchone()==(False,)
                columns=conn.execute("SELECT has_column_privilege(current_user,attrelid,attnum,'INSERT') FROM pg_attribute WHERE attrelid='regulated_delegation_revocations_v1'::regclass AND attnum>0 AND NOT attisdropped").fetchall()
                assert columns and not any(x[0] for x in columns)
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():
                        conn.execute("SELECT set_config('app.tenant',%s,true)",(TENANTS[0],))
                        conn.execute('INSERT INTO regulated_delegation_revocations_v1 DEFAULT VALUES')
    finally:
        recovery.close();owner.close()
