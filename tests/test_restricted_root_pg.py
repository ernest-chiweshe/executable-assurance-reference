"""Restricted root duty, real signed reviews/checkpoints, RLS and refusal checks.

Synthetic identity, host-held keys and authenticated app.tenant remain trusted.
No reporting-line model, external custody or physical commit-deadline claim.
"""
import json
from dataclasses import asdict
import psycopg
import pytest
from psycopg import sql
from regulated_core.approval import ApprovalError
from regulated_core.root_admission_pg import load_root_provenance_on
from restricted_root_pg_fixture import TENANTS,root_environment,request_root,approve,admit


def roots(roles,tenant):
    with roles.delegation_issuer.connection() as conn,conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
        return {table:conn.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(table))).fetchone()[0]
            for table in ('regulated_root_admissions_v1','regulated_delegation_grants_v1')}


def test_restricted_root_admission_reviews_checkpoint_replay_and_rls(tmp_path):
    env=root_environment(tmp_path)
    fixtures=[request_root(env,t) for t in TENANTS]
    refused=[];admitted={}
    for f in fixtures:
        result=admit(f)
        assert result.status=='refused' and result.grant is None and result.alert_id,result
        refused.append((f,result))
        counts=roots(env.roles,f.tenant)
        assert set(counts.values())=={0},(f.tenant,counts)
        before=f.store.get(f.tenant,f.review_id)
        with pytest.raises(ApprovalError,match='requester may not approve'):
            approve(f,'requester')
        assert f.store.get(f.tenant,f.review_id)==before
        approve(f,'instructor')
        result=admit(f)
        assert result.status=='refused' and result.grant is None and result.alert_id,result
        refused.append((f,result))
        counts=roots(env.roles,f.tenant)
        assert set(counts.values())=={0},(f.tenant,counts)
        approve(f,'supervisor',finalize=True)
        other=TENANTS[1] if f.tenant==TENANTS[0] else TENANTS[0]
        wrong=admit(f,other)
        assert wrong.status=='refused' and wrong.grant is None and wrong.alert_id,wrong
        result=admit(f)
        assert result.status=='admitted' and result.grant is not None and result.alert_id is None,result
        admitted[f.tenant]=result.grant
    for f in fixtures:
        result=admit(f)
        assert result.status=='admitted' and result.grant==admitted[f.tenant],result
        with env.roles.delegation_issuer.connection() as conn,conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)",(f.tenant,))
            proof=load_root_provenance_on(conn,f.tenant,result.grant.digest,verifier=f.verifier)
            assert proof.signed==result.grant
            for table in ('regulated_root_admissions_v1','regulated_delegation_grants_v1'):
                rows=conn.execute(sql.SQL('SELECT tenant FROM {}').format(sql.Identifier(table))).fetchall()
                assert rows==[(f.tenant,)],(table,f.tenant,rows)
            # Proves real committed checkpoint lookup is exercised under this login.
            rows=conn.execute('SELECT tenant FROM regulated_evidence_checkpoints_v1').fetchall()
            assert rows==[(f.tenant,)],('regulated_evidence_checkpoints_v1',f.tenant,rows)
            assert f.verifier.history.verify(conn,f.envelope.seq)==f.envelope
    alerts=[]
    for f,result in refused:
        alert=f.service.alerts.read(result.alert_id,tenant_id=f.tenant)
        assert alert['payload']['code']=='ADMISSION_REFUSED'
        alerts.append(alert)
    (tmp_path/'root-outcomes.json').write_text(json.dumps({'roots':{t:asdict(g) for t,g in admitted.items()},
        'alerts':alerts},indent=2),encoding='utf-8')


@pytest.fixture(scope='module')
def acl_environment(tmp_path_factory):
    return root_environment(tmp_path_factory.mktemp('root-acl'))


@pytest.mark.parametrize('role,table',[
    ('recorder','regulated_root_admissions_v1'),('recorder','regulated_delegation_grants_v1'),
    ('reviewer','regulated_root_admissions_v1'),('receiver','regulated_root_admissions_v1'),
    ('issuer','regulated_root_admissions_v1'),('delegation_issuer','regulated_decision_inputs_v1'),
    ('delegation_issuer','regulated_reviews_v1'),('delegation_issuer','regulated_database_receipts_v1'),
])
def test_root_cross_duty_writes_denied(acl_environment,role,table):
    with getattr(acl_environment.roles,role).connection() as conn:
        assert conn.execute("SELECT has_table_privilege(current_user,%s,'INSERT')",(table,)).fetchone()==(False,)
        columns=conn.execute("SELECT attname,has_column_privilege(current_user,attrelid,attnum,'INSERT') "
            "FROM pg_attribute WHERE attrelid=%s::regclass AND attnum>0 AND NOT attisdropped",(table,)).fetchall()
        assert columns and not any(allowed for name,allowed in columns),(role,table,columns)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)",(TENANTS[0],))
                conn.execute(sql.SQL('INSERT INTO {} DEFAULT VALUES').format(sql.Identifier(table)))


def test_root_disabled_owner_refuses_complete_reviews(tmp_path):
    env=root_environment(tmp_path,owner_enabled=False)
    f=request_root(env,TENANTS[0])
    approve(f,'instructor');approve(f,'supervisor',finalize=True)
    result=admit(f)
    assert result.status=='refused' and result.grant is None and result.alert_id,result
    assert set(roots(env.roles,f.tenant).values())=={0}


def test_root_hold_blocks_both_atomic_append_targets(tmp_path):
    env=root_environment(tmp_path)
    with env.roles.clock.connection() as conn,conn.transaction():
        assert conn.execute('SELECT reference_clock_floor_hold_v1(%s,%s,%s)',
            (env.roles.domain,'synthetic root profile hold',0)).fetchone()[0]>0
    for table in ('regulated_root_admissions_v1','regulated_delegation_grants_v1'):
        with env.roles.delegation_issuer.connection() as conn:
            with pytest.raises(psycopg.DatabaseError) as refused:
                with conn.transaction():
                    conn.execute("SELECT set_config('app.tenant',%s,true)",(TENANTS[0],))
                    conn.execute(sql.SQL('INSERT INTO {} SELECT * FROM {} WHERE false').format(sql.Identifier(table),sql.Identifier(table)))
            assert refused.value.sqlstate=='RH001'


def test_root_lock_privilege_cannot_mutate_current_identity(acl_environment):
    roles=acl_environment.roles
    with roles.delegation_issuer.connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)",(TENANTS[0],))
            assert conn.execute("SELECT subject FROM reference_root_members WHERE subject='owner' FOR SHARE").fetchone()==('owner',)
        with pytest.raises(psycopg.errors.RaiseException,match='append-only'):
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)",(TENANTS[0],))
                conn.execute("UPDATE reference_root_members SET lock_anchor=false WHERE subject='owner'")
