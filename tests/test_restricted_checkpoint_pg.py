"""Recorder-written signed checkpoints for both tenants; publication pin held by test host.

This exercises the product checkpoint writer through the new restricted recorder.
It does not establish external pin custody or the separate root-admission journey.
"""
import psycopg
import pytest
from regulated_core.evidence import GENESIS
from regulated_core.evidence_checkpoints_pg import checkpoint_on, PinnedHistory, PinnedVerifier
from restricted_prepared_pg_fixture import TENANTS, prepared_environment, restricted_prepared_cas_fixture


def test_restricted_recorder_checkpoints_are_signed_retained_and_tenant_isolated(tmp_path):
    env=prepared_environment(tmp_path)
    fixtures=[restricted_prepared_cas_fixture(tmp_path,tenant=t,environment=env) for t in TENANTS]
    pins={}
    for f in fixtures:
        tenant=f['tenant']
        def append(conn):
            through=conn.execute('SELECT max(seq) FROM regulated_decision_evidence_v1 WHERE tenant=%s',(tenant,)).fetchone()[0]
            assert through is not None
            return checkpoint_on(conn,tenant=tenant,through_seq=through,previous=None,
                expected_previous_digest=GENESIS,profile='restricted-checkpoint-fixture',
                signer=f['fixture']['signers']['evidence'],trust=f['fixture']['trust'],
                allowed_keys=frozenset({'root:evidence'}),max_entries=16)
        with env.roles.recorder.connection() as conn,conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
            pin=append(conn)
        # Publish to the test host only after the transaction exited successfully.
        pins[tenant]=pin
        with env.roles.recorder.connection() as conn,conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
            assert append(conn)==pin
            assert conn.execute('SELECT count(*) FROM regulated_evidence_checkpoints_v1').fetchone()==(1,)
    for tenant in TENANTS:
        pin=pins[tenant]
        verifier=PinnedVerifier(PinnedHistory(tenant,pin.profile,(pin,),pin.digest()),trust=env.f['trust'],
            current_key='root:evidence',max_entries=16,evidence_key_ids=frozenset({'root:evidence'}))
        for kind in ('recorder','issuer','receiver'):
            with getattr(env.roles,kind).connection() as conn,conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
                rows=conn.execute('SELECT tenant,checkpoint_digest FROM regulated_evidence_checkpoints_v1').fetchall()
                assert rows==[(tenant,pin.digest())], ('regulated_evidence_checkpoints_v1',kind,tenant,rows)
                envelope=verifier.verify(conn,pin.to_seq)
                assert envelope.record.tenant_id==tenant
        for kind in ('issuer','receiver','reviewer'):
            with getattr(env.roles,kind).connection() as conn:
                assert conn.execute("SELECT has_table_privilege(current_user,'regulated_evidence_checkpoints_v1','INSERT')").fetchone()==(False,)
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():
                        conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
                        conn.execute('INSERT INTO regulated_evidence_checkpoints_v1 DEFAULT VALUES')
