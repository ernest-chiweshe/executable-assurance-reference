import os
from contextlib import ExitStack
import pytest
from assurance_reference.local_fixture_host import configuration
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_roles import provision_local_roles
from regulated_core.permit import EmissionError
from test_reference_host import render_request

def test_signing_failure_releases_budget_after_final_caller_locks(tmp_path,monkeypatch):
    assert os.environ.get('REFERENCE_ISOLATED_PG_DATA')
    monkeypatch.setenv('REFERENCE_SHARED_EVIDENCE_FIXTURE','1')
    roles=provision_local_roles(os.environ['FACTORY_TEST_DB_URL'])
    with ExitStack() as cleanup:
        stores,authorities,alerts,qualifications,*_=configuration(roles,tmp_path/'host',shared_fixture_cleanup=cleanup.callback)
        host=compose_reference_host(stores,authorities,alerts=alerts,qualifications=qualifications,floor_not_used_reason='Isolated signing failure and lock-order qualification')
        base=host.factory.engine;original=base._budget;released=[]
        class CheckedBudget:
            def __getattr__(self,name):return getattr(original,name)
            def release(self,tenant,mission,reservation):
                with roles.receiver.connection() as c,c.transaction():
                    c.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
                    key='regulated-mission-budget:'+tenant+'\x1f'+mission
                    assert c.execute('SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0))',(key,)).fetchone()[0], 'release still holds caller mission lock'
                released.append(reservation)
                return original.release(tenant,mission,reservation)
        base._budget=CheckedBudget();signer=base.targets._signer
        class UnavailableSigner:
            key_id=signer.key_id;alg=signer.alg
            def sign(self,body):raise EmissionError('isolated signing service unavailable')
        base.targets._signer=UnavailableSigner()
        engine,authorization,target,body=render_request(host,tmp_path)
        assert not authorization.authorized and authorization.permit is None
        assert len(released)==1 and not target.path.exists()
        with roles.receiver.connection() as c,c.transaction():
            c.execute("SELECT set_config('app.tenant',%s,true)",('synthetic-host',))
            rows=c.execute('SELECT kind FROM regulated_mission_budget_events_v1 WHERE tenant=%s AND mission=%s ORDER BY kind',('synthetic-host','synthetic:host-render')).fetchall()
            assert rows==[('release',),('reserve',)]
