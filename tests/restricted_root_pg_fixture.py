"""Signed root admission with restricted writer duties and synthetic identity.

Host-held keys and app.tenant are trusted. This fixture does not demonstrate
external identity, separate-process key custody or a physical commit deadline.
"""
import os,json,hashlib
from types import SimpleNamespace
from dataclasses import asdict,replace
from psycopg import sql
from assurance_reference.local_roles import LocalPool
from assurance_reference.local_root_roles import provision_local_root_roles
from assurance_reference.role_contract import collect_access_matrix
from assurance_reference.clock_floor import DurableClock, install_recovery_guard
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.alerts import AlertJournal
from assurance_reference.root_admission import ReviewedRootAdmission
from regulated_core.clock_pg import DbClock
from regulated_core.signing import TrustDirectory,Ed25519Signer
from regulated_core import Action,ActionEffect,Actor,Assertion,PolicyContext,issue_credential
from regulated_core.canonical import canonical_bytes
from regulated_core.document_policy import DocumentPolicy
from regulated_core.policy_document import document_policy
from regulated_core.delegation import DelegationProposal,PROPOSAL_FIELD
from regulated_core.input_evidence import InputVerifier,DecisionInputs,InputAdmission
from regulated_core.input_evidence_pg import record_with_inputs
from regulated_core.identity import IdentityVerifier
from regulated_core.identity_provider import CredentialVerifier
from regulated_core.approval import ApprovalWorkflow
from regulated_core.approval_evidence import verified_approvals
from regulated_core.review_store import PostgresReviewStore
from regulated_core.root_admission_pg import RootAdmissionVerifier
from regulated_core.evidence import GENESIS
from regulated_core.evidence_checkpoints_pg import PinnedHistory,PinnedVerifier,checkpoint_on
from regulated_core.target import TargetRef
from isolated_worker_database import verify_isolated_worker_database
from restricted_prepared_pg_fixture import TenantReadPool
from test_root_admission import FixtureDirectory,FixtureCurrentness,TENANTS,TTL,OPERATION


def root_environment(tmp_path, *, owner_enabled=True):
    verify_isolated_worker_database()
    dsn=os.environ['FACTORY_TEST_DB_URL']
    roles=provision_local_root_roles(dsn)
    audit=collect_access_matrix(roles,partitioned_lifecycle=True,prepared_authority=True,root_admission=True)
    (tmp_path/'root-role-audit.json').write_text(json.dumps(audit,indent=2),encoding='utf-8')
    assert audit['privilege_contract_matches'],audit['errors']
    clock=DurableClock(DbClock(roles.delegation_issuer,roles.domain),floor_pool=roles.clock,
        recovery_not_used_reason='Synthetic restricted root admission')
    trust=TrustDirectory()
    signers={n:Ed25519Signer('root:'+n) for n in ('evidence','permit','identity','ingress','approval','credential','delegation','policy','alert')}
    for signer in signers.values():trust.register_signer(signer)
    expires=clock.now_us()+TTL
    content={'schema':'regulated/policy-content/v1','content_types':['course:mission'],'verifiers':{},'risk_tier':1,
        'actions':{OPERATION:{'effect':'authoritative','mission_budget':{'units':1,'limit':1},
        'approval':{'role_groups':[['instructor'],['supervisor']],'minimum_approvers':2}}}}
    doc=document_policy(signers['policy'],vertical='course',policy_id='restricted-root',version='fixture-1',
        content=content,jurisdictions=('synthetic',),effective_from_us=clock.now_us(),effective_until_us=expires)
    owner=LocalPool(dsn,roles.schema,'migration-owner')
    try:
        with owner.connection() as conn,conn.transaction():
            conn.execute('CREATE TABLE reference_root_members (tenant text,subject text,role text,revision text,'
                'enabled boolean,expires bigint,lock_anchor boolean NOT NULL DEFAULT true,PRIMARY KEY(tenant,subject))')
            conn.execute('CREATE TABLE reference_root_requests (tenant text,nonce text,input_digest text,'
                'lock_anchor boolean NOT NULL DEFAULT true,PRIMARY KEY(tenant,nonce))')
            for table in ('reference_root_members','reference_root_requests'):
                conn.execute(sql.SQL('ALTER TABLE {} ENABLE ROW LEVEL SECURITY').format(sql.Identifier(table)))
                conn.execute(sql.SQL('ALTER TABLE {} FORCE ROW LEVEL SECURITY').format(sql.Identifier(table)))
                conn.execute(sql.SQL("CREATE POLICY tenant_v1 ON {} USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true))").format(sql.Identifier(table)))
                conn.execute(sql.SQL('CREATE TRIGGER immutable_v1 BEFORE UPDATE OR DELETE ON {} FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1()').format(sql.Identifier(table)))
                conn.execute(sql.SQL('CREATE TRIGGER no_truncate_v1 BEFORE TRUNCATE ON {} FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1()').format(sql.Identifier(table)))
                for pool in (roles.recorder,roles.delegation_issuer):
                    conn.execute(sql.SQL('GRANT SELECT,UPDATE(lock_anchor) ON {} TO {}').format(sql.Identifier(table),sql.Identifier(pool.role)))
            conn.execute(sql.SQL('GRANT SELECT ON reference_root_members TO {}').format(sql.Identifier(roles.session_reader.role)))
            conn.execute(sql.SQL('GRANT INSERT ON reference_root_requests TO {}').format(sql.Identifier(roles.session_issuer.role)))
            for tenant in TENANTS:
                for who in ('requester','owner','instructor','supervisor'):
                    conn.execute("INSERT INTO reference_root_members (tenant,subject,role,revision,enabled,expires) VALUES(%s,%s,%s,'fixture-1',%s,%s)",
                        (tenant,who,who,owner_enabled if who=='owner' else True,expires))
        install_recovery_guard(owner)
    finally:owner.close()
    return SimpleNamespace(roles=roles,clock=clock,trust=trust,signers=signers,expires=expires,policy=DocumentPolicy(doc))


def request_root(env,tenant):
    roles,clock,trust,s=env.roles,env.clock,env.trust,env.signers
    history=PinnedVerifier(PinnedHistory(tenant,'restricted-root-fixture',(),'0'*64),trust=trust,
        current_key='root:evidence',max_entries=16,evidence_key_ids=frozenset({'root:evidence'}))
    inputs_verifier=InputVerifier(trust,'root:ingress','root:identity',FixtureCurrentness(env.policy,trust),
        'root:permit','root:approval','root:delegation',TTL,clock)
    approvals=ApprovalWorkflow(trust,s['approval'],IdentityVerifier(trust,'root:identity'),
        credential_authorities={FixtureDirectory.provider:'root:credential'})
    directory=FixtureDirectory(TenantReadPool(roles.session_reader,tenant),tenant)
    verifier=RootAdmissionVerifier(trust,'root:evidence','root:delegation','root:permit',approvals,
        inputs_verifier,history,env.policy,directory)
    alerts=AlertJournal(roles.alerts,s['alert'],trust)
    recorder=ReferenceDecisionRecorder(s['evidence'],trust,pool=roles.recorder,clock=clock)
    nonce=tenant+'-root-proposal';review_id=tenant+'-root-review'
    proposal=DelegationProposal('owner',('course:save-draft',),(TargetRef('postgres',roles.schema+'/'+tenant).digest(),),'one-draft',True,env.expires,env.expires,0)
    credential=issue_credential(s['identity'],actor_id='requester',tenant_id=tenant,kind='role:requester',expires_at_us=env.expires)
    ctx=PolicyContext(tenant,Actor('requester',tenant,frozenset({'requester'}),(credential,)),
        'education:delegation',nonce,clock.now_us(),requested_scope=frozenset({OPERATION}))
    assertion=Assertion(nonce,tenant,'course:mission',content_digest=hashlib.sha256(b'one draft').hexdigest())
    action=Action(OPERATION,ActionEffect.AUTHORITATIVE,canonical_bytes({PROPOSAL_FIELD:proposal.as_fields()}).decode())
    inputs=DecisionInputs(assertion,action,ctx,env.policy.ref)
    with roles.session_issuer.connection() as conn,conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
        conn.execute('INSERT INTO reference_root_requests(tenant,nonce,input_digest) VALUES(%s,%s,%s)',(tenant,nonce,inputs.digest()))
    ingress=InputAdmission.issue(s['ingress'],inputs,request_id=nonce,permit_nonce=nonce,identity_revision='fixture-1',
        issued_at_us=ctx.now_us,expires_at_us=env.expires,clock=clock)
    decision=env.policy.evaluate(assertion,action,ctx)
    envelope=record_with_inputs(recorder,inputs,decision,admission=ingress,verifier=inputs_verifier)
    with roles.recorder.connection() as conn,conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
        pin=checkpoint_on(conn,tenant=tenant,through_seq=envelope.seq,previous=None,
            expected_previous_digest=GENESIS,profile='restricted-root-fixture',
            signer=s['evidence'],trust=trust,allowed_keys=frozenset({'root:evidence'}),max_entries=16)
    # Host publication occurs after checkpoint COMMIT; no external custody claim.
    history=PinnedVerifier(PinnedHistory(tenant,pin.profile,(pin,),pin.digest()),trust=trust,
        current_key='root:evidence',max_entries=16,evidence_key_ids=frozenset({'root:evidence'}))
    verifier=replace(verifier,history=history)
    service=ReviewedRootAdmission(pool=roles.delegation_issuer,verifier=verifier,evidence_signer=s['evidence'],delegation_signer=s['delegation'],alerts=alerts)
    store=PostgresReviewStore(pool=roles.reviewer)
    store.transact(tenant,review_id,lambda old:{'review_id':review_id,'envelope':asdict(envelope),'grants':[],'credential_receipts':[],'certificate':None})
    request=approvals.open(request_id=review_id,requester_id='requester',tenant_id=tenant,assertion_id=assertion.assertion_id,
        decision_record_id=envelope.record.record_id,decision_record_hash=envelope.record_hash,requirement=decision.approval,now_us=envelope.record.decided_at_us)
    return SimpleNamespace(env=env,tenant=tenant,nonce=nonce,review_id=review_id,verifier=verifier,service=service,
        envelope=envelope,request=request,store=store,directory=directory,approvals=approvals)


def approve(f,reviewer,*,finalize=False):
    env=f.env
    prior=f.store.get(f.tenant,f.review_id)
    grants,_=verified_approvals(f.approvals,prior,f.envelope,f.request,now_us=env.clock.now_us())
    credentials=CredentialVerifier(env.trust,env.signers['credential'],f.directory,f.directory)
    receipt=credentials.verify(reviewer,f.tenant,reviewer,jurisdiction='synthetic',now_us=env.clock.now_us())
    grant=f.approvals.grant(f.request,Actor(reviewer,f.tenant,frozenset()),env.clock.now_us(),receipt=receipt)
    f.store.transact(f.tenant,f.review_id,lambda old:{**old,'grants':[*old['grants'],asdict(grant)],'credential_receipts':[*old['credential_receipts'],asdict(receipt)]})
    if finalize:
        cert=f.approvals.finalize(f.request,[*grants,grant],env.clock.now_us())
        f.store.transact(f.tenant,f.review_id,lambda old:{**old,'certificate':asdict(cert)})


def admit(f,tenant=None):
    return f.service.admit(tenant=f.tenant if tenant is None else tenant,review_id=f.review_id,nonce=f.nonce)
