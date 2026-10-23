"""Local authenticated supervisor flow on isolated PostgreSQL with intact guards."""
from hashlib import sha256
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from assurance_reference.roster_tenancy import tenant_roster_store
from types import SimpleNamespace
from uuid import uuid4

from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.engine import ReferenceEngine
from assurance_reference.epoch_withdrawal_admission import OPERATION, withdrawal_bytes
from assurance_reference.epoch_withdrawal_approval import EpochWithdrawalApprovalService
from assurance_reference.epoch_withdrawal_retention import retain_approved_withdrawal
from assurance_reference.epoch_withdrawal_review import EpochWithdrawalReviewLoader
from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger
from assurance_reference.epoch_withdrawal_target import epoch_withdrawal_target
from assurance_reference.governance_targets import roster_target
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.roster_authority import RosterAuthorityVerifier
from factory.pg_session import SessionBoundPool
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, Ed25519Signer,
    EmissionAuthority, IdentityVerifier, IntendedUse, IntendedUseRegistry,
    PolicyContext, PolicyRegistry, PreflightAuthority, TrustDirectory,
    VerificationTrustStore,
)
from regulated_core.clock_pg import DbClock
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.governance_roster import GovernanceRoster, RosterMember, RosterCredentials, roster_change_bytes
from regulated_core.governance_targets import GovernanceWithdrawalPolicy, WITHDRAWAL_CONTENT_TYPE, WITHDRAWAL_ROLE, issue_bootstrap
from regulated_core.persistence_pg import PostgresGovernanceLog, PostgresMissionBudget, PostgresPermitUseStore
from regulated_core.review_store import PostgresReviewStore
from regulated_core.target import BoundEffect, Outcome, TargetAuthority, effect_destination
from regulated_core.worm import LocalWormStore


class SupervisorWithdrawalFixture:
    def __init__(self, roles, tenant="synthetic-withdrawal-office", *, shared_ledger=None, shared_recorder=None, principal_prefix=""):
        if (shared_ledger is None) != (shared_recorder is None):
            raise ValueError("existing application ledger and recorder must be supplied together")
        if shared_ledger is not None and (
                not isinstance(shared_ledger, GuardedPostgresRevocationLedger)
                or not isinstance(shared_recorder, ReferenceDecisionRecorder)
                or shared_ledger.clock is not shared_recorder.clock):
            raise TypeError("existing application services must share the guarded ledger clock")
        self.roles, self.tenant = roles, tenant
        self.requester = principal_prefix + "requester"
        self.clock = (shared_ledger.clock if shared_ledger is not None else
                      DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock))
        self.trust = shared_recorder._trust if shared_recorder is not None else TrustDirectory()
        self.keys = {name: Ed25519Signer("fixture:epoch-withdrawal:" + name)
                     for name in ("evidence", "approval", "identity", "roster", "emission", "preflight", "alert")}
        for signer in self.keys.values():
            self.trust.register_signer(signer)
        self.guard = shared_ledger.governance_guard if shared_ledger is not None else GovernanceGuard()
        self.ledger = (shared_ledger if shared_ledger is not None else
            GuardedPostgresRevocationLedger(pool=SessionBoundPool(roles.governor),
                                            clock=self.clock, guard=self.guard))
        self.recorder = (shared_recorder if shared_recorder is not None else
            ReferenceDecisionRecorder(self.keys["evidence"], self.trust,
                                      pool=roles.recorder, clock=self.clock))
        self.uses = PostgresPermitUseStore(pool=roles.receiver)
        self.budget = PostgresMissionBudget(pool=roles.allocator)
        self.log = PostgresGovernanceLog(pool=roles.governor)
        # Tenant-scoped epoch fences are tenant-isolated (B-F7b); the installation roster keeps the shared log.
        self.epoch_log = TenantFencedGovernanceLog(pool=roles.governor, tenant=tenant)
        self.workflow = ApprovalWorkflow(self.trust, self.keys["approval"],
            IdentityVerifier(self.trust, self.keys["identity"].key_id),
            credential_authorities={"governance-roster:simulated": self.keys["roster"].key_id})
        policies = PolicyRegistry()
        policies.register(GovernanceWithdrawalPolicy())
        intended = IntendedUseRegistry()
        intended.declare(IntendedUse("governance", OPERATION, 3))
        self.preflight = PreflightAuthority(self.keys["preflight"], intended, self.trust)
        writer_authority = TargetAuthority(self.keys["emission"], self.trust,
            revocation_epoch=self.ledger.governance_epoch, clock=self.clock)
        self.engine = ReferenceEngine(
            targets=writer_authority, revocation=self.ledger, budget=self.budget, default_mission_budget={"limit": 4, "units": 1},
            registry=policies, recorder=self.recorder, retention=LocalWormStore(),
            alerts=AlertJournal(roles.alerts, self.keys["alert"], self.trust),
            verification_trust=VerificationTrustStore(self.trust), approvals=self.workflow,
            emission=EmissionAuthority(self.keys["emission"], self.trust, self.uses),
            preflight=self.preflight, clock=self.clock)
        self.installation = "fixture:epoch:" + tenant
        verifier = RosterAuthorityVerifier(tenant=tenant, installation=self.installation,
            authority=self.engine.targets, recorder=self.recorder, bootstrap_trust=self.trust,
            bootstrap_key_ids=frozenset({self.keys["identity"].key_id}))
        self.roster = tenant_roster_store(SessionBoundPool(roles.governor),
                                          guard=self.guard, proof_verifier=verifier)
        first = GovernanceRoster(self.installation, 1, (
            RosterMember(principal_prefix + "ordinary", frozenset({"governance-approver"}), "line-ordinary"),
            RosterMember(principal_prefix + "requester", frozenset({WITHDRAWAL_ROLE}), "line-requester"),
            RosterMember(principal_prefix + "supervisor", frozenset({WITHDRAWAL_ROLE}), "line-supervisor"),
        ), frozenset({"synthetic-monitor"}), True)
        first_target = roster_target(self.roster, self.installation, tenant_id=tenant,
            authority=self.engine.targets, uses=self.uses, log=self.log, guard=self.guard,
            budget=self.budget, bootstrap_trust=self.trust,
            bootstrap_key_ids=frozenset({self.keys["identity"].key_id}))
        body = roster_change_bytes(first)
        bootstrap = issue_bootstrap(self.keys["identity"], tenant_id=tenant,
            kind="governance-roster", subject=self.installation, output=body)
        result = first_target.bootstrap(bootstrap, body)
        assert result.outcome is Outcome.COMMITTED, result.detail
        assert self.roster.current(self.installation) == first
        self.loader = EpochWithdrawalReviewLoader(reviews=PostgresReviewStore(pool=roles.receiver),
            roster=self.roster, installation=self.installation, workflow=self.workflow,
            recorder=self.recorder, clock=self.clock)
        self.target = epoch_withdrawal_target(self.ledger, tenant_id=tenant, loader=self.loader,
            authority=self.engine.targets, uses=self.uses, log=self.epoch_log, budget=self.budget)
        self.sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer,
                                      clock=self.clock)
        self.tokens = {}
        for name in ("requester", "supervisor", "ordinary"):
            # New isolated synthetic account, never an existing user's password.
            password = "synthetic-epoch-" + uuid4().hex
            self.sessions.provision_identity(tenant, principal_prefix + name, principal_prefix + name, password)
            self.tokens[name] = self.sessions.login(tenant, principal_prefix + name, password)
        self.service = EpochWithdrawalApprovalService(loader=self.loader, sessions=self.sessions,
            credentials=RosterCredentials(self.roster, self.installation, self.keys["roster"]))

    def begin(self):
        ident = uuid4().hex
        change = {"tenant": self.tenant, "prior_epoch": self.ledger.epoch(self.tenant),
                  "reason": "Withdraw pending synthetic application delivery"}
        output = withdrawal_bytes(self.tenant, prior_epoch=change["prior_epoch"], reason=change["reason"])
        digest = sha256(output).hexdigest()
        ctx = PolicyContext(self.tenant, Actor(self.requester, self.tenant, frozenset()),
                            "fixture:supervised-withdrawal", ident, self.clock.now_us())
        assertion = Assertion(ident, self.tenant, WITHDRAWAL_CONTENT_TYPE, digest)
        action = Action(OPERATION, ActionEffect.EXTERNAL, effect_destination({},
            BoundEffect(digest, self.target.target, self.target.current_state(),
                        mission="fixture:epoch:" + ident)))
        capability = self.preflight.authorize(tenant_id=self.tenant, vertical="governance",
            action_id=OPERATION, risk_tier=3, correlation_id=ident, now_us=self.clock.now_us(),
            ttl_us=120_000_000, nonce="cap-" + ident)
        params = dict(vertical="governance", capability=capability, assertion=assertion,
            action=action, ctx=ctx, output=output, target=self.target,
            permit_ttl_us=60_000_000, nonce="effect-" + ident)
        missing = self.engine.authorize_for_target(**params)
        assert not missing.authorized and missing.permit is None
        decision = next(entry for entry in reversed(self.recorder.entries(self.tenant))
                        if entry.record.decision.kind.value == "require-approval")
        return SimpleNamespace(change=change, output=output, digest=digest, params=params,
                               decision=decision, review_id="review-" + ident)

    def approve(self, pending, reviewer="supervisor"):
        return self.service.approve(token=self.tokens[reviewer], review_id=pending.review_id,
            decision_record_id=pending.decision.record.record_id, change=pending.change)

    def authorize(self, pending, approved):
        reference = retain_approved_withdrawal(self.loader, tenant_id=self.tenant,
            change=pending.change, requester_id=self.requester, approved=approved)
        assert reference == pending.review_id
        authorized = self.engine.authorize_for_target(**pending.params,
            approval_cert=approved.certificate, approval_evidence=approved.envelope)
        assert authorized.authorized, authorized.reason
        assert authorized.permit.permit.approval_ref == reference
        return authorized
