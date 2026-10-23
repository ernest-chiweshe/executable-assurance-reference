"""Explicit shared-evidence target issuance composition.

Witness I/O runs after decision commit and before host final locks. All original
core decision checks run again; a changed decision/dependency refuses the attempt.
Host namespace adapters and their existing locks remain mandatory configuration.
Other inherited emission entry points are outside this composition's scope.
"""
from copy import copy
from dataclasses import replace
from regulated_core.budget import UNBUDGETED
from regulated_core.engine import TargetAuthorization,_Decided,_effect_mismatch,_restriction_problem
from regulated_core.evidence_dependencies import collect_dependencies
from regulated_core.evidence_publication import RetryRequired
from regulated_core.permit import EmissionError
from assurance_reference.floor_bound_engine import FloorBoundReferenceEngine

class SharedEvidenceIssuance:
    def __init__(self,*,shared_evidence,**kwargs):
        from regulated_core.evidence_runtime import SharedEvidenceRuntime
        if not isinstance(shared_evidence,SharedEvidenceRuntime):raise TypeError('explicit shared evidence runtime required')
        self.shared_evidence=shared_evidence
        super().__init__(**kwargs)

    def authorize_for_target(self,**request):
        local=copy(self);local._shared_request=dict(request)
        local._shared_epoch=self.targets.epoch(request['ctx'].tenant_id)
        with collect_dependencies() as deps:
            local._shared_dependencies=deps
            return super(SharedEvidenceIssuance,local).authorize_for_target(**request)

    def _issue_target_authorization(self,prepared,**parameters):
        runtime=self.shared_evidence;request=self._shared_request
        dependencies=tuple(self._shared_dependencies)
        original_budget=self._budget;deferred_releases=[]
        class DeferredReleaseBudget:
            def release(self,*args,**kwargs):deferred_releases.append((args,kwargs))
            def __getattr__(self,name):return getattr(original_budget,name)
        try:
            ticket=runtime.cover(prepared,dependencies)
            with runtime.final_locks(prepared):
                with collect_dependencies() as final_dependencies:
                    # These host checks include namespace state, budget liveness,
                    # caller membership and the existing application lock protocol.
                    runtime.final_checks(self,prepared)
                    ctx=replace(prepared.ctx,now_us=self.targets.now_us())
                    if self.targets.epoch(ctx.tenant_id)!=self._shared_epoch:
                        raise RetryRequired('authority epoch changed during witness wait')
                    if self._emission.uses.used(ctx.tenant_id,parameters['nonce']):
                        raise EmissionError('permit nonce is already spent')
                    problem=_effect_mismatch(prepared.bound,prepared.action.action_id,parameters['output'],request['target'])
                    if problem:raise EmissionError(problem)
                    if prepared.chain is not None:
                        chain=self._delegation.resolve(ctx.tenant_id,prepared.chain.leaf.digest(),now_us=self.targets.now_us())
                        if chain!=prepared.chain:raise RetryRequired('delegation changed during witness wait')
                        if self._source_status is not None:self._source_status(ctx.tenant_id,chain.leaf.digest())
                        ref=f'{prepared.decided.policy.vertical}/{prepared.decided.policy.policy_id}@{prepared.decided.policy.digest}'
                        problem=_restriction_problem(self._restrictions,set(chain.leaf.policy_refs)-{ref},prepared.assertion,prepared.action,ctx)
                        if problem:raise EmissionError(problem)
                    if hasattr(self,'_qualifications'):
                        from regulated_core.clock import read_clock
                        refs,deadline=self._qualifications.check(read_clock(self.targets.clock))
                        if refs!=parameters['qualification_digests']:raise RetryRequired('qualification changed')
                    ctx=replace(ctx,now_us=self.targets.now_us())
                    final=self._decide(vertical=request['vertical'],capability=request['capability'],assertion=prepared.assertion,
                        action=prepared.action,ctx=ctx,approval_cert=request.get('approval_cert'),
                        approval_evidence=request.get('approval_evidence'),existing_envelope=prepared.decided.envelope)
                    if not isinstance(final,_Decided):raise EmissionError('final decision refused')
                    if any(dep not in dependencies for dep in final_dependencies):
                        raise RetryRequired('final checks introduced uncovered dependency')
                    # Recheck fresh audit/retention validity without network or
                    # protected-head file locks while holding application locks.
                    parameters['retain_before_permit']=lambda:runtime.check_ticket(ticket,prepared,dependencies)
                    # TargetAuthority reads mutable epoch/chain state again
                    # while building and checking the signed permit. Check the
                    # collected dependencies at its actual signing boundary too.
                    original_targets=self._targets
                    guarded=copy(original_targets)
                    signer=original_targets._signer
                    def still_covered():
                        if any(dep not in dependencies for dep in final_dependencies):
                            raise RetryRequired('issuance introduced uncovered dependency')
                    class CoveredSigner:
                        key_id=signer.key_id
                        alg=signer.alg
                        def sign(self,body):
                            still_covered()
                            return signer.sign(body)
                    guarded._signer=CoveredSigner();self._targets=guarded
                    self._budget=DeferredReleaseBudget()
                    try:
                        result=super()._issue_target_authorization(prepared,**parameters)
                        still_covered()
                        return result
                    finally:self._targets=original_targets;self._budget=original_budget
        except BaseException:
            if prepared.reservation!=UNBUDGETED:
                try:self._budget.release(prepared.ctx.tenant_id,prepared.mission,prepared.reservation)
                except Exception:pass
            raise
        finally:
            # Core refusal releases run after the caller's locks have exited.
            # The allocator uses its own login, so releasing inside a held
            # mission lock would deadlock. No release operation is discarded.
            for args,kwargs in deferred_releases:
                original_budget.release(*args,**kwargs)

class SharedEvidenceReferenceEngine(SharedEvidenceIssuance,FloorBoundReferenceEngine):
    pass
