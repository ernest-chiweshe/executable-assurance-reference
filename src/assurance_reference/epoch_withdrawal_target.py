"""Registered, durable supervisor withdrawal target; no construction I/O."""
from assurance_reference.governance_targets import _options, _register
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from regulated_core.governance_targets import GovernanceTarget
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresGovernanceLog, PostgresPermitUseStore

from assurance_reference.epoch_withdrawal_admission import KIND, OPERATION, checked_change
from assurance_reference.epoch_withdrawal_review import EpochWithdrawalReviewLoader
from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger


def epoch_withdrawal_target(store, *, tenant_id, loader, authority, uses, log, budget):
    """Compose a tenant-bound writer through the existing reference registry.

    Review retention and authenticated supervisor approval happen before release.
    The writer independently reloads that retained approval in its transaction.
    There is no bootstrap path for incrementing an epoch.
    """
    if (not isinstance(store, GuardedPostgresRevocationLedger)
            or not isinstance(loader, EpochWithdrawalReviewLoader)
            or loader.roster._proof_verifier.tenant != tenant_id
            or not isinstance(uses, PostgresPermitUseStore)
            or not isinstance(log, TenantFencedGovernanceLog) or log.tenant != tenant_id):
        # B-F7b: this tenant-scoped scope keeps its fences in the tenant-isolated table.
        raise TypeError("epoch target requires matching tenant and durable reference services")
    if getattr(authority, "_epoch", None) != store.governance_epoch:
        raise TypeError("epoch target authority requires this ledger explicit governance reader")
    configured = _options(budget, {})
    store.bind_writer(loader=loader, authority=authority, log=log)

    def state():
        return str(store.governance_epoch(tenant_id))

    def direct(change):
        raise EmissionError("epoch withdrawal requires the owned governed transaction")

    def validate(change):
        checked_change(tenant_id, change)

    def expect(change, prior):
        checked = checked_change(tenant_id, change)
        if str(checked["prior_epoch"]) != prior:
            raise EmissionError("withdrawal request differs from current tenant epoch")
        return str(checked["prior_epoch"] + 1)

    return _register(GovernanceTarget(
        tenant_id=tenant_id, kind=KIND, subject=tenant_id, authority=authority,
        uses=uses, state=state, apply=direct, log=log, operation_name=OPERATION,
        guard=store.governance_guard, transact=store.apply, receipt=store.receipt,
        expect=expect, validate=validate, scope=KIND + ":" + tenant_id,
        **configured), budget)
