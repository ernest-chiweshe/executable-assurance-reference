"""A guarded receiving adapter for the two signed, pinned Education bundles."""

from assurance_reference.packs import verify_bundles
from factory.packs.lifecycle import ActivationLedger, LifecycleError
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.target import Outcome


class GovernedEducationPacks:
    """Static verified catalog with an in-memory lifecycle and receiving receipts.

    Use the core's pack governance targets to mutate this receiver. No request
    supplies a pack digest, disables the guard or chooses a signature authority.
    It does not install executable pack code or survive process loss.
    """

    def __init__(self):
        self.governance_guard = GovernanceGuard()
        self.ledger = ActivationLedger(guard=self.governance_guard)
        self._digests = {
            item["reference"]: item["manifest_digest"]
            for item in verify_bundles()["bundles"]
        }

    def _verified(self, reference):
        if reference not in self._digests:
            raise LifecycleError("reference is not in the pinned Education catalog")
        current = {
            item["reference"]: item["manifest_digest"]
            for item in verify_bundles()["bundles"]
        }
        if current.get(reference) != self._digests[reference]:
            raise LifecycleError("verified bundle differs from the pinned catalog")
        pack_id, _, version = reference.partition("#")
        return pack_id, version, self._digests[reference]

    def active(self, pack_id):
        return self.ledger.active(pack_id)

    def activation_for(self, tenant_id, pack_id):
        return self.ledger.resolve_record(tenant_id, pack_id)

    def activate(
        self, reference, *, at, reason="", approved_prior=None, before_commit=None,
        receipt=None, first_state_only=False,
    ):
        pack_id, version, digest = self._verified(reference)
        return self.ledger.activate(
            pack_id, version, digest, at=at, reason=reason, approved_prior=approved_prior,
            before_commit=before_commit, receipt=receipt, first_state_only=first_state_only,
        )

    def rollback(
        self, pack_id, *, at, reason, approved_target, approved_prior=None,
        before_commit=None, receipt=None,
    ):
        ident, _, _ = self._verified(approved_target)
        if ident != pack_id:
            raise LifecycleError("rollback target belongs to another pack")
        return self.ledger.rollback(
            pack_id, at=at, reason=reason, expected_target_reference=approved_target,
            approved_prior=approved_prior, before_commit=before_commit, receipt=receipt,
        )

    def pin_tenant(
        self, tenant_id, reference, *, approved_prior=None, before_commit=None, receipt=None,
    ):
        pack_id, version, _ = self._verified(reference)
        if not any(item.reference == reference for item in self.ledger.history(pack_id)):
            raise LifecycleError("pin requires a previously activated version")
        self.ledger.pin(
            tenant_id, pack_id, version, approved_prior=approved_prior,
            before_commit=before_commit, receipt=receipt,
        )

    def revoke(
        self, reference, *, at, reason, approved_prior=None, before_commit=None, receipt=None,
    ):
        pack_id, version, _ = self._verified(reference)
        return self.ledger.revoke(
            pack_id, version, at=at, reason=reason, approved_prior=approved_prior,
            before_commit=before_commit, receipt=receipt,
        )

    def governance_receipt(self, tenant_id, operation, nonce, change_digest):
        key = (tenant_id, operation, nonce, change_digest)
        if any(self.ledger.governance_receipt(pack_id, key) for pack_id in self.ledger.pack_ids()):
            return Outcome.COMMITTED
        # Memory cannot establish a durable negative receipt after process loss.
        return Outcome.UNKNOWN
