"""Signed Education catalog with guarded PostgreSQL lifecycle authority."""

import hashlib
from dataclasses import fields

from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.governed_packs import GovernedEducationPacks
from assurance_reference.packs import verify_bundles
from regulated_core.canonical import digest_hex
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.target import Outcome


class DurableGovernedEducationPacks(GovernedEducationPacks):
    """Re-read durable state on each operation; retain the existing governance guard.

    The host explicitly migrates the ledger before use. Connections, authority
    clock, signing keys and journal are host configuration, never request inputs.
    This adapter does not install or execute the bundled application code.
    """

    def __init__(self, *, pool, clock: DurableClock, alerts: AlertJournal, partitioned_lifecycle=True):
        if not isinstance(clock, DurableClock) or not isinstance(alerts, AlertJournal):
            raise TypeError("a durable authority clock and alert journal are required")
        if pool is None or not callable(getattr(pool, "connection", None)):
            raise TypeError("explicit host PostgreSQL connections are required")
        self.clock = clock
        self.alerts = alerts
        self.governance_guard = GovernanceGuard()
        if type(partitioned_lifecycle) is not bool:
            raise TypeError("partitioned_lifecycle must be an explicit boolean")
        if not partitioned_lifecycle:
            # Refused before any ledger is built: the shared pack_lifecycle store holds every tenant's pins and receipts; a qualified multi-tenant composition selects the partitioned lifecycle (B-F7b, candidate 060).
            raise ValueError("legacy shared pack lifecycle is not a qualified multi-tenant composition")
        from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
        self.ledger = PartitionedActivationLedger("", pool=pool, guard=self.governance_guard)
        self._digests = {
            item["reference"]: item["manifest_digest"]
            for item in verify_bundles()["bundles"]
        }

    def activate(
        self, reference, *, at, reason="", approved_prior=None, before_commit=None,
        receipt=None, first_state_only=False,
    ):
        # The approved change's `at` is descriptive input, never audit time.
        return super().activate(
            reference, at=str(self.clock.now_us()), reason=reason,
            approved_prior=approved_prior, before_commit=before_commit,
            receipt=receipt, first_state_only=first_state_only,
        )

    def rollback(
        self, pack_id, *, at, reason, approved_target, approved_prior=None,
        before_commit=None, receipt=None,
    ):
        return super().rollback(
            pack_id, at=str(self.clock.now_us()), reason=reason,
            approved_target=approved_target, approved_prior=approved_prior,
            before_commit=before_commit, receipt=receipt,
        )

    def revoke(
        self, reference, *, at, reason, approved_prior=None, before_commit=None, receipt=None,
    ):
        return super().revoke(
            reference, at=str(self.clock.now_us()), reason=reason,
            approved_prior=approved_prior, before_commit=before_commit, receipt=receipt,
        )

    def governance_receipt(self, tenant_id, operation, nonce, change_digest):
        key = (tenant_id, operation, nonce, change_digest)
        if any(self.ledger.governance_receipt(pack, key) for pack in self.ledger.pack_ids()):
            return Outcome.COMMITTED
        # Absence alone cannot establish that no outstanding attempt can commit.
        return Outcome.UNKNOWN

    def authorize(self, engine, **request):
        """Retain signed refusal/uncertainty for this host's authorization entry.

        Configuration/serialization errors before a valid request is formed are
        outside this entry's claim. Journal failures propagate to the host.
        """
        binding = {key: value for key, value in request.items() if key not in {"target", "output"}}
        # Assertion.attributes is immutable; canonicalize its fields without deepcopy.
        binding["assertion"] = {field.name: getattr(request["assertion"], field.name)
                                for field in fields(request["assertion"])}
        binding.update(
            target=request["target"].target,
            output_sha256=hashlib.sha256(request["output"]).hexdigest(),
        )
        request_hash = digest_hex(binding)
        tenant = request["ctx"].tenant_id
        try:
            result = engine.authorize_for_target(**request)
        except Exception:
            self.alerts.append_refusal(
                tenant_id=tenant, request_hash=request_hash, decision_hash=None,
                code="AUTHORIZATION_UNCERTAIN",
            )
            raise
        if not result.authorized:
            self.alerts.append_refusal(
                tenant_id=tenant, request_hash=request_hash,
                decision_hash=result.envelope.record_hash if result.envelope else None,
                code="AUTHORIZATION_REFUSED",
            )
        return result
