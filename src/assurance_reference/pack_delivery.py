"""Bind a local application receiver to one signed pack version."""

from assurance_reference.durable_governance import DurableGovernedEducationPacks
from regulated_core.canonical import digest_hex
from regulated_core.target import FilesystemTargetAdapter, Outcome, TargetRef, TargetResult


class PackBoundFilesystemTarget(FilesystemTargetAdapter):
    """Host-composed version binding with a PostgreSQL resolution guard at delivery.

    Only commit is extended. Existing permit checks, file locking, nonce use and
    receipts remain in the core receiver. This does not install pack code, attest
    running policy code, or establish an operating-system capability boundary.
    """

    def __init__(self, *, packs: DurableGovernedEducationPacks, reference: str, **parameters):
        if not isinstance(packs, DurableGovernedEducationPacks):
            raise TypeError("a guarded durable pack receiver is required")
        super().__init__(**parameters)
        self._packs = packs
        self._pack_id, _, self._pack_digest = packs._verified(reference)
        self._reference = reference

    @property
    def target(self):
        # Signed into the action's destination and the target permit. Bind the
        # exact version/digest, not a mutable pointer to whatever is active later.
        return TargetRef("pack-file/v1", digest_hex({
            "filesystem_target": super().target,
            "pack_reference": self._reference, "pack_digest": self._pack_digest,
        }))

    def _refused(self, signed, result):
        self._packs.alerts.append_refusal(
            tenant_id=self.tenant_id,
            request_hash=digest_hex(signed.permit.signed_body()),
            decision_hash=signed.permit.decision_record_hash,
            code="ADMISSION_REFUSED",
        )
        return result

    def commit(self, signed, output):
        try:
            # Authenticate the named receiver before consulting tenant pack state.
            # The ordinary receiver subsequently checks freshness and exact bytes.
            self.authority.authenticate(
                signed, tenant_id=self.tenant_id, target=self.target, operation=self.operation,
            )
            with self._packs.ledger.resolution_guard(self.tenant_id, self._pack_id) as record:
                if self.uses.used(self.tenant_id, signed.permit.nonce):
                    retained = super().status(signed)
                    if retained.outcome is Outcome.COMMITTED:
                        return retained
                    # A spent nonce plus absent/incomplete receipt is not proof
                    # that no concurrent or interrupted delivery can have occurred.
                    return TargetResult(Outcome.UNKNOWN, "PACK_DELIVERY_RECONCILIATION_REQUIRED")
                if (record is None or record.reference != self._reference
                        or record.pack_digest != self._pack_digest):
                    return self._refused(signed, TargetResult(
                        Outcome.FAILED, "PACK_VERSION_UNAVAILABLE", self.current_state(),
                    ))
                # Keep the shared lifecycle lock through the existing receiving path.
                result = super().commit(signed, output)
                if result.outcome is Outcome.FAILED:
                    return self._refused(signed, result)
                return result
        except Exception:
            # Propagate failures, retaining uncertainty when the journal is available.
            # Do not infer absence of an effect from a lost connection or exception.
            self._packs.alerts.append(
                tenant_id=self.tenant_id, decision_hash=signed.permit.decision_record_hash,
                permit_hash=digest_hex(signed.permit.signed_body()),
                code="TARGET_UNKNOWN", outcome="unknown",
            )
            raise
