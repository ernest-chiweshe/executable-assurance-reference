"""Retain qualification evidence alongside an unchanged gate's release decision."""

import json
from dataclasses import replace

from assurance_reference.qualified_engine import QualifiedReferenceEngine
from regulated_core.canonical import canonical_bytes
from regulated_core.engine import TargetAuthorization
from regulated_core.qualification import QualificationError


class LineageUnavailable(ValueError):
    """The release answer cannot carry verified qualification evidence."""


def attach_qualification_lineage(decision, *, qualifications, recorder, permit_authority):
    """Pure evidence augmentation; the permit and original decision stay intact."""
    if not decision.allowed:
        return decision
    authorization = decision.permit
    if (not isinstance(authorization, TargetAuthorization) or not authorization.authorized
            or authorization.permit is None):
        raise QualificationError("allowed release has no target authorization")
    envelope = authorization.envelope
    permit = authorization.permit.permit
    record = envelope.record
    if (not recorder.verify_entry(envelope)
            or permit.decision_record_id != record.record_id
            or permit.decision_record_hash != envelope.record_hash
            or permit.tenant_id != record.tenant_id or permit.principal != record.actor_id
            or permit.assertion_id != record.assertion_id or permit.action_id != record.action.action_id
            or permit.clock_domain != envelope.clock_domain):
        raise QualificationError("retained permit does not bind the verified decision")
    lineage = qualifications.retained_lineage(authorization.permit, permit_authority=permit_authority)
    evidence = dict(decision.evidence)
    if "qualification_lineage" in evidence or "authorization_decision" in evidence:
        raise QualificationError("qualification evidence must not overwrite retained fields")
    evidence["qualification_lineage"] = lineage
    evidence["authorization_decision"] = json.loads(canonical_bytes(envelope))
    return replace(decision, evidence=evidence)


class QualificationEvidenceGate:
    """Application-composition wrapper; all authority and receiving methods delegate.

    The original gate performs authorization first. Before its answer is handed
    to the workflow, add exact signed report/permit evidence for normal project
    retention. If augmentation fails, the original unreleased-reservation cleanup
    runs and no allowed answer is returned. Commit/reconciliation stay unchanged.
    """

    def __init__(self, gate, *, retention=None):
        if not isinstance(gate._engine, QualifiedReferenceEngine):
            raise TypeError("qualification evidence requires the reference engine")
        self._gate = gate
        if retention is not None and not callable(getattr(retention, "retain", None)):
            raise TypeError("lineage retention requires a retain method")
        self._retention = retention

    def __getattr__(self, name):
        return getattr(self._gate, name)

    def authorize_release(self, **request):
        decision = self._gate.authorize_release(**request)
        if not decision.allowed:
            return decision
        engine = self._gate._engine
        try:
            attached = attach_qualification_lineage(decision, qualifications=engine._qualifications,
                recorder=engine._recorder, permit_authority=engine.targets._signer.key_id)
            if self._retention is not None:
                self._retention.retain(attached)
            return attached
        except Exception as error:
            self._gate._return_unreleased_reservation(decision.permit)
            if isinstance(error, QualificationError):
                raise LineageUnavailable(str(error)) from error
            raise
