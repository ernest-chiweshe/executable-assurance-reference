"""Generation-floor admission on the reference filesystem commit entry point."""

from dataclasses import replace

from assurance_reference.generation_floor_admission import GenerationFloorAdmission
from assurance_reference.qualified_engine import QualifiedReferenceEngine
from regulated_core.permit import EmissionError
from regulated_core.target import FilesystemTargetAdapter, Outcome, ReleaseAdmissionUnavailable, TargetResult


class FloorBoundReferenceEngine(QualifiedReferenceEngine):
    """Host composition supplies a floor guard or an explicitly logged non-use.

    Policy siblings inherit this guard through ReferenceEngine.for_policy.
    Cancellation and receipt-only reconciliation do not re-execute an effect.
    Other inherited core entry points remain outside this composition's claim.
    """

    def __init__(self, *, generation_floor: GenerationFloorAdmission | None, **parameters):
        if generation_floor is not None and not isinstance(generation_floor, GenerationFloorAdmission):
            raise TypeError("reference generation floor requires a bound admission guard")
        self._generation_floor = generation_floor
        super().__init__(**parameters)

    def commit(self, authorization, output, target):
        if self._generation_floor is None:
            return super().commit(authorization, output, target)
        if not authorization.authorized or authorization.permit is None:
            raise EmissionError("no target permit was issued for this authorization")
        if not isinstance(target, FilesystemTargetAdapter):
            raise EmissionError("generation-floor admission requires a filesystem target effect check")
        try:
            with self._generation_floor.hold() as floor_current:
                previous = target.effect_check

                def before_effect():
                    # Floor reads may block. Complete them before the existing
                    # session/domain final check so its freshness decision is
                    # not followed by this adapter's additional database reads.
                    floor_current()
                    if previous is not None:
                        previous()
                    # Preserve the permit deadline and margin after all composed
                    # admission work. The floor transaction remains held.
                    target.authority.current(authorization.permit, at_effect=True)

                guarded = replace(target, effect_check=before_effect)
                result = guarded.commit(authorization.permit, output)
        except ReleaseAdmissionUnavailable:
            result = TargetResult(Outcome.UNKNOWN,
                "generation-floor admission unavailable; reconcile the retained target receipt")
        return self._record_outcome(authorization, result, reconciled=False)
