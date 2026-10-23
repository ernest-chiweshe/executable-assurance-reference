"""Bind application data to host-selected policies at the composition root."""

from factory.projectos.spec import VerticalSpec, validate_spec
from regulated_core.models import PolicyRef


def check_binding(spec: VerticalSpec, policy: PolicyRef, *, verifiers=()) -> None:
    """Reject a declaration/policy mismatch; grant no approval or authority."""
    if validate_spec(spec) or spec.name != policy.vertical:
        raise ValueError("application and host policy do not match")
    if spec.regulated is None:
        if verifiers:
            raise ValueError("ordinary application unexpectedly declares regulated verifiers")
        return
    reference = f"{policy.vertical}/{policy.policy_id}@{policy.version}"
    if spec.regulated.policy_ref != reference:
        raise ValueError("regulated application names a different policy")
    if tuple(verifiers) != spec.regulated.required_verifiers:
        raise ValueError("host verifiers differ from the application declaration")
