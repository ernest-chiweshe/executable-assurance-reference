"""Two synthetic applications expressed through the same original VerticalSpec.

This layer proposes bytes. It has no policy engine, approver, key or effect target.
The host supplies trusted declarations; this is not a sandbox for arbitrary code.
"""

from types import MappingProxyType

from factory.projectos.spec import (
    AXIS_ARTIFACT,
    KIND_PROJECT,
    Binding,
    RegulatedBlock,
    StageSpec,
    VerticalSpec,
    validate_spec,
)


def _lesson(_state, _item):
    return (
        "Fractions: a short practice lesson\n\n"
        "Objective: explain why two quarters equal one half.\n"
        "Activity: divide a paper circle into four equal parts and shade two.\n"
        "Check: draw one half, then explain how it matches the shaded quarters.\n\n"
        "Synthetic reference example; instructor approval is simulated with a local test identity.\n"
    )


def _handout(_state, _item):
    return (
        "SYNTHETIC HEALTH WORKFLOW — NOT CLINICAL ADVICE\n"
        "Sample patient: SAMPLE-001 (fictional)\n\n"
        "Your appointment checklist\n"
        "Write down the questions you want to ask at your appointment.\n"
        "Ask the clinic how to obtain a copy of your visit summary.\n\n"
        "This local demonstration sends nothing to a patient or provider.\n"
    )


_PROPOSE = StageSpec(
    id="propose", title="Prepare a synthetic draft", kind=KIND_PROJECT,
    inputs=(Binding("content", "fn:content"),),
)
EDUCATION = VerticalSpec(
    name="course", axis=AXIS_ARTIFACT, state_dir="lessons", id_field="lesson_id",
    stages=(_PROPOSE,), domain="education",
    computed_inputs=MappingProxyType({"content": _lesson}),
)
HEALTH = VerticalSpec(
    name="health", axis=AXIS_ARTIFACT, state_dir="handouts", id_field="handout_id",
    stages=(_PROPOSE,), domain="health",
    computed_inputs=MappingProxyType({"content": _handout}),
    regulated=RegulatedBlock(
        policy_ref="health/strict-health-authority@1.0.0",
        intended_use="Synthetic patient-education workflow qualification only",
        prohibited_uses=("clinical care", "patient delivery"),
        required_verifiers=(
            "health:phi-safety", "privacy:purpose-authorized", "privacy:minimum-necessary",
            "privacy:destination-authorized", "security:tenant-isolation",
            "source:fidelity", "health:clinical-validity",
        ),
        approver_roles=("clinician", "privacy-officer"),
        risk_tiers=MappingProxyType({"health:send-patient": 3}),
    ),
)


def propose(spec: VerticalSpec) -> bytes:
    """Resolve the one supported synthetic stage without granting permission."""
    problems = validate_spec(spec)
    if problems:
        raise ValueError("invalid application declaration: " + "; ".join(problems))
    if spec.stages != (_PROPOSE,):
        raise ValueError("the synthetic runner supports only its declared proposal stage")
    content = spec.computed_inputs["content"]({}, None)
    if not isinstance(content, str) or not content:
        raise ValueError("the proposal stage must produce nonempty text")
    return content.encode("utf-8")
