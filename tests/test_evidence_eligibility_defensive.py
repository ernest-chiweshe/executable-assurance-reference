"""Defensive boundary cases from independent CORE008 review (c)-(e)."""
import pytest

from regulated_core.evidence_eligibility import decision_question, outcome_question, stored_action_view
from regulated_core.evidence_questions import QuestionRefused
from regulated_core.models import Action, ActionEffect


class ActionSubclass(Action):
    pass


class StringSubclass(str):
    pass


@pytest.mark.parametrize("action", [
    None,
    ActionSubclass("sample", ActionEffect.REVERSIBLE),
    Action("sample", "reversible"),
    Action("sample", None),
])
def test_stored_projection_requires_decoded_exact_action_and_effect(action):
    with pytest.raises(ValueError, match="requires a decoded Action"):
        stored_action_view(action)


@pytest.mark.parametrize("kind", ["decision", "outcome"])
@pytest.mark.parametrize("key_id,clock_domain", [
    ("", "domain"), (None, "domain"), (1, "domain"),
    (StringSubclass("key"), "domain"), ("key", None),
    ("key", 1), ("key", StringSubclass("domain")),
])
def test_public_eligibility_questions_refuse_invalid_recorder_scope(kind, key_id, clock_domain):
    with pytest.raises(QuestionRefused, match="invalid recorder eligibility scope"):
        if kind == "decision":
            decision_question("hash", key_id=key_id, clock_domain=clock_domain)
        else:
            outcome_question("hash", "assertion", Action("sample", ActionEffect.REVERSIBLE),
                             key_id=key_id, clock_domain=clock_domain)


@pytest.mark.parametrize("record_hash,assertion_id", [
    (("hash",), "assertion"), ("hash", ("assertion",)),
])
def test_outcome_scalar_no_match_with_valid_action_does_not_build_a_lookup_key(record_hash, assertion_id):
    result = outcome_question(record_hash, assertion_id, Action("sample", ActionEffect.REVERSIBLE),
                              key_id="key", clock_domain="domain")
    assert result.matchable is False
    assert result.value is None
