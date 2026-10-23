"""X-18 binds a scripted decision to the complete displayed synthetic material."""

from copy import deepcopy

import pytest

from factory.education_workbench.source_material import work_digest
from regulated_core.canonical import digest_hex
from test_education_source_sessions import confirm, witness  # noqa: F401


def test_signed_witness_binds_exact_public_view_and_work_scope(witness):  # noqa: F811
    material = witness.service.material(witness.contract, witness.context)
    displayed = material.public_view()
    expected = digest_hex(displayed)
    assert expected == material.digest()
    result = confirm(witness, displayed=expected)
    assert result["confirmed"] and len(witness.signed) == 1
    signed = witness.signed[0]
    assert signed["material_digest"] == expected
    assert signed["scope"]["contract_digest"] == work_digest(witness.contract)
    assert signed["scope"]["tenant"] == witness.context.tenant
    assert signed["teacher_id"] == witness.context.actor_id


@pytest.mark.parametrize("field", ["learner_draft", "feedback", "rubric", "rubric_identifier",
                                 "rubric_criteria", "media_reference"])
def test_a_different_displayed_view_refuses_before_signing(witness, field):  # noqa: F811
    material = witness.service.material(witness.contract, witness.context)
    changed = deepcopy(material.public_view())
    if field == "rubric_criteria":
        changed[field].append("different fictional criterion")
    else:
        changed[field] += " different fictional display"
    with pytest.raises(ValueError, match="changed"):
        confirm(witness, displayed=digest_hex(changed))
    assert witness.signed == [] and witness.sessions.depth == 0
