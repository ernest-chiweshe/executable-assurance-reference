"""Ordinary signed supersession and stale-document observations via the operator."""
from dataclasses import replace

import pytest

from assurance_reference.operator_provisioning import ProvisioningStopped
from regulated_core.policy_document import document_policy
from test_operator_provisioning import host as host


@pytest.mark.parametrize("role", ["teacher", "head-of-department"])
def test_original_provisioner_refuses_older_generation_without_expected_revision(host, role):
    host.run(execute=True)
    original = host.docs[role]
    content = dict(original.content)
    content["given_name"] = "Updated synthetic"
    newer = document_policy(
        host.authority, vertical=original.vertical, policy_id=original.policy_id,
        version="2", content=content, jurisdictions=original.jurisdictions,
        effective_from_us=original.effective_from_us,
        effective_until_us=original.effective_until_us,
        supersedes=original.digest() if role == "head-of-department" else "",
    )
    host.docs[role] = newer
    pins = [replace(pin, expected_revision=1) if pin.role == role else pin
            for pin in host.pins()]
    update = host.run(execute=True, pins=pins)
    assert next(row for row in update["authorities"] if row["role"] == role)["revision"] == 2
    writes = host.store.writes
    # Old signed document remains within its time window, but its generation
    # cannot replace the newer state. The operator delegates this to the original
    # provisioner, including when no expected_revision is supplied.
    host.docs[role] = original
    stale_pins = host.pins()
    assert all(pin.expected_revision is None for pin in stale_pins)
    with pytest.raises(ProvisioningStopped) as stopped:
        host.run(execute=True, pins=stale_pins)
    assert stopped.value.receipt["attempted_role"] == role
    assert stopped.value.receipt["error_class"] == "WorkbenchError"
    assert host.store.writes == writes
    # Reapply the exact newer document and observe retained revision2 unchanged.
    host.docs[role] = newer
    observed = host.run(execute=True)
    assert next(row for row in observed["authorities"] if row["role"] == role)["revision"] == 2
    assert host.store.writes == writes
