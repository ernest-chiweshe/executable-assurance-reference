"""The same signed operator contracts under the restricted Education governor.

The pack lifecycle is a memory fixture. Database authority rows use the existing
tenant-scoped PostgreSQL composition; no production credentials or records.
"""

import os

import pytest

from assurance_reference.education_authority_store import compose_education_provisioner
from assurance_reference.local_roles import provision_local_roles
from factory.packs.examples import EDUCATION_ID
from test_signed_enrollment_contract import (
    build_enrollment,
    test_exact_signed_replay_is_idempotent_and_newer_revocation_advances,  # noqa: F401
    test_stale_compare_and_swap_cannot_overwrite_a_newer_operator_write,  # noqa: F401
    test_untrusted_stale_or_nonmonotonic_enrollment_preserves_current_state,  # noqa: F401
)


@pytest.fixture
def enrollment(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        store = compose_education_provisioner(pool=roles.education_governor,
                                              tenant="fictional-school")
        fixture = build_enrollment(tmp_path, store)
        fixture.roles = roles
        yield fixture
    finally:
        for value in vars(roles).values():
            if callable(getattr(value, "close", None)):
                value.close()


def test_signed_revocation_is_visible_through_a_reopened_store(enrollment):
    e = enrollment
    first = e.apply(e.document(1))
    winner = e.apply(e.document(2, status="tobedeleted"), expected_revision=first.version)
    reopened = compose_education_provisioner(pool=e.roles.education_governor,
                                             tenant="fictional-school")
    assert reopened.get(EDUCATION_ID, winner.collection, winner.tenant_id, winner.key) == winner
