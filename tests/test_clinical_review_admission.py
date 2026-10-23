"""Offline qualified role routing contracts; not authenticated application qualification."""
import pytest

from assurance_reference.clinical_review_admission import (
    ClinicalReviewCredentials, QUALIFIED_CLINICIAN, membership_query_role,
)
from factory.health_ui.clinician_credentials import CLINICIAN_ROLE, MEMBERSHIP_LICENCE
from factory.health_ui.session_release import ClinicalSessionCredentials
from regulated_core.identity_provider import CredentialError


def test_signed_membership_role_queries_base_provider_role_only():
    assert QUALIFIED_CLINICIAN == CLINICIAN_ROLE + "@" + MEMBERSHIP_LICENCE
    assert membership_query_role(QUALIFIED_CLINICIAN) == "clinician"


@pytest.mark.parametrize("role", ["clinician", "clinician@professional-register", "", None])
def test_adapter_does_not_route_other_role_profiles(role):
    with pytest.raises(CredentialError):
        membership_query_role(role)


def test_receiving_admission_is_inherited_and_direct_approval_is_disabled():
    assert ClinicalReviewCredentials.admit_release is ClinicalSessionCredentials.admit_release
    assert ClinicalReviewCredentials.requires_stored_review is True
