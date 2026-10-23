"""Guarded configuration contracts for stored-review receiving admission."""
from types import SimpleNamespace

import pytest

from regulated_core.identity_provider import CredentialError
from regulated_core.projectos_gate import _RegulatedGateBase


@pytest.mark.parametrize("port", [None, False, "not-an-admission-port"])
def test_stored_review_requires_callable_session_admission(port):
    gate = object.__new__(_RegulatedGateBase)
    gate._credverify = SimpleNamespace(requires_stored_review=True, admit_reviewers=port)
    with pytest.raises(CredentialError, match="requires reviewer session admission"):
        with gate._reviewer_admission({}, None, None):
            pytest.fail("invalid composition entered admission")


def test_legacy_non_stored_review_preserves_optional_admission():
    gate = object.__new__(_RegulatedGateBase)
    gate._credverify = SimpleNamespace(requires_stored_review=False)
    with gate._reviewer_admission({}, None, None) as current:
        assert current is None


def test_session_admission_requires_retained_approval_reference():
    gate = object.__new__(_RegulatedGateBase)
    def admission(**kwargs):
        pytest.fail("no retained approval was supplied")
    gate._credverify = SimpleNamespace(requires_stored_review=True, admit_reviewers=admission)
    authorization = SimpleNamespace(permit=SimpleNamespace(permit=SimpleNamespace(approval_ref=None)))
    with pytest.raises(CredentialError, match="retained reviewer approval"):
        with gate._reviewer_admission({}, None, authorization):
            pytest.fail("missing approval entered admission")

@pytest.mark.parametrize("port", [None, False, "not-an-admission-port"])
def test_stored_review_requires_callable_domain_admission(port):
    gate = object.__new__(_RegulatedGateBase)
    gate._credverify = SimpleNamespace(requires_stored_review=True, admit_release=port)
    with pytest.raises(CredentialError, match="requires domain release admission"):
        with gate._release_admission({}, None, None):
            pytest.fail("invalid domain composition entered admission")


def test_legacy_non_stored_review_preserves_optional_domain_admission():
    gate = object.__new__(_RegulatedGateBase)
    gate._credverify = SimpleNamespace(requires_stored_review=False)
    with gate._release_admission({}, None, None) as current:
        assert current is None
