"""X-14 offline: the signed rulebook selects the credential profile; the host selects receipt keys.

Installs genuine signed synthetic Health derivatives; no database, provider or network call. The ordinary retained
Health path composing this selection is exercised by the PostgreSQL clinical finalisation tests.
"""
from types import SimpleNamespace

import pytest

from assurance_reference.credential_profile import (KEY_FIELDS, CredentialProfile, ProfileCredentials,
                                                    required_credential_kind, select_credential_profile)
from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.health_ui.clinician_credentials import MEMBERSHIP_LICENCE
from factory.packs.registry import PackRegistry
from regulated_core.identity_provider import CredentialError
from regulated_core.signing import Ed25519Signer
from synthetic_health_versions import fixture_trust
from synthetic_profile_health import RELEASE, SYNTHETIC_PUBLISHER, build_profile_health_fixture


class Provider:
    provider = "health-identity-store"


class Admitting:
    def __init__(self, profile):
        self.profile = profile

    def admit_release(self, **request):
        raise AssertionError("not exercised offline")


def _installed(tmp_path, role_groups=None):
    trust = fixture_trust()
    if role_groups is None:
        return PackRegistry(trust=trust).install(FIXTURES / "bundles" / "health-workspace-membership",
                                                 publisher_key_id=PUBLISHER, today="2026-10-14")
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    trust.register_signer(publisher)
    target = tmp_path / "profile"
    build_profile_health_fixture(target, publisher=publisher, role_groups=role_groups)
    return PackRegistry(trust=trust).install(target, publisher_key_id=publisher.key_id, today="2026-10-14")


def _select(pack, *, providers=None, signers=None):
    signer = Ed25519Signer("fixture:host-membership-receipts")
    return select_credential_profile(
        pack, action=RELEASE,
        providers={MEMBERSHIP_LICENCE: Provider} if providers is None else providers,
        signers={Provider.provider: signer} if signers is None else signers), signer


def test_signed_membership_profile_selects_the_host_receipt_key(tmp_path):
    pack = _installed(tmp_path)
    assert required_credential_kind(pack, RELEASE) == MEMBERSHIP_LICENCE
    profile, signer = _select(pack)
    assert profile.kind == MEMBERSHIP_LICENCE and isinstance(profile.provider, Provider) and profile.signer is signer
    assert ProfileCredentials(profile, Admitting)().profile.signer is signer


def test_unverifiable_signed_profile_refuses_startup(tmp_path):
    pack = _installed(tmp_path, [["clinician@professional-register"]])
    assert required_credential_kind(pack, RELEASE) == "professional-register"
    with pytest.raises(ValueError, match="requires professional-register credentials"):
        _select(pack)


def test_two_signed_credential_kinds_refuse_rather_than_guess(tmp_path):
    pack = _installed(tmp_path, [["clinician@workspace-clinician-membership"], ["clinician@professional-register"]])
    with pytest.raises(ValueError, match="more than one credential kind"):
        _select(pack)


@pytest.mark.parametrize("signers", [{}, {"another-provider": Ed25519Signer("fixture:other")},
                                     {"health-identity-store": object()}])
def test_provider_without_a_configured_receipt_key_refuses_startup(tmp_path, signers):
    with pytest.raises(ValueError, match="no configured receipt-signing key"):
        _select(_installed(tmp_path), signers=signers)


@pytest.mark.parametrize("field", sorted(KEY_FIELDS))
def test_request_chosen_receipt_key_is_refused(tmp_path, field):
    profile, _ = _select(_installed(tmp_path))
    with pytest.raises(CredentialError, match="cannot choose the credential receipt-signing key"):
        ProfileCredentials(profile, Admitting)({field: Ed25519Signer("fixture:request-chosen")})


def test_host_maps_are_copied_at_selection(tmp_path):
    pack = _installed(tmp_path)
    signer, other = Ed25519Signer("fixture:host"), Ed25519Signer("fixture:late")
    signers = {Provider.provider: signer}
    profile = select_credential_profile(pack, action=RELEASE, providers={MEMBERSHIP_LICENCE: Provider},
                                        signers=signers)
    signers[Provider.provider] = other
    assert profile.signer is signer


def test_credentials_without_session_admission_refuse(tmp_path):
    profile, _ = _select(_installed(tmp_path))
    with pytest.raises(ValueError, match="exact-session release admission"):
        ProfileCredentials(profile, lambda selected: SimpleNamespace())()


def test_profile_type_is_required():
    with pytest.raises(TypeError):
        ProfileCredentials(SimpleNamespace(kind=None, provider=None, signer=None), Admitting)
    assert CredentialProfile(None, Provider(), None).kind is None
