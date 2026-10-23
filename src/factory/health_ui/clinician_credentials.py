"""The health workspace as the identity provider and credential registry a clinical approval is verified against.

Paper A binds every approval to a credential receipt verified at the instant of approval. For clinical writing
the verifying authority is the health workspace itself: an operator-provisioned clinician identity that is
active and a member of the workspace. These two adapters put that authority behind the regulated core's
existing seams, `IdentityProvider` and `LicenceRegistry`, so the core's own `CredentialVerifier` issues and
signs the receipt; nothing here signs anything.

What the receipt attests, stated exactly: an ACTIVE CLINICIAN MEMBERSHIP OF THIS WORKSPACE, read live from the
health identity store. It is not a professional licence register. `licence_type` says so
("workspace-clinician-membership"), and `provider` names the store. Verifying against a national professional
register is a separate provider and a separate owner decision; this module never implies it.

Membership is read at the instant of each approval: deactivating a clinician, removing a membership or revoking
a Hub customer key is seen by the next approval. A receipt is valid for a short window only, so a verified
membership cannot be carried far past the moment it was checked.
"""
from __future__ import annotations

import time
from collections.abc import Callable

from factory.health_ui.identity import ClinicianAuthenticator
from regulated_core.identity_provider import IdentitySubject, LicenceRecord

CLINICIAN_ROLE = "clinician"
MEMBERSHIP_LICENCE = "workspace-clinician-membership"
RECEIPT_WINDOW_US = 15 * 60 * 1_000_000


class HealthIdentityProvider:
    """`IdentityProvider` over the health identity store: a subject exists only while an active member."""

    provider_backed = True

    def __init__(self, authenticator: ClinicianAuthenticator) -> None:
        self._authenticator = authenticator

    def resolve(self, subject_id: str, tenant: str) -> IdentitySubject | None:
        identity = self._authenticator.active_member(subject_id, tenant)
        if identity is None:
            return None
        return IdentitySubject(identity.user_id, tenant, identity.display_name, active=True)


class HealthMembershipRegistry:
    """`LicenceRegistry` over one workspace's clinician memberships, bound to that workspace at construction."""

    provider = "health-identity-store"
    provider_backed = True

    def __init__(self, authenticator: ClinicianAuthenticator, *, workspace_id: str, jurisdiction: str,
                 clock_us: Callable[[], int] = lambda: time.time_ns() // 1_000) -> None:
        if not workspace_id or not jurisdiction:
            raise ValueError("a membership registry is bound to one workspace and names its jurisdiction")
        self._authenticator, self._workspace, self._jurisdiction = authenticator, workspace_id, jurisdiction
        self._clock_us = clock_us

    def lookup(self, subject_id: str, role: str) -> LicenceRecord | None:
        if role != CLINICIAN_ROLE or self._authenticator.active_member(subject_id, self._workspace) is None:
            return None
        return LicenceRecord(subject_id, CLINICIAN_ROLE, MEMBERSHIP_LICENCE, self._jurisdiction, "active",
                             self._clock_us() + RECEIPT_WINDOW_US)
