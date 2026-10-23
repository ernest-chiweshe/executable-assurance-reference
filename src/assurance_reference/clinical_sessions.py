"""Bind the unchanged clinical receiving adapter to restricted retained sessions.

This is a session adapter only. It grants no clinician membership, certificate,
professional licence, or approval. Those remain separate host authorities.
"""

from contextlib import contextmanager
import math

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable
from factory.health_ui.identity import ClinicianIdentity, IdentityStoreDegraded, SessionAdmissionRefused
from factory.health_ui.session_release import SESSION_SCHEMA


class RetainedClinicalSessions:
    """One authenticated request, with admission held through the actual effect."""

    def __init__(self, sessions, authenticated):
        if not isinstance(authenticated, AuthenticatedSession):
            raise ValueError("clinical admission requires an authenticated retained session")
        if not callable(getattr(sessions, "admit", None)):
            raise ValueError("clinical admission requires the retained session authority")
        self._sessions, self._authenticated = sessions, authenticated

    @property
    def identity(self):
        current = self._authenticated
        return ClinicianIdentity(current.principal, current.username, "", current.tenant,
            current.reference, current.expires_at_us / 1_000_000)

    def binding(self):
        identity = self.identity
        return {"schema": SESSION_SCHEMA, "user_id": identity.user_id,
                "username": identity.username, "workspace_id": identity.workspace_id,
                "reference": identity.session_reference, "expires_at": identity.session_expires_at}

    @contextmanager
    def admit_session(self, identity, *, not_after=None):
        expected = self.identity
        if (not isinstance(identity, ClinicianIdentity)
                or (identity.user_id, identity.username, identity.workspace_id,
                    identity.session_reference, identity.session_expires_at)
                != (expected.user_id, expected.username, expected.workspace_id,
                    expected.session_reference, expected.session_expires_at)):
            raise SessionAdmissionRefused("clinical operation requires its authenticated retained session")
        deadline = None
        if not_after is not None:
            if (type(not_after) not in (int, float) or not_after <= 0
                    or (type(not_after) is float and not math.isfinite(not_after))):
                raise SessionAdmissionRefused("clinical effect deadline must be finite and positive")
            # The original clinical port uses seconds. Round inward so its
            # float conversion cannot extend the microsecond authority window.
            bounded = min(not_after, expected.session_expires_at)
            deadline = math.floor(math.nextafter(bounded, -math.inf) * 1_000_000)
            if deadline <= 0:
                raise SessionAdmissionRefused("clinical effect deadline is already closed")
        try:
            with self._sessions.admit(self._authenticated, not_after_us=deadline) as current:
                def check():
                    try:
                        current()
                    except SessionRefused as error:
                        raise SessionAdmissionRefused(str(error)) from error
                    except SessionUnavailable as error:
                        raise IdentityStoreDegraded("clinical session authority unavailable") from error

                check()
                yield check
        except SessionRefused as error:
            raise SessionAdmissionRefused(str(error)) from error
        except SessionUnavailable as error:
            raise IdentityStoreDegraded("clinical session admission unavailable") from error
