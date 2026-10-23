"""Retain the approved clinician session through a governed clinical effect."""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import psycopg

from factory.health_ui.identity import ClinicianIdentity, IdentityStoreDegraded, SessionAdmissionRefused
from factory.projectos.regulated import EmissionContext
from regulated_core.engine import TargetAuthorization
from regulated_core.identity_provider import CredentialError, CredentialVerifier, IdentityProvider, LicenceRegistry
from regulated_core.permit import EmissionError
from regulated_core.signing import Signer, TrustDirectory
from regulated_core.target import ReleaseAdmissionUnavailable

SESSION_FIELD = "clinical_session"
SESSION_SCHEMA = "health/session-admission/v1"


class ClinicalSessionCredentials(CredentialVerifier):
    """Credential verification plus mandatory, exact-session release admission."""

    def __init__(self, trust: TrustDirectory, signer: Signer, identity: IdentityProvider,
                 registry: LicenceRegistry, *, sessions: Any) -> None:
        super().__init__(trust, signer, identity, registry)
        if not callable(getattr(sessions, "admit_session", None)):
            raise ValueError("clinical signing requires retained session admission")
        self._sessions = sessions

    @contextmanager
    def admit_release(self, *, contract: Mapping[str, Any], context: EmissionContext,
                      authorization: TargetAuthorization) -> Iterator[Callable[[], None]]:
        """The gate has verified this contract against its signed decision."""
        source = contract.get(SESSION_FIELD)
        required = {"schema", "user_id", "username", "workspace_id", "reference", "expires_at"}
        if (not isinstance(source, dict) or set(source) != required
                or source.get("schema") != SESSION_SCHEMA
                or any(not isinstance(source.get(k), str) or not source[k]
                       for k in ("user_id", "username", "workspace_id", "reference"))
                or type(source.get("expires_at")) not in (int, float)
                or source["user_id"] != context.actor_id or source["workspace_id"] != context.tenant
                or authorization.permit is None
                or authorization.permit.permit.principal != context.actor_id):
            raise CredentialError("the approved clinical operation requires its exact login session")
        identity = ClinicianIdentity(source["user_id"], source["username"], "", source["workspace_id"],
                                     source["reference"], float(source["expires_at"]))
        try:
            with self._sessions.admit_session(
                identity, not_after=authorization.permit.permit.expires_at_us / 1_000_000,
            ) as current:
                def check() -> None:
                    try:
                        current()
                    except SessionAdmissionRefused as refused:
                        # The target records an abort and releases its reservation.
                        raise EmissionError(str(refused)) from refused
                    except (IdentityStoreDegraded, psycopg.Error) as down:
                        raise ReleaseAdmissionUnavailable("session check unavailable before the effect") from down
                yield check
        except SessionAdmissionRefused as refused:
            # Entry failed before the target had any opportunity to write.
            raise CredentialError(str(refused)) from refused
        except (IdentityStoreDegraded, psycopg.Error) as down:
            # A connection error can also occur on context exit AFTER an effect.
            raise ReleaseAdmissionUnavailable(
                "clinical session admission unavailable; reconcile the target receipt",
            ) from down
