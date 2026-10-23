"""Reuse one already-held session admission inside a single host composition.

Each outer operation still acquires the real identity/session database locks.
Nested collection readers join that admission instead of consuming another
connection. Nested deadlines can only tighten it; checks expire on scope exit.
"""

from contextlib import contextmanager
from contextvars import ContextVar

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable


class SessionAdmissionScope:
    def __init__(self, source, authenticated):
        if (not isinstance(authenticated, AuthenticatedSession)
                or not callable(getattr(source, "admit", None))
                or not callable(getattr(getattr(source, "clock", None), "now_us", None))):
            raise ValueError("an authenticated identity and current session authority are required")
        self.source, self.authenticated, self.clock = source, authenticated, source.clock
        self._held = ContextVar("reference_session_admission", default=None)

    @contextmanager
    def _scope(self, parent, deadline):
        active = True

        def current():
            if not active:
                raise SessionRefused("session admission scope has ended")
            parent()
            if deadline is not None:
                try:
                    now = self.clock.now_us()
                except Exception as error:
                    raise SessionUnavailable("session deadline time unavailable") from error
                if now >= deadline:
                    raise SessionRefused("nested session deadline expired")

        current()
        token = self._held.set(current)
        try:
            yield current
        finally:
            active = False
            self._held.reset(token)

    def admit_many(self, identities, *, not_after_us):
        """Separate explicit group admission; never joins requester-only scope."""
        admit = getattr(self.source, "admit_many", None)
        if not callable(admit):
            raise SessionUnavailable("retained reviewer group admission unavailable")
        return admit(identities, not_after_us=not_after_us)

    @contextmanager
    def admit(self, identity, *, not_after_us=None):
        if not isinstance(identity, AuthenticatedSession) or identity != self.authenticated:
            raise SessionRefused("admission scope belongs to a different authenticated session")
        if not_after_us is not None and (type(not_after_us) is not int or not_after_us <= 0):
            raise SessionRefused("positive effect deadline required")
        parent = self._held.get()
        if parent is not None:
            with self._scope(parent, not_after_us) as current:
                yield current
        else:
            with self.source.admit(identity, not_after_us=not_after_us) as admitted:
                with self._scope(admitted, None) as current:
                    yield current
