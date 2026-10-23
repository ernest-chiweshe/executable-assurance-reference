"""Hold the recovered generation-floor lock across a caller's local effect.

This adapter owns a separate restricted connection and transaction. It never
wraps a SessionBoundPool's independently committed store operations in an outer
transaction. Floor publication and role retirement remain external operations.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import re

from psycopg import Error
from psycopg.pq import TransactionStatus

from factory.customer.generation_floor_pg import GenerationFloorVerifier
from factory.pg_session import SessionBoundPool
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.target import ReleaseAdmissionUnavailable


@dataclass(frozen=True)
class GenerationFloorAdmission:
    """Explicit host binding; construction performs no database or signing I/O.

    The caller must keep hold() open through its actual effect and invoke the
    yielded check immediately before that effect. This object alone does not
    wire a host, select a winner after restore, or qualify a deployment.
    """

    verifier: GenerationFloorVerifier
    pool: object
    expected_domain: str
    expected_database: str
    expected_login: str

    def __post_init__(self):
        if not isinstance(self.verifier, GenerationFloorVerifier):
            raise TypeError("generation floor admission requires the recovered verifier")
        if isinstance(self.pool, SessionBoundPool) or not callable(getattr(self.pool, "connection", None)):
            raise ValueError("generation floor admission requires an independent connection pool")
        if (not isinstance(self.expected_domain, str)
                or re.fullmatch(r"pg:[0-9]{1,20}", self.expected_domain) is None):
            raise ValueError("generation floor admission requires a pinned primary domain")
        for value in (self.expected_database, self.expected_login):
            if (not isinstance(value, str) or not 1 <= len(value) <= 63
                    or not value.isprintable() or value != value.strip()):
                raise ValueError("generation floor admission requires explicit database and login")

    def _require_on(self, connection):
        binding = connection.execute(
            "SELECT current_database(), current_user, session_user").fetchone()
        if binding != (self.expected_database, self.expected_login, self.expected_login):
            raise CredentialError("generation floor connection differs from host database or login")
        DbClock(None, self.expected_domain).read_on(connection)
        return self.verifier.require_on(connection)

    @contextmanager
    def hold(self):
        """Yield a scope-bound recheck; close uncertainty never means no effect."""
        try:
            with self.pool.connection() as connection:
                if (connection.info.transaction_status != TransactionStatus.IDLE
                        or connection.autocommit is not True):
                    raise CredentialError("generation floor admission requires an idle autocommit connection")
                with connection.transaction():
                    self._require_on(connection)
                    active = True

                    def before_effect():
                        if not active:
                            raise EmissionError("generation floor admission scope has ended")
                        try:
                            self._require_on(connection)
                        except CredentialError as refused:
                            raise EmissionError(str(refused)) from refused
                        except (Error, ClockError, OSError, RuntimeError) as unavailable:
                            raise ReleaseAdmissionUnavailable(
                                "generation floor unavailable before effect") from unavailable

                    try:
                        yield before_effect
                    finally:
                        active = False
        except (Error, ClockError, OSError, RuntimeError) as unavailable:
            if isinstance(unavailable, ReleaseAdmissionUnavailable):
                raise
            raise ReleaseAdmissionUnavailable(
                "generation floor admission unavailable; reconcile any possible effect") from unavailable
