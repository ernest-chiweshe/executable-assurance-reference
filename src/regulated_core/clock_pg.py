"""Read primary PostgreSQL authority time without migrations or grant changes."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from psycopg import Error

from .clock import ClockError, ClockReading

_DOMAIN = re.compile(r"pg:[0-9]{1,20}\Z")
_READ = """
    SELECT 'pg:' || system_identifier::text,
           (extract(epoch FROM pg_catalog.clock_timestamp())*1000000)::bigint,
           pg_catalog.pg_is_in_recovery()
    FROM pg_catalog.pg_control_system()
"""


@dataclass(frozen=True)
class DbClock:
    """Require a host-pinned cluster domain and a primary on every reading.

    The release configuration supplies expected_domain; request data never does.
    An unavailable catalog function refuses rather than selecting another clock.
    No elevated function, migration or privilege provisioning is performed.
    """

    pool: Any
    expected_domain: str

    def __post_init__(self) -> None:
        if not isinstance(self.expected_domain, str) or not _DOMAIN.fullmatch(self.expected_domain):
            raise ValueError("database clock requires an explicit PostgreSQL domain")

    @property
    def domain(self) -> str:
        return self.expected_domain

    def read_on(self, connection: Any) -> ClockReading:
        """Read on the caller's connection without changing transaction or scope."""
        return self._finish_read(self._queue_read_on(connection))

    def _queue_read_on(self, connection: Any) -> Any:
        """Queue the unchanged SQL; a pipeline owner controls synchronization."""
        try:
            return connection.execute(_READ)
        except Error as exc:
            raise ClockError("database authority clock is unavailable") from exc

    def _finish_read(self, cursor: Any) -> ClockReading:
        """Validate a completed query exactly as for an ordinary fresh read."""
        try:
            rows = cursor.fetchall()
        except Error as exc:
            raise ClockError("database authority clock is unavailable") from exc
        if len(rows) != 1:
            raise ClockError("database clock must return exactly one reading")
        domain, now, recovery = rows[0]
        if domain != self.expected_domain or recovery is not False:
            raise ClockError("database authority clock requires the configured primary domain")
        return ClockReading(domain, now)

    def read(self) -> ClockReading:
        if self.pool is None:
            raise ClockError("database clock requires a configured pool or caller connection")
        try:
            with self.pool.connection() as connection:
                return self.read_on(connection)
        except Error as exc:
            raise ClockError("database authority clock connection is unavailable") from exc

    def now_us(self) -> int:
        return self.read().now_us
