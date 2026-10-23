"""Explicit managed installation of prepared authority schemas and writer grants."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any

from .persistence_pg import SCHEMA as BASE_SCHEMA
from .evidence_checkpoints_pg import SCHEMA as CHECKPOINT_SCHEMA
from .retained_authority_pg import SCHEMA as USE_SCHEMA
from .input_evidence_pg import SCHEMA as INPUT_SCHEMA
from .root_admission_pg import SCHEMA as ROOT_SCHEMA
from .database_receiver_pg import SCHEMA as RECEIVER_SCHEMA


class AuthorityMigrationError(ValueError):
    """The configured authority writer policy cannot be installed safely."""


@dataclass(frozen=True)
class WriterPolicy:
    """Exact database logins admitted by the migration owner, never by requests."""

    budget: tuple[tuple[str, str], ...]
    preparation: tuple[str, ...]
    customer_readers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        names = [role for role, _ in self.budget] + list(self.preparation) + list(self.customer_readers)
        if (
            not isinstance(self.customer_readers, tuple)
            or len(set(self.customer_readers)) != len(self.customer_readers)
            or not self.budget
            or not self.preparation
            or len(set(self.budget)) != len(self.budget)
            or len(set(self.preparation)) != len(self.preparation)
            or any(
                not isinstance(n, str) or not n or "\x00" in n or len(n.encode("utf-8")) > 63
                for n in names
            )
            or {kind for _, kind in self.budget} != {"reserve", "consume", "release"}
        ):
            raise AuthorityMigrationError("explicit, distinct writer grants are required")

        allocators = {role for role, kind in self.budget if kind in {"reserve", "release"}}
        receivers = {role for role, kind in self.budget if kind == "consume"}
        if allocators & receivers or set(self.preparation) & (allocators | receivers):
            raise AuthorityMigrationError(
                "allocator, receiver and recorder logins must be disjoint"
            )

    @classmethod
    def from_mapping(cls, raw: object) -> WriterPolicy:
        """Parse the explicit authority_writers field of a reviewed release manifest."""
        try:
            if (
                not isinstance(raw, Mapping)
                or set(raw) not in ({"budget", "preparation"}, {"budget", "preparation", "customer_readers"})
                or not isinstance(raw.get("customer_readers", []), list)
                or not isinstance(raw["budget"], Mapping)
                or set(raw["budget"]) != {"reserve", "consume", "release"}
                or not isinstance(raw["preparation"], list)
                or any(not isinstance(names, list) or not names for names in raw["budget"].values())
            ):
                raise ValueError("writer configuration shape")
            return cls(
                tuple((name, kind) for kind, names in raw["budget"].items() for name in names),
                tuple(raw["preparation"]),
                tuple(raw.get("customer_readers", [])),
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise AuthorityMigrationError(
                "invalid explicit authority writer configuration"
            ) from exc


def migrate_prepared_authority(pool: Any, policy: WriterPolicy) -> None:
    """Install schemas and an initial exact writer map in one transaction.

    Existing nonempty maps must match exactly; changing authority later needs a
    separately reviewed governance operation. This does not create accounts,
    grant table privileges, migrate business data, or establish key isolation.
    """
    names = sorted({role for role, _ in policy.budget} | set(policy.preparation))
    with pool.connection() as conn, conn.transaction():
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
            ("regulated-authority-schema-v1",),
        )
        rows = conn.execute(
            "SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb"
            " FROM pg_roles WHERE rolname=ANY(%s)",
            (names,),
        ).fetchall()
        if len(rows) != len(names) or any(not row[1] or any(row[2:]) for row in rows):
            raise AuthorityMigrationError("writers must be existing restricted LOGIN roles")
        groups = [
            {role for role, kind in policy.budget if kind in {"reserve", "release"}},
            {role for role, kind in policy.budget if kind == "consume"},
            set(policy.preparation),
        ]
        for left, group in enumerate(groups):
            for other in groups[left + 1 :]:
                for first in group:
                    for second in other:
                        if conn.execute(
                            "SELECT pg_has_role(%s,%s,'MEMBER') OR pg_has_role(%s,%s,'MEMBER')",
                            (first, second, second, first),
                        ).fetchone()[0]:
                            raise AuthorityMigrationError("writer role membership crosses duties")
        for name in names:
            privileged = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE"
                " (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb)"
                " AND pg_has_role(%s,oid,'MEMBER'))",
                (name,),
            ).fetchone()[0]
            owns_schema = conn.execute(
                "SELECT pg_has_role(%s,nspowner,'MEMBER')"
                " FROM pg_namespace WHERE nspname=current_schema()",
                (name,),
            ).fetchone()
            if privileged or owns_schema is None or owns_schema[0]:
                raise AuthorityMigrationError("writer has administrative or schema-owner authority")
        for statement in (BASE_SCHEMA, CHECKPOINT_SCHEMA, USE_SCHEMA, INPUT_SCHEMA, ROOT_SCHEMA, RECEIVER_SCHEMA):
            conn.execute(statement)
        for name in names:
            owns_relation = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace"
                " WHERE n.nspname=current_schema() AND c.relname LIKE 'regulated_%%'"
                " AND pg_has_role(%s,c.relowner,'MEMBER'))",
                (name,),
            ).fetchone()[0]
            mutable_map = conn.execute(
                "SELECT has_table_privilege(%s,'regulated_budget_writer_roles_v1','INSERT,UPDATE,DELETE,TRUNCATE')"
                " OR has_table_privilege(%s,'regulated_preparation_writers_v1','INSERT,UPDATE,DELETE,TRUNCATE')",
                (name, name),
            ).fetchone()[0]
            if owns_relation or mutable_map:
                raise AuthorityMigrationError("writer can alter authority tables or writer policy")
        budget = set(
            conn.execute("SELECT role_name,kind FROM regulated_budget_writer_roles_v1").fetchall()
        )
        preparation = {
            r[0] for r in conn.execute("SELECT role_name FROM regulated_preparation_writers_v1")
        }
        if (budget and budget != set(policy.budget)) or (
            preparation and preparation != set(policy.preparation)
        ):
            raise AuthorityMigrationError(
                "existing writer policy differs; implicit authority changes refused"
            )
        for role, kind in policy.budget:
            conn.execute(
                "INSERT INTO regulated_budget_writer_roles_v1 VALUES(%s,%s) ON CONFLICT DO NOTHING",
                (role, kind),
            )
        for role in policy.preparation:
            conn.execute(
                "INSERT INTO regulated_preparation_writers_v1 VALUES(%s) ON CONFLICT DO NOTHING",
                (role,),
            )
