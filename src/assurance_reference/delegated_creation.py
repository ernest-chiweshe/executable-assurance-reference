"""Bind a host creation to one narrowed child of a reviewed, retained root."""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from regulated_core.canonical import digest_hex
from regulated_core.delegation import DelegationAuthority, DelegationError, SignedGrant
from regulated_core.delegation_chain_pg import resolve_stored_chain_on
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresGrantStore


@dataclass(frozen=True)
class ChildRequest:
    tenant: str
    parent_digest: str
    creation_id: str
    actor: str
    operations: tuple[str, ...]
    targets: tuple[str, ...]
    expires_at_us: int
    delegable: bool = False
    policy_refs: tuple[str, ...] | None = None


class CreationAuthority(Protocol):
    """Host-owned authentication and a durable creation-to-executor binding.

    The host authenticates the caller before invoking this service. This check
    must lock and verify the current actor membership and the exact retained
    (tenant, creation, parent, actor) claim on the supplied connection. It returns
    the composition-owned executor subject and a nonempty identity revision.
    A request-supplied subject or a name prefix alone is not authentication.
    """

    def verify_on(self, conn, request: ChildRequest) -> tuple[str, str]: ...


class _CallerConnection:
    """Keep core grant-store operations inside the service's outer transaction."""

    def __init__(self, conn):
        self.conn = conn

    @contextmanager
    def connection(self):
        yield self.conn


@dataclass(frozen=True)
class ChildResult:
    status: str
    grant: SignedGrant | None = None
    alert_id: str | None = None
    detail: str = ""


class ReviewedChildCreation:
    """Revalidate retained provenance and host identity before storing a child.

    Core grant writes use nested transactions on the same connection, so the
    ancestry revocation locks survive until the outer commit. A child creates
    neither an effect permit nor budget consumption. Receiver checks remain
    mandatory. Connection loss yields UNKNOWN, never a claim of no grant.
    Runtime calls do not provision schemas, identities, claims or permissions.
    """

    def __init__(self, *, pool, root_verifier, signer, creations: CreationAuthority, alerts):
        self.pool, self.root = pool, root_verifier
        self.signer, self.creations, self.alerts = signer, creations, alerts

    def create(self, request: ChildRequest) -> ChildResult:
        request_hash = digest_hex({"schema": "executable-assurance/child-request/v1",
                                   "request": request})
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('app.tenant', %s, true)", (request.tenant,))
                conn.execute("SET LOCAL lock_timeout = '5s'")
                conn.execute("SET LOCAL statement_timeout = '10s'")
                if self.signer.key_id != self.root.delegation_key_id:
                    raise EmissionError("child signer differs from the retained root authority")
                epoch = conn.execute(
                    "SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 WHERE tenant=%s",
                    (request.tenant,),
                ).fetchone()[0]
                checked = resolve_stored_chain_on(
                    conn, request.tenant, request.parent_digest,
                    verifier=self.root, expected_epoch=int(epoch),
                )
                identity = self.creations.verify_on(conn, request)
                if (not isinstance(identity, tuple) or len(identity) != 2
                        or any(not isinstance(v, str) or not v.strip() for v in identity)):
                    raise EmissionError("host creation lacks an executor or identity revision")
                subject, _ = identity
                if request.actor != checked.chain.leaf.subject:
                    raise EmissionError("only the authenticated parent holder may create its child")
                authority = DelegationAuthority(
                    self.signer, self.root.trust,
                    PostgresGrantStore(pool=_CallerConnection(conn)),
                )
                grant = authority.ensure_child(
                    request.tenant, request.parent_digest, actor=request.actor, subject=subject,
                    operations=request.operations, targets=request.targets,
                    expires_at_us=request.expires_at_us, delegable=request.delegable,
                    creation_id=request.creation_id, policy_refs=request.policy_refs,
                    clock=lambda: self.root.inputs.now_on(conn),
                )
                if self.creations.verify_on(conn, request) != identity:
                    raise EmissionError("host creation or actor identity changed during issuance")
                # Includes actual admission time, signatures, current inputs and
                # all newly acquired ancestry locks before returning authority.
                resolve_stored_chain_on(conn, request.tenant, grant.digest,
                                        verifier=self.root, expected_epoch=int(epoch))
            return ChildResult("created", grant=grant)
        except (DelegationError, EmissionError) as exc:
            code, status = "ADMISSION_REFUSED", "refused"
            detail = str(exc)
        except Exception:
            code, status = "AUTHORIZATION_UNCERTAIN", "unknown"
            detail = "Child creation was not confirmed; reconcile the retained claim and alert."
        alert_id = self.alerts.append_refusal(
            tenant_id=request.tenant, request_hash=request_hash, decision_hash=None, code=code,
        )
        return ChildResult(status, alert_id=alert_id, detail=detail)
