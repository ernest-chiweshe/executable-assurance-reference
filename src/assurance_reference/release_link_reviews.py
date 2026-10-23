"""Read-only X22 projection through the retained ApprovalExchange verifier.

The material port is trusted host composition. It must derive the full governed
contract and context from authoritative project state, never from request data.
Its locked_on operation must retain project/activation/source/inherited-grant
locks on the supplied transaction until publication ends. This stage supplies
the signed-review adapter; a concrete material port is still required.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from typing import Protocol

from factory.projectos.regulated import EmissionContext, ReleaseAuthorityBinding
from regulated_core.approval_exchange import ApprovalExchange
from regulated_core.review_store import PostgresReviewStore
from assurance_reference.release_link import ReleaseLinkRefused, VerifiedReleaseBinding


@dataclass(frozen=True)
class ReleaseMaterial:
    contract: dict
    context: EmissionContext


class ReleaseLinkMaterial(Protocol):
    def read(self, goal, request) -> ReleaseMaterial: ...

    def locked_on(self, connection, goal, request) -> ReleaseMaterial: ...


class StoredSignedReleaseReviews:
    """Reuses full original signature, credential and certificate verification.

    ApprovalExchange._validated is an explicit internal coupling, pinned in the
    stage provenance. Its approval.open call constructs an unsigned request;
    neither that method nor this adapter issues grants or signs evidence.
    """

    def __init__(self, *, exchange, material, clock):
        if not isinstance(exchange, ApprovalExchange):
            raise TypeError("existing ApprovalExchange required")
        if not isinstance(exchange.store, PostgresReviewStore):
            raise TypeError("existing durable Postgres review store required")
        if any(not callable(getattr(material, name, None)) for name in ("read", "locked_on")):
            raise TypeError("complete host material authority required")
        if not callable(getattr(clock, "now_us", None)):
            raise TypeError("host clock required")
        self.exchange, self.material, self.clock = exchange, material, clock

    def _project(self, state, material, goal, request):
        if not isinstance(material, ReleaseMaterial) or not isinstance(material.contract, dict):
            raise ReleaseLinkRefused("host retained release material required")
        context = material.context
        if (not isinstance(context, EmissionContext)
                or (context.tenant, context.actor_id, context.vertical_name, context.project_id,
                    context.approval, context.release_target) !=
                (goal.tenant, goal.executor, request.vertical, request.project_id,
                 request.review_id, request.destination)
                or context.actor_roles or context.is_producer):
            raise ReleaseLinkRefused("host context differs from executor release")
        now = self.clock.now_us()
        if type(now) is not int or now <= 0:
            raise ReleaseLinkRefused("trusted review clock unavailable")
        context = replace(context, now_us=now)
        approval, envelope, original, _, certificate = self.exchange._validated(
            state, material.contract, context, request.review_id)
        if (certificate is None or original.actor_id != goal.executor
                or envelope.record.tenant_id != goal.tenant):
            raise ReleaseLinkRefused("executor's approved signed review required")
        inherited = material.contract.get("release_authority")
        if (not isinstance(inherited, dict)
                or set(inherited) != {"schema", "grant_digest", "chain_digest", "root_digest", "mission"}
                or inherited.get("schema") != "regulated/release-authority/v1"):
            raise ReleaseLinkRefused("current inherited release authority required")
        authority = ReleaseAuthorityBinding(**{k: v for k, v in inherited.items() if k != "schema"})
        # Match the original gate destination's exact contract hashing.
        contract_digest = hashlib.sha256(json.dumps(material.contract, sort_keys=True,
            separators=(",", ":"), default=str, allow_nan=False).encode()).hexdigest()
        return VerifiedReleaseBinding(
            goal.tenant, original.actor_id, request.vertical, request.project_id,
            goal.project_instance, request.review_id, request.destination,
            original.action_id, original.nonce, envelope.record_hash, contract_digest,
            approval.expires_at_us, authority)

    def verify(self, goal, request):
        material = self.material.read(goal, request)
        state = self.exchange.store.get(goal.tenant, request.review_id)
        return self._project(state, material, goal, request)

    def current_on(self, connection, goal, request, verified):
        # The store's read_locked_on checks active READ COMMITTED transaction,
        # tenant scope and holds the review's original shared lock to commit.
        # Acquire material authority locks first, following the host lock order.
        material = self.material.locked_on(connection, goal, request)
        connection.execute("SELECT set_config('app.tenant',%s,true)", (goal.tenant,))
        state = PostgresReviewStore.read_locked_on(connection, goal.tenant, request.review_id)
        current = self._project(state, material, goal, request)
        if current != verified:
            raise ReleaseLinkRefused("current signed review differs from verified preflight")
        return current
