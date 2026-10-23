"""Read-only arming of a recovery-capable clock against the witnesses (R-2b).

Before a process may act, it learns an external lower bound for the durable clock floor: every head a witness
quorum acknowledged was signed with a reading from the same floor-protected clock, so the stored floor can never
legitimately be below the latest witnessed ``issued_at_us``. A floor below it means the database was restored to
before that head. Arming needs no signing key, journal or pin; a stale witness can only weaken the bound. Without
a verified quorum for every configured scope the process stays unarmed and refuses (fail closed); the cluster is
not held for a witness outage.

The resumption ceremony uses the same verified replies to require that the local log holds exactly every
witnessed head: a lost or forked tail stays on hold.
"""
from __future__ import annotations

import secrets
from typing import Any, Iterator, Mapping

from .clock import ClockError
from .evidence_witness import Checkpoint, HeadPolicy, WitnessSet, _ack_valid, _signed
from .evidence_witness_store import decode_ack, decode_head
from .signing import Signature, TrustDirectory


class WitnessArming:
    def __init__(self, *, members: WitnessSet, witness_trust: TrustDirectory, endpoints: Mapping[str, Any],
                 policies: tuple[HeadPolicy, ...]) -> None:
        members.validate(witness_trust)
        if set(endpoints) != {identity for identity, _ in members.members}:
            raise ValueError("arming needs exactly one endpoint per witness")
        if not policies or any(type(policy) is not HeadPolicy for policy in policies):
            raise ValueError("arming needs the head policy of every scope on the cluster")
        self._members, self._trust, self._endpoints, self._policies = members, witness_trust, dict(endpoints), policies

    def _verified(self, policy: HeadPolicy) -> Iterator[tuple[Any, Checkpoint] | None]:
        """Each witness's verified latest head and checkpoint, or None for a verified empty history.

        An unreachable, malformed or unverifiable witness yields nothing and so does not count.
        """
        for identity, key in self._members.members:
            nonce = secrets.token_hex(16)
            try:
                reply = self._endpoints[identity].latest(policy.scope, nonce)
                body, signature = reply["body"], reply["signature"]
                if type(signature) is dict:
                    signature = Signature(**signature)
                if (not _signed(body, signature, key, self._trust)
                        or body.get("schema") != "regulated/witness-latest/v1"
                        or body.get("witness_id") != identity or body.get("nonce") != nonce
                        or any(body.get(k) != v for k, v in policy.scope.fields().items())):
                    continue
                if body["head"] is None:
                    if body["ack"] is None:
                        yield None
                    continue
                head, ack = decode_head(body["head"]), decode_ack(body["ack"])
                point = Checkpoint.from_head(head, policy)
                if not _ack_valid(ack, identity, key, policy.scope, point, self._trust):
                    continue
            except Exception:
                continue
            yield head, point

    def _require_domain(self, domain: str) -> None:
        if any(policy.clock_domain != domain for policy in self._policies):
            raise ClockError("witnessed heads are not signed with this clock's domain")

    def lower_bound(self, domain: str) -> int:
        """The largest head time a verified quorum reports, across every configured scope."""
        self._require_domain(domain)
        bound = 0
        for policy in self._policies:
            verified = 0
            for result in self._verified(policy):
                if result is not None:
                    bound = max(bound, result[0].issued_at_us)
                verified += 1
            if verified < self._members.quorum:
                raise ClockError("unarmed: no verified witness quorum for " + policy.scope.scope_id)
        return bound

    def require_local_matches(self, domain: str, head_at: Any) -> list[tuple[str, int, str]]:
        """For every scope, the local head at each verified witness checkpoint must be exactly that head.

        ``head_at(scope_id, size)`` returns the locally stored head of that size, or None. Returns the matched
        (scope, size, head digest) checkpoints; raises when a quorum is unavailable or any witnessed head is
        missing or different locally (a lost or forked tail stays on hold).
        """
        self._require_domain(domain)
        matched = []
        for policy in self._policies:
            verified = 0
            for result in self._verified(policy):
                if result is not None:
                    _, point = result
                    local = head_at(policy.scope.scope_id, point.size)
                    if local is None or local.digest() != point.head_digest:
                        raise ClockError("witnessed evidence is missing or different locally: "
                                         + policy.scope.scope_id)
                    matched.append((policy.scope.scope_id, point.size, point.head_digest))
                verified += 1
            if verified < self._members.quorum:
                raise ClockError("no verified witness quorum for " + policy.scope.scope_id)
        return matched


def evidence_head_at(providers: Mapping[str, Any]):
    """``head_at`` for arming and the resumption ceremony, read from the durable evidence store.

    ``providers`` maps each witnessed scope id to its store reader (a PostgresEvidenceProvider: ``head_at(size)``
    returns the signed head of that size, verified, or raises when it is missing). A scope with no reader, or a
    head the store does not hold, is None, so a lost or forked tail stays on hold. Any other failure propagates.
    """
    from .evidence_service import EvidenceError

    def head_at(scope_id: str, size: int):
        provider = providers.get(scope_id)
        if provider is None:
            return None
        try:
            return provider.head_at(size)
        except EvidenceError as missing:
            if str(missing) != "requested signed head is missing":
                raise
            return None
    return head_at
