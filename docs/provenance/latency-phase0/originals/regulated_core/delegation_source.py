"""The core half of the delegated-project source: turn a durable host binding into a verified release binding.

docs/ARCHITECTURE-OF-RECORD/13 and ledger 3090. The Project OS host (`factory/delegation/release_authority.py`, source review)
owns durable project admission and derives the executor identity; it never verifies a chain itself and never imports
this package. It calls a verification port with the references it holds, and this adapter answers only after the
core has re-resolved the signed chain on the engine's trusted clock and matched every expectation:

* the chain resolves, every signature is the delegation authority's, and no grant is revoked or expired now;
* the root is the one the host admitted (`root_digest`) and its subject is the goal's accountable principal;
* the leaf is the grant the host holds and its subject is the host-derived executor.

Only then does it return the platform's `ReleaseAuthorityBinding`, which the engine re-verifies once more at release.
Any mismatch or failure raises `DelegationError`; the host turns that into a recorded refusal, never an ordinary path.
"""
from __future__ import annotations

from collections.abc import Callable

from factory.projectos.regulated import ReleaseAuthorityBinding

from .delegation import DelegationAuthority, DelegationError
from .engine import RegulatedEngine


class VerifiedReleaseAuthority:
    """Verification port for the host's delegated-project source. Composition-owned; holds no credential."""

    def __init__(self, engine: RegulatedEngine) -> None:
        if engine.delegation is None:
            raise DelegationError("a delegated-project source needs an engine with a delegation authority")
        self._delegation: DelegationAuthority = engine.delegation
        self._clock: Callable[[], int] = engine.targets.now_us

    @classmethod
    def over(cls, delegation: DelegationAuthority, clock_us: Callable[[], int]) -> VerifiedReleaseAuthority:
        """The same port over a delegation authority and the trusted clock every engine of the host shares, for a
        host that composes its engines per pack (source review 3189): same signer, trust and durable grant store."""
        port = cls.__new__(cls)
        port._delegation, port._clock = delegation, clock_us
        return port

    def resolve(self, *, tenant_id: str, grant_digest: str, root_digest: str, subject: str,
                root_subject: str) -> ReleaseAuthorityBinding:
        delegation = self._delegation
        # Every blocking read first (grants, signatures, revocations), then the trusted clock, then expiry, the same
        # order as the target's final check (source review 3096).
        chain = delegation.resolve(tenant_id, grant_digest, now_us=None)
        if self._clock() >= chain.expires_at_us:
            raise DelegationError("the delegated authority has expired")
        if chain.root.digest() != root_digest:
            raise DelegationError("the chain does not descend from the root the host admitted")
        if chain.root.subject != root_subject:
            raise DelegationError("the root's subject is not the goal's accountable principal")
        if chain.leaf.subject != subject:
            raise DelegationError("the grant's subject is not the executor the host derived")
        return ReleaseAuthorityBinding(grant_digest=chain.leaf.digest(), chain_digest=chain.digest,
                                       root_digest=chain.root.digest(), mission=chain.root.root_mission)


__all__ = ["VerifiedReleaseAuthority"]
