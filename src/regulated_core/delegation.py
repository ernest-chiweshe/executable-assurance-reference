"""Delegated authority: a child acts only within its parent's authority, on the same mission budget.

Paper A section 4.2; the joint contract is docs/ARCHITECTURE-OF-RECORD/13-delegated-authority.md.

A `DelegationGrant` is a signed, immutable record. A ROOT grant is admitted only from an ordinary authorized
decision, whose record id and approval certificate digest it binds. A CHILD grant is issued by the subject of
its parent, and only if the parent is delegable, live and unrevoked. Every child is a narrowing of its parent:

* the same tenant and the same root mission, with the root's budget limit, so no child opens a fresh allowance;
* operations and targets that are subsets of the parent's, named exactly, never by pattern;
* every policy the parent names, and possibly restrictions of its own; the engine releases only when every
  named policy is one it evaluates, so an added restriction is never carried unchecked (review 3081);
* an expiry no later than the parent's.

`resolve` never trusts what issuance checked. It re-reads every stored grant from the leaf to the root, verifies
each signature against the trust directory under the authority's own key, and re-proves every narrowing rule,
so a record altered in storage, a missing link, a cycle or excess depth refuses. A revoked or expired ancestor
invalidates every descendant, and the target re-reads that status at its final check (see target.py).

The store is append-only: grants and revocations are added, never changed or removed. The in-memory store is
correct for one process and says so; hosts inject the durable Postgres store.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from .canonical import canonical_bytes
from .signing import Signature, Signer, TrustDirectory

GRANT_SCHEMA = "regulated/delegation-grant/v1"
RELEASE_AUTHORITY_SCHEMA = "regulated/release-authority/v1"
# The reserved contract and destination field (docs/ARCHITECTURE-OF-RECORD/13). The Project OS names the same key;
# it is spelled here too because governance imports the platform, never the reverse of that for new names.
RELEASE_AUTHORITY_FIELD = "release_authority"
MAX_DEPTH = 8                          # a root and at most seven generations of delegation beneath it
# Delegated subjects are composition-owned executor principals, never human accounts (review 3077, 3080). The host
# derives them from tenant, goal and immutable instance; the prefix is a classification, not an authentication.
EXECUTOR_PREFIX = "executor:"


class DelegationError(Exception):
    """A grant could not be admitted, issued, revoked or resolved; the reason says which rule refused it."""


@dataclass(frozen=True, slots=True)
class DelegationGrant:
    tenant_id: str
    parent_digest: str                 # "" only for a root
    issuer_subject: str                # who granted it: the root's approving actor, or the parent's subject
    subject: str                       # who may act under it
    delegable: bool
    operations: tuple[str, ...]        # exact signed action ids
    targets: tuple[str, ...]           # exact TargetRef digests
    policy_refs: tuple[str, ...]       # "policy_ref@digest", every one of which binds any action under it
    root_mission: str
    budget_limit: int                  # the root's mission ceiling, fixed at admission from the signed policy
    expires_at_us: int
    decision_record_id: str            # root only: the ordinary authorized decision that admitted it
    approval_digest: str               # root only: the approval certificate over that decision
    issued_at_us: int

    def body(self) -> dict[str, Any]:
        return {"schema": GRANT_SCHEMA, "tenant_id": self.tenant_id, "parent_digest": self.parent_digest,
                "issuer_subject": self.issuer_subject, "subject": self.subject, "delegable": self.delegable,
                "operations": list(self.operations), "targets": list(self.targets),
                "policy_refs": list(self.policy_refs), "root_mission": self.root_mission,
                "budget_limit": self.budget_limit, "expires_at_us": self.expires_at_us,
                "decision_record_id": self.decision_record_id, "approval_digest": self.approval_digest,
                "issued_at_us": self.issued_at_us}

    def digest(self) -> str:
        return sha256(canonical_bytes(self.body())).hexdigest()

    @property
    def is_root(self) -> bool:
        return not self.parent_digest


@dataclass(frozen=True, slots=True)
class SignedGrant:
    grant: DelegationGrant
    signature: Signature

    @property
    def digest(self) -> str:
        return self.grant.digest()


@dataclass(frozen=True, slots=True)
class GrantRevocation:
    grant_digest: str
    actor: str
    reason: str
    at_us: int


@dataclass(frozen=True, slots=True)
class Chain:
    """A verified chain, root first. `digest` names the whole lineage; `leaf` is the grant being acted under."""

    grants: tuple[DelegationGrant, ...]

    @property
    def root(self) -> DelegationGrant:
        return self.grants[0]

    @property
    def leaf(self) -> DelegationGrant:
        return self.grants[-1]

    @property
    def digest(self) -> str:
        return sha256(canonical_bytes([g.digest() for g in self.grants])).hexdigest()

    @property
    def expires_at_us(self) -> int:
        return min(g.expires_at_us for g in self.grants)


@dataclass(frozen=True, slots=True)
class ReleaseAuthority:
    """The delegated binding a signed action names beside its effect. It is a claim to be verified: the core
    re-resolves the grant chain and requires these digests and this mission to match what it finds."""

    grant_digest: str
    chain_digest: str
    root_digest: str
    mission: str

    def as_fields(self) -> dict[str, str]:
        return {"schema": RELEASE_AUTHORITY_SCHEMA, "grant_digest": self.grant_digest,
                "chain_digest": self.chain_digest, "root_digest": self.root_digest, "mission": self.mission}


def release_authority_of(named: object) -> ReleaseAuthority | None:
    """Parse a release-authority object from a contract or a destination. None when absent; `DelegationError`
    when present but malformed, or when it carries a host refusal (the reason is in the message)."""
    if named is None:
        return None
    if not isinstance(named, dict) or named.get("schema") != RELEASE_AUTHORITY_SCHEMA:
        raise DelegationError("release authority is malformed")
    if set(named) == {"schema", "refused"}:
        raise DelegationError(f"release authority unresolved: {named['refused']}")
    keys = {"schema", "grant_digest", "chain_digest", "root_digest", "mission"}
    if set(named) != keys or not all(isinstance(named[k], str) and named[k] for k in keys):
        raise DelegationError("release authority is malformed")
    return ReleaseAuthority(named["grant_digest"], named["chain_digest"], named["root_digest"], named["mission"])


PROPOSAL_FIELD = "delegation_admission"
PROPOSAL_SCHEMA = "regulated/delegation-admission/v1"


@dataclass(frozen=True, slots=True)
class DelegationProposal:
    """What a human approves when they approve delegating a mission (review 3084).

    It travels inside the signed action of the admitting decision, so the approval certificate over that decision
    covers every field: who is the accountable root subject, exactly which targets and operations, the mission, whether
    it may be delegated further, how long it lives, the deadline to admit it, and the tenant's revocation epoch when it
    was proposed. An ordinary effect approval carries no proposal and so never grants delegation."""

    subject: str
    operations: tuple[str, ...]
    targets: tuple[str, ...]
    root_mission: str
    delegable: bool
    expires_at_us: int
    admit_by_us: int
    revocation_epoch: int

    def as_fields(self) -> dict[str, Any]:
        return {"schema": PROPOSAL_SCHEMA, "subject": self.subject, "operations": sorted(self.operations),
                "targets": sorted(self.targets), "root_mission": self.root_mission, "delegable": self.delegable,
                "expires_at_us": self.expires_at_us, "admit_by_us": self.admit_by_us,
                "revocation_epoch": self.revocation_epoch}


def delegation_proposal_of(named: object) -> DelegationProposal | None:
    """Parse a delegation proposal; None when absent, `DelegationError` when present but malformed."""
    if named is None:
        return None
    keys = {"schema", "subject", "operations", "targets", "root_mission", "delegable", "expires_at_us",
            "admit_by_us", "revocation_epoch"}
    if not isinstance(named, dict) or set(named) != keys or named["schema"] != PROPOSAL_SCHEMA:
        raise DelegationError("delegation proposal is malformed")
    lists = (named["operations"], named["targets"])
    if (not isinstance(named["subject"], str) or not isinstance(named["root_mission"], str)
            or not all(isinstance(v, list) and v and all(isinstance(x, str) and x for x in v) for v in lists)
            or type(named["delegable"]) is not bool
            or not all(type(named[k]) is int for k in ("expires_at_us", "admit_by_us", "revocation_epoch"))):
        raise DelegationError("delegation proposal is malformed")
    return DelegationProposal(named["subject"], tuple(sorted(named["operations"])), tuple(sorted(named["targets"])),
                              named["root_mission"], named["delegable"], named["expires_at_us"],
                              named["admit_by_us"], named["revocation_epoch"])


class GrantStore(Protocol):
    """Append-only storage of signed grants and their revocations, partitioned by tenant: no lookup crosses one."""

    def put(self, signed: SignedGrant) -> None:
        """Add a grant under its own tenant. Adding the same digest again is a no-op; nothing is replaced."""
        ...

    def get(self, tenant_id: str, digest: str) -> SignedGrant | None: ...

    def revoke(self, tenant_id: str, revocation: GrantRevocation) -> None: ...

    def revoked(self, tenant_id: str, digests: Iterable[str]) -> frozenset[str]:
        """Which of these grant digests have been revoked in this tenant."""
        ...

    def delegated_to(self, tenant_id: str, subject: str) -> tuple[SignedGrant, ...]:
        """Every non-root grant naming this subject in this tenant, live or not; the caller verifies them."""
        ...

    def ensure_child(self, tenant_id: str, parent_digest: str, subject: str, candidate: SignedGrant) -> SignedGrant:
        """The one stored child of `parent_digest` for `subject`: the stored one if any, else `candidate`, stored.

        Under one lock of (tenant, parent, subject), shared by every process, the store returns an existing child or
        stores the candidate in the same transaction, so a concurrent or restarted call can never store a second
        child and a failure before the commit stores nothing. The candidate is verified and signed BEFORE the lock, so
        the store never reads authority while it holds a connection. A signed candidate that is not stored grants
        nothing: authority is only what resolves from the store. More than one stored child for the key is an
        integrity failure, never a choice."""
        ...


class InMemoryGrantStore:
    """One process's grant store. Correct only while a single process issues, resolves and commits."""

    durable = False

    def __init__(self) -> None:
        self._grants: dict[tuple[str, str], SignedGrant] = {}
        self._revocations: dict[tuple[str, str], GrantRevocation] = {}
        self._lock = threading.Lock()

    def put(self, signed: SignedGrant) -> None:
        with self._lock:
            self._grants.setdefault((signed.grant.tenant_id, signed.digest), signed)

    def get(self, tenant_id: str, digest: str) -> SignedGrant | None:
        with self._lock:
            return self._grants.get((tenant_id, digest))

    def revoke(self, tenant_id: str, revocation: GrantRevocation) -> None:
        with self._lock:
            self._revocations.setdefault((tenant_id, revocation.grant_digest), revocation)

    def revoked(self, tenant_id: str, digests: Iterable[str]) -> frozenset[str]:
        with self._lock:
            return frozenset(d for d in digests if (tenant_id, d) in self._revocations)

    def delegated_to(self, tenant_id: str, subject: str) -> tuple[SignedGrant, ...]:
        with self._lock:
            return tuple(g for (t, _), g in self._grants.items()
                         if t == tenant_id and g.grant.subject == subject and not g.grant.is_root)

    def ensure_child(self, tenant_id: str, parent_digest: str, subject: str, candidate: SignedGrant) -> SignedGrant:
        with self._lock:
            found = self._children(tenant_id, parent_digest, subject)
            if len(found) > 1:
                raise DelegationError("more than one child is stored for this parent and executor")
            if found:
                return found[0]
            self._grants[(tenant_id, candidate.digest)] = candidate
            return candidate

    def stored_child(self, tenant_id: str, parent_digest: str, subject: str) -> SignedGrant | None:
        with self._lock:
            found = self._children(tenant_id, parent_digest, subject)
        if len(found) > 1:
            raise DelegationError("more than one child is stored for this parent and executor")
        return found[0] if found else None

    def _children(self, tenant_id: str, parent_digest: str, subject: str) -> list[SignedGrant]:
        return [g for (t, _), g in self._grants.items()
                if t == tenant_id and g.grant.parent_digest == parent_digest and g.grant.subject == subject]


def _fixed(now_us: int | None) -> Callable[[], int]:
    """A clock that answers the instant a trusted caller already holds."""
    assert now_us is not None
    instant = now_us
    return lambda: instant


def _names(values: Iterable[str], what: str) -> tuple[str, ...]:
    names = tuple(sorted(set(values)))
    if not names or any(not isinstance(v, str) or not v.strip() for v in names):
        raise DelegationError(f"a grant names at least one {what}, each explicitly")
    return names


def _narrows(child: DelegationGrant, parent: DelegationGrant) -> str | None:
    """None if `child` is a valid narrowing of `parent`; otherwise the rule it breaks."""
    if child.parent_digest != parent.digest():
        return "the child does not name this parent"
    if child.tenant_id != parent.tenant_id:
        return "a child stays in its parent's tenant"
    if child.root_mission != parent.root_mission or child.budget_limit != parent.budget_limit:
        return "a child inherits its root mission and budget; it cannot open a fresh allowance"
    if child.issuer_subject != parent.subject:
        return "only the parent's subject may delegate it"
    if not parent.delegable:
        return "the parent is not delegable"
    if not set(child.operations) <= set(parent.operations):
        return "a child cannot reach operations its parent cannot"
    if not set(child.targets) <= set(parent.targets):
        return "a child cannot reach targets its parent cannot"
    if not set(parent.policy_refs) <= set(child.policy_refs):
        return "a child keeps every policy its parent is bound by"
    if child.expires_at_us > parent.expires_at_us:
        return "a child cannot outlive its parent"
    if child.decision_record_id or child.approval_digest:
        return "only a root carries the admitting decision"
    return None


class DelegationAuthority:
    """Admits roots, issues children, revokes, and resolves verified chains, under one registered key."""

    def __init__(self, signer: Signer, trust: TrustDirectory, store: GrantStore) -> None:
        if not trust.is_known(signer.key_id):
            raise DelegationError("the delegation authority's key must be a registered trust anchor")
        self._signer, self._trust, self._store = signer, trust, store

    @property
    def store(self) -> GrantStore:
        return self._store

    def _sign(self, grant: DelegationGrant) -> SignedGrant:
        signed = SignedGrant(grant, self._signer.sign(grant.body()))
        self._store.put(signed)
        return signed

    def admit_root(self, *, tenant_id: str, approver: str, subject: str, operations: Sequence[str],
                   targets: Sequence[str], policy_refs: Sequence[str], root_mission: str, budget_limit: int,
                   expires_at_us: int, decision_record_id: str, approval_digest: str, delegable: bool,
                   now_us: int, issued_at_us: int | None = None) -> SignedGrant:
        """Admit a root from an ordinary authorized decision. The caller (the engine) has verified that decision
        and its approval; this record binds both, so the root can never be separated from what authorized it."""
        if not all(v.strip() for v in (tenant_id, approver, subject, root_mission, decision_record_id,
                                        approval_digest)):
            raise DelegationError("a root names its tenant, approver, subject, mission, decision and approval")
        if subject.startswith(EXECUTOR_PREFIX):
            raise DelegationError("a root's subject is the accountable principal, never an executor")
        if type(budget_limit) is not int or budget_limit < 1:
            raise DelegationError("a delegable mission must carry a budget: an unbudgeted policy cannot delegate")
        if expires_at_us <= now_us:
            raise DelegationError("a root must expire in the future")
        return self._sign(DelegationGrant(
            tenant_id, "", approver, subject, delegable, _names(operations, "operation"),
            _names(targets, "target"), _names(policy_refs, "policy"), root_mission, budget_limit,
            expires_at_us, decision_record_id, approval_digest, now_us if issued_at_us is None else issued_at_us))

    def issue_child(self, tenant_id: str, parent_digest: str, *, actor: str, subject: str, operations: Sequence[str],
                    targets: Sequence[str], policy_refs: Sequence[str] | None = None, expires_at_us: int,
                    delegable: bool, now_us: int | None = None,
                    clock: Callable[[], int] | None = None) -> SignedGrant:
        """Issue a narrowing of a live parent, by that parent's subject. Omitting `policy_refs` keeps the
        parent's; naming them may only add.

        Give exactly one of `now_us` (an instant the caller already holds) or `clock` (a trusted clock). With a
        clock, time is read AFTER every blocking read of the parent's ancestry and revocation status and before
        anything is signed or stored, so a slow read can never let a child be issued under a parent that expired
        meanwhile (review 3234). A host should always pass its trusted clock."""
        if (now_us is None) == (clock is None):
            raise DelegationError("give exactly one of now_us or clock")
        signed = self._signed_child(tenant_id, parent_digest, actor=actor, subject=subject, operations=operations,
                                    targets=targets, policy_refs=policy_refs, expires_at_us=expires_at_us,
                                    delegable=delegable, clock=clock if clock is not None else _fixed(now_us))
        self._store.put(signed)
        return signed

    def _signed_child(self, tenant_id: str, parent_digest: str, *, actor: str, subject: str,
                      operations: Sequence[str], targets: Sequence[str], policy_refs: Sequence[str] | None,
                      expires_at_us: int, delegable: bool, clock: Callable[[], int]) -> SignedGrant:
        """A signed narrowing of a live parent, NOT stored: time is read after the parent's ancestry and revocation
        reads, and every issuance rule is checked before signing (review 3234)."""
        chain = self._verified_chain(tenant_id, parent_digest)
        self.check_live(chain, now_us=None)                     # the blocking revocation read, before the clock
        now_us = clock()
        self.check_live_at(chain, now_us)
        if expires_at_us <= now_us:
            raise DelegationError("a child must expire after it is issued")
        parent = chain.leaf
        if len(chain.grants) >= MAX_DEPTH:
            raise DelegationError(f"delegation is limited to {MAX_DEPTH} generations")
        if actor != parent.subject:
            raise DelegationError("only the parent's subject may delegate it")
        if not subject.startswith(EXECUTOR_PREFIX) or not subject[len(EXECUTOR_PREFIX):].strip():
            raise DelegationError(f"a child's subject is a composition-owned executor ({EXECUTOR_PREFIX}...)")
        child = DelegationGrant(
            parent.tenant_id, parent_digest, actor, subject, delegable, _names(operations, "operation"),
            _names(targets, "target"), _names(policy_refs if policy_refs is not None else parent.policy_refs,
                                              "policy"),
            parent.root_mission, parent.budget_limit, expires_at_us, "", "", now_us)
        broken = _narrows(child, parent)
        if broken is not None:
            raise DelegationError(broken)
        return SignedGrant(child, self._signer.sign(child.body()))

    def ensure_child(self, tenant_id: str, parent_digest: str, *, actor: str, subject: str,
                     operations: Sequence[str], targets: Sequence[str], expires_at_us: int, delegable: bool,
                     creation_id: str, clock: Callable[[], int],
                     policy_refs: Sequence[str] | None = None) -> SignedGrant:
        """Issue the child of a creation exactly once, however often, concurrently or after a restart, it is asked.

        The identity of the creation is (tenant, parent, executor subject): a host derives the executor from the
        instance it claimed for this creation, so the subject is unique to it, and `creation_id` names the host's
        durable claim (it must be given; the host binds it to that subject). A stored child for the key is returned
        only if it asks for exactly the same authority (operations, targets, policy references, expiry, delegability
        and issuing actor) and still verifies and is live NOW, on the trusted clock read after its reads; any
        difference refuses, and nothing is re-issued. Only when no child is stored is one issued, under the same
        rules as `issue_child`, and stored in the store's own transaction (review 3272)."""
        if not creation_id.strip():
            raise DelegationError("an idempotent child issuance names the host's creation claim")
        want_ops, want_targets = _names(operations, "operation"), _names(targets, "target")
        # A retry answers from storage without signing again; only a first call verifies and signs a candidate,
        # before the store's lock, which the store then keeps or discards in favour of a child stored meanwhile.
        stored = self._stored_child(tenant_id, parent_digest, subject)
        if stored is None:
            candidate = self._signed_child(tenant_id, parent_digest, actor=actor, subject=subject,
                                           operations=operations, targets=targets, policy_refs=policy_refs,
                                           expires_at_us=expires_at_us, delegable=delegable, clock=clock)
            stored = self._store.ensure_child(tenant_id, parent_digest, subject, candidate)
        grant = stored.grant
        chain = self._verified_chain(tenant_id, stored.digest)             # the stored record verifies, from storage
        self.check_live(chain, now_us=None)
        self.check_live_at(chain, clock())
        want_policy = (_names(policy_refs, "policy") if policy_refs is not None
                       else chain.grants[-2].policy_refs if len(chain.grants) > 1 else grant.policy_refs)
        if (grant.tenant_id != tenant_id or grant.parent_digest != parent_digest or grant.subject != subject
                or grant.issuer_subject != actor or grant.operations != want_ops or grant.targets != want_targets
                or grant.policy_refs != want_policy or grant.expires_at_us != expires_at_us
                or grant.delegable != delegable):
            raise DelegationError("this creation already issued a child with different authority; nothing re-issued")
        return stored

    def _stored_child(self, tenant_id: str, parent_digest: str, subject: str) -> SignedGrant | None:
        lookup = getattr(self._store, "stored_child", None)
        if callable(lookup):
            found: SignedGrant | None = lookup(tenant_id, parent_digest, subject)
            return found
        return None

    def may_withdraw(self, tenant_id: str, grant_digest: str, actor: str) -> bool:
        """Whether `actor` holds authority over this grant: its holder (relinquishing it), or the issuer of it or of
        any ancestor, up to the human who approved the root. Derived ONLY from a verified lineage (every record's
        digest and delegation-authority signature, acyclic, bounded, admitted root, narrowing): an unverifiable,
        altered or cyclic record grants nothing (review 3219). Liveness is deliberately not required, so an expired
        or already revoked grant can still be withdrawn (idempotent) by those who held authority over it."""
        if not actor.strip():
            return False
        try:
            chain = self._verified_chain(tenant_id, grant_digest)
        except DelegationError:
            return False
        holders = {chain.leaf.subject, *(grant.issuer_subject for grant in chain.grants)}
        return actor in holders

    def revoke_authorized(self, tenant_id: str, grant_digest: str, *, actor: str, reason: str, now_us: int,
                          supervisor: Callable[[str, str], bool] | None = None) -> GrantRevocation:
        """Withdraw a grant only for an actor with authority over it (may_withdraw), or one the host's supervisor
        policy authorizes for this tenant (review 3214). Authentication alone is never enough."""
        if not self.may_withdraw(tenant_id, grant_digest, actor) and not (
                supervisor is not None and supervisor(tenant_id, actor)):
            raise DelegationError("this actor holds no authority to withdraw this grant")
        return self.revoke(tenant_id, grant_digest, actor=actor, reason=reason, now_us=now_us)

    def revoke(self, tenant_id: str, grant_digest: str, *, actor: str, reason: str,
               now_us: int) -> GrantRevocation:
        """Withdraw a grant and, with it, every descendant. Recorded with who and why; never undone."""
        if self._store.get(tenant_id, grant_digest) is None:
            raise DelegationError("no such grant")
        if not actor.strip() or not reason.strip():
            raise DelegationError("a revocation names the revoking actor and the reason")
        revocation = GrantRevocation(grant_digest, actor, reason, now_us)
        self._store.revoke(tenant_id, revocation)
        return revocation

    def is_delegate(self, tenant_id: str, subject: str) -> bool:
        """True for any executor principal, and for any subject a grant has ever delegated to, live or not.

        The classification never lapses: an executor whose grants expired or were revoked is still an executor, so
        dropping its chain can never turn it into a root principal on a fresh mission (review 3080)."""
        return subject.startswith(EXECUTOR_PREFIX) or bool(self._store.delegated_to(tenant_id, subject))

    def resolve(self, tenant_id: str, leaf_digest: str, *, now_us: int | None) -> Chain:
        """The verified, live chain from the root to this grant, or `DelegationError` naming what refused.

        `now_us=None` checks everything except expiry. The target uses it at its final check, where the permit's
        own expiry, capped at issuance by the chain's, is judged on the target authority's clock."""
        chain = self._verified_chain(tenant_id, leaf_digest)
        self.check_live(chain, now_us=now_us)
        return chain

    def _verified_chain(self, tenant_id: str, leaf_digest: str) -> Chain:
        """The chain from the root to this grant, every record verified: each stored grant matches its digest and is
        signed by the delegation authority, the lineage is acyclic, bounded and ends at an admitted, budgeted root,
        and every child narrows its parent. Liveness (revocation, expiry) is NOT judged here."""
        lineage: list[DelegationGrant] = []
        seen: set[str] = set()
        digest = leaf_digest
        while True:
            if digest in seen:
                raise DelegationError("delegation cycle")
            if len(lineage) >= MAX_DEPTH:
                raise DelegationError(f"delegation is limited to {MAX_DEPTH} generations")
            seen.add(digest)
            signed = self._store.get(tenant_id, digest)
            if signed is None:
                raise DelegationError("missing grant in the chain")
            if signed.grant.tenant_id != tenant_id:
                raise DelegationError("a grant from another tenant")
            if signed.grant.digest() != digest:
                raise DelegationError("a stored grant does not match its digest")
            if (signed.signature.key_id != self._signer.key_id
                    or not self._trust.verify(signed.grant.body(), signed.signature)):
                raise DelegationError("grant signature invalid or not the delegation authority's")
            lineage.append(signed.grant)
            if signed.grant.is_root:
                break
            digest = signed.grant.parent_digest
        grants = tuple(reversed(lineage))
        root = grants[0]
        if not (root.decision_record_id and root.approval_digest) or root.budget_limit < 1:
            raise DelegationError("the root was not admitted from an authorized, budgeted decision")
        for parent, child in zip(grants, grants[1:]):
            broken = _narrows(child, parent)
            if broken is not None:
                raise DelegationError(broken)
        return Chain(grants)

    @staticmethod
    def check_live_at(chain: Chain, now_us: int) -> None:
        """Raise if the chain has expired at `now_us`: the expiry half of `check_live`, with no storage read, for a
        caller that has already read revocation status and then took the time."""
        if now_us >= chain.expires_at_us:
            raise DelegationError("the delegated authority has expired")

    def check_live(self, chain: Chain, *, now_us: int | None) -> None:
        """Raise unless no grant in the chain is revoked or expired, read now. Revocation status is read first,
        and `now_us` should be taken after it, so a slow status read cannot make an expired chain pass."""
        revoked = self._store.revoked(chain.root.tenant_id, (g.digest() for g in chain.grants))
        if revoked:
            raise DelegationError("an ancestor grant has been revoked")
        if now_us is not None and now_us >= chain.expires_at_us:
            raise DelegationError("the delegated authority has expired")


__all__ = ["Chain", "DelegationAuthority", "DelegationError", "DelegationGrant", "EXECUTOR_PREFIX", "GRANT_SCHEMA",
           "GrantRevocation", "GrantStore", "InMemoryGrantStore", "MAX_DEPTH", "PROPOSAL_FIELD", "PROPOSAL_SCHEMA", "DelegationProposal", "RELEASE_AUTHORITY_FIELD",
           "RELEASE_AUTHORITY_SCHEMA", "ReleaseAuthority", "SignedGrant", "delegation_proposal_of", "release_authority_of"]
