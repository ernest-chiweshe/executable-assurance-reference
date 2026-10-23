"""The routing policy as signed, versioned data (deliberation A8, resolved): what care requires of a
policy document and how it reads one, without knowing how the document is signed.

Care declares a narrow ``VerifiedDocumentLoader`` protocol; the composition root adapts the
platform's signing envelope to it (``factory/care_composition.py``), so this package never imports
the regulated core. A loaded policy carries its provenance (signed document or declared default,
version, issuing identity, document digest, content digest) and the staff roster: which operator
handles hold which capabilities. The roster is part of the signed content, so who may act on a case
is the owner's signed word, not a console setting.

Refuses (each a test): a content schema other than ``care/routing-policy/v1``; a policy that does
not validate (every problem named, not the first); a capability that is not in the closed set; a
queue owner who is not on the roster; a last-resort owner without ``care.queue_manage``; a document
for another vertical or policy id; a document not yet effective; a document whose version differs
from the policy's; production without a signed document.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from factory.care.contracts import CareContractError, CareRefused, IssueClass, RoutingPolicy

ROUTING_SCHEMA = "care/routing-policy/v1"
ROUTING_VERTICAL = "care"
ROUTING_POLICY_ID = "routing"

_OPERATOR_HANDLE = re.compile(r"^operator:[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$")


class RoutingPolicyError(CareContractError):
    """The routing document is absent, untrusted, invalid or not in force; the message says which."""


class Capability(str, Enum):
    """What an operator handle may do to a case (02 section 10: least privilege, separated write
    types). Regulated classes need the domain specialist to resolve authoritatively (decision 7)."""

    ASSIGN = "care.assign"                    # take or hand a case within its queue
    RESPOND = "care.respond"                  # public replies, triage, waiting on a third party
    NOTE = "care.note"                        # internal notes (a different write type)
    PROPOSE_REMEDY = "care.propose_remedy"    # link a governed operation's resource as the remedy
    RESOLVE = "care.resolve"                  # resolve with a verified receipt or a stated class; close
    QUEUE_MANAGE = "care.queue_manage"        # reassign any case, reopen, override separation of duties
    SPECIALIST_EDUCATION = "care.specialist.education"
    SPECIALIST_HEALTH = "care.specialist.health"


ALL_CAPABILITIES: frozenset[Capability] = frozenset(Capability)
SPECIALIST_FOR: Mapping[IssueClass, Capability] = {
    IssueClass.EDUCATION: Capability.SPECIALIST_EDUCATION,
    IssueClass.HEALTH: Capability.SPECIALIST_HEALTH,
}
Staff = Mapping[str, frozenset[Capability]]


@dataclass(frozen=True, slots=True)
class VerifiedDocument:
    """What a loader hands care: a trusted, in-force document and its identity. The loader has
    already verified the signature against its trust root; care never sees a key."""

    vertical: str
    policy_id: str
    version: str
    content: Mapping[str, Any]
    digest: str                 # the signed envelope's digest (covers the signature)
    issued_by: str              # the signing identity's key id; never a person's name
    effective_from: datetime
    supersedes: str = ""


@runtime_checkable
class VerifiedDocumentLoader(Protocol):
    def load(self, *, vertical: str, policy_id: str, at: datetime) -> VerifiedDocument:
        """The trusted document in force at ``at``, or raise RoutingPolicyError."""
        ...


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
    source: str                 # "signed-document" | "declared-default"
    version: str
    issued_by: str
    document_digest: str        # "" for the declared default
    content_digest: str         # RoutingPolicy.digest, pinned on every case

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "version": self.version, "issued_by": self.issued_by,
                "document_digest": self.document_digest, "content_digest": self.content_digest}


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    policy: RoutingPolicy
    staff: Staff
    provenance: PolicyProvenance


def policy_content(policy: RoutingPolicy, staff: Staff) -> dict[str, Any]:
    """The document content a signer signs: the schema tag, the policy and the roster."""
    return {"schema": ROUTING_SCHEMA, "policy": policy.to_dict(),
            "staff": {handle: sorted(c.value for c in caps) for handle, caps in sorted(staff.items())}}


def default_staff(policy: RoutingPolicy) -> Staff:
    """The S1 posture: every queue owner holds every capability (one designated care partner)."""
    return {queue.owner: ALL_CAPABILITIES for queue in policy.queues.values()}


def parse_policy_content(content: Mapping[str, Any]) -> tuple[RoutingPolicy, Staff]:
    """Validate everything and report every problem, or return the policy and the roster."""
    problems: list[str] = []
    if not isinstance(content, Mapping):
        raise RoutingPolicyError("routing document content must be a mapping")
    if content.get("schema") != ROUTING_SCHEMA:
        problems.append(f"content schema must be {ROUTING_SCHEMA!r}")
    policy: RoutingPolicy | None = None
    try:
        policy = RoutingPolicy.from_dict(dict(content["policy"]))
    except (KeyError, ValueError, TypeError, CareContractError) as exc:
        problems.append(f"policy does not validate: {exc}")
    staff: dict[str, frozenset[Capability]] = {}
    raw_staff = content.get("staff", {})
    if not isinstance(raw_staff, Mapping):
        problems.append("staff must be a mapping of operator handle to capabilities")
    else:
        for handle, names in raw_staff.items():
            if not isinstance(handle, str) or not _OPERATOR_HANDLE.fullmatch(handle):
                problems.append(f"staff handle {handle!r} must be operator:<handle>")
                continue
            if not isinstance(names, (list, tuple)):
                problems.append(f"staff {handle}: capabilities must be a list")
                continue
            caps: set[Capability] = set()
            for name in names:
                try:
                    caps.add(Capability(str(name)))
                except ValueError:
                    problems.append(f"staff {handle}: unknown capability {name!r}")
            staff[handle] = frozenset(caps)
    if policy is not None:
        for queue in policy.queues.values():
            held = staff.get(queue.owner)
            if held is None:
                problems.append(f"queue {queue.queue_id} owner {queue.owner} is not on the staff roster")
                continue
            if Capability.ASSIGN not in held or Capability.RESPOND not in held:
                problems.append(f"queue {queue.queue_id} owner {queue.owner} needs {Capability.ASSIGN.value} and {Capability.RESPOND.value}")
            if queue.last_resort and Capability.QUEUE_MANAGE not in held:
                problems.append(f"last-resort owner {queue.owner} needs {Capability.QUEUE_MANAGE.value}")
    if problems or policy is None:
        raise RoutingPolicyError("routing policy content refused: " + "; ".join(problems))
    return policy, staff


def load_routing_policy(loader: VerifiedDocumentLoader | None, *, at: datetime, default: RoutingPolicy | None,
                        production: bool) -> LoadedPolicy:
    """The policy in force: the signed document through the loader, or (outside production only) the
    declared default with its provenance saying so. Production without a loader refuses (A8)."""
    if loader is None:
        if production:
            raise RoutingPolicyError("production requires a signed routing document: set FACTORY_CARE_ROUTING_DOCUMENT "
                                     "and FACTORY_CARE_TRUST_KEYS (docs/customer-care/04, A8)")
        if default is None:
            raise RoutingPolicyError("no routing document and no declared default")
        return LoadedPolicy(default, default_staff(default),
                            PolicyProvenance("declared-default", default.version, "", "", default.digest))
    document = loader.load(vertical=ROUTING_VERTICAL, policy_id=ROUTING_POLICY_ID, at=at)
    if document.vertical != ROUTING_VERTICAL or document.policy_id != ROUTING_POLICY_ID:
        raise RoutingPolicyError(f"the document is {document.vertical}/{document.policy_id}, not {ROUTING_VERTICAL}/{ROUTING_POLICY_ID}")
    if document.effective_from > at:
        raise RoutingPolicyError(f"the routing document is not in force until {document.effective_from.isoformat()}")
    policy, staff = parse_policy_content(document.content)
    if policy.version != document.version:
        raise RoutingPolicyError(f"the document version {document.version!r} differs from the policy version {policy.version!r}")
    return LoadedPolicy(policy, staff, PolicyProvenance("signed-document", document.version, document.issued_by,
                                                       document.digest, policy.digest))


def require_capability(staff: Staff, actor: str, capability: Capability) -> None:
    """Refuse (FORBIDDEN, 403 at the surface) unless the actor is on the roster with the capability."""
    held = staff.get(actor)
    if held is None:
        raise CareRefused("FORBIDDEN", f"{actor} is not on the care roster")
    if capability not in held:
        raise CareRefused("FORBIDDEN", f"{actor} does not hold {capability.value}")


__all__ = ["ALL_CAPABILITIES", "ROUTING_POLICY_ID", "ROUTING_SCHEMA", "ROUTING_VERTICAL", "SPECIALIST_FOR",
           "Capability", "LoadedPolicy", "PolicyProvenance", "RoutingPolicyError", "Staff", "VerifiedDocument",
           "VerifiedDocumentLoader", "default_staff", "load_routing_policy", "parse_policy_content",
           "policy_content", "require_capability"]
