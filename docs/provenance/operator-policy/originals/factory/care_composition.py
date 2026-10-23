"""Compose customer care from the environment: the store, the routing policy, the truth readers.

Lives outside `factory.care` on purpose: this is the one place that holds handles to the billing
ledgers (read-only here) and hands care its resolver; care itself imports none of them (the
import-boundary test proves it). The store selector mirrors credit lots: ``FACTORY_CARE_STORE``
``pg`` (requires ``FACTORY_DB_URL``) or ``memory``; production (``FACTORY_PRODUCTION_MODE=1``)
refuses memory and refuses an absent selector, because a support case must be durable. The pg
store migrates itself at composition except under ``FACTORY_PRODUCT_SCHEMA_MODE=external-migration-task``,
where the managed migration task applies the care schema before any service task starts.

The S1 routing policy is the owner's ten decisions of 2026-09-06 as declared data (work order
section 1). S2 (A8) loads it as a signed document: ``FACTORY_CARE_ROUTING_DOCUMENT`` names a
regulated-core policy document (vertical ``care``, policy id ``routing``) and
``FACTORY_CARE_TRUST_KEYS`` the public keys it may be signed with; ``RegulatedCoreDocumentLoader``
adapts that envelope to care's ``VerifiedDocumentLoader`` protocol. Production refuses to compose
care without both, and a document that does not verify leaves care unavailable and visibly
reported while the rest of the Hub runs (``compose_care``). Outside production the declared
default stands, with provenance that says so. The policy's content digest is pinned on every case.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from factory.care.contracts import IssueClass, Queue, RoutingPolicy, Targets
from factory.care.policy import (
    LoadedPolicy,
    PolicyProvenance,
    RoutingPolicyError,
    Staff,
    VerifiedDocument,
    VerifiedDocumentLoader,
    load_routing_policy,
    parse_policy_content,
)
from factory.care.service import CareService, Identity, SupportEntitlement
from factory.care.remedies import RemedyDescriptor, RemedyRegistry, ReceiptOutcome
from factory.care.store import CaseStore, InMemoryCaseStore
from factory.care.truth import ReferenceResolver, commercial_code_reader, invoice_reader, payment_reader
from factory.care.contracts import ReferenceKind
from factory.customer.commercial_state import COMMERCIAL_CODES

STORE_ENV = "FACTORY_CARE_STORE"
ROUTING_DOCUMENT_ENV = "FACTORY_CARE_ROUTING_DOCUMENT"
TRUST_KEYS_ENV = "FACTORY_CARE_TRUST_KEYS"
POLICY_AUTHORITY_ENV = "FACTORY_CARE_POLICY_AUTHORITY"
#: The dev-signed routing document that ships in the package (the Hub image copies `factory/`);
#: an estate names it, or its own, through the two environment variables above.
PACKAGED_ROUTING_DOCUMENT = Path(__file__).resolve().parent / "care" / "policies" / "routing-policy.signed.json"
PACKAGED_TRUST_KEYS = Path(__file__).resolve().parent / "care" / "policies" / "trust-keys.json"
TRUST_KEYS_SCHEMA = "care/trust-keys/v1"
_log = logging.getLogger("factory.care_composition")


class CareConfigError(RuntimeError):
    """Care cannot be composed as configured; the reason is the message."""


class CarePolicyRefused(CareConfigError):
    """The routing document is absent, untrusted or invalid: care stays unavailable, the Hub runs (A8)."""


#: Owner decision 1 (2026-09-06): hours and targets per support level, in business hours of a
#: Monday-to-Friday 08:00-17:00 Africa/Johannesburg calendar (9 business hours per day).
#: next_update_hours 0 means "no scheduled update promise"; resolution_hours 0 means "no promise".
DECISION_TARGETS: Mapping[str, Targets] = {
    "free": Targets(first_response_hours=18, next_update_hours=0, resolution_hours=0),
    "standard": Targets(first_response_hours=9, next_update_hours=18, resolution_hours=45),
    "pro": Targets(first_response_hours=4, next_update_hours=9, resolution_hours=27),
    "education-pilot": Targets(first_response_hours=9, next_update_hours=9, resolution_hours=27),
    "health-pilot": Targets(first_response_hours=4, next_update_hours=9, resolution_hours=27),
}

#: Owner decisions 2 and 7: one queue, owned by the designated care partner under a handle that
#: names no person; it is also the last resort. Regulated classes route to the same queue and
#: carry `specialist_required` until a specialist is assigned (the service does that).
CARE_PARTNER = "operator:care-partner"


def default_routing_policy(env: Mapping[str, str] | None = None) -> RoutingPolicy:
    env = env or {}
    return RoutingPolicy(
        policy_id="care-routing", version="2026-09-06.1", timezone="Africa/Johannesburg",
        business_days=(1, 2, 3, 4, 5), business_start_hour=8, business_end_hour=17,
        targets=dict(DECISION_TARGETS),
        queues={"general": Queue("general", env.get("FACTORY_CARE_OWNER", CARE_PARTNER).strip() or CARE_PARTNER,
                                 "Customer Care", last_resort=True)},
        routes={issue: "general" for issue in IssueClass},
        retention_months_after_close=24,
        region=env.get("FACTORY_CARE_REGION", "").strip() or env.get("AWS_REGION", "").strip() or "estate-default",
        courier=env.get("FACTORY_INVITATION_COURIER", "").strip() or "estate-courier",
        pilot_authorities={"education": "practising-teacher", "health": "licensed-clinician"},
        default_support_level="free",
    )


def case_store_from_env(env: Mapping[str, str]) -> CaseStore:
    selector = env.get(STORE_ENV, "").strip().lower()
    production = env.get("FACTORY_PRODUCTION_MODE", "").strip() == "1"
    if selector == "pg":
        dsn = env.get("FACTORY_DB_URL", "").strip()
        if not dsn:
            raise CareConfigError(f"{STORE_ENV}=pg requires FACTORY_DB_URL")
        from factory.care.pg_store import PostgresCaseStore
        store = PostgresCaseStore(dsn, max_size=3)
        # Managed profile: the external migration task applies the schema (factory/managed_migration);
        # a service task never runs DDL. Everywhere else the store migrates itself, idempotently.
        if env.get("FACTORY_PRODUCT_SCHEMA_MODE", "").strip() != "external-migration-task":
            store.migrate()
        return store
    if selector == "memory":
        if production:
            raise CareConfigError(f"{STORE_ENV}=memory is refused in production: a support case must be durable")
        return InMemoryCaseStore()
    if selector == "":
        if production:
            raise CareConfigError(f"{STORE_ENV} is required in production: set pg")
        return InMemoryCaseStore()
    raise CareConfigError(f"unknown {STORE_ENV} {selector!r}; expected pg or memory")


@dataclass(frozen=True)
class CareServices:
    service: CareService
    store: CaseStore
    policy: RoutingPolicy
    staff: Staff
    provenance: PolicyProvenance


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_document_path(value: str) -> Path:
    """Absolute, or relative to the repository (the image's /app), so one value serves every estate."""
    path = Path(value)
    return path if path.is_absolute() else _repo_root() / path


def trust_directory_from_file(path: Path) -> Any:
    """The trust root: public keys only (`care/trust-keys/v1`). A private key here is refused."""
    from regulated_core.signing import TrustDirectory

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CarePolicyRefused(f"the care trust keys at {path} cannot be read: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != TRUST_KEYS_SCHEMA or not isinstance(raw.get("keys"), list):
        raise CarePolicyRefused(f"the care trust keys at {path} are not a {TRUST_KEYS_SCHEMA} document")
    trust = TrustDirectory()
    for entry in raw["keys"]:
        if not isinstance(entry, dict) or "private" in json.dumps(entry).lower():
            raise CarePolicyRefused("a care trust key entry is malformed or carries private material")
        try:
            trust.register(str(entry["key_id"]), bytes.fromhex(str(entry["public_key_hex"])), str(entry.get("alg", "ed25519")))
        except (KeyError, ValueError, TypeError) as exc:
            raise CarePolicyRefused(f"a care trust key entry is invalid: {exc}") from exc
    if not trust._keys:  # noqa: SLF001 - the directory exposes no size; an empty root trusts nobody
        raise CarePolicyRefused(f"the care trust keys at {path} name no key")
    return trust


def document_from_dict(raw: Mapping[str, Any]) -> Any:
    """A regulated-core PolicyDocument from its JSON form (the signing tool's output)."""
    from regulated_core.policy_document import PolicyDocument
    from regulated_core.signing import Signature

    signature = raw["signature"]
    return PolicyDocument(
        vertical=str(raw["vertical"]), policy_id=str(raw["policy_id"]), version=str(raw["version"]),
        content=dict(raw["content"]), jurisdictions=tuple(str(j) for j in raw.get("jurisdictions", ())),
        effective_from_us=int(raw["effective_from_us"]), effective_until_us=int(raw.get("effective_until_us", 0)),
        issued_by=str(raw["issued_by"]), supersedes=str(raw.get("supersedes", "")),
        signature=Signature(str(signature["key_id"]), str(signature["value"]), str(signature.get("alg", "ed25519"))),
    )


def document_to_dict(doc: Any) -> dict[str, Any]:
    return {**doc.signed_body(), "signature": {"key_id": doc.signature.key_id, "value": doc.signature.value,
                                              "alg": doc.signature.alg}, "digest": doc.digest()}


@dataclass(frozen=True)
class RegulatedCoreDocumentLoader:
    """Care's VerifiedDocumentLoader over the regulated core's signed policy document and trust
    directory. Verification is anchored in the trust file, never in the document; an unknown or
    wrong identity, a broken signature, another vertical or policy, or a document outside its
    effective window each refuse with the reason."""

    document_path: Path
    trust_path: Path
    authority: str = ""        # the expected signing key id, or "" for any trusted key

    def load(self, *, vertical: str, policy_id: str, at: datetime) -> VerifiedDocument:
        from regulated_core.policy_document import verify_document

        try:
            raw = json.loads(self.document_path.read_text(encoding="utf-8"))
            doc = document_from_dict(raw)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CarePolicyRefused(f"the care routing document at {self.document_path} cannot be read: {exc}") from exc
        trust = trust_directory_from_file(self.trust_path)
        if not verify_document(trust, doc, authority=self.authority or None):
            raise CarePolicyRefused("the care routing document is not signed by a trusted identity"
                                    + (f" ({self.authority})" if self.authority else ""))
        if doc.vertical != vertical or doc.policy_id != policy_id:
            raise CarePolicyRefused(f"the document is {doc.vertical}/{doc.policy_id}, not {vertical}/{policy_id}")
        now_us = int(at.timestamp() * 1_000_000)
        if not doc.effective_at(now_us):
            raise CarePolicyRefused(f"the care routing document {doc.version} is not in force at {at.isoformat()}")
        return VerifiedDocument(
            vertical=doc.vertical, policy_id=doc.policy_id, version=doc.version, content=doc.content,
            digest=doc.digest(), issued_by=doc.issued_by,
            effective_from=datetime.fromtimestamp(doc.effective_from_us / 1_000_000, tz=timezone.utc),
            supersedes=doc.supersedes,
        )


def routing_document_loader_from_env(env: Mapping[str, str]) -> VerifiedDocumentLoader | None:
    """Both variables or neither: a document without a trust root (or the reverse) is a refusal."""
    document = env.get(ROUTING_DOCUMENT_ENV, "").strip()
    trust = env.get(TRUST_KEYS_ENV, "").strip()
    if not document and not trust:
        return None
    if not document or not trust:
        raise CarePolicyRefused(f"{ROUTING_DOCUMENT_ENV} and {TRUST_KEYS_ENV} are required together")
    return RegulatedCoreDocumentLoader(resolve_document_path(document), resolve_document_path(trust),
                                       env.get(POLICY_AUTHORITY_ENV, "").strip())


def load_policy_from_env(env: Mapping[str, str], *, at: datetime) -> LoadedPolicy:
    """The routing policy in force for this estate, with its provenance."""
    production = env.get("FACTORY_PRODUCTION_MODE", "").strip() == "1"
    try:
        return load_routing_policy(routing_document_loader_from_env(env), at=at, default=default_routing_policy(env),
                                   production=production)
    except RoutingPolicyError as exc:
        raise CarePolicyRefused(str(exc)) from exc


def care_services_from_env(env: Mapping[str, str], *, lots: Callable[[], Any] = lambda: None,
                           payments: Callable[[], Any] = lambda: None,
                           catalog: Callable[[], Any] = lambda: None,
                           clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> CareServices:
    """The care family. `lots` and `payments` are read-only providers of the billing ledgers (the
    credit-lot store and the payments store); absent providers leave those reference kinds without
    a reader, which intake reports as a content-free refusal rather than an error."""
    store = case_store_from_env(env)
    loaded = load_policy_from_env(env, at=clock())
    policy = loaded.policy
    readers: dict[ReferenceKind, Any] = {
        ReferenceKind.COMMERCIAL_CODE: commercial_code_reader(COMMERCIAL_CODES),
    }

    def read_invoice(invoice_id: str) -> Any:
        ledger = lots()
        return None if ledger is None else ledger.invoice(invoice_id)

    def read_payments(workspace_id: str) -> Any:
        ledger = payments()
        if ledger is None:
            return []
        # Every intent of the workspace, across tenants the caller may hold: the reader still
        # requires the id to match, and the workspace scoping is the store's own.
        return ledger.intents(tenant_id=f"subscription-workspace:{workspace_id}", workspace_id=workspace_id)

    readers[ReferenceKind.INVOICE] = invoice_reader(read_invoice)
    readers[ReferenceKind.PAYMENT] = payment_reader(read_payments)
    def support(identity: Identity) -> SupportEntitlement:
        reader = catalog()
        binding = None if reader is None else reader.current_binding(identity.subscription_id)
        level = "" if binding is None else binding.plan_version_id.split("@")[0]
        source = "unbound-default" if binding is None else "plan:" + binding.plan_version_id
        return SupportEntitlement(level if level in policy.targets else policy.default_support_level, source)

    def verify_adjustment(case: Any, remedy: Any) -> ReceiptOutcome:
        ledger = lots()
        if ledger is None:
            return ReceiptOutcome.UNAVAILABLE
        receipt = ledger.application(remedy.receipt_ref)
        if receipt is None:
            return ReceiptOutcome.NOT_FOUND
        valid = (receipt.subscription_id == case.subscription_id and receipt.source.value == "operator_adjustment"
                 and receipt.source_id == remedy.resource_ref and not receipt.reversal_of
                 and not any(r.reversal_of == receipt.application_id for r in ledger.applications_for(case.subscription_id)))
        return ReceiptOutcome.VERIFIED if valid else ReceiptOutcome.MISMATCH

    def verify_reinstate(case: Any, remedy: Any, not_before: datetime) -> ReceiptOutcome:
        ledger = lots()
        if ledger is None:
            return ReceiptOutcome.UNAVAILABLE
        receipt = next((r for r in ledger.transitions_for(case.subscription_id) if r.transition_id == remedy.receipt_ref), None)
        if receipt is None:
            return ReceiptOutcome.NOT_FOUND
        current = ledger.lifecycle(case.subscription_id)
        valid = (remedy.resource_ref == case.subscription_id and receipt.to_state.value == "active"
                 and receipt.at > not_before and receipt.reason.value == "operator"
                 and receipt.from_state.value != "active" and receipt.actor.startswith("operator:")
                 and receipt.subscription_id == case.subscription_id and current is not None and current.state.value == "active")
        return ReceiptOutcome.VERIFIED if valid else ReceiptOutcome.MISMATCH

    # Invoice status alone cannot prove the exact void operation; it is deliberately not registered.
    remedies = RemedyRegistry({
        "billing.credit_adjustment": RemedyDescriptor(frozenset({IssueClass.BILLING_ACCESS}), r"[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}", verify_adjustment),
        "billing.lifecycle_reinstate": RemedyDescriptor(frozenset({IssueClass.BILLING_ACCESS}), r"[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}",
            lambda _case, _remedy: ReceiptOutcome.MISMATCH, verify_after=verify_reinstate),
    })
    archive = env.get("FACTORY_CARE_ROUTING_ARCHIVE", "").strip()
    if archive and not env.get(TRUST_KEYS_ENV, "").strip():
        raise CarePolicyRefused("a routing archive requires the configured care trust root")

    def historical_policy(case: Any) -> RoutingPolicy:
        if not archive:
            raise CarePolicyRefused("FACTORY_CARE_ROUTING_ARCHIVE is not configured")
        # The contract validates this digest as 64 lowercase hex characters, so it cannot escape.
        loader = RegulatedCoreDocumentLoader(resolve_document_path(archive) / f"{case.policy_digest}.signed.json",
                                             resolve_document_path(env[TRUST_KEYS_ENV]),
                                             env.get(POLICY_AUTHORITY_ENV, "").strip())
        document = loader.load(vertical="care", policy_id="routing", at=case.created_at)
        prior_policy, _old_staff = parse_policy_content(document.content)
        if prior_policy.digest != case.policy_digest or prior_policy.version != document.version:
            raise CarePolicyRefused("the archived routing document does not match the case")
        # Current signed staff capabilities remain authority; history controls only recorded promises.
        return prior_policy

    service = CareService(store, resolver=ReferenceResolver(readers), policy=policy, clock=clock,
                          support=support, staff=loaded.staff, remedies=remedies, historical_policy=historical_policy,
                          staff_provider=lambda: load_policy_from_env(env, at=clock()).staff)
    return CareServices(service=service, store=store, policy=policy, staff=loaded.staff, provenance=loaded.provenance)


def compose_care(env: Mapping[str, str], *, lots: Callable[[], Any] = lambda: None,
                 payments: Callable[[], Any] = lambda: None,
                 catalog: Callable[[], Any] = lambda: None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> CareServices | None:
    """The Hub's entry: a store fault still refuses to compose (the estate is misconfigured and the
    preflight says so), but a routing-document fault leaves care UNAVAILABLE and visibly logged while
    the rest of the Hub starts (A8): the surfaces answer 503 until the document is repaired."""
    try:
        return care_services_from_env(env, lots=lots, payments=payments, catalog=catalog, clock=clock)
    except CarePolicyRefused as exc:
        _log.error("customer care is unavailable: routing policy refused: %s", exc)
        return None


__all__ = ["CARE_PARTNER", "DECISION_TARGETS", "PACKAGED_ROUTING_DOCUMENT", "PACKAGED_TRUST_KEYS", "POLICY_AUTHORITY_ENV",
           "ROUTING_DOCUMENT_ENV", "STORE_ENV", "TRUST_KEYS_ENV", "TRUST_KEYS_SCHEMA", "CareConfigError",
           "CarePolicyRefused", "CareServices", "RegulatedCoreDocumentLoader", "care_services_from_env",
           "case_store_from_env", "compose_care", "default_routing_policy", "document_from_dict", "document_to_dict",
           "load_policy_from_env", "resolve_document_path", "routing_document_loader_from_env",
           "trust_directory_from_file"]
