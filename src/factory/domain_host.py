"""The one domain host every domain front end composes its regulated gate through (owner, 28 September 2026).

Education in the Hub, clinical writing in Health, the D5 demonstrations and every future industry interface (finance,
insurance) are domains of ONE installation. They share one governance core, which this host holds once, from the
managed host: the runtime signer and its trust directory, the durable regulated stores (recorder, permits, budget,
reviews, revocation, activation), the write-once evidence store, the outage alarm, the independent monitor's heartbeat
and, where the installation composes it, delegation. Nothing here is rebuilt per domain.

A domain contributes only a `DomainBinding`: which pack it serves, how its approvers' credentials are verified, which
host verifiers answer its checks, and an optional review extension. The host dispatches by the installed pack's id; a
pack no binding declares is refused, so no domain can be served by another domain's credentials. Each call composes
through `compose_regulated_host`, exactly as the per-domain factories did before, so every authority check, trust
anchor requirement and store binding is the same one.

The host is also the `PackGateFactory` a `RegulatedHostRuntime` holds (called as `(pack, registry, surface)`), and it
keeps the attributes callers already read from the managed host's factory: `signer`, `trust`, `worm`, `outage_alarm`,
`heartbeat`, `stores`.
"""
from __future__ import annotations

from regulated_core.production_gate import PackReadiness

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from types import MappingProxyType
from typing import Any

from regulated_core.clock import TrustedClock
from regulated_core.budget import host_budget_terms
from regulated_core.document_gate import VerifierRegistry
from regulated_core.host_runtime import RuntimeAuthorities, compose_regulated_host
from regulated_core.signing import Signer


@dataclass(frozen=True)
class DomainRequest:
    """One gate composition: the installed pack, its registry, the surface that binds it, and the domain's own
    request inputs (for example the Health store and workspace a clinical document lives in)."""

    pack: Any
    registry: Any
    surface: Any
    host: DomainHost
    inputs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DomainAuthorityKeys:
    """Installation-owned keys for distinct authority domains.

    Configuration supplies existing trusted signers; construction never generates
    keys or contacts a provider. Credential issuers are declared per domain.
    """

    approval_signer: Signer
    emission_signer: Signer
    preflight_signer: Signer
    identity_authority: str
    verifier_signers: Mapping[str, Signer]
    delegation_signer: Signer | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "verifier_signers", MappingProxyType(dict(self.verifier_signers)))


@dataclass(frozen=True)
class DomainBinding:
    """What a domain supplies to the shared core, and nothing more.

    `credentials` returns the CredentialVerifier for this request; the approver's credential kind is the active signed
    profile's (docs/ARCHITECTURE-OF-RECORD/10), and the binding supplies the provider that verifies it. `verifiers`
    returns the host verifiers for the pack's checks. `review_extension` returns an optional review-extension factory
    (a source witness or a source release guard). `delegates` says whether this domain's releases may carry delegated
    authority when the installation composes delegation. `credential_authority` names the trusted key that signs this
    domain's credential receipts when deployment trust requires one distinct from the runtime signer (an institution's
    or a labelled test authority's issuer); it is declared by the binding at composition and must be a trust anchor,
    never chosen by a request. Legacy composition retains its existing runtime-key default.
    With explicit installation authority keys, `credential_authorities` must instead
    declare every admitted provider and its trusted signing key; no default applies."""

    pack_id: str
    name: str
    credentials: Callable[[DomainRequest], Any]
    verifiers: Callable[[DomainRequest], VerifierRegistry] = lambda request: VerifierRegistry()
    review_extension: Callable[[DomainRequest], Any] | None = None
    delegates: bool = False
    credential_authority: str | None = None
    credential_authorities: Mapping[str, str] | None = None
    credential_provider_families: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        for name in ("credential_authorities", "credential_provider_families"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, MappingProxyType(dict(value)))


class UnboundDomain(ValueError):
    """The installed pack belongs to no declared domain of this installation."""


class DomainHost:
    """The shared governance core of one installation, and the registry of the domains it serves."""

    def __init__(self, *, stores: Any, trust: Any, signer: Any, worm: Any, clock: TrustedClock,
                 outage_alarm: Any = None, heartbeat: Any = None,
                 delegation_source_status: Callable[[str, str], None] | None = None,
                 authority_keys: DomainAuthorityKeys | None = None,
                 production_assurance: PackReadiness | None = None,
                 default_mission_budget: Mapping[str, int] | None = None) -> None:
        if stores is None or trust is None or signer is None or worm is None:
            raise ValueError("the domain host needs the installation's stores, trust, runtime signer and evidence store")
        if not isinstance(clock, TrustedClock):
            raise ValueError("domain host requires a named trusted clock")
        self.stores, self.trust, self.signer, self.worm = stores, trust, signer, worm
        self.clock = clock
        self.clock_us: Callable[[], int] = clock.now_us
        self.outage_alarm, self.heartbeat = outage_alarm, heartbeat
        self.delegation_source_status = delegation_source_status
        self._authority_keys = authority_keys
        self.production_assurance = production_assurance
        self._default_mission_budget = host_budget_terms(default_mission_budget)
        self._bindings: dict[str, DomainBinding] = {}
        self._lock = Lock()

    def bind(self, binding: DomainBinding) -> None:
        """Declare one domain. A pack is served by exactly one domain; a second binding for it refuses."""
        if not isinstance(binding, DomainBinding) or not binding.pack_id or not callable(binding.credentials):
            raise ValueError("a domain binding names its pack and supplies its credential verification")
        if binding.credential_authority is not None and not self.trust.is_known(binding.credential_authority):
            raise ValueError(f"domain {binding.name!r} names a credential authority that is not a trust anchor")
        credential_keys = (*((binding.credential_authorities or {}).values()),
                           *((binding.credential_provider_families or {}).values()))
        if self._authority_keys is not None:
            if not credential_keys or binding.credential_authority is not None:
                raise ValueError("explicit authority keys require a provider credential map with no default")
            if any(not self.trust.is_known(key) for key in credential_keys):
                raise ValueError("domain credential providers must name trusted keys")
        elif binding.credential_authorities is not None or binding.credential_provider_families is not None:
            raise ValueError("provider credential maps require explicit installation authority keys")
        with self._lock:
            if binding.pack_id in self._bindings:
                raise ValueError(f"pack {binding.pack_id} is already served by domain "
                                 f"{self._bindings[binding.pack_id].name!r}")
            self._bindings[binding.pack_id] = binding

    def binding(self, pack_id: str) -> DomainBinding | None:
        with self._lock:
            return self._bindings.get(pack_id)

    @property
    def domains(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(b.name for b in self._bindings.values()))

    def gate(self, pack: Any, registry: Any, surface: Any, **inputs: Any) -> Any:
        """The regulated gate for this installed pack, composed on the shared core with its domain's binding."""
        binding = self.binding(pack.manifest.id)
        if binding is None:
            raise UnboundDomain(f"no domain of this installation serves pack {pack.manifest.id}")
        request = DomainRequest(pack, registry, surface, self, dict(inputs))
        signer = self.signer
        delegating = binding.delegates and self.delegation_source_status is not None
        keys = self._authority_keys
        if keys is not None:
            missing = set(pack.rulebook.check_ids()) - keys.verifier_signers.keys()
            if missing:
                raise ValueError("domain checks need explicit verifier signing keys: " + ", ".join(sorted(missing)))
            if delegating and keys.delegation_signer is None:
                raise ValueError("a delegating domain requires an explicit delegation signing key")
        authorities = RuntimeAuthorities(
            trust=self.trust,
            approval_signer=keys.approval_signer if keys is not None else signer,
            emission_signer=keys.emission_signer if keys is not None else signer,
            preflight_signer=keys.preflight_signer if keys is not None else signer,
            identity_authority=keys.identity_authority if keys is not None else signer.key_id,
            credential_authority=None if keys is not None else binding.credential_authority or signer.key_id,
            credential_authorities=binding.credential_authorities,
            credential_provider_families=binding.credential_provider_families,
            credential_verifier=binding.credentials(request), host_verifiers=binding.verifiers(request),
            verifier_signers={check: keys.verifier_signers[check] if keys is not None else signer
                              for check in pack.rulebook.check_ids()}, worm=self.worm,
            review_extension_factory=binding.review_extension(request) if binding.review_extension else None,
            outage_alarm=self.outage_alarm, production_assurance=self.production_assurance,
            delegation_signer=(keys.delegation_signer if keys is not None else signer) if delegating else None,
            delegation_source_status=self.delegation_source_status if delegating else None,
            clock=self.clock, default_mission_budget=self._default_mission_budget,
            **(self.heartbeat.authorities() if self.heartbeat is not None else {}))
        return compose_regulated_host(self.stores, authorities)(pack, registry, surface)

    def __call__(self, pack: Any, registry: Any, surface: Any) -> Any:
        """The PackGateFactory shape a RegulatedHostRuntime calls; domains needing request inputs call `gate`."""
        return self.gate(pack, registry, surface)


__all__ = ["DomainAuthorityKeys", "DomainBinding", "DomainHost", "DomainRequest", "UnboundDomain"]
