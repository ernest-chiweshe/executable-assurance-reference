"""D5 domain bindings on the installation's shared host; no separate authority runtime.

Authorities are explicitly configured by the host. This adapter creates no keys,
activates no pack and cannot infer professional credentials from membership.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from factory.domain_host import DomainBinding, DomainHost, DomainRequest
from factory.projectos.regulated import ReleaseAuthoritySource
from regulated_core.document_gate import VerifierRegistry
from regulated_core.projectos_gate import CredentialVerifier

from .composition import PackComposition, PackCompositionError
from .demonstration_surfaces import CurrentSnapshotVerifier, demonstration_surface
from .demonstrations import EVIDENCE_CHECK, USES
from .reviewed_evidence import RetainedEvidence, SourceReleaseGuard


class DemonstrationBindings:
    """Register declared D5 packs on the SAME host that serves the other domains.

    Supply domain_host as compose_packs' gate_factory, then pass hub_kwargs to
    create_hub_app. Credentials are host-configured factories, never request data.
    A domain's credential factory must issue receipts using the host's signer.
    """

    def __init__(self, *, domain_host: DomainHost,
                 pack_ids: Mapping[str, str],
                 credentials: Mapping[str, Callable[[DomainRequest], CredentialVerifier]],
                 source_authorities: Mapping[str, frozenset[str]]) -> None:
        configured = dict(pack_ids)
        if (not configured or set(configured) != set(credentials)
                or set(configured) != set(source_authorities) or any(use not in USES for use in configured)):
            raise ValueError("D5 domains require matching explicit pack, credential and source bindings")
        if any(not isinstance(value, str) or not value.strip() for value in configured.values()):
            raise ValueError("D5 pack identities must be explicit")
        if len(set(configured.values())) != len(configured):
            raise ValueError("D5 domains require distinct pack identities")
        if any(not callable(factory) for factory in credentials.values()):
            raise ValueError("D5 credential factories must be explicitly configured")
        self.domain_host = domain_host
        self._pack_ids = configured
        self.source = RetainedEvidence(pool=domain_host.stores.pool, trust=domain_host.trust,
                                       authorities=source_authorities)
        for use, pack_id in configured.items():
            domain_host.bind(self._binding(use, pack_id, credentials[use]))

    def _binding(self, use: str, pack_id: str,
                 credentials: Callable[[DomainRequest], CredentialVerifier]) -> DomainBinding:
        def validate(request: DomainRequest) -> None:
            if request.pack.manifest.id != pack_id or request.pack.manifest.capability != use:
                raise PackCompositionError("D5 pack does not match its declared domain binding")
            demonstration_surface(request.pack, source=self.source, clock_us=request.host.clock_us)

        def credential_source(request: DomainRequest) -> CredentialVerifier:
            validate(request)
            return credentials(request)

        def verifiers(request: DomainRequest) -> VerifierRegistry:
            validate(request)
            checks = VerifierRegistry()
            checks.register(EVIDENCE_CHECK, CurrentSnapshotVerifier(self.source, use))
            return checks

        def extension(request: DomainRequest) -> Callable[..., SourceReleaseGuard]:
            validate(request)
            def make(**kwargs: Any) -> SourceReleaseGuard:
                return SourceReleaseGuard(self.source, request.pack, request.registry, request.host.clock_us)
            return make

        return DomainBinding(pack_id=pack_id, name=use, credentials=credential_source,
                             verifiers=verifiers, review_extension=extension)

    def hub_kwargs(self, composition: PackComposition, *, references: Sequence[str],
                   project_surfaces_factory: Callable[[], Mapping[str, Any]],
                   release_authority_factory: Callable[[str], ReleaseAuthoritySource] | None = None,
                   regulated_scope_factory: Callable[[str], Callable[[str, str], None]] | None = None,
                   ) -> dict[str, Any]:
        """Preserve customer surfaces and add only explicitly selected catalog pins.

        No latest-version selection, install, activation or source signing occurs.
        Every selected artifact remains subject to the common lifecycle controls.
        """
        if composition._gate_factory is not self.domain_host:
            raise PackCompositionError("D5 Hub composition must use the shared domain host")
        selected = tuple(references)
        if not selected or len(set(selected)) != len(selected):
            raise PackCompositionError("Select distinct explicit D5 pack references")
        additions = {}
        for reference in selected:
            pack = composition.registry.get(reference)
            if pack is None:
                raise PackCompositionError("Selected D5 pack is not installed in this catalog")
            if self._pack_ids.get(pack.manifest.capability) != pack.manifest.id:
                raise PackCompositionError("This D5 pack has no configured domain binding")
            surface = demonstration_surface(pack, source=self.source, clock_us=self.domain_host.clock_us,
                release_authority_factory=release_authority_factory, regulated_scope_factory=regulated_scope_factory)
            composition.document_loader(surface)
            if surface.name in additions:
                raise PackCompositionError("Two D5 versions would claim the same customer route")
            additions[surface.name] = surface

        def surfaces() -> dict[str, Any]:
            existing = dict(project_surfaces_factory())
            if existing.keys() & additions.keys():
                raise PackCompositionError("D5 route would replace an existing customer surface")
            return {**existing, **additions}

        surfaces()
        return {**composition.hub_kwargs(), "project_surfaces_factory": surfaces}
