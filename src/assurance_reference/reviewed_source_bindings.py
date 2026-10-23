"""Explicit reviewed-source bindings on the existing reference domain host.

This startup adapter creates no keys, signs nothing, installs no packs and does
not construct customer UI routes. Source and credential policy come from the
host; every composed request retains the concrete source-release extension.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from assurance_reference.domain_host import ReferenceDomainHost
from assurance_reference.reviewed_evidence import RetainedEvidence, SourceReleaseGuard
from assurance_reference.reviewed_evidence_support import CurrentSnapshotVerifier
from factory.domain_host import DomainBinding, DomainRequest
from factory.packs.demonstrations import EVIDENCE_CHECK, USES
from regulated_core.document_gate import VerifierRegistry


class ReferenceBindingError(ValueError):
    """A declaration or request does not match its explicit host binding."""


class ReviewedSourceBindings:
    """Register exact declarations during host startup, before serving requests."""

    def __init__(
        self, *, domain_host: ReferenceDomainHost,
        pack_ids: Mapping[str, str],
        credentials: Mapping[str, Callable[[DomainRequest], Any]],
        source_authorities: Mapping[str, frozenset[str]],
        credential_authorities: Mapping[str, Mapping[str, str]] | None = None,
        credential_provider_families: Mapping[str, Mapping[str, str]] | None = None,
    ) -> None:
        if not isinstance(domain_host, ReferenceDomainHost):
            raise ReferenceBindingError("An existing reference domain host is required")
        configured = dict(pack_ids)
        factories = dict(credentials)
        sources = {use: frozenset(keys) for use, keys in source_authorities.items()}
        providers = {use: dict(keys) for use, keys in (credential_authorities or {}).items()}
        families = {use: dict(keys) for use, keys in (credential_provider_families or {}).items()}
        uses = set(configured)
        if (not uses or uses != set(factories) or uses != set(sources)
                or any(use not in USES for use in uses)
                or not set(providers).issubset(uses) or not set(families).issubset(uses)):
            raise ReferenceBindingError("Matching explicit domain configuration is required")
        if any(not callable(factory) for factory in factories.values()):
            raise ReferenceBindingError("Explicit callable credential factories are required")
        for use, pack_id in configured.items():
            if not isinstance(pack_id, str) or not (
                pack_id == "lumiwright.demo." + use
                or pack_id.startswith("lumiwright.demo." + use + ".")
            ):
                raise ReferenceBindingError("Pack identity must match its declared demonstration")
            if domain_host.binding(pack_id) is not None:
                raise ReferenceBindingError("Pack already has a host binding")
            keys = {**providers.get(use, {}), **families.get(use, {})}
            all_pairs = [*providers.get(use, {}).items(), *families.get(use, {}).items()]
            if not keys or any(
                not isinstance(provider, str) or not provider.strip()
                or not isinstance(key, str) or not key.strip()
                or not domain_host.trust.is_known(key)
                for provider, key in all_pairs
            ):
                raise ReferenceBindingError("Explicit trusted credential provider maps are required")
        if len(set(configured.values())) != len(configured):
            raise ReferenceBindingError("Distinct configured pack identities are required")
        source = RetainedEvidence(
            pool=domain_host.stores.pool, trust=domain_host.trust, authorities=sources,
        )
        self.domain_host = domain_host
        self.source = source
        self._pack_ids = configured
        for use, pack_id in configured.items():
            domain_host.bind(self._binding(
                use, pack_id, factories[use], providers.get(use), families.get(use),
            ))

    def _binding(self, use, pack_id, credentials, providers, families):
        def validate(request):
            if (request.host is not self.domain_host
                    or request.pack.manifest.id != pack_id
                    or request.pack.manifest.capability != use):
                raise ReferenceBindingError("Pack does not match its declared domain binding")
            if (len(request.pack.rulebook.actions("external")) != 1
                    or EVIDENCE_CHECK not in request.pack.rulebook.check_ids()):
                raise ReferenceBindingError("Pack needs one release action and its evidence check")

        def credential_source(request):
            validate(request)
            return credentials(request)

        def verifiers(request):
            validate(request)
            checks = VerifierRegistry()
            checks.register(EVIDENCE_CHECK, CurrentSnapshotVerifier(self.source, use))
            return checks

        def extension(request):
            validate(request)

            def make(**kwargs):
                return SourceReleaseGuard(
                    self.source, request.pack, request.registry, request.host.clock_us,
                )

            return make

        return DomainBinding(
            pack_id=pack_id, name=use, credentials=credential_source,
            verifiers=verifiers, review_extension=extension,
            credential_authorities=providers, credential_provider_families=families,
        )
