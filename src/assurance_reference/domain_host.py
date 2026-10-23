"""Shared pack declarations composed exclusively through reference authority checks.

This adapter does not migrate application entry points or qualify a source-release
guard. Signed-document applications retain their existing document-gate path.
"""

from dataclasses import replace
from types import MappingProxyType

from assurance_reference.host_runtime import compose_reference_host
from factory.domain_host import DomainAuthorityKeys, DomainHost, DomainRequest, UnboundDomain


class ReferenceDomainHost(DomainHost):
    """Retain complete host services while resolving explicitly declared domains."""

    def __init__(self, *, stores, authorities, alerts, qualifications,
                 generation_floor=None, floor_not_used_reason=None):
        # Snapshot caller-owned maps; no request may change the host's key policy.
        self._template = replace(
            authorities,
            verifier_signers=MappingProxyType(dict(authorities.verifier_signers)),
            credential_authorities=(None if authorities.credential_authorities is None else
                                    MappingProxyType(dict(authorities.credential_authorities))),
            credential_provider_families=(None if authorities.credential_provider_families is None else
                                         MappingProxyType(dict(authorities.credential_provider_families))),
        )
        self._reference_config = dict(
            alerts=alerts, qualifications=qualifications, generation_floor=generation_floor,
            floor_not_used_reason=floor_not_used_reason,
        )
        # Validate all shared services before accepting domain declarations.
        compose_reference_host(stores, self._template, **self._reference_config)
        super().__init__(
            stores=stores, trust=authorities.trust, signer=authorities.emission_signer,
            worm=authorities.worm, clock=authorities.clock,
            outage_alarm=authorities.outage_alarm,
            delegation_source_status=authorities.delegation_source_status,
            production_assurance=authorities.production_assurance,
            default_mission_budget=self._template.default_mission_budget,
            authority_keys=DomainAuthorityKeys(
                authorities.approval_signer, authorities.emission_signer,
                authorities.preflight_signer, authorities.identity_authority,
                self._template.verifier_signers, authorities.delegation_signer,
            ),
        )

    def compose_for(self, pack, registry, surface, **inputs):
        """Resolve one registered pack and retain every non-domain host service."""
        binding = self.binding(pack.manifest.id)
        if binding is None:
            raise UnboundDomain(f"no reference domain serves pack {pack.manifest.id}")
        missing = set(pack.rulebook.check_ids()) - self._template.verifier_signers.keys()
        if missing:
            raise ValueError("domain checks need explicit verifier signing keys: " + ", ".join(sorted(missing)))
        if binding.delegates and (self._template.delegation_signer is None
                                 or self._template.delegation_source_status is None):
            raise ValueError("delegating domain requires the configured signer and source status")
        request = DomainRequest(pack, registry, surface, self, MappingProxyType(dict(inputs)))
        resolved = replace(
            self._template,
            credential_authority=None,
            credential_authorities=binding.credential_authorities,
            credential_provider_families=binding.credential_provider_families,
            credential_verifier=binding.credentials(request),
            host_verifiers=binding.verifiers(request),
            review_extension_factory=(binding.review_extension(request)
                                      if binding.review_extension else None),
            delegation_signer=self._template.delegation_signer if binding.delegates else None,
            delegation_source_status=(self._template.delegation_source_status
                                      if binding.delegates else None),
        )
        return compose_reference_host(self.stores, resolved, **self._reference_config)

    def gate(self, pack, registry, surface, **inputs):
        return self.compose_for(pack, registry, surface, **inputs)(pack, registry, surface)
