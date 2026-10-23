"""Domain packs: a signed, versioned, multi-artifact bundle of DATA, in the domain's own standard
vocabulary, that the governed runtime installs, activates and governs without importing a line of
pack code.

The shape is not invented here. It follows what regulated software already does, and the
ten-domain research pass that fixed the requirements (``docs/verticals - research/00 DOMAIN-PACK-
FOUNDATION-RESEARCH-2026-09-06.md``):

* the package: a content-indexed, signed bundle with a manifest that names its identity, KIND
  (base / profile / overlay), version, compatibility, dependencies and the namespaces it OWNS
  (OPA bundles: ``.manifest`` ``revision`` / ``roots`` / ``.signatures.json``; FHIR NPM packages:
  ``package.json`` ``name`` / ``version`` / ``fhirVersions`` / ``dependencies``; NIEM package
  descriptions: identity, lineage, conformance targets);
* three distinct trust facts: the publisher's files signature, the SLSA/in-toto build provenance,
  and the domain expert's signed attestation over a semantic surface (Sigstore and SLSA separate
  signature from provenance; expert approval is a third fact);
* policy as data validated against a typed schema and evaluated by one generic, default-deny
  engine (Cedar: entity types, actions with ``appliesTo`` and a context shape); jurisdiction and
  organization OVERLAYS as second signed documents that may only tighten the base (OSCAL: catalog,
  profile, implementation and assessment stay separate but linked);
* deterministic verification as HOST-QUALIFIED capabilities a pack parameterises, never as
  imported pack code; a custom executable verifier is a separately listed, host-allowed exception;
* advisory output as CARDS a human accepts or overrides, with the outcome fed back (CDS Hooks:
  ``summary`` / ``indicator`` / ``source`` / ``suggestions`` / ``overrideReasons``);
* the domain's own vocabulary, locked by edition (education: 1EdTech CASE, OneRoster, Caliper;
  health: FHIR implementation guides; finance: XBRL taxonomies), never a private learner blob;
* the OPA bundle lifecycle: verify, then activate atomically, keep the last known good, roll back,
  revoke, pin a tenant; every activation has an id that release receipts carry;
* conformance by LEVEL (structural, semantic, offline behavioral, expert validated) where a lower
  level never implies a higher one; host integration and production qualification are never
  claimed offline (1EdTech conformance suites; AppExchange review before listing).

Modules, in dependency order: ``manifest``, ``signing``, ``schema``, ``verifiers`` (host
capabilities), ``rulebook`` (policy as data, overlays, the interpreter), ``checks`` (conformance
cases and the bounded custom path), ``sources`` (the knowledge lock), ``workflow`` (typed stages),
``collections`` (durable per-tenant data with migrations), ``cards``, ``receipt`` (the nine pins),
``attestations`` (expert review as a signed fact), ``lifecycle`` (activation ledger), ``registry``
(install and activate, fail-closed per pack), ``conformance`` (the levelled drive), ``examples``
(the Education reference pack, its ZA overlay, and the minimal pack for the fourth-pack law).
"""
from __future__ import annotations

__all__ = ["PACK_SCHEMA", "PLATFORM_CONTRACT"]

#: The manifest schema this platform reads.
PACK_SCHEMA = "lumiwright.domain-pack/v1"
#: The platform contract a pack must declare compatibility with (compared like ``fhirVersions``).
PLATFORM_CONTRACT = "governed-runtime/1"
