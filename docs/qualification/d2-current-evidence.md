# Current host evidence (X-24)

`assurance_reference.current_evidence.CurrentSnapshotVerifier` extracts the
current-custody check from the pinned original `demonstration_surfaces.py`.
Its provenance record and retained original are in `docs/provenance/current-evidence/`.
The original application surface and its domain constants are not composed by this wrapper.

The host injects a reader and an immutable set of permitted use identifiers. Each
contextual check calls that reader with the authenticated context's tenant, the
host-selected use, and the requested case. The returned `EvidenceSnapshot` must
match that tenant and case. Missing, degraded or mismatched evidence fails closed;
the contract cannot supply a fallback snapshot. Each successful read is checked
by the existing snapshot verifier for time, revision, digest, conflicts and exact
rendered output. An accepted snapshot is never cached between checks.

The synthetic tests exercise Education, Health and product_spec use identifiers,
current revision changes, source withdrawal, unavailable stores, identity
mismatches and missing trusted context. This establishes the local wrapper
contract, not a durable store, authenticated transport or completed release.

The host must supply a trustworthy `EmissionContext` and evidence reader. The
wrapper does not hold a source lock through a later effect; the retained source
review guard and release composition remain separate obligations. A PASS is an
evidence-check result, not release authority. X-23 and X-24 remain OPEN until
independent review and the applicable qualification are complete. No runtime
dependency has been added.
