"""factory/customer/ — the declarations a CUSTOMER-facing surface needs, and nothing more.

The operator Hub can afford to show a stage graph and let a human infer the rest. A customer
surface cannot: it has to state, before anything spends, what a step will use, who will do it,
and how it bills — and it has to refuse when it cannot establish that.

None of those facts existed in a form a surface could read. `/api/verticals` declared only
`spends: true`; `/api/harnesses` declared only `{name, model}`; billing was declared solely on
`AdvisoryQualification`, so twenty of thirty lanes carried no label at all. This package adds the
missing DECLARATIONS — it computes no new truth and it guesses nothing:

  - `requirements.py` declares what each stage of each vertical needs from the provider fleet,
    and resolves a requirement to the lanes that satisfy it with their declared billing.
  - `authority.py` declares the invitation-beta principal -> membership ->
    subscription -> workspace -> entitlement graph and resolves it fail-closed.
    `authority_store.py` and `authority_pg_store.py` provide matching local and
    versioned Postgres storage semantics without credential-carried joins.
  - `membership_lifecycle.py` declares governed, idempotent revocation/expiry;
    both stores enforce actor authority and the last-owner invariant atomically.
  - `workspace_closure.py` admits an owner-authorized workspace into terminal
    offboarding only after confirmation bound to the exact workspace record;
    both stores atomically close the workspace and sole live subscription so
    new governed work fails closed without claiming deletion or purge.
  - `authentication.py` defines secret-free, graph-bound invitation, session,
    service-credential, and provider-reference records;
    `authentication_store.py` and `authentication_pg_store.py` persist only
    bearer digests or vault references and reject cross-workspace rebinding.
  - `governance.py` defines inert, content-free approval, idempotency, publish,
    and audit records; its stores re-derive authority before accepting
    security-sensitive records without executing the governed effect.
  - `credit.py` defines typed-USD subscription and aggregate-liability balance
    snapshots plus graph-bound reservation records; its stores verify
    references without claiming Phase 2 atomic admission or settlement.
  - `schema.py` preflights and orders the six accepted customer-schema
    migrators, then verifies exact versions and required relations without
    creating a pool, resolving credentials, or wiring application startup.
    `expand_contract.py` freezes every numbered migration source digest,
    labels the historical sequence without retroactive compatibility claims,
    and admits future expand/contract steps only across the complete declared
    application rollback window before any component mutation. That window is
    derived from explicit known current and rollback-eligible release IDs;
    schema composition has no default release evidence.
  - `artifact_objects.py` is the Phase 6A-3 provider-neutral artifact boundary.
    It qualifies only private encrypted versioned object ports, derives
    workspace- and retention-scoped content-addressed keys, binds content-free
    records to complete customer authority, and re-hashes the exact stored
    version on every read. Concrete S3 composition and lifecycle evidence
    remain Phase 8 work.
  - `artifact_metadata_store.py` and `artifact_metadata_pg_store.py` are the
    Phase 6A-4 semantic twins for the exact secret-free object record. They
    revalidate authority, bind artifact and exact object-version identities,
    verify row digests, and compose an immutable expand migration without
    creating an object client or wiring startup.
  - `application_authority.py` admits already-authenticated durable sessions
    and service credentials by re-resolving their complete active authority
    graph, service scopes, exact membership, and resource-workspace binding.
  - `authentication_lifecycle.py` issues one-time-visible, server-generated
    opaque invitation/session/service bearers and verifies their type-bound,
    keyed, domain-separated digests. Its bounded versioned keyring issues only
    under the current pepper, verifies under the producing current/previous
    key, and emits zero-active-record retirement evidence without owning
    routes or production key management.
  - `invitation_acceptance.py` is the single-lock Phase 3B semantic twin for
    consuming one invitation into an explicit human principal, membership,
    consent/audit record, and fresh customer session without email joins.
  - `invitation_acceptance_pg_store.py` performs the same acceptance in one
    PostgreSQL transaction, locking the invitation and authority parents
    before creating authority, session, consent and audit records.
  - `human_session_lifecycle.py` is the offline Phase 3D twin for host-only
    secure cookie descriptors, session-bound CSRF, atomic rotation, logout,
    and authority-lifecycle revocation without mounting a route.
  - `service_credential_lifecycle.py` is the offline Phase 3F twin for
    owner-authorized service credential issuance, authority/scope
    revalidation, atomic non-broadening rotation, and retained revocation.
    Phase 3G-A supplies the shared lifecycle-store protocol and matching
    fake-SQL-tested PostgreSQL session/service transitions.
  - `authentication_http.py` and `authentication_transition_hooks.py` supply
    the unmounted Phase 3G-B composition boundary: one human/service request
    authentication shape and an explicit proactive-invalidation caller after
    governed authority transitions. Scope-registry availability incidents
    are exported content-free through the shared store and schema v5.
  - `scope_registry.py` and `application_composition.py` are the unmounted
    Phase 4A-1 foundation: one immutable, enumerated minimal-grant vocabulary
    and one root that constructs authentication, application authority, and
    proactive transition hooks. Canonical REST/MCP adapters remain Phase 4A-2.
  - `canonical_adapters.py` and `openapi_contract.py` are the unmounted
    Phase 4A-2A foundation: REST route templates and curated MCP tool names
    resolve through the same registry, authority root, exact handler set, and
    sanitized versioned contract. Framework mounting remains Phase 4A-2B.
  - `retained_surface_inventory.py` is the Phase 4A-2B1 no-loss gate: every
    retained `/api/public/*` route has one proposed canonical REST operation,
    scope and explicit curated-MCP disposition. It mounts nothing; 4A-2B2
    still owns real handlers, security adapters and beta-profile eligibility.
    Phase 4A-2B2A derives a separate complete immutable application registry
    and sanitized contract from that closed inventory without replacing the
    bounded 4A-2A registry. `retained_application_mount.py` is the bounded
    Phase 4A-2B2B mount: asynchronous canonical dispatch reaches the same 37
    retained business handlers in-process through a server-owned authority
    bridge, and supplied FastAPI/FastMCP instances receive the complete REST
    and curated MCP sets. Production transport security, composition,
    no-bypass proof and profile eligibility remain Phase 4A-2B2C.
    `mcp_transport_security.py` is the unmounted Phase 4A-2B2C1 contract for
    HTTPS OAuth discovery metadata, exact resource/audience/scope/Origin
    admission over already-verified access, explicit static-service
    compatibility, deterministic local rate admission and token-free
    application forwarding. It does not verify tokens or claim production
    transport composition.
  - `mcp_access_token.py` is the offline Phase 4A-2B2C2A verifier for compact
    signed OAuth access-token JWTs. It uses an operator-provisioned public-key
    allowlist, exact issuer/resource/audience/time/scope claims and a
    server-side subject directory so credentials never carry workspace or
    subscription authority. Phase 4A-2B2C2B1 preserves the server-resolved
    principal kind in token-free transport admission, re-resolves the complete
    active authority graph for the admitted operation, and dispatches through
    the existing canonical retained handler. `mcp_http_mount.py` is the
    bounded Phase 4A-2B2C2B2 HTTPS-only ASGI root: it serves sanitized
    protected-resource metadata, verifies the provisioned JWT keyring, applies
    Origin/scope/rate admission, and reaches the retained handler through the
    token-free bridge. Authorization-server key discovery, TLS/proxy
    deployment, Phase 2E funding composition and beta-profile eligibility
    remain later work.
  - `effect_policy.py` is the unmounted Phase 4B-1 classification boundary:
    all 39 retained operations have one immutable effect kind and an exact
    prerequisite set covering authority, funding, approval, idempotency,
    audit, durable results, external effects, and repurpose-job signing/state.
    It fails closed on incomplete or contradictory registries but does not yet
    enforce those prerequisites or execute any effect.
  - `effect_admission.py` is the mandatory Phase 4B-2A pre-dispatch seam.
    Canonical REST and MCP adapters require one server-owned provider after
    complete application authority and validate its immutable operation,
    authority, effect-kind, and exact-prerequisite binding before entering a
    retained handler. It also validates any attached two-phase funding
    admission against the same authority, operation and surface.
  - `effect_funding.py` is the unmounted Phase 4B-2B1 concrete funding
    provider. It resolves a server-owned content-free Phase 2E request,
    verifies exact authority/surface/operation binding, and performs account
    cap plus platform reservation before returning the effect receipt.
    `effect_execution.py` is the bounded Phase 4B-2B2 continuation: it verifies
     exact content-free approval, pending idempotency/result-slot and audit
     evidence before consuming that admission once, then requires exact result
     confirmation before returning the accessible funding receipt. Real
     PostgreSQL evidence and later publish/repurpose/production gates remain
     unclaimed.
   - `effect_publish.py` is the offline Phase 4C-1 external-publish fence.
     It atomically claims exact approval, pending idempotency/result, allowed
     audit and planned publish-history evidence before one supplied
     `publish.run` handler, then requires exact terminal record confirmation.
     Handler or confirmation uncertainty is a distinct no-retry outcome.
     `publish_outbox_store.py` and `publish_outbox_pg_store.py` provide the
     Phase 6A-5 one-winner in-memory and PostgreSQL evidence twins: a staged
     four-record snapshot is authority-revalidated and atomically claimed
     before handler entry, then its idempotency, publish history and outbox
     attempt reach one exact terminal state in a transaction. Production
     publisher composition and uncertain-attempt reconciliation remain
     unclaimed.
   - `effect_repurpose.py` is the unmounted Phase 4C-2A workspace-job and
     callback-signing evidence boundary. It requires exact authority,
     funding/provider/lane, governance, job-state and active opaque signing
     reference binding before a planned job can become started, validates an
     exact terminal transition, and workspace-binds status reads. It never
     resolves the signing secret, invokes a provider, or delivers a callback.
     `effect_repurpose_execution.py` is the bounded Phase 4C-2B execution
     composition: canonical create marks the exact workspace job started
     before one injected provider-start, exact terminal confirmation precedes
     one optional opaque-reference callback port, and all post-entry
     uncertainty is a distinct no-retry result. The composition remains
     offline, unmounted, secret-free, and without a real provider or callback.
     `repurpose_job_store.py` and `repurpose_job_pg_store.py` provide the
     Phase 6A-6 one-winner in-memory and PostgreSQL evidence twins: one staged
     approval/idempotency/audit/job/callback-reference snapshot is
     authority-revalidated before the exact planned-to-started transition,
     then job and idempotency reach one terminal result transactionally.
     Provider/callback invocation, secret resolution, uncertain-start
     reconciliation, startup composition and deployment remain unclaimed.
   - `invitation_beta_application.py` is the Phase 4D-1 offline
     production-candidate root. It mounts canonical REST on a fresh public
     application and secured MCP on the same authority/effect seams while the
     retained Hub application remains a private in-process handler target.
     Phase 4D-2 composes the retained lifecycle outside the MCP lifecycle so
     partial MCP startup unwinds retained state and shutdown runs in reverse.
     Production startup selection and operational no-bypass remain unclaimed.
  - Existing `spending.py` remains the customer-facing honest historical spend
    projection. `spending_store.py` adds the separate Phase 2A offline atomic
    platform-credit admission twin without changing that existing contract.
    `spending_pg_store.py` carries the same admission laws into one durable
    PostgreSQL transaction and Phase 2C adds exact-idempotent settlement plus
    unused monetary release. Phase 2D adds pre-dispatch operation state,
    fail-closed abandoned reconciliation, and overage incidents.
    Phase 2F adds human-owner-only adjudication for locked UNKNOWN and
    incident states, with exact balance correction and content-free evidence,
    approval, audit, and customer-receipt records.
  - `funding_execution.py` is the Phase 2E shared offline gateway for future
    customer REST and MCP adapters. It preserves the existing `CostGovernor`,
    keeps BYO and platform credentials on separate non-substituting branches,
    now exposes exact `admit`/`execute_admitted` phases while preserving its
    one-call `execute` behavior, requires durable provider-start before
    platform credential resolution or execution, and returns text-labelled
    billing and entitlement receipts.
    Current beta routes remain fail-closed until Phases 3/4.
  - `spending_read.py` is the unmounted Phase 7A-24 application boundary for
    the retained project-spending view. It closes REST project selection,
    rebinds all four authority identities, reconstructs rows and billing-kind
    totals from one injected workspace port, and refuses inconsistent charged,
    notional, local, unknown, or publishing evidence without constructing a
    store or publishing a wire schema.

The rule the whole package exists to serve: an undeclared requirement is not "probably fine", it
is a refusal. See `docs/customer-web/00-arc-audit.md` for the measurements that motivated it.
"""
