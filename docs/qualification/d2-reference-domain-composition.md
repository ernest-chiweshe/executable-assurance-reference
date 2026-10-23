# Reference domain composition adapter

`assurance_reference.domain_host.ReferenceDomainHost` uses the recovered original
domain declaration contracts and a complete configured `RuntimeAuthorities`
template. It composes only through `compose_reference_host`; it never calls the
original `DomainHost.gate`. Original recovered bytes remain unchanged.

Construction validates shared reference configuration. A domain supplies explicit
trusted credential-provider maps, session-admitting credentials, verifiers and
an optional review extension. Unknown packs and missing verifier signing keys
refuse before credential resolution. Delegation requires both configured shared
services; non-delegating bindings explicitly disable delegation for that domain.
Other host services remain on the template, including heartbeat, restrictions,
tier-four settings, jurisdiction and outage handling. Reference configuration
continues to require a bound generation floor or an explicit logged non-use.

Offline contracts use no-I/O pools, non-signing construction signers and synthetic
pack descriptors. They establish construction behavior and preserve the reference
factory, qualification engine, clock and configured floor; they do not emit a
release or qualify a real application. Existing application entry points are not
migrated by this increment. In particular, product_spec's signed-document path
remains a document gate; no installed product pack is invented.

Capability validation, source-release guard wiring, application integration and
complete independent regression remain required. I-4 and X-25 remain OPEN.
