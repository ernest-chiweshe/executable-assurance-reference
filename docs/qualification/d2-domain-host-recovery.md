# Shared domain-host recovery (I-4, X-25 prerequisite)

`factory.domain_host` is recovered byte-for-byte from the frozen original commit
and blob recorded in `source-provenance-domain-host.json`. Its five direct
authority imports were already present; no existing runtime source was replaced
and no dependency was added.

The bounded offline tests check declarations on one shared host: explicit pack
bindings, duplicate and unknown pack refusal, required shared configuration,
named clock, explicit credential-provider trust and verifier signing keys.
They construct no real gate, issue no credentials and perform no effect.

Recovery does not integrate this original host with the reference's additional
qualification, authenticated-session, durable-clock-floor and generation-floor
controls. The original `DomainHost.gate` calls the original host composer;
adopters must not treat it as the reference composition entry point. The existing
Education, Health and product_spec entry points remain the applicable reference
paths. Generic X-25 pack/capability validation and `SourceReleaseGuard` wiring
remain required work. I-4 and X-25 remain OPEN; this recovery is not an application
release, deployment qualification or proof of complete authority composition.
