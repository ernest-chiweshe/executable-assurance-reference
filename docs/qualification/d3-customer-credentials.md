# Offline customer credential interface

The B-F7c increment recovers `factory.credentials` and its exact original import
closure from commit `6bba989aeca27575b971c78a103cbf3745cfda6a`.
`source-provenance-credentials-interface.json` records all 15 files, their original
Git blob identifiers and SHA256 values. Four files were already present; eleven
are newly included. The original credential module is retained under
`docs/provenance/bf7c/originals/factory/credentials.py`. Its explicit strengthening
and the previously accepted A21 changes are described by the combined pinned
manifest `docs/provenance/bf7c/adaptations.json`; the A21 manifest is unchanged.

`ProviderResolver` binds a provider slot to the existing `CredentialStore`
interface. `TenantRoutedCredentialStore` chooses the customer store for the
host's effective customer tenant. `VaultCredentialStore` resolves the exact
tenant/slot pair; absence raises the original `MissingCredentialError` without
operator fallback. With an approved credential revision, the original currency
check requires a matching versioned snapshot before returning its value.

The strengthened boundary allows operator environment credentials only for
`SELF.tenant_id`. Every other identifier is routed to its own customer store or
refused, regardless of its prefix, spelling or originating surface. An ambient
operator context cannot override an explicitly supplied non-operator tenant.
The historical prefix classifier remains available for compatibility but no
longer decides permission to use operator credentials. Tenant identity must
still come from the authenticated host; the string `self` is not authentication.
The authenticated host must reserve that identifier for its own operator
principal. Every customer-facing surface must reject `self` as an externally
supplied or externally assigned tenant identifier, including during tenant
creation and context construction. A display name does not authenticate a
principal: any context whose tenant identifier is `self` is treated as operator
by this low-level interface. These credential contracts do not establish that
all host surfaces enforce the reserved identifier; that integration assurance
remains an explicit limit.

The offline tests exercise fictional model and tool slots, separate customer
deposits, absent deposits, an absent customer store, ambient customer routing,
operator-environment refusal, exact revision snapshots and rotation/removal
refusal. They use only fake values and backends. Run:

```console
python -B -m pytest tests/test_customer_credentials.py -q -p no:cacheprovider
```

The host must authenticate and supply tenant context and a trustworthy credential
backend. A backend returning a different tenant's secret under the requested
identifier violates that trusted interface; this adapter cannot independently
establish ownership of a bare secret string. Successful lookup does not prove a
provider accepts the credential. Values returned to the caller remain secrets
whose lifecycle and access must be protected by the host.

## Dependency and coupling assessment

The credential currency implementation imports `factory.collaboration.contracts`
for canonical binding digests. Its original package initializer imports the
collaboration contracts/store/supervisor declarations. Exact closure recovery
therefore includes those modules and their static imports. Keeping that closure
preserves original import behavior and avoids introducing a second digest or
currency implementation. No collaboration service is composed or started.

No dependency or version is added to `pyproject.toml`. The closure contains an
optional S3 backend whose constructor lazily imports `boto3` when no client is
provided. This backend is not used or instantiated here; `boto3` is not installed
or made a runtime requirement. The optional PostgreSQL backend uses the already
pinned pool dependency and is likewise not instantiated by these tests. Future
use of either backend needs its own necessity/coupling assessment and applicable
authorization. Presence of source is not qualification of those integrations.

This delivers the offline credential interface portion of B-F7c. Agent CLI
subscription-home handling, live model/tool execution, real customer vault
custody and signing custody are not established by these fixtures. Signing
custody remains the separate A11 signer obligation. No original-platform change,
provider call or obligation promotion follows from this increment. B-F7c remains
OPEN until independent scope/evidence review and governance disposition.
