# Admitted CAS and local signer/vault seams

These reference additions are integrated into candidate 039 for qualification.
They are not part of the adopted baseline. The existing generic draft receiver remains unchanged. This guide
describes implemented behavior and its present qualification limits; it does
not change the frozen authority obligations.

## Composed versioned-row receiver

`assurance_reference.versioned_cas` composes the existing
`PostgresTargetReceiver` with a transaction-bound admission and an existing-row
compare-and-swap effect.

The host supplies the tenant, target, operation, expected revision, receiver
authorities and authentication callback. These are trusted composition values,
not request-selected policy. The same admission object is attached to both the
receiver and its effect.

```python
from assurance_reference.versioned_cas import compose_retained_versioned_receiver

receiver = compose_retained_versioned_receiver(
    pool=host_pool,
    authority=receiver_authority,
    tenant_id=host_tenant,
    target=host_target,
    operation=host_operation,
    expected_revision=approved_revision,
    authenticate_and_lock_on=authenticate_and_lock_current_request,
)
result = receiver.commit(signed_prepared_permit, exact_approved_bytes)
```

The example requires a fully configured host. It does not create an approval,
issue a permit, provision a database or supply credentials. Callers must handle
the receiver's outcome and reconcile an uncertain result through its observation
API before considering another effect attempt.

The host authentication callback runs on the receiver's existing transaction.
It must authenticate the exact principal and request, lock current customer
and reviewer membership in the established order, and return their earliest
exclusive database-clock expiry. It must neither commit nor replace that
transaction. The retained verifier then acquires the shared review lock and
uses the original retained-decision and approval verification.

The original receiver independently retains its signature, current authority,
preparation, budget, nonce, target-state and deadline checks. The admission
proof is consumed once at the effect boundary. Consumption checks the same
connection, PostgreSQL transaction identity and exact output digest. It also
checks the stored exclusive admission deadline against database time immediately
before the CAS write; the original receiver still checks its final deadline. The proof
also records the permit digest; it does not replace the receiver's permit
authentication or durable nonce enforcement.

The CAS effect locks the existing row, compares its signed target-state digest,
and updates only the configured tenant, target and expected revision. The
revision advances by one; returned bytes must equal the approved output.
An uncomposed `VersionedRowEffect` refuses writes. Row creation is a separate
host provisioning operation, not an implicit receiver behavior.

The schema declares tenant RLS and existing writer/immutability guards.
Schema declarations alone are not evidence of restricted-role operation.
Migration privileges, runtime grants, role separation and actual rollback
must be qualified in the integrated host. Python proof objects do not provide
credential custody or an isolation boundary.

## Original signer and payload-vault adapters

The recovered `regulated_core.adapters` preserves the original implementation,
comments and docstrings. It imports the factory signing, tenant and encrypted
artifact seams eagerly.

`FactorySignerAdapter` requires an explicitly supported signature algorithm.
It canonicalizes structured payloads before delegating signing. A missing or
unsupported algorithm refuses construction; a signing-driver error propagates
at first use without returning a signature.

`FactoryPayloadVault` delegates tenant-scoped storage and returns the content
address plus SHA256. A missing store or unavailable key operation propagates
an error. A failed first wrap can leave an empty tenant directory; the local
contract establishes that no artifact was published in that case.

The original convenience defaults remain: `register_factory_identity` can
create a local signer, and the encrypted store can select a local software
key provider. These defaults are not production custody requirements.
The local provider keeps its master key in process memory. The HSM interface
stub refuses first use without a backend. The optional KMS provider's SDK path
remains unselected in the reference qualification; no provider availability
or external custody is claimed.

The encrypted-store and software key-persistence implementations have separate
concurrency and recovery concerns. The local roundtrip check reconstructs the
store with the same in-memory provider; it does not qualify process restart,
master-key persistence, multi-writer behavior or crash consistency.

## Evidence and integration boundary

Current scoped evidence comprises:

- 30 offline CAS/admission contracts using synthetic transaction observations.
- 14 offline signer/vault contracts using local synthetic drivers.
- A first combined overlay run of those contracts and the existing host
  construction and customer-credential contracts: 105 passed, none skipped.
- Ten intact PostgreSQL contracts passed on Windows PG17 in a fresh isolated
  local cluster (205.19 seconds). This used the staged CAS implementation over
  candidate 038; candidate 039 still requires its own integration qualification.

The PostgreSQL fixture composes real signed local decisions, two synthetic
reviewer grants, a retained certificate, budget reservation, preparation and
the original issuer. Its proof-binding observations never deliver an effect
outside the full receiver. Its stale-revision case is a host revision mismatch,
not a concurrent update race. The fixture uses one local login and does not
establish RLS role separation.

The adapter is pinned to the frozen Git blob
`a96bf32d9903370f9819e40ab37cf46b483bcea9`.
The adapter and both factory dependencies were subsequently compared with the
retained frozen v12 commit `6bba989aeca27575b971c78a103cbf3745cfda6a`;
all three are byte-identical. Their hashes and Git blob identities are retained
in `source-provenance-i5-adapters.json`. The local path uses the already declared
cryptography dependency. No new package installation is required by these
local contracts.

Candidate 039 qualification requires complete static effect-inventory
accounting, the complete retained private audit, applicable runtime regression
and independent acceptance. Source and document inclusion is explicit.
Private review records, owner records and paper drafts are not distributable
documentation. X-1, X-2 and I-5 remain OPEN; this guide makes no row-closure,
deployment or production-readiness claim.
