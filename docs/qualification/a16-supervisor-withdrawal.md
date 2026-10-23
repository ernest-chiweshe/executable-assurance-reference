# Supervised tenant withdrawal: candidate 035

This is a local reference candidate awaiting independent acceptance. A16 remains
OPEN. The adopted 033 baseline, frozen v12 obligations, CP24 and historical
implemented/deployed facts are unchanged. This document describes additional
candidate behavior; it does not replace historical qualification records.

## Composition and authority

The ordinary Education, clinical Health and product_spec hosts, and the
standalone demo and Health constructors, use the guarded PostgreSQL epoch ledger.
Direct legacy writes through that ledger refuse. The separate historical
revocation demonstration retains its original diagnostic scope.

A withdrawal starts with an ordinary policy decision requiring supervisor
approval. The approval service authenticates an actual local session, obtains
the supervisor credential from the persisted signed roster, rejects self
approval, and retains the original approval and credential receipts. It never
refreshes signed evidence at receiving time. The registered governance target
binds the exact tenant, prior epoch, request bytes, original review, decision,
clock domain, permit and budget reservation.

The receiver rereads retained authority under roster, review, epoch and budget
locks in that order. Epoch append, exact receiving proof and budget consumption
share one owned PostgreSQL transaction. The proof retains the original signed
permit, decision, review, roster digest and event time. Historical receipt
authentication does not pretend that an already completed effect becomes
uncommitted when its permit subsequently expires.

The ordinary application epoch reader is inherited unchanged from
PostgresRevocationLedger. The separate supervisor target authority explicitly
selects governance_epoch, which reuses the governance log's owned session,
including epoch reads during admission. Nested effect-time epoch reads use a strictly
tenant-bound transaction on the current synchronous thread; that binding is
cleared on normal and exceptional exits. The clock floor still commits on its
separate connection. The three-connection local pool was not enlarged.

## Historical targeted observations and current repair

Candidate 034 failed independent full Windows and Linux regression. Both peer
runs reported 1,440 passes, 11 failures and 67 errors. The reported causes were
missing governor pools in shared construction fixtures, an epoch-reader identity
mismatch and stale table-count assertions. Candidate 035 retains every original
identity assertion, restores the inherited application reader, explicitly
selects a separate governance reader, validates a distinct governor login, and
updates the fixed table counts with exact receipt-duty assertions. A missing
revocation store again gives its existing startup configuration error.

The affected offline suites passed 145 tests on the initial candidate 035
repair. Its first complete retained-private audit passed 88 tests before later
test/document integration. Fresh guarded runtime run 001 reported 69 passes
and one role-duty failure. Run 002 reported eight passes (including all four
standalone reconstruction cases) and one remaining fixed-count failure. The
focused role rerun passed five tests after correcting that count.

Candidate 034 added receiver roster SELECT relative to adopted 033. The
amended role expectations did not accept that widening. Candidate 035 now
restores governor-only roster access. Retention starts with the receiver review
transaction, holds the database-wide shared roster lock through review commit,
and briefly reads verified roster history on a nested governor connection.
The roster remains SCOPE_REVIEW outside forced tenant RLS; the governor's
installation-scope obligation stays OPEN.

The reviewed original-core adaptation reserves a distinct permit-use connection
before entering reconciliation's governor scope. Its claim SELECT still occurs
under the governing lock, using that held connection and the original tenant
checks. Shared-pool composition retains one-session behavior; cleanup runs on
normal and exceptional exit. No grant, dependency or pool size was added.
The cumulative explicit adaptation is
docs/provenance/a16-resource-order/adaptations.json; retained original hashes
and the earlier a17 manifest remain available.

Fresh integrated targeted regression passed 102 tests in 148.63 seconds.
Six additional synthetic ownership cases also passed in their earlier overlay.
A separate fresh run passed two ordinary concurrency/lock observations in
19.89 seconds: three retained approvals, three reconciliations and one ordinary
Education delivery completed together with exact original outcomes and intact
guards; a nonblocking probe found the shared roster lock held after legitimate
review insertion and available after commit. Observed peak leases were two
receiver and one governor, with the existing maximum of three unchanged.
This was not a capacity-saturation result. A later batch with four independent
retentions, four signed reconciliations and one actual Education delivery also
passed, alongside the lock observation (two tests in 21.41 seconds). Its measured
peaks were two receiver and two governor leases. Dual-pool capacity saturation
was not exercised; this remains an explicit acceptance limitation.
A first attempt at the new concurrency fixture refused a request timestamp predating newly appended fixture evidence;
the request was refreshed using current authority time, with no clock guard
changed. The failed run is retained.

The static resource-order review covers these concrete reference paths:
retention receiver then governor; application activation receiver then ordinary
epoch governor; reconciliation permit-use receiver then governor; and the
epoch writer reusing its owned governor connection for review, roster, epoch
and budget checks. Durable-clock reads use the independent clock-floor
connection, and recorder reads use the recorder role. This is not a universal
proof over arbitrary callbacks, custom hosts or every governance adapter.
Independent review of the remaining concurrency acceptance criterion is pending.

The earlier 034 observations below are historical. Fresh 035 run receipts retain
their exact source hashes and the failed runs; no aggregate full-pass claim is
made. Package and full Windows/Linux qualification remain pending. The exact
B-F2 same-decision projection test is now included after its separately staged
ordinary signed-release run passed; B-F2 remains OPEN.

## Historical targeted contracts

- All three integrated applications and both standalone paths committed exact
  bytes using current authority after reconstruction. Following an ordinary
  supervised withdrawal, rebuilt receivers refused the original pending permit
  without creating the application artifact or spending its application nonce.
- Local authenticated ordinary-role and self-approval requests refused.
  The new receipt table and governor duties were registered in the runtime
  contract, but the later full role suites failed on stale fixed table totals.
  Candidate 035 corrects those totals without broadening runtime privileges.
- Two exact concurrent deliveries settled to one epoch, receipt and budget
  consume. Two and three separately approved requests for the same prior epoch
  produced one committed winner and definite refusals for the others.
  Each tested delivery batch finished within a 15-second local test bound.
- An uncommitted short-lived permit refused after normal database-clock expiry.
  A committed original receipt, reconciliation and idempotent retry remained
  valid after expiry and the withdrawal's own epoch increment.
- An additional constraint on a fresh isolated receipt table caused a real
  PostgreSQL storage error. The owned transaction rolled back the epoch append
  and budget consume together. No receiving receipt remained; the prepared
  attempt stayed UNKNOWN and fenced. The thread-local read binding was cleared.

These are the contracts in test_epoch_supervisor_pg.py,
test_epoch_application_reconstruction.py,
test_standalone_revocation_reconstruction.py,
test_epoch_concurrent_delivery.py, test_epoch_permit_expiry_pg.py and
test_epoch_storage_atomicity_pg.py. Construction, approval and retained-review
contracts supplement them. Exact run receipts and independent verdicts are
retained privately outside the distributable package.

## Runtime role additions

The receiver has no roster-table read grant. Retention reads the verified
roster through the configured governor while the receiver owns the shared lock.
The governor reads original reviews and epoch receipts, and inserts epoch
receipts in the same transaction as the epoch change. Neither receives receipt
UPDATE, DELETE or TRUNCATE privileges. The receipt table has forced tenant RLS,
append-only triggers, a tenant/epoch foreign key and exact-operation uniqueness.
Provisioning is explicit host administration before runtime; constructors do
not migrate or repair an existing database.

## Limits and review state

A losing concurrent withdrawal may consume its one-use nonce without an epoch,
receipt or budget effect. The core claims a nonce before waiting for the
governance scope lock. This fail-closed historical behavior is retained; no nonce
is fabricated as unspent. An UNKNOWN attempt is not automatically reclassified
as NOT_COMMITTED merely because a receiving receipt is absent.

The 15-second bound describes these local tests, not a distributed latency
guarantee. Reconstruction is within one process with configured keys, policies,
clock and evidence services retained. The withdrawal tests order revocation
before application delivery; they do not qualify every race between an
application effect and a concurrent withdrawal. The storage test covers one
statement-failure boundary, not every outage, process crash or lost
acknowledgment. Database-clock checks do not establish physical UTC accuracy.
Local sessions and signed fixture rosters do not establish deployed human
identity, key custody or production authorization.

The complete retained private candidate must pass its authority, provenance,
effect inventory and publication audits. Archive-only testing is not a
replacement. Package preflight and source sealing do not close A16; independent
full Windows/Linux regression and an explicit acceptance decision remain
necessary. No publication, deployment or paid provider use is authorized by
this candidate.
