# Publication evidence update — 18 October 2026

Read this dated update alongside Paper A v1.8 and Paper B v14. It reconciles the
completed reference milestone with their earlier snapshots. It does not replace
historical measurements, certify a production deployment, or close unresolved
requirements by changing their wording.

## Claims and their evidence

| Claim | Evidence population | What the evidence supports | Remaining boundary |
|---|---|---|---|
| Implemented and deployed governance platform | Historical platform; Paper B evaluation | The reported implementation, domain demonstrations, and retained operational records | These are not measurements of the October reference |
| Hardware-backed signing, retained evidence and measured latency | Historical July profiles; [measurement record](historical-measurements.md) | Recorded 300-decision baselines: median 82.10/92.13 ms and p95 130.71/162.98 ms for managed/STRICT profiles | Staging used GOVERNANCE retention; this does not qualify production COMPLIANCE configuration or current custody |
| Ordinary reference qualification | Complete private Candidate 062, 1,014 source files | 2,079 passing tests on Windows/PostgreSQL 17 and separately on Linux/PostgreSQL 18; source hashes unchanged in both runs | Synthetic identities, named test boundaries and retained private inputs; no general production guarantee |
| Governed outbound action | Candidate 062 X-8 contracts | Exact admitted payload, duplicate refusal without a second POST or budget spend, and receipt-bound reconciliation without blind resend | Synthetic destination contracts; deployment must withhold direct credentials and enforce mediation; no universal exactly-once external delivery |
| Tenant isolation | Candidate 062 B-F7b coverage | Seeded observations across the named 35-table scope and the qualified partitioned lifecycle | Administrative setup and host metadata assumptions remain; not a proof of every possible deployment or composition |
| Commitment and recovery | Candidate 062 A15 contracts | Named durable receiving, issuer, budget and reconciliation cases | Filesystem and remote HTTP boundaries are not one distributed atomic transaction; unresolved outcomes remain UNKNOWN |
| Reproducible package | Version 0.1.7 installed-package evidence | Installed imports and archive inclusion were examined | The installed-package suite was **not a pass**: 1,957 passed, 75 failed, 40 errors; 115 outcomes depended on excluded private assets |
| Broader containment, monitor performance and human protection | Paper A hypotheses and proposed evaluations | Architectural rationale and stated testable hypotheses | Those hypotheses are not established by the reference test count |

The frozen 69-obligation census remains **63 MET, four ordinary OPEN
(A15, A19, B-F7b, X-4), and two OPEN BY DESIGN (R-1b, R-2b)**. The separately
accepted operational scope has 67 accepted with recorded limits and two by
design. Neither number is a percentage of real-world safety. Operational
acceptance does not convert the four frozen OPEN requirements to MET.

## Reference latency — measurement correction pending

The first reported run was collected under cProfile. Its elapsed times are
withdrawn as performance measurements because instrumentation inflated them.
The profile remains diagnostic evidence of whole-chain traversal. A clean,
unprofiled run with raw samples is pending; no steady-state latency or measured
rotation remedy is claimed. Historical platform measurements remain separate.

## Reproduction and retained inputs

The complete private qualification and the distributable archive are different
inputs. Private Health evidence, owner records, approved requirements and some
publication inputs are excluded from distribution. The 115 installed-package
outcomes were classified as 92 Health, 14 owner-record, six publication and three
requirements cases. They remain recorded failures/errors, not retroactive passes
or an implied public full-suite qualification.

A public reader can exercise the included synthetic examples and the tests whose
inputs are distributed. Reproducing the private full-suite result requires its
exact retained inputs. Follow [installation](installation.md) and inspect the
actual run result; do not infer a full-suite pass from successful installation.

The sealed candidate and original qualification records remain private and
immutable. Publication cleanup produces a distinct derivative: a result obtained
against the sealed source is not automatically a result against changed bytes.

### Evidence fingerprints

These SHA-256 values identify the original private records, not files asserted to
be included in the public package:

- Candidate 062 file inventory: `1e68e3b07d12aafcccd57fa14dde58c67a3e06fc55093cc48f9d67381c3ba0ff`.
- Windows verification: `e8eda1f70b3a3fe26833e0460f43e8ba364294a4d9230c7e72a71bfcc4d631ad`.
- Linux verification: `3ba2b3247311f61c0f2e0ad7063075d7ab1aa9fffe1083a2535edfcd6833e02a`.
- Final ordinary row verdicts: `fafa8bfe708a14f6010c9af44fe9e630fd87619db4b323920d0154ad2d0b69a6`.
- Corrected enactment: `7101a7d9c1fbad2d20dc2cfa8e676adf72ac126793d9d894409f027000f0c793`.

## Paper A Appendix B reconciliation

The appendix is an earlier work list. Apply the following disposition rather than
reading every item as absent or marking every item complete:

| Earlier item | Current disposition |
|---|---|
| Target adapter conformance and release tag | Named reference contracts now exist; full A19 conformance remains OPEN. A published source tag must identify the actual publication derivative, not silently inherit the private candidate qualification. |
| Mandatory retention construction | Reference constructor and pre-permit retention contracts exist. Local contracts do not establish production write-once custody; retain the deployment-specific requirement. |
| Independent E1 evaluation and harmful permitted actions | Remains a proposed evaluation. Ordinary test counts do not measure H1 or H1′. |
| Replay, races, reconciliation and witness cosigning | Named replay/reconciliation cases are implemented and tested. Do not equate a preclaimed losing branch with simultaneous concurrency coverage, or local receipts with independent witness cosigning. |
| Walls across every reachable host | Remains a deployment obligation; a boundary diagram is a specification, not evidence of enforced network isolation. |
| Public register, contribution instructions and videos | Evidence and video sources exist. Public release and the final audience-specific video corrections remain distinct publication tasks. |
| Literature, legislation and precedent checks | Retain the targeted-review limitation; implementation completion does not establish comprehensive novelty or complete these checks. |
| Preregistration and human-study ethics | Remain prerequisites for their proposed studies, not results of the reference implementation. |

## The boundary to show in a walkthrough

```mermaid
flowchart LR
    A[Agent proposes an action] --> G[Authority checks policy, qualification and approval]
    G --> E[Durable pre-action evidence]
    E --> P[Exact-byte, single-use permit]
    P --> T[Receiving adapter verifies and claims authority]
    T --> O[Named target effect]
    O --> R[Outcome receipt or UNKNOWN]
```

The deployment must prevent the agent from reaching the target through another
credential or channel. The identity/policy authorities, receiving adapter,
evidence dependencies and host isolation are part of the stated trust boundary.
UNKNOWN requires reconciliation; it is not permission to resend. Correct
permission enforcement does not establish that the policy or approved content
is harmless.

The existing threat models and related-work sections remain the primary
discussion. The contribution to foreground is the implemented composition,
including checker-qualification binding and fresh credential-bound approval.
This update makes no new priority claim over other published systems.
