# Local policy loading and operator provisioning

Candidate041 adds explicit policy loading and pinned local operator provisioning. Staged modules and all42 synthetic contract cases retain exact reviewed bytes. Original care composition, parser and operator files are retained with frozen commit/blob/hash provenance in docs/provenance/operator-policy/DERIVATION.json. The care parser is imported only by a test harness from retained originals; no care service is added to runtime.

The policy loader binds public trust, vertical, policy identity, authority and optional document digest. Historical lookup preserves the application content digest separately from the signed-document digest and returns evidence, not a current release gate.

The operator defaults to preflight and applies already signed teacher, student and head-of-department authorities only on explicit execution. Original provisioners retain their guards, monotonic history and store revision behavior. Each write is read back. Membership is checked once before the batch, and exact pack selection is observed before each write. These observations do not provide atomic revocation or exact pack transition guarantees. Partial completion must be inspected before any retry.

X11 and X16 OPEN; candidate040 is a sealed pending parent, not an adopted baseline.

Policy loading requires explicit host public trust, identities and caller-supplied observation time; current gate integration remains separate.

Historical policy observation retains frozen care content/version semantics but grants no current authority; care originals imported only by test harness.

Operator uses original guarded enrollment and appointment writes; preflight-only membership, caller-clock custody, private validator coupling and non-atomic exact pack observation remain limits.

Three operator writes are not an atomic batch; partial completion requires inspection, not blind retry.

No hosted identity, customer route, live custody, service/UI deployment or new runtime dependency.

Full audit requires complete retained private candidate including private signed Health bundle; archives omit it and archive-only default clinical qualification remains unavailable.

Zero new direct syntax sites does not mean zero effects; indirect provisioning and host callbacks require their separate review.
