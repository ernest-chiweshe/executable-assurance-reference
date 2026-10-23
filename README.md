# Executable Assurance - Reference Architecture

Executable Assurance separates the capability core, execution runtime and governance runtime so that capability is not authority. It turns paper-based policies into executable checks before consequential actions, and generates evidence as part of the decision rather than relying only on auditing after the event.

This repository contains the standalone reference implementation accompanying two papers by Ernest Chiweshe:

- [Capability Is Not Authority: Executable Assurance as Infrastructure for Containing AI Risk to Humankind](https://doi.org/10.5281/zenodo.23580975)
- [Governed AI as Runtime Infrastructure: A Unified Authority and Evidence Architecture for Regulated Agentic Systems](https://doi.org/10.5281/zenodo.23581016)

The underlying LumiWright Agent Factory was implemented and deployed before this
reference extraction. Its domain implementations and deployment history are the
subject of the papers. The focused examples here reproduce selected mechanisms;
their smaller scope does not redefine the platform as a proposal.

Both papers were published on 22 October 2026. The reference implementation and the deployed platform have separate evidence scopes, described in the papers and reproduction records.

## The authority path

1. An agent proposes an action and its exact payload.
2. Governance checks the applicable policy, identity, scope and evidence requirements.
3. An allowed action receives a cryptographic permit bound to the decision and payload, with evidence recorded before release.
4. The receiving boundary verifies the permit and enforces the applicable replay, budget and transaction rules. Unresolved outcomes remain subject to reconciliation or HOLD.

The guarantees depend on the receiving boundary. Transactional database effects and external filesystem or HTTP effects do not have identical atomicity guarantees.

## Release and reproduction

Version **0.1.8rc5** is an attribution-cleaned public derivative of frozen candidate004, previously packaged as **0.1.8rc3**. Runtime logic is retained; the cleanup changes historical commentary, two runtime module docstrings, test attribution comments and the frozen-fixture integrity pin, and the provenance tooling needed to distinguish cleaned copies from the original bytes. Eleven new synthetic tests exercise that tooling's integrity checks.

The public profile contains **2,837 tests**: all 2,826 original public cases plus those 11 integrity tests. The same **124 cases requiring private inputs** remain explicitly excluded and are never counted as public passes. `PUBLIC-TEST-PARTITION.json` lists the case identities and source hashes. The public profile does not substitute for the complete private-input qualification.

Follow `REPRODUCE.txt` with the release wheel, source archive and pinned dependencies. Runtime imports must come from the installed wheel, not an editable checkout. Use an isolated PostgreSQL cluster and retain its logs and data directory. The release's `PUBLIC-VALIDATION.json` records the actual completed environment, artifact hashes and outcome; the test count alone is not a pass claim.

The earlier rc3 artifact passed 2,826 public tests on Linux with Python 3.14 and PostgreSQL 18. That result belongs to rc3 and is not reused as rc4 validation. The complete private candidate's 2,950-case results are also separate from public installed-package qualification.

## Provenance

This repository's initial commit records the public export, not the beginning of development. Earlier development history and original evidence are preserved separately.

The source archive used as the cleanup baseline has SHA-256 `ea01c93993c72fbfa2fafa455dcc7e3ac5fc1157dde1ade1fa472193616bab7b`. `docs/provenance/public-attribution-sanitization.json` records the files changed by the attribution pass. Historical upstream hashes remain historical references. Cleaned retained copies have separate hashes under the explicit v2 adaptation schema; their exact patches are checked. Checking a cleaned copy does not itself prove that it is byte-identical to upstream. Comparing against the preserved baseline and independent review remain separate steps.

Historical reports describe the versions and hashes they actually tested. They do not supersede the current release validation report or imply that every historical variant is the current runtime.

## Engineering boundaries

- **R1b:** expiry detected by the database's in-COMMIT check is rejected; this mechanism does not establish a bound on physical completion after that check.
- **R2b:** complete safe authority resumption after restore remains unfinished; unsafe recovery cases stay on HOLD.
- Formal latency acceptance for this candidate remains open. Timing results from earlier candidates are not transferred to it.

## Contribute a layer

The authority path is one layer in a wider strategy. We invite contributions from security, systems engineering, law, human factors and domain practice: identify what your layer prevents, its assumptions, how it fails, and how another layer can detect or contain that failure. The goal is an integrated set of protections whose gaps do not all align.

Walkthroughs and video updates: [lumiwright.com/videos](https://www.lumiwright.com/videos).

## Author

Ernest Chiweshe, Founder & CEO, LumiWright  
Email: [ernest.chiweshe@lumiwright.com](mailto:ernest.chiweshe@lumiwright.com)

## Licensing

The software is licensed under Apache License 2.0; see `LICENSE`. This retains the licensing basis of the preceding public repository. The papers are published separately under Creative Commons Attribution 4.0, as recorded on Zenodo.
