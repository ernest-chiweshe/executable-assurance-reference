# Executable Assurance: Reference Architecture

Most security systems infer authority from capability: if an agent holds the credentials or API keys to perform an action, the system permits it. In autonomous systems, this assumption fails. Executable Assurance separates runtime execution from governance execution so that *capability is not authority*. Rather than relying on reactive post-hoc auditing or model alignment, the architecture compiles governance policies into deterministic, before-the-fact runtime gates. Consequential actions pass through a single, fail-closed choke-point that verifies single-use cryptographic permits and commits immutable evidence before any real-world effect is released.

This repository is the standalone reference implementation accompanying two papers, published on 22 October 2026:

- [Capability Is Not Authority: Executable Assurance as Infrastructure for Containing AI Risk to Humankind](https://doi.org/10.5281/zenodo.23580975)
- [Governed AI as Runtime Infrastructure: A Unified Authority and Evidence Architecture for Regulated Agentic Systems](https://doi.org/10.5281/zenodo.23581016)

The underlying LumiWright Agent Factory was implemented and deployed in July 2026, before this
reference extraction. Its domain implementations and deployment history are the
subject of the papers. The focused examples here reproduce selected mechanisms;
their smaller scope does not redefine the platform as a proposal.

## Design causes

- **Separation of capability from authority.** Holding database credentials, network sockets or execution environments is not the authority to act; a valid cryptographic permit is. An agent or model proposes; it never holds the authority to execute on its own.
- **Preventative enforcement before the fact.** Static, paper-based compliance rules become deterministic, fail-closed runtime gates. Consequential side-effects are blocked before they can occur, rather than detected and audited after the damage is done.
- **Write-once evidence as a precondition for effect.** Proof of the authorization, or of the refusal, is durably committed before any bytes are released. If recording fails, execution aborts.
- **Deterministic single-use permits.** A permit is bound to who, which tenant, which target, the exact byte hash of the payload, and a strict deadline. Once consumed, it is spent and cannot be replayed or extended.
- **Fail-closed default.** In any ambiguity, partition, timeout or lost acknowledgement, the system refuses and holds the state as `UNKNOWN` rather than guessing or blindly retrying.

## The authority path

1. An agent proposes an action and its exact payload.
2. Governance checks the applicable policy, identity, scope and evidence requirements.
3. An allowed action receives a cryptographic permit bound to the decision and payload, with evidence recorded before release.
4. The receiving boundary verifies the permit and enforces the applicable replay, budget and transaction rules. Unresolved outcomes remain subject to reconciliation or HOLD.

The system does not attempt to solve model alignment, filter prompt semantics, or replace operating-system sandboxing. It is an execution choke-point between an autonomous proposer and the actuator: in James Reason's Swiss-cheese model, the preventative gate layer.

## Release and reproduction

Version **0.1.8rc5** is the public release of candidate004, with assistant attributions removed from historical commentary and provenance copies. Runtime logic is unchanged.

- **2,837 public tests:** the 2,826 original public tests plus 11 tests that check the provenance records of that cleanup. A further 124 tests need private inputs and are listed, with their reasons, in `PUBLIC-TEST-PARTITION.json`.
- **Tested on Windows** (Python 3.12, PostgreSQL 17) **and Linux** (Python 3.14, PostgreSQL 18), each installed three ways: from the wheel, offline from pinned dependencies, and from a fresh clone of this repository. Results, environments and artifact hashes are in `PUBLIC-VALIDATION.json`.

Follow `REPRODUCE.txt` with the release wheel, source archive and `requirements-tested.txt`, against an isolated PostgreSQL cluster.

This repository's first commit is the public export, not the beginning of development; earlier history and original evidence are preserved separately. `docs/provenance/public-attribution-sanitization.json` lists every file the cleanup changed.

Open engineering items, as stated in the papers: **R-1b**, the database refuses an expired permit inside COMMIT, but completion after that check is not bounded by this mechanism; **R-2b**, safe resumption of authority after a restore is unfinished, and unsafe recovery cases stay on HOLD.

## Contribute a layer

Because no single boundary can guarantee complete safety, this authority path is one layer within a multi-discipline Swiss-cheese model. We invite practitioners in systems security, formal methods, safety engineering and law to contribute complementary, independent layers whose protections cover one another's gaps.

Walkthrough videos: [lumiwright.com/videos](https://www.lumiwright.com/videos)

## Author

Ernest Chiweshe, Founder and CEO, LumiWright

[ernest.chiweshe@lumiwright.com](mailto:ernest.chiweshe@lumiwright.com) · [LinkedIn](https://www.linkedin.com/in/ernest-chiweshe-6b7732433/) · [X @ernest_chiweshe](https://x.com/ernest_chiweshe) · [YouTube](https://www.youtube.com/channel/UCO3vVGTjgFR9CCwKOcMMCpg) · [TikTok @ernest.chiweshe](https://www.tiktok.com/@ernest.chiweshe)

## Licensing

The software is licensed under the Apache License 2.0; see `LICENSE`. The papers are published under Creative Commons Attribution 4.0 on Zenodo.
