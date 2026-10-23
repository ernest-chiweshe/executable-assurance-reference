# Included abstract protocol model

The reference includes the original standard-library Python breadth-first state
explorer and recorded results, byte for byte. Source commit, paths and SHA256
values are recorded in `docs/provenance/protocol-model.json`. This is a Python
model, not a TLC run. No runtime dependency is added.

Run the packaged model, including after installing the wheel:

```console
python -B -m assurance_reference.protocol_model.check_protocol --json
```

Run its regression from the complete retained private candidate:

```console
python -B -m pytest tests/test_protocol_model.py -q -p no:cacheprovider
```

The regression verifies the original source and result hashes, reproduces all
three Table 1 baseline configurations and all seven Table 2 abstract variants,
and checks six deliberately inconsistent synthetic state snapshots against the
invariant predicates. The baseline state/transition counts are 176/604, 576/2184
and 1456/5622. Exact structured results, including the recorded symbolic traces,
must match the pinned `results.json` resource distributed in both archives.

The model manipulates immutable in-memory states. Its specification variants
do not change runtime controls, access a database, contact a network target or
perform external effects. They establish properties only at the recorded small
bounds. Clocks, network delay, cryptography, key compromise, reservation
reclamation, heterogeneous targets and model cognition are outside this model.
Runtime conformance (A19), physical timing and deployment safety remain separate
obligations. Inclusion and a passing local test do not by themselves promote
A18: independent review, full Windows/Linux regression and governance acceptance
remain required.

Only this model, its results and minimal provenance/qualification documentation
are added to package inclusion lists. Paper drafts and private owner records stay
outside distributable archives. Full audit checks still require the complete
retained private candidate.
