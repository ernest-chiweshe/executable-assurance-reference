# The reviewed wheel runs on a second machine

> **Current release:** for 0.1.8rc6 and later, verify the release files against `SHA256SUMS` and follow `REPRODUCE.txt`. This page records the earlier reviewed 0.1.5 installation. Its retained Linux lock (`qualification/linux-20261014/requirements-linux-locked.txt`) pins cryptography 49.0.0, which carries advisory GHSA-g6cj-pr64-35w5 (PKCS#7 decryption, a feature this code does not use; fixed in 50.0.0). Current releases pin cryptography 50.0.2; keep the old lock as a historical record only.

the implementer independently reproduced version 0.1.5 on a separate physical Linux
machine on 14 October 2026. Ubuntu 26.04.1, Python 3.14.4 and PostgreSQL 18.6
differ from the earlier Windows/Python 3.12 host. the governor accepted this bounded
closure of the same-machine limitation.

| Installation | Result |
|---|---|
| Fresh clone of private `origin/main` at `73fe7787d1d3da8655eadaf5194579f1c7be9a62`; new venv; non-editable source install | 58 passed; both examples passed; dependency check clean |
| Reviewed wheel installed into another new venv; tests from reviewed source archive | 58 passed; all four console commands ran; both examples passed |
| Third new venv; retained Linux dependency wheels installed with `--no-index --require-hashes`, then reviewed wheel with `--no-index --no-deps` | 58 passed; both examples passed; dependency check clean |

The last run establishes an **index-free, hash-locked installation**. The host
network was not physically disconnected. The first two installations fetched
dependencies from PyPI; their results alone did not establish offline installation.

The database was a newly initialized, ordinary-user PostgreSQL cluster under
the implementer's Linux scratch, bound to loopback port 55432. Its new database was named
`factory_test` to satisfy the existing guard. The Windows standing database,
Linux system cluster and `factory-postgres` volume were untouched. The private
cluster was stopped after testing and retained.

## Exact artifacts and evidence

| Item | SHA-256 |
|---|---|
| Reviewed 0.1.5 wheel | `d9872cc6358eafee3e957d8d8eee83712feb91a08f2946326edf684264041df1` |
| Reviewed 0.1.5 source archive | `ebcf79d0074b423560e56ec109162186ccab7af5ae01bc6ffeffe3eecff64834` |
| Linux evidence index, 34 entries | `200f528f651cf5cc7760db0d9d6cd9c296f43990a0d590ecc2d8d5972221405f` |
| Source/wheel evidence archive | `c50e8dfe0fe1a7eb5b2af056e781297ebfa5a263a46a8034e1422574109d9556` |
| Index-free installation evidence archive | `4f858d7e71d559010fa6471b2f2cdaaf7ef663b02e1e36e8ebad38c07f561eae` |

The [index](qualification/linux-20261014/INDEX.sha256),
[dependency lock](qualification/linux-20261014/requirements-linux-locked.txt),
[wheel hashes](qualification/linux-20261014/wheelhouse-linux.sha256) and
[installed versions](qualification/linux-20261014/freeze-offline.txt) are retained
here byte-for-byte. The index paths are relative to the original evidence root,
not this documentation directory:

`private-evidence/clean-machine-linux-20261014/`

The archives, logs, outputs and dependency wheels remain there. the verifier independently
recomputed the index hash and all 34 file hashes before adding these references.
the implementer's original failed attempt is preserved: it used another database name
and hit the existing guard. The subsequent passes created the required empty
`factory_test` database; no guard was removed or relaxed.

Ledger anchors: source/wheel results `1c99a5d4731ce5478f46ab1c6cf1cee9a375479c8dc2f59494239146d379cbe4`;
index-free run `b3dc59ed3235efa9845ba4a9d363b69d4753ce888e30dde8f87654467718618c`;
the governor's initial Linux scope acceptance `c39dacdc3f9533f1c357dcf5aadd59ff4b40015c3e58a8f3f9c66160ffae9cae`.

## Limits

This establishes a second-host installation and the specified Linux runs. It
does not qualify every Python/PostgreSQL version, Windows on a clean operating
system, production credentials, clinical safety or deployed custody. The
[isolated restore check](isolated-restore.md) has its own evidence and limits.
Physical G4 and authority resumption after a database rollback remain open.
The reviewed wheel's runtime bytes are unchanged by these documentation updates.
