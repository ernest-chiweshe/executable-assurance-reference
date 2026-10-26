# Install the reviewed package in a fresh environment

> **Current release:** for 0.1.8rc6 and later, verify the release files against `SHA256SUMS` and follow `REPRODUCE.txt`. This page records the earlier reviewed 0.1.5 installation. Its retained Linux lock (`qualification/linux-20261014/requirements-linux-locked.txt`) pins cryptography 49.0.0, which carries advisory GHSA-g6cj-pr64-35w5 (PKCS#7 decryption, a feature this code does not use; fixed in 50.0.0). Current releases pin cryptography 50.0.2; keep the old lock as a historical record only.

Use Python 3.11 or later. The reviewed runs used Windows/Python 3.12 and a
separate Ubuntu/Python 3.14 machine. A fresh Python environment excludes inherited
Python packages; deployment identity, custody and recovery need separate evidence.

Version 0.1.7 is built from the v12 candidate 062 tree (candidate 060, the issuer budget assertion, and four public evidence files the 0.1.6 inclusion list omitted); 0.1.6 was never accepted and is superseded. Its wheel and source
archive hashes are recorded outside the tree, in the packaging review packet (PACKAGE.json), because an archive cannot
contain its own digest; they are not reviewed installation evidence until that packet is accepted.

The artifact hashes below identify the earlier reviewed 0.1.5 installation.
They do not cover subsequent v12 source candidates. Those candidates retain
their own source manifests and validation records; a new installed-package
qualification remains pending until it is run against exact new package bytes.

Check the exact artifacts before installing. A version number alone is not enough:

| Artifact | SHA-256 |
|---|---|
| `executable_assurance_reference-0.1.5-py3-none-any.whl` | `d9872cc6358eafee3e957d8d8eee83712feb91a08f2946326edf684264041df1` |
| `executable_assurance_reference-0.1.5.tar.gz` | `ebcf79d0074b423560e56ec109162186ccab7af5ae01bc6ffeffe3eecff64834` |

Several earlier candidates also say 0.1.5. Only these bytes carry the reviewed
installation evidence. The [separate-machine record](separate-machine.md)
identifies the Linux run and dependency hashes.

The database must be named **exactly `factory_test`**. The examples refuse other
names. On a new machine, create an empty database in a new, dedicated test
cluster; do not rename, drop or repurpose an existing database. Current v12
validation on Windows and Linux uses newly owned, loopback-only clusters and
explicit isolated ports. Keep the standing database out of these runs. Coordinate
the serial database window before starting a cluster on a shared test host.

```powershell
python -m venv "$runRoot/venv"
& "$runRoot/venv/Scripts/python.exe" -m pip install "<reviewed wheel path>[test]"
& "$runRoot/venv/Scripts/python.exe" -m pip check
$env:FACTORY_TEST_DB_URL = "<connection string for your newly owned factory_test cluster>"
& "$runRoot/venv/Scripts/assurance-demo.exe" --output "$runRoot/lesson"
& "$runRoot/venv/Scripts/assurance-health-demo.exe" --output "$runRoot/health"
```

Never reuse an output folder. Keep the source distribution beside the wheel:
it includes the tests, their process worker, source provenance, technical scripts
and an explicit list of installation and A21 provenance documents. The wheel
contains runtime packages and signed fixtures. Tests are not installed as a
runtime package.

Current packaging excludes owner records, authority-scope documents and paper
drafts from the source archive. Their publication scope remains an owner decision.
They are retained in the private source candidate, with unchanged hashes. Full
publication, obligation and source-trace audit checks require that separately
retained candidate: the source archive alone is not a self-contained full audit
bundle, and collecting every test without those assets can fail. Do not skip
those checks and call the result full qualification. The full-suite commands
below require the complete, hash-verified private audit source. Earlier reviewed
artifact hashes describe their original contents, not this packaging revision.

When validating an accepted v12 source adaptation, pass its recorded
`--source-adaptation-manifest` and independently accepted
`--source-adaptation-sha256` explicitly to pytest. Use the values bound by the
exact checkpoint's acceptance evidence; package version 0.1.5 does not select a
source adaptation. Omitting these options retains strict source tracing. An
archive build or installation smoke check does not replace the complete private
audit or full runtime regression.

For offline reproduction, retain the dependency wheels and their hashes. Install
using `--no-index --find-links <wheelhouse>` and the reviewed wheel, then run
`pip check`. This checks dependency consistency, not supply-chain authenticity.
The direct runtime dependencies are pinned in `pyproject.toml`; a retained
dependency-wheel manifest identifies the exact transitive versions used in a run.
Wheelhouses are platform- and Python-specific: the Windows wheelhouse is not a
Linux dependency bundle. The retained Linux lock file covers the tested x86-64
Ubuntu/Python 3.14 environment. `--no-index` means no package-index lookup; the
qualification did not physically disconnect the host network.

## Linux: a dedicated test service and a new environment

With PostgreSQL server/client binaries and Python's venv support already installed,
choose a fresh folder. The example uses a private, loopback-only cluster and a
local trust-authenticated test login. It is not a production authentication setup.
Choose an available loopback port. If another process takes it before PostgreSQL
starts, let startup fail and choose a new port; do not stop that process.

```sh
set -eu
runRoot=$(mktemp -d "$HOME/ea-reference.XXXXXXXX")
PG_BIN=$(pg_config --bindir)
pgPort=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
mkdir "$runRoot/socket"
"$PG_BIN/initdb" -D "$runRoot/pgdata" --auth-local=trust --auth-host=trust
"$PG_BIN/pg_ctl" -D "$runRoot/pgdata" -l "$runRoot/postgres.log" \
  -o "-h 127.0.0.1 -p $pgPort -k $runRoot/socket" -w start
trap '"$PG_BIN/pg_ctl" -D "$runRoot/pgdata" -m fast -w stop' EXIT
"$PG_BIN/createdb" -h 127.0.0.1 -p "$pgPort" -U "$USER" factory_test
export FACTORY_TEST_DB_URL="host=127.0.0.1 port=$pgPort user=$USER dbname=factory_test"
export PYTHONNOUSERSITE=1
unset PYTHONPATH
python3 -m venv "$runRoot/venv"
```

Set `wheel` to the reviewed wheel's absolute path and `wheelhouse` to the retained
Linux wheels. From this checkout, verify and install the exact package:

```sh
printf '%s  %s\n' d9872cc6358eafee3e957d8d8eee83712feb91a08f2946326edf684264041df1 "$wheel" | sha256sum --check -
"$runRoot/venv/bin/python" -m pip install --no-index --require-hashes \
  --find-links "$wheelhouse" -r docs/qualification/linux-20261014/requirements-linux-locked.txt
"$runRoot/venv/bin/python" -m pip install --no-index --no-deps "$wheel"
"$runRoot/venv/bin/python" -m pip check
"$runRoot/venv/bin/assurance-demo" --output "$runRoot/lesson"
"$runRoot/venv/bin/assurance-health-demo" --output "$runRoot/health"
```

Verify the source archive against the table above, extract it into a fresh folder,
and run its tests with the installed environment's Python:

```sh
cd /path/to/extracted/executable_assurance_reference-0.1.5
"$runRoot/venv/bin/python" -m pytest -p no:cacheprovider --basetemp "$runRoot/tests"
"$PG_BIN/pg_ctl" -D "$runRoot/pgdata" -m fast -w stop
trap - EXIT
```

Retain the logs, outputs and test data for review. The stop command targets only
the new cluster created above. Run the blocks in the same shell; its exit trap
also stops that owned cluster if a later command fails. Do not run cleanup
against a shared data directory.

Run the tests from the extracted source distribution with the environment's
Python. Remove `PYTHONPATH`, disable user-site packages and avoid editable
installation. Verify that imported `assurance_reference`, `factory` and
`regulated_core` modules come from the environment's `site-packages`.

The declaration-isolation test deliberately opens the source distribution's
pure declaration module with site packages disabled. Provenance and publication
checks also read retained source assets. Those checks complement the installed
runtime tests; they are not installed-runtime evidence themselves.

Do not substitute the old 0.1.4 wheel for later source checkpoints or call a
successful build an accepted installation. Version 0.1.5's exact wheel hashes,
dependency hashes, import origins, run outputs and independent verdicts belong
in the release evidence. Check those records before treating a candidate as
accepted.

Windows virtual environments use a Python redirector. The recovery test therefore
records both launcher and worker IDs, checks their parent relationship and kills
only that owned process tree. A retained synchronize-only process handle confirms
the actual worker has exited before any database-state check or reconciliation.
The original rollback, receipt and replay checks
remain unchanged. The standing database is never terminated. See Python's
[venv documentation](https://docs.python.org/3.11/library/venv.html) and Microsoft's
[taskkill tree semantics](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill).

The signed Health workspace-membership qualification fixture contains private owner requirements. The entire unchanged bundle at src/assurance_reference/fixtures/packs/bundles/health-workspace-membership is retained only in the complete private candidate and omitted from both archives. Removing one signed knowledge file would invalidate the bundle, so no partial bundle is shipped. The default local clinical qualification fixture requires this retained private bundle; an archive-only installation cannot run that fixture or full qualification. Education bundles, Health runtime code and the explicit synthetic Health fixture path remain included. This is a packaging boundary, not an exclusion of Health obligations or a full installed-Health qualification claim.
