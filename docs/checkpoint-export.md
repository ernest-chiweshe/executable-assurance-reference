# Export a local checkpoint report

From a private source checkout or source archive, with the reference package
installed, run `python scripts/export_checkpoint_report.py --help`. This tool
verifies supplied A13 checkpoint observations and writes a local JSON report,
readable HTML report and `EXPORT.json` integrity receipt. It makes no network
calls and changes no receiving target or authority state.

Supply an evidence JSON list. Each element has `checkpoint`, `report` and
`receipts` from the existing reconciliation interfaces. Select a separate trusted
public-key file containing only `keys`, whose entries contain `key_id`,
`public_key_hex` and `alg` (`ed25519`). The host must establish the keys' authority
independently; accepting keys packaged by an evidence supplier does not do so.
No private signing key is needed.

Pass explicit `--issuer`, repeated `--witness`, `--tenant`, `--previous-digest`,
`--start-seq`, `--end-seq` and `--now-us` arguments. These pin the exact observation
position and verification time. Use an empty previous digest for an initial
position. The time is a host assertion; the tool does not establish a qualified
clock or current validity when the report is subsequently opened.

Use `--evidence`, `--trust` and `--output` to name the two input files and a **new**
output directory in an existing parent. Existing output paths are refused.
Evidence is limited to 4 MiB and 128 candidates; the trust file is limited to
128 KiB and 128 distinct keys. Inputs must be finite JSON without duplicate keys.

Exit status 0 means one verified checkpoint was observed within the supplied
scope. Exit status 1 means a report was exported with incomplete, discrepant or
conflicting observations; rejected evidence remains in the report. Exit status 2
means input or filesystem processing failed. After a filesystem failure, a new
directory may contain partial output; retain it for diagnosis. `EXPORT.json` is
written last, and readers should verify its listed file hashes.

All outputs are unsigned local evidence. Their hashes do not constitute an
authority signature. Protect read access because supplied evidence may contain
sensitive identifiers. Nothing here proves universal history completeness,
independent witness custody, delivery to a person or permission to publish. A13
remains subject to its outstanding operational evidence and independent review.
