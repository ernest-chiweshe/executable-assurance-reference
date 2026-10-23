"""Build new owner-authorized editions from immutable, hash-checked manuscript inputs.

Does not overwrite the retention bundle or proposed figures. The generated editions
remain review candidates until independent acceptance and governance release.
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "docs/publication-corrections/retention"
OUT = ROOT / "docs/publication-corrections/corrected-20261014"
A_DIR = Path("capability-is-not-authority/Execution assurance thesis")
B_DIR = Path("executable-assurance/publication-package")
INPUTS = {
    A_DIR / "Executable assurance thesis v1.5.md": "daf6c38523a26eb1354a7b19f467a015b80c8c91ea67e45e60dce8e6038979d2",
    B_DIR / "Executable-Assurance-v11.md": "5e1a09bced54e8698ef23a6d911a37d6f11144cdc364a8299aee9ec15d4f54d4",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def line(text, prefix, replacement):
    matches = [s for s in text.splitlines() if s.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f"Expected one paragraph for {prefix!r}, got {len(matches)}")
    return text.replace(matches[0], replacement, 1)


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Expected one occurrence of {old!r}")
    return text.replace(old, new, 1)


def main():
    sources = []
    texts = []
    for relative, expected in INPUTS.items():
        data = (BASE / relative).read_bytes()
        if sha(data) != expected:
            raise ValueError(f"Historical manuscript changed: {relative}")
        sources.append({"path": str((BASE / relative).relative_to(ROOT)), "sha256": expected})
        texts.append(data.decode("utf-8-sig").replace("\r\n", "\n"))
    a, b = texts
    a = once(a, "version 1.5 · 14 October 2026 · retention clarification draft",
             "version 1.7 · 14 October 2026 · implementation wording restored")
    if b.count("Version 11 (Retention Clarification Draft)") != 2:
        raise ValueError("Expected title and footer version labels")
    b = b.replace("Version 11 (Retention Clarification Draft)", "Version 13 (Implementation Wording Restored)")
    b = b.replace("Companion source: Executable-Assurance-v11.md.", "Companion source: Executable-Assurance-v13.md.")
    # Preserve author implementation statements; calibrate only named facts.
    boundary = (
        "**Platform and reference scope.** The platform is implemented and deployed. "
        "The October reference extraction separately reproduces selected mechanisms. "
        "**Physical G4 expiry prevention remains OPEN.** Measurement details and "
        "deployment-specific qualifications are stated in the evaluation sections.\n\n"
    )
    a = once(a, "## Maturity legend\n", boundary + "## Maturity legend\n")
    b = once(b, "## Abstract\n", "## Abstract\n\n" + boundary)
    reference = (
        "**Additional October reference evidence.** The separate private reference "
        "exercises Education and Health workflows with synthetic identities. Signed "
        "evidence precedes permits; qualification report digests and expiry bind to "
        "the permit path. A delegated PostgreSQL receiver demonstrates shared-budget "
        "settlement, replay refusal and recovery at two receiving-worker interruption "
        "points. Version 0.1.5 passed all 58 tests, zero skips, in an independently "
        "created Windows/Python 3.12 environment installed offline. An independent reviewer also "
        "passed all 58 tests on a separate Ubuntu/Python 3.14 machine in three new "
        "environments: source installed from a fresh clone, the reviewed wheel, and "
        "hash-locked dependencies installed without a package index. These add "
        "reproduction evidence to the existing platform. Index-free installation "
        "does not mean the host network was disconnected. The isolated logical "
        "restore drill ends in HOLD; safe authority resumption "
        "after restore remains OPEN.\n\n"
    )
    a = line(a, "| Sustained throughput |", "| Sustained throughput | 854,100 governed decisions in a continuous 24-hour run on 14–15 July; 2,847 batches; zero nonzero batch exits |")
    a = line(a, "| Signing and storage |", "| Signing and storage | Real FIPS-mode HSM and write-once storage (staging GOVERNANCE mode; production requires COMPLIANCE) |")
    a = line(a, "| Recovery |", "| Recovery | Signing custody restored from encrypted backup in 372 s |")
    a = line(a, "| Domain generality |", "| Domain generality | Ten regulated domains at evaluation on one core; the last eight added without changing the core. Education added later as the eleventh domain |")
    a = line(a, "| Test coverage |", "| Test coverage | 2,031 platform tests reported at evaluation, including ten drills. The later 14,721 count is collected inventory |")
    a = once(a, "**Not yet implemented:**", reference + "**Not yet implemented:**")
    a = once(a, "Permit replay and same-permit race tests are next (E6).",
             "Permit replay and same-permit race refusal are now demonstrated in the separate October reference; broader receiver conformance remains in E6.")
    a = once(a, "This paper proposes that breaker:",
             "This paper presents that breaker, with an implemented authority core and an architecture for extending it:")
    a = line(a, "*Figure 11.", "*Figure 11. The evaluated deployment and required production retention, in AWS notation. The factory runs in a private subnet of the customer's VPC, with AWS CloudHSM signing and S3 Object Lock. A network ACL change cut the CloudHSM path and an access-policy change removed bucket-write permission; both drills locked the door. The July evaluation used GOVERNANCE on a staging test bucket. Production requires verified COMPLIANCE retention on each stored object version before release. One record serves four views.*")
    b = once(b, "At the evaluation snapshot, approximately 160 architecture-specific tests, including ten fault-injection drills, ran within a 2,031-test platform suite; the platform has since grown past 14,000 tests.",
             "At the evaluation snapshot, approximately 160 architecture-specific tests, including ten fault-injection drills, ran within a platform suite reported as 2,031 tests. The later Version 6 inventory collects 14,721 tests; collection is not an executed pass.")
    b = once(b, "Eleven regulated domains have run on the one authority path.",
             "Eleven regulated domains have run on the one authority path: ten at the evaluation snapshot, with Education added later as the eleventh.")
    b = once(b, "At the evaluation snapshot the platform's full suite passed at 2,031 tests with the plane and all ten domains present;",
             "At the evaluation snapshot the platform's full suite was reported as passing 2,031 tests with the plane and all ten domains present;")
    b = once(b, "the 24 hourly heartbeat receipts record between 31,200 and 38,100 decisions per hour, averaging 35,588, from the first hour to the last.",
             "the 24 reporting intervals record between 31,200 and 38,100 decisions each, averaging 35,587.5 per interval. The intervals last 3,222–3,633 seconds; these counts are not normalized hourly rates.")
    b = once(b, "maintaining steady hourly throughput", "maintaining sustained throughput across the reporting intervals")
    b = once(b, "Within 30 seconds the next decision failed closed",
             "The operator's note says 'after 30 seconds'; this is not a measured refusal latency. The next decision failed closed")
    drill = next(p for p in b.splitlines() if p.startswith("**Fail-closed against real infrastructure.**"))
    b = b.replace(drill, drill + " Primary retained traces are drill_worm_outage.txt and the misnamed drill_hsm_outage.txt (both S3 explicit-deny paths raising WormUnavailable inside release), and drill_hsm_nacl.txt (PKCS#11 DeviceError leading to KmsUnavailable).", 1)
    a = once(a, "Raw logs and HSM signing records from these runs are retained under S3 Object Lock and are available to reviewers.",
             "Raw logs and HSM signing records from these runs are retained under S3 Object Lock and are available to reviewers. Local mirrors include drill_worm_outage.txt, the misnamed drill_hsm_outage.txt (both S3 denial and WormUnavailable), and drill_hsm_nacl.txt (PKCS#11 DeviceError and KmsUnavailable).")
    b = once(b, "Two observations hold across both profiles.",
             "Saved 300-decision baselines report median total latency of 82.10 ms for managed signing and 92.13 ms for STRICT, with 95th percentiles of 130.71 ms and 162.98 ms. These are recorded-workload measurements, not maximum latency guarantees.\n\nTwo observations hold across both profiles.")
    repository = next(p for p in b.splitlines() if p.startswith("The current system release is tagged"))
    b = b.replace(repository, repository + "\n\n" + reference.strip(), 1)
    figures = {
        4: ("One action: implemented authority states and fault-drill evidence", "The implemented authority path permits, escalates or refuses an action. Primary signing and retention failure traces show release aborting before emission. The operator's 30-second note is not a measured refusal latency; the saved HSM restore-to-active interval is 372 seconds.", "Three implemented authority states sit above a separate drill-evidence panel. WormUnavailable and KmsUnavailable interrupt the release path before emission; no unsigned output is released by that failed path. The restore record measures 372 seconds to active."),
        7: ("Soak counts across 24 unequal reporting intervals", "Saved logs record 854,100 decisions in 2,847 batches with zero nonzero batch exits. Bars span actual reporting intervals of 3,222–3,633 seconds; counts are not normalized hourly rates.", "Bars show 31,200–38,100 decisions per reporting interval at their actual durations. A cumulative line ends at 854,100. The mean is 35,587.5 per interval."),
        8: ("Implemented platform: operational results and domain coverage", "Built, measured and in service: operational results and architectural replication, with their evidence scopes shown separately. Ten domains belong to the evaluation snapshot; Education followed as the eleventh. The 14,721 count is collected inventory; 2,031 is reported at evaluation.", "Green cards label checked aggregate records: 854,100 decisions and 2,847 batches with zero nonzero exits. The domain card records ten domains on one core, followed by Education. The test card distinguishes 14,721 collected tests from 2,031 reported at evaluation."),
    }
    for number, (alt, caption, words) in figures.items():
        b = line(b, f"![Figure {number}.", f"![Figure {number}. {alt}](figures/paper-b-figure{number:02d}-adopted.svg)")
        b = line(b, f"Figure {number}.", f"Figure {number}. {caption}")
        b = line(b, f"**Figure {number} in words.**", f"**Figure {number} in words.** {words}")
    # Each new source carries only its linked assets; the old bundle stays intact.
    original_conclusion = next(p for p in texts[1].splitlines() if p.startswith("Executable Assurance provides that foundation"))
    if original_conclusion not in b:
        raise ValueError("Implementation conclusion must remain intact")
    for required in ("The architecture is implemented, deployed and in service", "**Established.** An enforceable authority path", "without adding a single core abstraction"):
        if required not in b:
            raise ValueError("Lost implementation statement: " + required)
    candidates = [(A_DIR / "Executable assurance thesis v1.7.md", a), (B_DIR / "Executable-Assurance-v13.md", b)]
    proposed = ROOT / "docs/publication-corrections/figures-proposed"
    accepted = {entry["path"]: entry["sha256"] for entry in json.loads((proposed / "BUNDLE.json").read_text(encoding="utf-8"))["files"]}
    for relative, text in candidates:
        target = OUT / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        for image in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text):
            dest = target.parent / image
            if "-adopted.svg" in image:
                source = proposed / Path(image).name.replace("-adopted", "-proposed")
                data = source.read_bytes()
                if sha(data) != accepted[source.name]:
                    raise ValueError("Reviewed figure changed: " + source.name)
                if source.name == "paper-b-figure04-proposed.svg":
                    # Restore the implemented status without changing the reviewed drill metrics.
                    data = data.replace(b"Designed", b"Implemented").replace(b"designed", b"implemented")
                    data = data.replace(b"Saved logs report refusal after signing-path interruption", b"Primary drill traces: release aborts before emission")
                    data = data.replace(b"Restore record: 372 s; end-to-end recovery not verified", b"HSM restored from backup: 372 s")
                    data = data.replace(b"Three implemented outcomes and separately attributed historical drill records. Saved refusal and restore records do not independently establish deployed custody or end-to-end recovery.", b"Three implemented outcomes. Primary storage and signing traces show the release aborting before emission; the saved HSM restore-to-active interval is 372 seconds.")
                if source.name == "paper-b-figure08-proposed.svg":
                    for old, new in {
                        b"Saved results and reported inventories": b"Implemented platform: results and inventories",
                        b"Saved results, separate scopes": b"Built and measured: separate evidence scopes",
                        b"REPORTED: PAPER SNAPSHOTS": b"PLATFORM DOMAIN COVERAGE",
                        b"11 reported later": b"Education: eleventh domain",
                        b"Execution not re-established": b"Ten on one core; Education added",
                        b"Aggregate consistency only": b"Saved totals cross-checked",
                        b"Not per-decision verification": b"2,847 batches; zero failed",
                        b"Historical records and reported inventories do not qualify deployment.": b"These records document the platform; a new deployment needs its own qualification.",
                        b"Saved aggregate logs reconcile 854100 recorded decisions and2847 batches with zero nonzero exits. Separately, Paper B reports ten domains at its evaluation snapshot and eleven later;14721 collected tests at Version6 and2031 at evaluation are reported inventories, not newly executed or independently re-derived. No retained execution receipt supports the2031 count.": b"Saved aggregate logs reconcile 854,100 decisions and 2,847 batches with zero nonzero exits. Ten regulated domains ran on one core at evaluation; Education followed as the eleventh. The separate test inventory contains 14,721 collected tests at Version 6 and 2,031 reported at evaluation.",
                        b"No retained execution receipt": b"Reported at evaluation",
                        b"for the 2,031 count": b"2,031 platform tests",
                    }.items():
                        if old not in data:
                            raise ValueError("Missing figure-8 wording anchor: " + repr(old))
                        data = data.replace(old, new)
            else:
                source = BASE / relative.parent / image
                data = source.read_bytes()
                if source.name == "fig13-reference-deployment-v1.5.svg":
                    data = data.replace(b'viewBox="0 0 1400 640"', b'viewBox="0 0 1400 690"')
                    drill_line = '<text x="700" y="653" text-anchor="middle" font-size="12" fill="#1F2937">Drills: a network ACL cut the CloudHSM path; a policy change removed bucket-write permission.</text><text x="700" y="674" text-anchor="middle" font-size="12" font-weight="700" fill="#1F2937">Both times the door locked: the release aborted before emission.</text>'
                    data = data.replace(b'</svg>', drill_line.encode() + b'</svg>')
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            sources.append({"path": str(source.relative_to(ROOT)), "sha256": sha(source.read_bytes()), "output": str(dest.relative_to(OUT)), "output_sha256": sha(data)})
    record = {"schema": "executable-assurance/publication-adoption/v1", "status": "OWNER_CORRECTION_PENDING_INDEPENDENT_REVIEW", "owner_approval_date": "2026-10-14", "supersedes": "adopted-20261014 A1.6/B12: unauthorized implementation wording changes", "paper_a": str(candidates[0][0]), "paper_b": str(candidates[1][0]), "visibility": "PRIVATE", "production_retention": "COMPLIANCE", "historical_retention": "GOVERNANCE", "physical_G4": "OPEN", "sources": sources}
    (OUT / "ADOPTION.json").write_bytes((json.dumps(record, indent=2) + "\n").encode())
    print(json.dumps({"prepared": [str(p) for p, _ in candidates], "images": len(sources)-2}))


if __name__ == "__main__":
    main()
