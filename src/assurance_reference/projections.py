"""Read-only views of exported reference evidence, with a DSSE attestation."""

from __future__ import annotations

import argparse
import copy
import json
from hashlib import sha256
from pathlib import Path

from assurance_reference.projection_completeness import chain_names, complete_snapshot_views
from regulated_core.canonical import canonical_bytes
from regulated_core.reporting import project_dsse_attestation
from regulated_core.signing import Ed25519Signer, Signature, Signer, TrustDirectory


def _checked_chains(bundle: dict) -> tuple[list[dict], list[dict]]:
    """Check chain consistency under bundled keys, not deployment identity or completeness."""
    trust = TrustDirectory()
    for key_id, public in bundle["public_keys"].items():
        trust.register(key_id, bytes.fromhex(public))
    heads, trace = [], []
    tenants = set()
    names = chain_names(bundle)
    for name in names:
        if name not in bundle:
            continue
        entries = bundle[name]
        if not entries:
            raise ValueError(f"empty evidence chain: {name}")
        tenant = entries[0]["record"]["tenant_id"]
        domain = entries[0]["domain"]
        signer = entries[0]["signature"]["key_id"]
        if not tenant or tenant in tenants or not domain:
            raise ValueError("each chain needs a distinct tenant and a clock domain")
        tenants.add(tenant)
        previous = "0" * 64
        previous_time = -1
        for seq, entry in enumerate(entries):
            record = entry["record"]
            if (
                entry["seq"] != seq
                or entry["prev_hash"] != previous
                or record["tenant_id"] != tenant
                or entry["domain"] != domain
                or entry["signature"]["key_id"] != signer
            ):
                raise ValueError("inconsistent evidence chain")
            if record["decided_at_us"] < previous_time:
                raise ValueError("evidence time goes backwards")
            previous_time = record["decided_at_us"]
            if sha256(canonical_bytes(record)).hexdigest() != entry["record_hash"]:
                raise ValueError("record digest mismatch")
            link = {key: entry[key] for key in ("seq", "prev_hash", "record_hash")}
            body = dict(link, schema="regulated/evidence/v2", clock_domain=domain)
            if not trust.verify(body, Signature(**entry["signature"])):
                raise ValueError("evidence signature does not verify")
            previous = sha256(
                canonical_bytes(
                    dict(link, schema="regulated/evidence-chain/v2", clock_domain=domain)
                )
            ).hexdigest()
            trace.append(
                {
                    "source": f"{name}[{seq}]",
                    "tenant": tenant,
                    "sequence": seq,
                    "record_hash": entry["record_hash"],
                    "previous_chain_hash": entry["prev_hash"],
                    "chain_hash": previous,
                    "signer": signer,
                    "decision": copy.deepcopy(record["decision"]),
                }
            )
        heads.append({"source": name, "tenant": tenant, "head": previous, "entries": len(entries)})
    if not heads or heads[0]["source"] != names[0]:
        raise ValueError("the primary evidence chain is required")
    return heads, trace


def project(bundle: dict, signer: Signer, *, complete: bool = False,
            system_name: str = "", provider: str = "") -> dict:
    """Derive views without changing the source or interpreting approval as permission."""
    source = copy.deepcopy(bundle)
    regulator, inventory = None, None
    if complete:
        regulator, inventory = complete_snapshot_views(source, system_name=system_name, provider=provider)
    heads, trace = _checked_chains(source)
    source_digest = sha256(canonical_bytes(source)).hexdigest()
    lines = ["# What the record says", "", f"Canonical source SHA-256: `{source_digest}`", ""]
    for item in trace:
        decision = item["decision"]
        kind = decision["kind"]
        reasons = decision["reason_codes"]
        if kind == "require-approval":
            label = "Approval required; this decision alone does not permit release"
        elif kind == "deny":
            label = "Denied"
        elif kind == "allow" and "OUTCOME_COMMITTED" in reasons:
            label = "Recorded committed outcome"
        elif kind in ("allow", "allow-with-annotation"):
            label = "Policy allowed; this alone does not prove a completed effect"
        else:
            label = f"Recorded decision: {kind}"
        lines.append(
            f"- {item['tenant']} / {item['sequence']}: {label}. Reasons: {', '.join(reasons)}."
        )
    limits = [
        "Decision-chain hashes and signatures checked under the included public keys; no independent identity anchor.",
        "Approval, permit and verifier objects are preserved; this projection does not requalify them.",
        "A consistent exported prefix does not prove that the source log is complete or current.",
        "The report signature binds this snapshot; it grants no execution authority.",
        "No clinical, deployment-custody, physical-expiry or regulatory-compliance qualification.",
    ]
    lines += ["", "## Scope", ""] + [f"- {limit}" for limit in limits]
    human = "\n".join(lines) + "\n"
    audit = {
        "schema": "reference/audit-view/v1",
        "source_digest": source_digest,
        "heads": heads,
        "trace": trace,
        "limits": limits,
    }
    if complete:
        audit["field_inventory"] = inventory
        audit["record_fields_complete"] = True
        audit["completeness_basis"] = regulator["completeness_basis"]
        audit["application_evidence_complete"] = False
    # The core's DSSE projector is reused with no emission_permit field: a permit is
    # not evidence that its output was emitted. Preserve the full source instead.
    evidence = {
        "schema": "reference/evidence-projection/v1",
        "evidence_head_hash": heads[0]["head"],
        "canonical_source_sha256": source_digest,
        "source_bundle": source,
        "audit": audit,
        "human_report_sha256": sha256(human.encode("utf-8")).hexdigest(),
        "limits": limits,
    }
    if complete:
        regulator["source_digest"] = source_digest
        regulator["verified_chain_heads"] = copy.deepcopy(heads)
        regulator["limits"] = copy.deepcopy(limits)
        evidence["regulator"] = regulator
    views = {
        "human": human,
        "audit": audit,
        "attestation": project_dsse_attestation(signer, evidence),
    }
    if complete:
        views["regulator"] = regulator
    return views


def run(evidence: Path, output: Path, *, complete: bool = False,
        system_name: str = "", provider: str = "") -> dict:
    raw = evidence.read_bytes()
    bundle = json.loads(raw)
    signer = Ed25519Signer("reference:projection-snapshot")
    views = project(bundle, signer, complete=complete, system_name=system_name, provider=provider)
    output.mkdir(parents=True, exist_ok=False)
    (output / "source-evidence.json").write_bytes(raw)
    (output / "reader.md").write_text(views["human"], encoding="utf-8", newline="\n")
    for name, data in (
        ("audit.json", views["audit"]),
        ("attestation.dsse.json", views["attestation"]),
    ):
        (output / name).write_bytes(canonical_bytes(data) + b"\n")
    if complete:
        (output / "regulator.json").write_bytes(canonical_bytes(views["regulator"]) + b"\n")
    receipt = {
        "source_file_sha256": sha256(raw).hexdigest(),
        "signer": signer.key_id,
        "public_key_hex": signer.public_key_bytes.hex(),
        "key_custody": "ephemeral local demo key",
    }
    (output / "projection.json").write_bytes(canonical_bytes(receipt) + b"\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--complete-records", action="store_true")
    parser.add_argument("--system-name", default="")
    parser.add_argument("--provider", default="")
    args = parser.parse_args()
    print(json.dumps(run(args.evidence, args.output, complete=args.complete_records,
                         system_name=args.system_name, provider=args.provider), indent=2))


if __name__ == "__main__":
    main()
