"""D5 declaration-only pack builders using the existing signed bundle format.

The bundles request host evidence and credential checks; they never supply their
own checker implementation or source trust. These are offline demonstrations,
with expert applicability and production qualification deliberately outstanding.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from regulated_core.signing import Signer

from .examples import BUILD_TYPE, BUILDER_ID, finish_pack, write_cases, write_rulebook
from .manifest import PackManifest
from .registry import InstalledPack
from .rulebook import OVERLAY_SCHEMA, RULEBOOK_SCHEMA, validate_overlay
from .schema import SCHEMA_ID
from .signing import write_provenance

APPROVAL_SHA256 = "0d065f9446b92a7aa9b48e967f7697ab07ae263e67b03be05976c1d81b09c08c"
EVIDENCE_CHECK = "evidence:host-reviewed-snapshot"

# Product semantics live in declarations, outside the core and authority engines.
USES = {
    "investment-research": {
        "domain": "finance", "title": "Investment research brief", "data_class": "financial",
        "roles": ("research-principal", "compliance"),
        "purpose": "A dated source-grounded brief with material figures and conflict disclosures.",
        "prohibited": ("personalized investment advice", "trade execution", "guaranteed returns"),
    },
    "financial-onboarding": {
        "domain": "finance", "title": "Financial onboarding case packet", "data_class": "pii",
        "roles": ("compliance-reviewer",),
        "purpose": "A reviewable case with ownership evidence, discrepancies and a recorded resolution.",
        "prohibited": ("account opening", "sanctions clearance", "suspicious-activity filing"),
    },
    "patient-education": {
        "domain": "health", "title": "Patient education handout", "data_class": "phi",
        "roles": ("clinician",),
        "purpose": "An understandable projection of reviewed sources without patient identifiers.",
        "prohibited": ("diagnosis", "triage", "prescribing", "autonomous patient delivery"),
    },
}


def build_demonstration_pack(target: Path, *, use: str, publisher: Signer,
                             rulebook_authority: Signer, approved_requirements: bytes,
                             mission_limit: int = 1) -> PackManifest:
    """Build a fresh bundle; identity and signer trust are provisioned by the caller.

    No credentials, activation or production authority are minted here. The source
    lock describes the owner's demonstration requirement, not a legal instrument.
    """
    if use not in USES:
        raise ValueError("unknown D5 demonstration use")
    if hashlib.sha256(approved_requirements).hexdigest() != APPROVAL_SHA256:
        raise ValueError("the exact owner-approved D5 requirements are required")
    if type(mission_limit) is not int or mission_limit < 0:
        raise ValueError("mission limit must be a non-negative integer")
    if target.exists():
        raise ValueError("use a fresh bundle destination; existing artifacts are preserved")
    profile = USES[use]
    domain = str(profile["domain"])
    roles = list(profile["roles"])
    draft_action, release_action = f"{domain}:draft-{use}", f"{domain}:release-{use}"
    target.mkdir(parents=True)

    def write(name: str, value: object) -> None:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")

    schema = {
        "schema": SCHEMA_ID, "namespace": domain,
        "entity_types": {
            "Reviewer": {"parents": [], "roles": roles + ["government-reviewer", "industry-reviewer"],
                         "attributes": {"id": {"type": "string"}}},
            "EvidencePacket": {"parents": [], "attributes": {"id": {"type": "string"}}},
        },
        "actions": {
            action: {"effect": effect,
                     "applies_to": {"principal_types": ["Reviewer"], "resource_types": ["EvidencePacket"]},
                     "context": {"nonce": {"type": "string"}}}
            for action, effect in ((draft_action, "reversible"), (release_action, "external"))
        },
    }
    checks = {
        "content:present": {"kind": "deterministic", "version": "1", "capability": "text.non-empty@1", "params": {}},
        EVIDENCE_CHECK: {"kind": "platform", "version": "1"},
    }
    content = {
        "schema": RULEBOOK_SCHEMA, "content_types": [f"{domain}:{use}"],
        "data_classes": [profile["data_class"]], "retention_years": 1,
        "checks": checks,
        "rules": {
            draft_action: {"required_checks": list(checks), "annotations": [
                {"kind": "disclaimer", "text": "Fictional offline demonstration; further review required."}]},
            release_action: {
                "required_checks": list(checks), "requires_lineage": True,
                "mission_budget": {"limit": mission_limit, "units": 1},
                "approval": {"role_groups": [[role] for role in roles], "minimum_approvers": len(roles),
                             "requester_may_approve": False, "expires_after_hours": 1},
                "card": {"indicator": "warning", "summary": f"Review the fictional {use} packet before release."},
            },
        },
    }
    write("schema/schema.json", schema)
    policy_digest = write_rulebook(target, authority=rulebook_authority, vertical=domain, policy_id=use,
                                   version="1.0.0", content=content, jurisdictions=("global",))
    write_cases(target, {"content:present": {"golden": [
        {"name": "content", "draft": "Fictional packet", "contract": {}, "expected": "pass"},
        {"name": "empty", "draft": " ", "contract": {}, "expected": "fail"},
    ]}})
    source = target / "knowledge" / "approved-requirements.md"
    source.parent.mkdir(parents=True)
    source.write_bytes(approved_requirements)
    guide = target / "kit" / "README.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(
        f"# {profile['title']} — offline demonstration\n\n## Journey\n\n{profile['purpose']}\n"
        "Host-supplied evidence is projected, checked and reviewed before the existing gate grants a permit.\n"
        "This bundle contains no customer records. Unresolved discrepancies refuse release.\n\n"
        "## Rulebook sources\n\nThe pinned owner-approved D5 requirement defines this demonstration.\n"
        "No legal applicability, clinical suitability or real issuer recognition is established.\n\n"
        f"## Approvers\n\nRequired roles: {', '.join(roles)}. Demonstration credentials are simulated.\n\n"
        "## Evidence\n\nPolicy, installed bundle, source snapshot, exact output and approval remain separately bound.\n"
        "Source updates invalidate old snapshot digests. Customer evidence stays in host custody.\n\n"
        f"Signed mission ceiling: {mission_limit} effect unit(s), one unit per release. "
        "This is a fictional resource policy, not a statutory limit.\n\n"
        "## Expert validation\n\nPending. The one-year fixture retention is not a statutory retention claim.\n"
        f"Excluded authority: {', '.join(profile['prohibited'])}. No production qualification is supplied.\n",
        encoding="utf-8",
    )
    manifest = finish_pack(target, {
        "id": f"lumiwright.demo.{use}", "version": "0.1.0", "kind": "base", "domain": domain,
        "title": str(profile["title"]) + " (offline demonstration)", "publisher": "simulated-publisher",
        "jurisdictions": ["global"], "license": "proprietary", "roots": [f"{domain}/{use}"],
        "capability": use, "scopes": [{"name": "reviewed-case-evidence", "data_class": profile["data_class"],
                                      "rationale": "review the bounded case; no autonomous downstream action"}],
        "dependencies": [], "vocabularies": [], "experts": {"required_roles": roles + ["privacy-officer"]},
        "workflow": {"stages": [
            {"id": "draft", "trigger": "request", "action": draft_action,
             "inputs": ["host-evidence"], "outputs": ["review-packet"]},
            {"id": "release", "trigger": "stage:draft", "action": release_action,
             "inputs": ["review-packet", "approval"], "outputs": ["release-receipt"]},
        ]},
        "rulebook": {"ref": f"{domain}/{use}@1.0.0", "digest": policy_digest, "path": "rulebook/rulebook.json"},
        "knowledge": {"sources": [{"id": "owner-d5", "title": "Owner-approved D5 demonstration requirements",
            "kind": "organization-policy", "edition": "2026-09-27", "effective_date": "2026-09-27",
            "licence": "owner-provided", "jurisdiction": "global", "digest": APPROVAL_SHA256}]},
        "collections": [], "conformance": {"expected_decisions": {release_action: "APPROVAL_REQUIRED"}},
    }, publisher=publisher)
    write_provenance(target, manifest, builder_id=BUILDER_ID, build_type=BUILD_TYPE,
                     external_parameters={"source": __name__, "pack": manifest.reference}, signer=publisher)
    return manifest


def build_demonstration_overlay(target: Path, *, base: InstalledPack, layer: str,
                                publisher: Signer, overlay_authority: Signer,
                                mission_limit: int | None = None) -> PackManifest:
    """Tighten review authority with a fictional government or industry layer.

    This demonstrates intersection of reviewer requirements and, when declared,
    a tighter effect budget. It does not grant policy-change authority or prove
    delegation attenuation. Runtime enforcement stays in the existing gate.
    """
    if layer not in ("government", "industry") or not base.manifest.id.startswith("lumiwright.demo."):
        raise ValueError("an overlay requires a known demonstration layer and installed demonstration base")
    if target.exists():
        raise ValueError("use a fresh overlay destination")
    role = layer + "-reviewer"
    action = base.rulebook.actions("external")[0]
    original = base.rulebook.effective_content["rules"][action]["approval"]
    groups = [list(group) for group in original["role_groups"]]
    if [role] in groups:
        raise ValueError("this demonstration layer has already contributed")
    groups.append([role])
    document = base.rulebook.document
    base_ref = f"{document.vertical}/{document.policy_id}@{document.version}"
    policy_id = document.policy_id + "." + layer
    rule: dict[str, object] = {"approval": {"role_groups": groups, "minimum_approvers": len(groups),
                                          "requester_may_approve": False}}
    if mission_limit is not None:
        parent_budget = base.rulebook.mission_budget(action)
        if parent_budget is None:
            raise ValueError("a resource overlay needs a declared parent mission budget")
        rule["mission_budget"] = {"limit": mission_limit, "units": parent_budget["units"]}
    content = {
        "schema": OVERLAY_SCHEMA, "base": base_ref,
        "organization": f"FICTIONAL {layer} issuer — no recognized regulatory authority",
        "rules": {action: rule},
    }
    problems = validate_overlay(content, base.rulebook.effective_content)
    if problems:
        raise ValueError("; ".join(problems))
    target.mkdir(parents=True)
    digest = write_rulebook(target, authority=overlay_authority, vertical=document.vertical,
                            policy_id=policy_id, version="1.0.0", content=content,
                            jurisdictions=("global",), name="overlay.json")
    guide = target / "kit" / "README.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(
        f"# Fictional {layer} overlay\n\n## Journey\n\nAdd one independent credentialed reviewer.\n\n"
        "## Rulebook sources\n\nOwner D5 demonstration of policy intersection; no legal rule is asserted.\n\n"
        f"## Approvers\n\nEvery base group plus {role}. No base group or check is removed.\n\n"
        "## Evidence\n\nThe signed base dependency and effective policy digests remain pinned.\n\n"
        + (f"Signed mission ceiling: {mission_limit} effect unit(s); the parent charge is retained.\n\n"
           if mission_limit is not None else "") +
        "## Expert validation\n\nNot reached. Issuer identity and approvals are simulated.\n"
        "Other covered effects require their actual adapters and separate evidence.\n", encoding="utf-8")
    manifest = finish_pack(target, {
        "id": base.manifest.id + "." + layer, "version": "0.1.0", "kind": "overlay",
        "domain": base.manifest.domain, "title": f"Fictional {layer} review overlay", "publisher": "simulated-publisher",
        "jurisdictions": ["global"], "license": "proprietary",
        "roots": [root + "/" + layer for root in base.manifest.roots], "capability": base.manifest.capability,
        "scopes": [], "dependencies": [base.reference], "vocabularies": [],
        "experts": {"required_roles": [role]}, "workflow": {"inherits": True},
        "rulebook": {"ref": f"{document.vertical}/{policy_id}@1.0.0", "digest": digest,
                     "path": "rulebook/overlay.json", "base": base_ref},
        "knowledge": {"sources": [source.to_dict() for source in base.sources]},
        "conformance": {"expected_decisions": {action: "APPROVAL_REQUIRED with every contributing group"}},
    }, publisher=publisher)
    write_provenance(target, manifest, builder_id=BUILDER_ID, build_type=BUILD_TYPE,
                     external_parameters={"source": __name__, "pack": manifest.reference}, signer=publisher)
    return manifest
