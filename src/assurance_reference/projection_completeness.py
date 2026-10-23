"""Field accounting and a regulator view of an exported decision snapshot.

The section layout follows the pinned reporting module. It is not a statement
that this export satisfies a regulation or that its application evidence is complete.
"""

import copy
from dataclasses import fields
from hashlib import sha256

from regulated_core.canonical import canonical_bytes
from regulated_core.models import Action, Annotation, ApprovalRequirement, Decision, DecisionRecord, PolicyRef


def chain_names(bundle):
    """Select a declared export layout without rewriting the retained source."""
    if "entries" in bundle and "chain" in bundle:
        raise ValueError("ambiguous primary evidence chain")
    if "chain" in bundle:
        if bundle.get("schema") != "reference/local-education-example/v1":
            raise ValueError("unsupported evidence chain layout")
        return ("chain", "tenant_boundary_entries")
    return ("entries", "tenant_boundary_entries")


def _require_fields(value, model, path):
    if not isinstance(value, dict):
        raise ValueError(f"required evidence object missing: {path}")
    missing = sorted(field.name for field in fields(model) if field.name not in value)
    if missing:
        raise ValueError(f"required evidence fields missing at {path}: {', '.join(missing)}")


def field_inventory(value, path=""):
    """Account for every JSON leaf, including nulls and empty containers."""
    if isinstance(value, dict) and value:
        rows = []
        for key in sorted(value):
            escaped = key.replace("~", "~0").replace("/", "~1")
            rows.extend(field_inventory(value[key], path + "/" + escaped))
        return rows
    if isinstance(value, list) and value:
        return [row for index, item in enumerate(value)
                for row in field_inventory(item, path + "/" + str(index))]
    return [{"source_pointer": path, "value_sha256": sha256(canonical_bytes(value)).hexdigest(),
             "retained_in": "attestation.predicate.source_bundle"}]


def complete_snapshot_views(bundle, *, system_name, provider):
    """Refuse omitted record fields before projection; preserve unknown extra fields.

    Structural completeness is separate from signature verification, credential
    qualification and proof that every applicable application artifact was exported.
    The caller must still verify the decision chains before issuing these views.
    """
    if not all(isinstance(value, str) and value.strip() for value in (system_name, provider)):
        raise ValueError("explicit host-supplied system and provider labels required")
    records = []
    for name in chain_names(bundle):
        if name not in bundle:
            continue
        if not isinstance(bundle[name], list):
            raise ValueError(f"required evidence list missing: /{name}")
        for index, entry in enumerate(bundle[name]):
            path = f"/{name}/{index}/record"
            if not isinstance(entry, dict):
                raise ValueError(f"required evidence object missing: /{name}/{index}")
            record = entry.get("record")
            _require_fields(record, DecisionRecord, path)
            for key, model in (("action", Action), ("policy", PolicyRef), ("decision", Decision)):
                _require_fields(record[key], model, path + "/" + key)
            decision = record["decision"]
            if decision["approval"] is not None or decision["kind"] == "require-approval":
                _require_fields(decision["approval"], ApprovalRequirement, path + "/decision/approval")
            if not isinstance(decision["annotations"], list):
                raise ValueError(f"required evidence list missing: {path}/decision/annotations")
            for number, annotation in enumerate(decision["annotations"]):
                _require_fields(annotation, Annotation, path + f"/decision/annotations/{number}")
            records.append({"source_pointer": path, "record": copy.deepcopy(record)})
    if not records:
        raise ValueError("complete projection requires decision records")
    inventory = field_inventory(bundle)
    outside = {"status": "not established by this decision snapshot",
               "required_from": "the responsible management system and applicable evidence"}
    regulator = {
        "schema": "reference/regulator-snapshot/v1",
        "format_basis": "section layout in pinned regulated_core.reporting; no conformity verdict",
        "1_general_description": {"system_name": system_name, "provider": provider,
                                  "label_source": "host-supplied, not independently authenticated"},
        "2_detailed_description": [{"source_pointer": item["source_pointer"],
            "assertion_id": item["record"]["assertion_id"],
            "content_commitment": item["record"]["assertion_digest"],
            "action": item["record"]["action"], "policy": item["record"]["policy"]} for item in records],
        "3_monitoring_and_human_oversight": [{"source_pointer": item["source_pointer"],
            "request_actor": item["record"]["actor_id"], "decision": item["record"]["decision"],
            "note": "request actor is not inferred to be an approver; approval-required remains pending"}
            for item in records],
        "4_performance_metrics_and_appropriateness": copy.deepcopy(outside),
        "5_risk_management_system": {"recorded_policies": [item["record"]["policy"] for item in records],
                                     "management_system": copy.deepcopy(outside)},
        "6_lifecycle_changes": copy.deepcopy(outside),
        "7_harmonised_standards": copy.deepcopy(outside),
        "8_declaration_of_conformity": copy.deepcopy(outside),
        "9_post_market_monitoring": {"retention_and_operator_delivery": copy.deepcopy(outside)},
        "record_fields_complete": True,
        "completeness_basis": "field presence only; no independent semantic or application qualification",
        "application_evidence_complete": False,
        "field_inventory": inventory,
    }
    return regulator, inventory
