"""Run an explicitly fictional Education release in the owned local test cluster.

No pytest imports, external providers, real pupils, or real human approvals.
Full D1 remains OPEN; this is a runnable protocol example, not domain validation.
"""

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.education_workflow import compose_education_workflow
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.approval_evidence import ReviewError
from regulated_core.canonical import canonical_bytes


def verify_owned_cluster(dsn: str, port: str, directory: str) -> None:
    """Check the launcher's endpoint and data directory before any migration.

    This prevents accidental use of another local database. These host-supplied
    values are not a security boundary against an administrator forging them.
    """
    settings = conninfo_to_dict(dsn)
    if (not port.isdecimal() or not 1 <= int(port) <= 65535 or not directory
            or settings.get("dbname") != "factory_test"
            or settings.get("host") != "127.0.0.1"
            or settings.get("hostaddr", "127.0.0.1") != "127.0.0.1"
            or settings.get("port") != port or settings.get("service")):
        raise ValueError("use the explicit isolated PostgreSQL launcher")
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        actual = connection.execute("SHOW data_directory").fetchone()[0]
    if Path(actual).resolve() != Path(directory).resolve():
        raise ValueError("connected database is not the launcher's owned cluster")


def run(dsn: str, *, port: str, directory: str, output: Path, teacher_only=False,
        scoped_authority=False) -> dict:
    verify_owned_cluster(dsn, port, directory)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # Administrator use ends at explicit fresh-schema provisioning. The host
    # receives only the separate restricted runtime pools.
    app = build_education_fixture(provision_local_roles(dsn), output, scoped_authority=scoped_authority)
    state, release = compose_education_workflow(app)
    saved = {"contract": app.contract}
    if scoped_authority:
        saved["source_material"] = app.scoped.retained
    state.create("geometry", saved)
    context = replace(app.context, release_target=str(app.path))
    source_confirmation = None
    if scoped_authority:
        context = replace(context, retained_state=state.load("geometry")["source_material"])
    prepared = release.contract("geometry", tenant="school-a", context=context)
    contract = prepared.for_approval()
    if scoped_authority:
        teacher = replace(context, actor_id="teacher", now_us=app.clock.now_us())
        view = app.gates["teacher"].get_source_review(spec=app.spec, contract=contract, context=teacher)
        source_confirmation = app.gates["teacher"].confirm_source_review(spec=app.spec,
            contract=contract, context=teacher, expected_material_digest=view["material_digest"],
            confirmed=True, request_id="SCRIPTED-FIXTURE-SOURCE-CONFIRMATION")
    opened = app.gates["requester"].open_review(spec=app.spec, contract=contract, context=context)
    reviewers = [("teacher", "teacher")]
    if not teacher_only:
        reviewers.append(("head", "head-of-department"))
    review = opened
    for principal, role in reviewers:
        review = app.gates[principal].grant_review(spec=app.spec, contract=contract,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
            review_id=opened["review_id"], role=role)
    context = replace(context, approval=opened["review_id"])
    observation = None
    replay_unchanged = None
    refusal = None
    try:
        release.release("geometry", str(app.path), context)
    except ReviewError as error:
        # Only this expected pre-effect quorum refusal is a successful negative
        # example. Other errors remain failures; never infer a safe outcome from
        # a general exception after handing anything to the receiving boundary.
        if (not teacher_only or review["status"] != "awaiting-review"
                or str(error) != "human review has not reached the required quorum"):
            raise
        if app.path.exists():
            raise RuntimeError("refused release unexpectedly has an output")
        status = "REFUSED"
        refusal = {"boundary": "stored-review-resolution", "reason": str(error)}
    else:
        if teacher_only:
            raise RuntimeError("one reviewer unexpectedly released the artifact")
        if app.path.read_bytes() != prepared.prepared.content:
            raise RuntimeError("released bytes differ from approved preparation")
        written = app.path.stat().st_mtime_ns
        rebuilt_state, rebuilt = compose_education_workflow(app)
        rebuilt.release("geometry", str(app.path), context)
        replay_unchanged = (app.path.stat().st_mtime_ns == written
                            and len(rebuilt_state.load("geometry")["emissions"]) == 1)
        if not replay_unchanged:
            raise RuntimeError("receipt replay changed the release")
        observation = rebuilt.observe("geometry", str(app.path), context)
        if observation.outcome.state != "committed" or observation.receipt is None:
            raise RuntimeError("committed release has no verified receiving receipt")
        status = "COMMITTED"
    chain_valid = app.stores.recorder.verify_chain("school-a")
    if not chain_valid:
        raise RuntimeError("Education evidence chain does not verify")
    evidence = {
        "schema": "reference/local-education-example/v1",
        "status": status, "full_D1": "OPEN", "fictional": True,
        "scoped_authority": scoped_authority, "scripted_source_confirmation": source_confirmation,
        "scripted_reviewers": [principal for principal, _ in reviewers],
        "review_status": review["status"], "contract": contract,
        "refusal": refusal,
        "artifact_sha256": hashlib.sha256(prepared.prepared.content).hexdigest(),
        "target_exists": app.path.exists(), "receipt_replay_unchanged": replay_unchanged,
        "observation": observation, "chain_valid": chain_valid,
        "chain": app.stores.recorder.entries("school-a"), "public_keys": app.public_keys,
        "release_evidence": [row["evidence"] for row in state.load("geometry").get("emissions", [])],
        "limits": ["Scripted fictional people; no human source-witness evidence (X-19).",
                   "Assessment-scoped appointments (X-6) remain open.",
                   "Synthetic checker qualification is not educational validation.",
                   "Local keys and retention are not deployed HSM or compliance WORM.",
                   "Physical G4, safe rollback resumption and full D1 remain open."],
    }
    (output / "evidence.json").write_bytes(canonical_bytes(evidence))
    return {"status": status, "full_D1": "OPEN", "fictional": True,
            "evidence": str(output / "evidence.json"),
            "artifact": str(app.path) if app.path.exists() else None,
            "chain_valid": chain_valid, "receipt_replay_unchanged": replay_unchanged}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fictional-fixture", action="store_true", required=True,
                        help="Explicitly provision scripted identities and local fixture keys")
    parser.add_argument("--output", type=Path, required=True, help="New output directory")
    parser.add_argument("--teacher-only", action="store_true",
                        help="Demonstrate refusal before release with only one reviewer")
    parser.add_argument("--scoped-authority", action="store_true",
                        help="Use signed fictional appointments and an explicit scripted source confirmation")
    args = parser.parse_args()
    result = run(os.environ.get("FACTORY_TEST_DB_URL", ""),
        port=os.environ.get("REFERENCE_ISOLATED_PG_PORT", ""),
        directory=os.environ.get("REFERENCE_ISOLATED_PG_DATA", ""),
        output=args.output, teacher_only=args.teacher_only, scoped_authority=args.scoped_authority)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
