"""Apply the already signed pilot authorities after hosted accounts and migration.

Run through the release's managed database entrypoint. Default is a read-only
preflight; --execute writes the three exact signed authorities. This creates no
account, signs nothing, sends no mail, activates no pack and changes no schema.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any

from factory.customer_web.member_directory import PostgresMemberDirectory
from factory.packs.collections import PackCollectionStore, PostgresPackCollectionStore
from factory.packs.composition import compose_packs, load_trust_anchors
from factory.packs.examples import EDUCATION_ID
from factory.packs.lifecycle_pg import PostgresActivationLedger
from factory.packs.registry import PackRegistry
from factory.pg_pool import open_pool
from factory.pg_session import SessionBoundPool
from regulated_core.policy_document import PolicyDocument, verify_document
from regulated_core.signing import TrustDirectory

from .appointments import ReviewerAppointments, _decode
from .provisioning import provision_enrollment

ROOT = Path(__file__).resolve().parents[2] / "deploy/packs"
AUTHORITY = "education-pilot-authority-2026-09-10"
REFERENCE = EDUCATION_ID + "#0.1.1"
WORKSPACE = "education-local-demo-20260910"
SCHOOL = "education-local-school-20260910"
CLASS = "geometry-local-20260910"
INPUTS = {
    "hosted-pilot-provisioning.prepared.json": "14648a0039359c891d5b1e87f0e23ff85d4d0fbd507c990c0c479196d2b546c2",
    "signed-enrollments-20260910.json": "6c46d9e181b1e76f386692619365d45ee2da3cdedf1ec2491917fa2907745013",
    "signed-reviewer-appointment-20260910.json": "de102aa80c4150264d6f475e7f65283c98546e13dcc27eb3b16a5f9de5d61499",
}


def documents(root: Path, trust: TrustDirectory, now_us: int) -> dict[str, PolicyDocument]:
    loaded: dict[str, Any] = {}
    for name, expected in INPUTS.items():
        raw = (root / "pilot-provisioning" / name).read_bytes()
        if sha256(raw).hexdigest() != expected:
            raise ValueError("pilot input digest differs: " + name)
        loaded[name] = json.loads(raw)
    scope = loaded["hosted-pilot-provisioning.prepared.json"]
    if scope["scope"] != {"workspace_id": WORKSPACE, "school_id": SCHOOL,
                          "class_id": CLASS, "expires_at_us": 1789603200000000}:
        raise ValueError("pilot scope differs")
    retained = dict(loaded["signed-enrollments-20260910.json"]["documents"])
    retained["head-of-department"] = loaded["signed-reviewer-appointment-20260910.json"]
    result = {}
    for role, account in (("teacher", "teacher"), ("student", "learner"), ("head-of-department", "reviewer")):
        document = _decode(retained[role]["document"])
        content = document.content
        if (document.digest() != scope["signed_document_digests"][role]
                or document.digest() != retained[role]["digest"]
                or not document.effective_at(now_us)
                or not verify_document(trust, document, authority=AUTHORITY)
                or content["tenant_id"] != WORKSPACE or content["class_id"] != CLASS
                or content["role"] != role or content["status"] != "active"
                or content["principal"] != scope["accounts"][account]["member_subject"]):
            raise ValueError("signed pilot authority differs or expired: " + role)
        result[role] = document
    return result


def provision(registry: PackRegistry, store: PackCollectionStore, trust: TrustDirectory,
              member: Callable[[str, str], bool], *, root: Path, now_us: int, execute: bool) -> dict[str, Any]:
    signed = documents(root, trust, now_us)
    pack = registry.for_tenant(WORKSPACE, EDUCATION_ID)
    if pack is None or pack.reference != REFERENCE:
        raise ValueError("pilot requires the selected active Education 0.1.1 pack")
    # Validate ALL memberships before the first authority write. Never infer a
    # teacher/HoD identity from an operator key or a workspace administrator.
    if not all(member(WORKSPACE, doc.content["principal"]) for doc in signed.values()):
        raise ValueError("all three approved individual memberships must already exist")
    receipt: dict[str, Any] = {"schema": "education/hosted-authority-provisioning/v1",
        "status": "preflight-clear", "workspace": WORKSPACE, "pack": REFERENCE,
        "account_writes": 0, "signing_calls": 0, "model_calls": 0, "authorities": []}
    if not execute:
        return receipt
    for role in ("teacher", "student"):
        doc = signed[role]
        saved = provision_enrollment(registry, store, doc, trust=trust,
                                     school_authority=AUTHORITY, now_us=now_us)
        reread = store.get(EDUCATION_ID, "roster-user", WORKSPACE, saved.key)
        if reread is None or reread.payload["enrollmentDocumentDigest"] != doc.digest():
            raise ValueError("retained enrollment verification failed")
        receipt["authorities"].append({"role": role, "digest": doc.digest(), "revision": reread.version})
    appointments = ReviewerAppointments(registry, store, trust=trust,
                                       owner_authority=AUTHORITY, schools={WORKSPACE: SCHOOL})
    doc = signed["head-of-department"]
    saved = appointments.provision(doc, now_us=now_us)
    if appointments.current(WORKSPACE, doc.content["principal"], CLASS, now_us=now_us).digest() != doc.digest():
        raise ValueError("retained appointment verification failed")
    receipt["authorities"].append({"role": "head-of-department", "digest": doc.digest(), "revision": saved.version})
    receipt["status"] = "provisioned-and-read-back"
    return receipt


def _no_emission(*args: Any) -> Any:
    raise RuntimeError("authority provisioning cannot emit")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if (os.environ.get("FACTORY_PRODUCT_STORE_MODE") != "postgres"
            or os.environ.get("FACTORY_PRODUCT_SCHEMA_MODE") != "external-migration-task"):
        raise ValueError("requires the migrated managed PostgreSQL task environment")
    pool = open_pool(os.environ["FACTORY_DB_URL"], max_size=3, autocommit=True, env={})
    bound = SessionBoundPool(pool)
    composition = None
    try:
        store = PostgresPackCollectionStore("", pool=bound)
        composition = compose_packs(root=ROOT / "bundles", catalog_path=ROOT / "deployment-catalog.json",
            trust_path=ROOT / "trust-anchors.json", activation=PostgresActivationLedger("", pool=bound),
            collections=store, gate_factory=_no_emission)
        receipt = provision(composition.registry, store, load_trust_anchors(ROOT / "trust-anchors.json"),
            PostgresMemberDirectory(bound), root=ROOT, now_us=int(datetime.now(timezone.utc).timestamp() * 1_000_000),
            execute=args.execute)
        print(json.dumps(receipt, sort_keys=True), flush=True)
        return 0
    finally:
        if composition is not None:
            composition.close()
        pool.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Never serialize a DB exception or its parameters (which may contain credentials).
        print(json.dumps({"status": "stopped-inspect-state", "error_class": type(error).__name__,
                          "retry": False}), flush=True)
        raise SystemExit(1) from None
