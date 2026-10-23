"""Owned test worker: reconstruct host configuration and use retained PG authority.

Synthetic fixture keys arrive through stdin, never command arguments or files.
This is a test host, not a production identity or key-custody implementation.
"""

from dataclasses import asdict
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_reference.delegated_draft import AuditedDelegatedReceiver
from assurance_reference.prepared_budget_demo import BODY, DraftEffect
from regulated_core.canonical import digest_hex
from regulated_core.policy_document import PolicyDocument
from regulated_core.signing import Ed25519Signer, Signature, TrustDirectory
from regulated_core.target import Outcome, SignedTargetPermit, TargetPermit, TargetRef
from test_delegated_draft import DraftCurrentness, assemble_delegated_fixture
from test_root_admission import assemble_root_fixture
from isolated_worker_database import verify_isolated_worker_database


def emit(value):
    print(json.dumps({"pid": os.getpid(), "parent_pid": os.getppid(), **value}), flush=True)


class PausedDraft(DraftEffect):
    def apply_on(self, conn, output):
        super().apply_on(conn, output)
        emit({"marker": "effect-written-uncommitted"})
        # The parent kills only this Popen child. EOF must never let it commit.
        sys.stdin.readline()
        raise RuntimeError("test interruption was not performed")


def main():
    config = json.loads(sys.stdin.readline())
    dsn, domain = verify_isolated_worker_database()
    assert domain == config["domain"], "worker clock domain differs from its owned fixture"
    signers = {name: Ed25519Signer("root:" + name,
               Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw)))
               for name, raw in config["fixture_keys"].items()}
    trust = TrustDirectory()
    for signer in signers.values():
        trust.register_signer(signer)
    doc = dict(config["document"])
    doc["jurisdictions"] = tuple(doc["jurisdictions"])
    doc["signature"] = Signature(**doc["signature"])
    document = PolicyDocument(**doc)
    fixture = {"schema": config["schema"], "signers": signers, "trust": trust}
    fixture["assemble"] = lambda tenant: assemble_root_fixture(
        tenant, dsn=dsn, schema=config["schema"], domain=config["domain"],
        document=document, trust=trust, signers=signers, currentness_factory=DraftCurrentness,
    )
    raw = dict(config["signed"]["permit"])
    raw["qualification_digests"] = tuple(raw["qualification_digests"])
    signed = SignedTargetPermit(TargetPermit(**raw), Signature(**config["signed"]["signature"]))
    tenant = signed.permit.tenant_id
    pool, _, _, _, _, receiver, _, alerts = assemble_delegated_fixture(fixture, tenant)
    mode = config["mode"]
    if mode == "before-commit":
        receiver = AuditedDelegatedReceiver(
            pool=pool, effect=PausedDraft(tenant, TargetRef("postgres", config["schema"] + "/" + tenant)),
            authority=receiver._authority, alerts=alerts,
        )
    if mode in {"before-commit", "after-commit"}:
        result = receiver.commit(signed, BODY)
        assert mode == "after-commit" and result.outcome is Outcome.COMMITTED, result
        emit({"marker": "committed-before-caller-ack", "result": asdict(result) | {"outcome": result.outcome.value}})
        sys.stdin.readline()
        raise RuntimeError("test interruption was not performed")
    assert mode == "reconcile"
    observed = receiver.observe(signed)
    reconciled = receiver.status(signed)
    replay = receiver.commit(signed, BODY)
    emit({"permit_digest": digest_hex(signed.permit.signed_body()),
          "observed": observed.outcome.value, "reconciled": reconciled.outcome.value,
          "replay": replay.outcome.value, "state": replay.target_state})


if __name__ == "__main__":
    main()
