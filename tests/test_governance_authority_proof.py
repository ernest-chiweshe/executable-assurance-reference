"""Signed first-state evidence is retained without changing bootstrap checks."""
from regulated_core.governance_targets import GovernanceTarget, GovernanceLog, change_bytes, issue_bootstrap
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import Outcome
from test_reference_host_budget_contract import composition


def test_first_state_host_receives_exact_verified_bootstrap_and_repeat_is_refused(tmp_path):
    engine, _, _, _, _, uses = composition(tmp_path, {"limit": 1, "units": 1}, engine_type="core")
    signer = Ed25519Signer("synthetic:bootstrap-proof")
    trust = TrustDirectory()
    trust.register_signer(signer)
    state = {"value": "absent"}
    received = []

    def transact(change):
        change.final_check()
        received.append(change)
        state["value"] = "version-one"

    target = GovernanceTarget(tenant_id="fixture", kind="fixture", subject="state",
        authority=engine.targets, uses=uses, state=lambda: state["value"],
        apply=lambda change: None, log=GovernanceLog(), operation_name="fixture:change",
        transact=transact, bootstrap_trust=trust, bootstrap_key_ids=frozenset({signer.key_id}))
    output = change_bytes("fixture", "state", {"value": "version-one"})
    signed = issue_bootstrap(signer, tenant_id="fixture", kind="fixture", subject="state", output=output)
    assert target.bootstrap(signed, output).outcome is Outcome.COMMITTED
    assert len(received) == 1 and received[0].authority_proof is signed
    assert received[0].first_state_only and received[0].approved_prior == "absent"
    assert target.bootstrap(signed, output).outcome is Outcome.FAILED
    assert len(received) == 1
