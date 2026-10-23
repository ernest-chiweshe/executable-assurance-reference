"""Fictional local Education release with real retained sessions and two reviews.

This exercises the restricted host, not X-6 appointment scopes or X-19 witnesses.
All people, credentials, qualification data and source content are test fixtures.
"""

from dataclasses import replace
from pathlib import Path
import hashlib
import json
from types import SimpleNamespace


from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.packs import FIXTURES, PUBLISHER
from assurance_reference.session_credentials import SESSION_FIELD, SessionBoundCredentials
from factory.packs.demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from factory.packs.registry import PackRegistry
from factory.pg_session import SessionBoundPool
from factory.projectos.governed_release import MISSION_FIELD, PREPARATION_FIELD, TARGET_FIELD
from factory.projectos.regulated import EmissionContext
from factory.projectos.spec import RegulatedBlock, VerticalSpec
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE, issue_certificate
from regulated_core.document_gate import VerifierRegistry
from regulated_core.governance_targets import change_bytes, issue_bootstrap
from assurance_reference.governance_targets import pack_activation_target
from regulated_core.heartbeat import HeartbeatIngress, issue_heartbeat
from regulated_core.persistence_pg import PostgresGovernanceLog, PostgresHeartbeatStore
from regulated_core.target import Outcome
from regulated_core.signing import Ed25519Signer

from assurance_reference.local_fixture_host import configuration


def build_education_fixture(roles, tmp_path: Path, *, clock_source=None,
                            retention=None, session_type=LocalSessions,
                            signer_factory=Ed25519Signer, outage_alarm=None, scoped_authority=False,
                            partitioned_lifecycle=False, fixture_validity_us=120_000_000,
                            monitor_heartbeat=False, production_assurance=None,
                            fixture_budget_limit=1, synthetic_pack_directory=None,
                            synthetic_publisher=None):
    """Compose a fictional school profile using already-provisioned restricted roles.

    Bootstrap, scripted identities and certificates are explicit fixture actions.
    No administrator connection is accepted or retained by this composition.
    """
    if type(monitor_heartbeat) is not bool:
        raise ValueError("fixture monitor selection must be an explicit boolean")
    stores, authorities, alerts, qualifications, report, keys = configuration(
        roles, tmp_path, clock_source=clock_source, retention=retention,
        signer_factory=signer_factory, outage_alarm=outage_alarm, partitioned_lifecycle=partitioned_lifecycle,
        fixture_validity_us=fixture_validity_us)
    clock, trust = authorities.clock, authorities.trust
    # Explicit test quota; no production terms are chosen by this fictional fixture.
    authorities = replace(authorities, production_assurance=production_assurance,
        default_mission_budget=(None if fixture_budget_limit is None else
                                {"limit": fixture_budget_limit, "units": 1}))
    if (synthetic_pack_directory is None) != (synthetic_publisher is None):
        raise ValueError("synthetic pack requires both its directory and explicit fixture publisher")
    bundle, publisher_id = FIXTURES / "bundles" / "education-0.1.2", PUBLISHER
    if synthetic_pack_directory is not None:
        if synthetic_publisher.key_id != "fixture:education-budget-publisher":
            raise ValueError("only the explicitly synthetic budget publisher is accepted here")
        bundle, publisher_id = Path(synthetic_pack_directory), synthetic_publisher.key_id
        trust.register_signer(synthetic_publisher)
    if monitor_heartbeat:
        authorities = replace(authorities,
            heartbeat_monitor_key_ids=frozenset({keys["monitor"].key_id}),
            heartbeat_installation="synthetic-education-host")

    def publish_monitor_heartbeat(sequence=1):
        """Publish a fictional monitor observation through the verified ingress."""
        if not monitor_heartbeat:
            raise ValueError("fixture monitor was not selected")
        ingress = HeartbeatIngress(store=PostgresHeartbeatStore(pool=roles.monitor_ingress), trust=trust,
            installation=authorities.heartbeat_installation,
            monitor_key_ids=authorities.heartbeat_monitor_key_ids, clock_us=clock.now_us)
        beat = issue_heartbeat(keys["monitor"], installation=authorities.heartbeat_installation,
                               sequence=sequence, beat_at_us=clock.now_us())
        ingress.receive(beat)
        return beat
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    registry = PackRegistry(trust=trust, activation=stores.activation)
    pack = registry.install(bundle, publisher_key_id=publisher_id, today="2026-10-14")
    sessions = session_type(
        reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    identities = {}
    certificates = CertificateRegistry(trust, {keys["issuer"].key_id: DEMONSTRATION_CERTIFICATE})
    def certify(principal, role):
        certificates.present(issue_certificate(keys["issuer"], subject_id=principal,
            role=role, jurisdiction="ZA", expires_at_us=clock.now_us() + fixture_validity_us))

    for principal, role in (("requester", None), ("teacher", "teacher"),
                            ("head", "head-of-department")):
        sessions.provision_identity("school-a", principal, principal + ".local", "fictional-password-001")
        identities[principal] = sessions.authenticate("school-a", sessions.login(
            "school-a", principal + ".local", "fictional-password-001"))
        if role:
            certify(principal, role)
    now = clock.now_us()
    snapshot = EvidenceSnapshot("school-a", "geometry", "1", "Fictional formative feedback",
        (("rubric", "1", "Label the equal sides."),), (("rubric", "Label the equal sides."),),
        ("Synthetic local fixture; no educational validity claim.",), now, now + fixture_validity_us)
    verifiers = VerifierRegistry()
    verifiers.register("source:fidelity", SnapshotVerifier((snapshot,)))
    authorities = replace(authorities, host_verifiers=verifiers,
        verifier_signers={name: keys["verifier"] for name in pack.rulebook.effective_content["checks"]})
    doc = pack.rulebook.document
    spec = VerticalSpec("education", "knowledge-backed", "education", "project_id", (),
        regulated=RegulatedBlock(policy_ref=f"{doc.vertical}/{doc.policy_id}",
            intended_use="formative feedback", policy_digest=doc.digest(), pack_version=pack.reference))
    def make_gate(authenticated):
        credentials = SessionBoundCredentials(trust, keys["credential"], sessions, certificates,
                                              sessions=sessions, authenticated=authenticated)
        host = compose_reference_host(stores, replace(authorities, credential_verifier=credentials),
                                      alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
        from assurance_reference.lineage_gate import QualificationEvidenceGate
        return QualificationEvidenceGate(host(pack, registry, SimpleNamespace(spec=spec)))

    gates = {principal: make_gate(authenticated) for principal, authenticated in identities.items()}
    # Explicit first-state bootstrap through the existing signed governance target.
    # The fixture issuer is named locally; this never represents owner approval.
    governor = PackRegistry(trust=trust, activation=type(stores.activation)("",
        pool=SessionBoundPool(roles.governor), guard=stores.activation.governance_guard))
    governor.install(bundle, publisher_key_id=publisher_id, today="2026-10-14")
    target = pack_activation_target(governor, pack.reference, budget=stores.budget, tenant_id="school-a",
        authority=gates["requester"]._engine.targets, uses=stores.permits,
        log=PostgresGovernanceLog(pool=SessionBoundPool(roles.governor)),
        bootstrap_trust=trust, bootstrap_key_ids=frozenset({keys["issuer"].key_id}))
    output = change_bytes("pack-activation", pack.manifest.id,
        {"activate": pack.reference, "at": "2026-10-14", "reason": "Explicit fictional first-state fixture"})
    bootstrap = issue_bootstrap(keys["issuer"], tenant_id="school-a", kind="pack-activation",
                                subject=pack.manifest.id, output=output)
    if target.bootstrap(bootstrap, output).outcome is not Outcome.COMMITTED:
        raise RuntimeError("fictional pack bootstrap did not commit")
    path = tmp_path / "feedback.txt"
    body = snapshot.render().encode()
    context = EmissionContext(tenant="school-a", actor_id="requester", project_id="geometry",
        vertical_name="education", action_id="release", nonce="fictional-release",
        now_us=clock.now_us(),
        not_after_us=identities["requester"].expires_at_us)
    contract = {**snapshot.contract(), MISSION_FIELD: "synthetic:school-a:geometry",
        "rubric_criteria": ["reasoning"],
        "criteria_addressed": ["reasoning"], "reference_answer": "42", "findings": [],
        SESSION_FIELD: identities["requester"].binding(),
        "provenance": {"run_id": "fictional-local-education-001", "model_id": "deterministic-fixture",
                       "prompt": "Immutable fictional rubric statement; no model call",
                       "policy": pack.reference, "gate": "reference-session-pack-host"},
        PREPARATION_FIELD: {"artifact_sha256": hashlib.sha256(body).hexdigest()},
        TARGET_FIELD: gates["requester"].describe_target(spec=spec, out_path=str(path), context=context)}
    app = SimpleNamespace(roles=roles, stores=stores, gates=gates, sessions=sessions, identities=identities,
        spec=spec, path=path, body=body, context=context, contract=contract, report=report,
        clock=clock, fault_source=clock_source, fault_retention=retention, certify=certify, make_gate=make_gate,
        publish_monitor_heartbeat=publish_monitor_heartbeat,
        public_keys={key.key_id: key.public_key_bytes.hex() for key in keys.values()})
    if scoped_authority:
        from assurance_reference.scoped_education_fixture import compose_scoped_fixture
        compose_scoped_fixture(app, authorities=authorities, keys=keys, registry=registry,
            pack=pack, alerts=alerts, qualifications=qualifications, signer_factory=signer_factory,
            fixture_validity_us=fixture_validity_us)
    return app

