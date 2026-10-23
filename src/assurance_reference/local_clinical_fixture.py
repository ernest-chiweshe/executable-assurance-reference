"""Fictional Health finalisation through the retained reference authority path.

The default uses the unchanged signed workspace-membership qualification pack.
An explicit synthetic publisher and directory select the separate stored-review
fixture. Its host-bound reviewer assignment is test provisioning, not a public
authorization API.
Membership is the original local file provider, not a professional register or
the eventual restricted database membership service. No real clinical data,
cloud provider, owner signature or external delivery is involved.
"""

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from assurance_reference.clinical_sessions import RetainedClinicalSessions
from assurance_reference.clinical_review import ReviewedClinicalFinalisation
from assurance_reference.clinical_review_admission import ClinicalReviewCredentials, ClinicalReviewGrant
from assurance_reference.clinical_review_attempts import RetainedClinicalReviewAttempts
from assurance_reference.clinical_lineage import RetainedClinicalLineage
from assurance_reference.clinical_state import RetainedClinicalStore
from assurance_reference.credential_profile import ProfileCredentials, select_credential_profile
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.packs import FIXTURES, PUBLISHER
from assurance_reference.session_admission_scope import SessionAdmissionScope
from assurance_reference.retained_clinical_checks import retained_clinical_checks
from factory.health_ui.clinical_release import ClinicalFinalisation, owner_of
from factory.health_ui.clinician_certificates import ClinicianCertificateStore
from factory.health_ui.clinician_credentials import MEMBERSHIP_LICENCE, HealthIdentityProvider, HealthMembershipRegistry
from factory.health_ui.identity import IdentityStore
from factory.health_ui.session_release import ClinicalSessionCredentials
from factory.ledger import FileArtifactStore
from factory.packs.registry import PackRegistry
from factory.pg_session import SessionBoundPool
from factory.projectos.spec import RegulatedBlock, VerticalSpec
from regulated_core.document_gate import VerifierRegistry
from regulated_core.governance_targets import change_bytes, issue_bootstrap
from assurance_reference.governance_targets import pack_activation_target
from regulated_core.persistence_pg import PostgresGovernanceLog
from regulated_core.target import Outcome
from regulated_core.signing import Ed25519Signer


CLINICAL_RELEASE_ACTION = "health:release-clinical-writing"
TIER4_PUBLISHER = "fixture:health-tier4-publisher"
PROFILE_PUBLISHER = "fixture:health-profile-publisher"


def _clinical_pack_selection(directory, publisher):
    if (directory is None) != (publisher is None):
        raise ValueError("synthetic Health pack requires both its directory and fixture publisher")
    if directory is None:
        return FIXTURES / "bundles" / "health-workspace-membership", PUBLISHER
    if getattr(publisher, "key_id", None) not in {TIER4_PUBLISHER, PROFILE_PUBLISHER}:
        raise ValueError("only an explicitly named synthetic Health fixture publisher is accepted")
    return Path(directory), publisher.key_id


def build_clinical_fixture(roles, tmp_path, *, clock_source=None, session_type=LocalSessions,
                           partitioned_lifecycle=True, signer_factory=Ed25519Signer,
                           tier4_directory=None, tier4_cooling_off_us=0,
                           synthetic_pack_directory=None, synthetic_publisher=None,
                           certificate_issuers=None):
    """Explicit fictional provisioning; runtime composition retains no admin DSN."""
    bundle, publisher_id = _clinical_pack_selection(synthetic_pack_directory, synthetic_publisher)
    # Only the tier-four derivative selects the reviewed workflow; a credential-profile derivative does not.
    reviewed = synthetic_pack_directory is not None and synthetic_publisher.key_id == TIER4_PUBLISHER
    stores, authorities, alerts, qualifications, report, keys = configuration(
        roles, tmp_path, clock_source=clock_source, partitioned_lifecycle=partitioned_lifecycle,
        signer_factory=signer_factory, tier4_directory=tier4_directory,
        tier4_cooling_off_us=tier4_cooling_off_us)
    clock, trust = authorities.clock, authorities.trust
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    if synthetic_pack_directory is not None:
        trust.register_signer(synthetic_publisher)
    registry = PackRegistry(trust=trust, activation=stores.activation)
    pack = registry.install(bundle, publisher_key_id=publisher_id, today="2026-10-14")
    workspace = "health-fixture-" + uuid4().hex
    membership = IdentityStore(tmp_path / "fictional-membership.json", clock=lambda: clock.now_us() / 1e6)
    member = membership.bootstrap_user("clinician.local", "Fictional clinician",
                                       "fictional-password-001", [workspace])
    sessions = session_type(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    sessions.provision_identity(workspace, member.user_id, member.username, "fictional-password-001")
    authenticated = sessions.authenticate(workspace, sessions.login(
        workspace, member.username, "fictional-password-001"))
    scope = SessionAdmissionScope(sessions, authenticated)
    reviewer_sessions = {}
    if reviewed:
        # Explicit local operator provisioning, separate from owner authentication.
        peer = membership.bootstrap_user("reviewer.local", "Fictional peer clinician",
                                         "fictional-reviewer-password-001", [workspace])
        sessions.provision_identity(workspace, peer.user_id, peer.username,
                                    "fictional-reviewer-password-001")
        peer_authenticated = sessions.authenticate(workspace, sessions.login(
            workspace, peer.username, "fictional-reviewer-password-001"))
        reviewer_sessions = {
            "owner": (scope, authenticated),
            "peer": (SessionAdmissionScope(sessions, peer_authenticated), peer_authenticated),
        }
    bridge = RetainedClinicalSessions(scope, authenticated)
    # The display name comes from the separately provisioned membership record,
    # never from a request field or the blank session adapter display name.
    clinician = replace(bridge.identity, display_name=member.display_name)
    state = RetainedClinicalStore(pool=roles.project_state, sessions=scope, authenticated=authenticated)
    verifiers = VerifierRegistry()
    # X-12: the retained store raises StoreDegraded per operation; its checks yield INDETERMINATE.
    for name, check in retained_clinical_checks(state, owner_of).items():
        verifiers.register(name, check)
    credentials_type = ClinicalReviewCredentials if reviewed else ClinicalSessionCredentials
    # X-14: the signed rulebook selects the credential profile; this installation verifies only workspace
    # membership, and the host alone selects that provider's receipt-signing key.
    providers = {MEMBERSHIP_LICENCE: lambda: HealthMembershipRegistry(
        membership, workspace_id=workspace, jurisdiction="global", clock_us=clock.now_us)}
    signers = {HealthMembershipRegistry.provider: keys["credential"]}
    certificates = None
    if certificate_issuers is not None:
        # X-6: an explicit local certificate authority (fixture issuers already trust anchors); the store
        # re-verifies signature, issuer kind, expiry, tombstone and current membership on every lookup.
        certificates = ClinicianCertificateStore(tmp_path / "certificate-records", certificate_issuers,
                                                 membership, clock_us=clock.now_us)
        for kind in set(certificate_issuers.values()):
            providers[kind] = lambda: certificates.provider()(trust, workspace)
        signers["health-certificate-store"] = keys["credential"]
    profile = select_credential_profile(pack, action=CLINICAL_RELEASE_ACTION, providers=providers,
                                        signers=signers)
    credentials = ProfileCredentials(profile, lambda selected: credentials_type(
        trust, selected.signer, HealthIdentityProvider(membership), selected.provider, sessions=bridge,
        **({"clock_us": clock.now_us, "reviewer_session_authority": sessions} if reviewed else {})))()
    authorities = replace(authorities, credential_verifier=credentials, host_verifiers=verifiers,
        verifier_signers={name: keys["verifier"] for name in pack.rulebook.effective_content["checks"]})
    document = pack.rulebook.document
    spec = VerticalSpec("health", "knowledge-backed", "health", "session_id", (),
        regulated=RegulatedBlock(policy_ref=f"{document.vertical}/{document.policy_id}",
            intended_use="clinical-writing", policy_digest=document.digest(), pack_version=pack.reference))
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    from assurance_reference.lineage_gate import QualificationEvidenceGate
    lineage = RetainedClinicalLineage(pool=roles.project_state, sessions=scope,
        authenticated=authenticated, qualifications=qualifications, recorder=stores.recorder,
        permit_authority=keys["emission"].key_id)
    gate = QualificationEvidenceGate(host(pack, registry, SimpleNamespace(spec=spec)), retention=lineage)
    governor = PackRegistry(trust=trust, activation=type(stores.activation)("",
        pool=SessionBoundPool(roles.governor), guard=stores.activation.governance_guard))
    governor.install(bundle, publisher_key_id=publisher_id, today="2026-10-14")
    target = pack_activation_target(governor, pack.reference, budget=stores.budget, tenant_id=workspace,
        authority=gate._engine.targets, uses=stores.permits,
        log=PostgresGovernanceLog(pool=SessionBoundPool(roles.governor)),
        bootstrap_trust=trust, bootstrap_key_ids=frozenset({keys["issuer"].key_id}))
    output = change_bytes("pack-activation", pack.manifest.id,
        {"activate": pack.reference, "at": "2026-10-14", "reason": "Explicit fictional Health qualification fixture"})
    bootstrap = issue_bootstrap(keys["issuer"], tenant_id=workspace, kind="pack-activation",
                                subject=pack.manifest.id, output=output)
    if target.bootstrap(bootstrap, output).outcome is not Outcome.COMMITTED:
        raise RuntimeError("fictional Health pack bootstrap did not commit")
    records = tmp_path / "finalised"
    artifacts = FileArtifactStore(tmp_path / "private-artifacts")
    review_attempts = (RetainedClinicalReviewAttempts(pool=roles.project_state, sessions=scope,
        authenticated=authenticated) if reviewed else None)
    finaliser_type = ReviewedClinicalFinalisation if reviewed else ClinicalFinalisation
    review_options = {"review_attempts": review_attempts} if reviewed else {}
    finaliser = finaliser_type(**review_options, gate=gate, spec=spec, store=state, artifacts=artifacts,
        finalised_root=records, workspace_id=workspace, now_us=clock.now_us,
        clock_utc=lambda: datetime.fromtimestamp(clock.now_us() / 1e6, timezone.utc).isoformat(),
        authorisation_window_us=30_000_000)
    def review_grant(reviewer, session, document):
        """Bind one explicit fictional assignment to a provisioned reviewer.

        The caller selects a fixture alias, never an actor or signed credential.
        Production assignment and transport authorization are outside this fixture.
        """
        if not reviewed or reviewer not in reviewer_sessions:
            raise ValueError("stored review requires an explicitly provisioned fixture reviewer")
        reviewer_scope, reviewer_identity = reviewer_sessions[reviewer]

        def request():
            with scope.admit(authenticated) as current:
                contract, context = finaliser.review_request(session, document, clinician)
                opened = gate.open_review(spec=spec, contract=contract, context=context)
                current()
                return spec, contract, context, opened["review_id"]

        return ClinicalReviewGrant(gate=gate, credentials=credentials, sessions=reviewer_scope,
                                   authenticated=reviewer_identity, request=request)

    return SimpleNamespace(finaliser=finaliser, gate=gate, store=state, stores=stores, lineage=lineage, verifiers=verifiers,
        certificates=certificates, trust=trust, workspace=workspace, profile=profile,
        clinician=clinician, sessions=sessions, authenticated=authenticated, records=records,
        membership=membership, pack=pack, clock=clock, spec=spec, report=report, artifacts=artifacts,
        review_attempts=review_attempts, review_grant=review_grant,
        review_identities={name: pair[1] for name, pair in reviewer_sessions.items()},
        public_keys={key.key_id: key.public_key_bytes.hex() for key in keys.values()})
