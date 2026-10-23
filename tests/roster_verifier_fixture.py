"""Configured but disconnected roster verifier for factory-only checks."""
from assurance_reference.roster_authority import RosterAuthorityVerifier
from regulated_core.persistence_pg import PostgresDecisionRecorder, PostgresRosterStore
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import TargetAuthority
from test_prepermit_retention import FixtureClock


def verified_store(installation="fixture", tenant="fixture"):
    trust = TrustDirectory()
    signer = Ed25519Signer("synthetic:roster-verifier")
    trust.register_signer(signer)
    clock = FixtureClock()
    authority = TargetAuthority(signer, trust, revocation_epoch=lambda tenant: 0, clock=clock)
    recorder = PostgresDecisionRecorder(signer, trust, pool=None, clock=clock)
    verifier = RosterAuthorityVerifier(tenant=tenant, installation=installation, authority=authority,
        recorder=recorder, bootstrap_trust=trust, bootstrap_key_ids=frozenset({signer.key_id}))
    return PostgresRosterStore(pool=None, proof_verifier=verifier), signer
