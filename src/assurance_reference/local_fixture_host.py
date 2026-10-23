"""Explicit synthetic local host profile, shared by examples and contract tests.

This is not deployed identity, custody, or domain qualification evidence.
"""
from contextlib import contextmanager
from dataclasses import replace
from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.host_runtime import compose_reference_stores
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.qualified_engine import QualificationSet, RequiredQualification
from regulated_core import Ed25519Signer, TrustDirectory
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE
from regulated_core.clock_pg import DbClock
from regulated_core.document_gate import VerifierRegistry
from regulated_core.host_runtime import RuntimeAuthorities
from regulated_core.identity_provider import CredentialError, CredentialVerifier, LocalIdentityProvider
from regulated_core.qualification import LabeledCase, QualificationDataset, qualify


class UnauthenticatedSessionFixture(CredentialVerifier):
    """A missing session always refuses; this fixture cannot admit an effect."""

    @contextmanager
    def admit_release(self, **request):
        raise CredentialError("no authenticated session in this composition test")
        yield  # pragma: no cover



def _with_synthetic_tier4(authorities, *, directory, cooling_off_us, monitor_key_id):
    """Bind explicitly supplied fictional organisational authority.

    This selects host controls only. It never changes a policy's signed risk
    tier, approval requirements, existing decisions, or identity authorities.
    """
    if directory is None:
        if type(cooling_off_us) is not int or cooling_off_us != 0:
            raise ValueError("a cooling-off period requires an explicit fixture directory")
        return authorities
    if not callable(getattr(directory, "reporting_line", None)):
        raise ValueError("fixture directory must resolve tenant-scoped reporting lines")
    if type(cooling_off_us) is not int or cooling_off_us <= 0:
        raise ValueError("fixture tier four requires an explicit positive cooling-off period")
    if not authorities.trust.is_known(monitor_key_id):
        raise ValueError("fixture monitor key must already be registered")
    return replace(authorities, tier4_directory=directory,
                   tier4_monitor_key_ids=frozenset({monitor_key_id}),
                   tier4_cooling_off_us=cooling_off_us)


def configuration(roles, tmp_path, *, clock_source=None, retention=None,
                  signer_factory=Ed25519Signer, outage_alarm=None, partitioned_lifecycle=True,
                  fixture_validity_us=120_000_000, tier4_directory=None, tier4_cooling_off_us=0,
                  recovery=None, shared_fixture_cleanup=None):
    if type(fixture_validity_us) is not int or not 0 < fixture_validity_us <= 600_000_000:
        raise ValueError("fictional evidence validity must be positive and at most ten minutes")
    # R-2b: ``recovery`` = dict(arming=..., max_permit_lifetime_us=..., sentinel_file=..., heartbeat_s=...)
    # composes the full rollback-recovery profile; without it the fixture names its non-use explicitly.
    profile = dict(recovery or {})
    heartbeat_s = profile.pop("heartbeat_s", None)
    clock = DurableClock(clock_source if clock_source is not None else DbClock(roles.receiver, roles.domain),
                         floor_pool=roles.clock, **profile,
                         recovery_not_used_reason=None if recovery else (
                             "Synthetic local fixture; rollback recovery is qualified by tests/test_recovery_*"))
    if recovery:
        clock.start_heartbeat(heartbeat_s if heartbeat_s is not None else 1.0)
    trust = TrustDirectory()
    keys = {name: signer_factory("reference-host-fixture:" + name) for name in (
        "evidence", "approval", "emission", "preflight", "identity", "credential",
        "issuer", "verifier", "qualification", "alert", "monitor",
    )}
    for key in keys.values():
        trust.register_signer(key)
    certificates = CertificateRegistry(trust, {keys["issuer"].key_id: DEMONSTRATION_CERTIFICATE})
    credentials = UnauthenticatedSessionFixture(
        trust, keys["credential"], LocalIdentityProvider(), certificates,
    )
    stores = compose_reference_stores(roles, evidence_signer=keys["evidence"], trust=trust, clock=clock,
                                      partitioned_lifecycle=partitioned_lifecycle)
    authorities = RuntimeAuthorities(
        trust, keys["approval"], keys["emission"], keys["preflight"],
        keys["identity"].key_id, keys["credential"].key_id, credentials,
        VerifierRegistry(), {"fixture:marker": keys["verifier"]},
        retention if retention is not None else LocalRetentionStore(tmp_path / "retention"), clock,
        outage_alarm=outage_alarm,
    )
    authorities = _with_synthetic_tier4(
        authorities, directory=tier4_directory, cooling_off_us=tier4_cooling_off_us,
        monitor_key_id=keys["monitor"].key_id)
    dataset = QualificationDataset("synthetic-marker", "1", "Synthetic protocol fixture only.", (
        LabeledCase("marker", True), LabeledCase("other", False),
    ))
    report = qualify(
        keys["qualification"], verification_class="fixture:marker", verifier_version="1",
        dataset=dataset, predicate=lambda value: value == "marker",
        qualified_at_us=clock.now_us(), valid_for_us=fixture_validity_us,
        jurisdictions=("fixture",), languages=("en",), document_types=("synthetic",),
        limitations=("No educational or clinical validity claim.",),
    )
    qualifications = QualificationSet(
        trust=trust, authority=keys["qualification"].key_id, clock_domain=clock.domain,
        required=(RequiredQualification("fixture:marker", "1", dataset.digest(),
                                        "fixture", "en", "synthetic", "1", "1"),),
        reports=(report,),
    )
    alerts = AlertJournal(roles.alerts, keys["alert"], trust)
    import os
    if os.environ.get("REFERENCE_SHARED_EVIDENCE_FIXTURE") == "1":
        from assurance_reference.shared_evidence_fixture import configure_shared_fixture
        stores=configure_shared_fixture(stores,authorities,roles,tmp_path,register_cleanup=shared_fixture_cleanup)
    return stores, authorities, alerts, qualifications, report, keys


