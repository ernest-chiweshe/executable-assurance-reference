"""Offline fixture composition only; no application tier-four qualification."""
from dataclasses import fields

import pytest

from assurance_reference.local_fixture_host import _with_synthetic_tier4
from regulated_core.host_runtime import RuntimeAuthorities
from regulated_core.signing import Ed25519Signer, TrustDirectory


class FictionalDirectory:
    def reporting_line(self, tenant_id, subject_id):
        if tenant_id != "fictional-tenant":
            return None
        return {"reviewer-a": "line-a", "reviewer-b": "line-b"}.get(subject_id)


def authorities_and_monitor():
    trust = TrustDirectory()
    monitor = Ed25519Signer("fixture:tier-profile:monitor")
    trust.register_signer(monitor)
    # The real authority value type is used; unused dependencies are opaque
    # sentinels so preservation can be observed without composing a database.
    values = {field.name: object() for field in fields(RuntimeAuthorities)
              if field.name in (
                  "approval_signer", "emission_signer", "preflight_signer",
                  "identity_authority", "credential_authority", "credential_verifier",
                  "host_verifiers", "verifier_signers", "worm", "clock")}
    return RuntimeAuthorities(trust=trust, **values), monitor


def test_ordinary_profile_keeps_the_same_authority_object():
    original, monitor = authorities_and_monitor()
    assert _with_synthetic_tier4(original, directory=None, cooling_off_us=0,
                                monitor_key_id=monitor.key_id) is original
    assert original.tier4_directory is None
    assert original.tier4_monitor_key_ids == frozenset()


def test_explicit_profile_preserves_all_other_authorities():
    original, monitor = authorities_and_monitor()
    directory = FictionalDirectory()
    configured = _with_synthetic_tier4(original, directory=directory,
                                      cooling_off_us=2_000_000, monitor_key_id=monitor.key_id)
    assert configured.tier4_directory is directory
    assert configured.tier4_monitor_key_ids == frozenset({monitor.key_id})
    assert configured.tier4_cooling_off_us == 2_000_000
    for field in fields(original):
        if not field.name.startswith("tier4_"):
            assert getattr(configured, field.name) is getattr(original, field.name)
    assert original.tier4_directory is None
    assert directory.reporting_line("unconfigured-tenant", "reviewer-a") is None
    assert directory.reporting_line("fictional-tenant", "unknown") is None


@pytest.mark.parametrize("period", [0, -1, True, 1.5, "100"])
def test_explicit_directory_requires_a_positive_integer_period(period):
    original, monitor = authorities_and_monitor()
    with pytest.raises(ValueError, match="positive cooling-off"):
        _with_synthetic_tier4(original, directory=FictionalDirectory(),
                             cooling_off_us=period, monitor_key_id=monitor.key_id)


@pytest.mark.parametrize("period", [1, False, None])
def test_partial_profile_is_not_silently_ignored(period):
    original, monitor = authorities_and_monitor()
    with pytest.raises(ValueError, match="explicit fixture directory"):
        _with_synthetic_tier4(original, directory=None, cooling_off_us=period,
                             monitor_key_id=monitor.key_id)


def test_directory_contract_and_registered_monitor_are_required():
    original, monitor = authorities_and_monitor()
    with pytest.raises(ValueError, match="tenant-scoped"):
        _with_synthetic_tier4(original, directory=object(), cooling_off_us=1,
                             monitor_key_id=monitor.key_id)
    with pytest.raises(ValueError, match="already be registered"):
        _with_synthetic_tier4(original, directory=FictionalDirectory(), cooling_off_us=1,
                             monitor_key_id="fixture:not-registered")
