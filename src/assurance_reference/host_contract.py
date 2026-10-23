"""Offline configuration checks for the reference's complete authority host."""

from itertools import combinations

from assurance_reference.alerts import AlertJournal
from assurance_reference.qualified_engine import QualificationSet
from assurance_reference.retention_contract import require_retention_operations
from regulated_core.governance_guard import GovernanceGuard


def require_reference_host_contract(stores, authorities, *, alerts, qualifications):
    """Reject incomplete configuration without signing, connecting or invoking effects.

    Key separation concerns trusted public material, not just different labels.
    These checks do not establish process isolation, deployed custody or readiness.
    The original host's own validation still runs after this additional contract.
    """
    for name in ("pool", "activation", "recorder", "permits", "reviews", "budget",
                 "revocation", "grants", "clearances", "governance", "heartbeats"):
        if getattr(stores, name, None) is None:
            raise ValueError(f"reference host requires the {name} store")
    if not isinstance(getattr(stores.activation, "governance_guard", None), GovernanceGuard):
        raise ValueError("reference host requires governed pack lifecycle")
    require_retention_operations(authorities.worm)
    if not isinstance(alerts, AlertJournal) or alerts.trust is not authorities.trust:
        raise ValueError("reference alert journal must share the host trust directory")
    if not isinstance(qualifications, QualificationSet) or qualifications._trust is not authorities.trust:
        raise ValueError("reference qualifications must share the host trust directory")
    if qualifications._domain != authorities.clock.domain:
        raise ValueError("reference qualifications must use the host clock domain")

    mapped = authorities.credential_authorities is not None or authorities.credential_provider_families is not None
    credentials = (set((authorities.credential_authorities or {}).values())
                   | set((authorities.credential_provider_families or {}).values())) if mapped else {
                       authorities.credential_authority}
    groups = {
        "evidence": {stores.recorder._signer.key_id},
        "approval": {authorities.approval_signer.key_id},
        "emission": {authorities.emission_signer.key_id},
        "preflight": {authorities.preflight_signer.key_id},
        "identity": {authorities.identity_authority},
        "credentials": credentials,
        "verification": {signer.key_id for signer in authorities.verifier_signers.values()},
        "alerts": {alerts.signer.key_id},
        "qualification": {qualifications._authority},
    }
    if authorities.delegation_signer is not None:
        groups["delegation"] = {authorities.delegation_signer.key_id}
    monitor_keys = set(authorities.heartbeat_monitor_key_ids) | set(authorities.tier4_monitor_key_ids)
    if monitor_keys:
        groups["monitor"] = monitor_keys
    for name, keys in groups.items():
        if not keys or any(not key or not authorities.trust.is_known(key) for key in keys):
            raise ValueError(f"reference {name} requires explicit trusted keys")
    for (left, left_keys), (right, right_keys) in combinations(groups.items(), 2):
        if any(not authorities.trust.distinct_keys((a, b)) for a in left_keys for b in right_keys):
            raise ValueError(f"reference authority keys must be separated: {left} and {right}")
