"""Mandatory durable-budget composition for supported reference governance hosts."""
from assurance_reference.durable_registries import PostgresIssuerRegistry, PostgresQualificationRegistry
from assurance_reference.roster_authority import RosterAuthorityVerifier
from threading import RLock
from weakref import WeakKeyDictionary

from factory.packs.lifecycle_pg import PostgresActivationLedger
from regulated_core import governance_targets as core
from regulated_core.governance_roster import roster_target as core_roster_target
from regulated_core.governance_transaction import PostgresGovernanceBudget
from regulated_core.persistence_pg import PostgresRosterStore


def _options(budget, options):
    reserved = {"budget_binding", "budget_transaction", "transact", "receipt"}
    if reserved.intersection(options):
        raise ValueError("reference governance transaction and budget wiring are host-owned")
    return {**options, "budget_binding": PostgresGovernanceBudget(budget), "budget_transaction": True}


def _pack(factory, registry, args, budget, options):
    if not isinstance(getattr(registry, "ledger", None), PostgresActivationLedger):
        raise TypeError("reference governance requires the PostgreSQL lifecycle transaction")
    return _register(factory(registry, *args, **_options(budget, options)), budget)


def pack_activation_target(registry, *args, budget, **options):
    return _pack(core.pack_activation_target, registry, args, budget, options)


def pack_pin_target(registry, *args, budget, **options):
    return _pack(core.pack_pin_target, registry, args, budget, options)


def pack_rollback_target(registry, *args, budget, **options):
    return _pack(core.pack_rollback_target, registry, args, budget, options)


def pack_revocation_target(registry, *args, budget, **options):
    return _pack(core.pack_revocation_target, registry, args, budget, options)


def roster_target(store, installation, *, budget, **options):
    if not isinstance(store, PostgresRosterStore):
        raise TypeError("reference governance requires the PostgreSQL roster transaction")
    configured = _options(budget, options)
    verifier = store._proof_verifier
    if (not isinstance(verifier, RosterAuthorityVerifier) or verifier.installation != installation
            or verifier.tenant != options.get("tenant_id") or verifier.authority is not options.get("authority")):
        raise TypeError("reference roster requires matching persisted authority verification")
    return _register(core_roster_target(store, installation, **configured), budget)


def qualification_target(registry, report, *, budget, **options):
    """Checker qualification under the mandatory budget, only over the durable registry (A15, candidate 062)."""
    if not isinstance(registry, PostgresQualificationRegistry):
        raise TypeError("reference governance requires the PostgreSQL qualification transaction")
    return _register(core.qualification_target(registry, report, **_options(budget, options)), budget)


def issuer_target(registry, issuer_key_id, *, budget, **options):
    """Approver-issuer recognition under the mandatory budget, only over the durable registry (A15, candidate 062)."""
    if not isinstance(registry, PostgresIssuerRegistry):
        raise TypeError("reference governance requires the PostgreSQL issuer transaction")
    return _register(core.issuer_target(registry, issuer_key_id, **_options(budget, options)), budget)


# This registry describes host composition within this process. It is not an
# isolation boundary against arbitrary Python code running in the same host.
_compositions = WeakKeyDictionary()
_composition_lock = RLock()


def _register(target, budget):
    with _composition_lock:
        _compositions[target] = (budget, target._budget_binding, target._transact, target._receipt)
    return target


def require_governance_composition(target, budget):
    """Refuse unsupported governance hosts before reference authority/effects."""
    if not isinstance(target, core.GovernanceTarget):
        return
    with _composition_lock:
        configured = _compositions.get(target)
    if configured is None:
        raise TypeError("governance target requires a supported reference governance factory")
    allocator, binding, transact, receipt = configured
    if (allocator is not budget or target._budget_binding is not binding
            or binding.budget is not allocator
            or target._transact is not transact or target._receipt is not receipt):
        raise TypeError("reference governance target must retain the engine's durable budget and host wiring")
