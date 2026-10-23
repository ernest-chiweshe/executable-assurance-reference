"""Intact offline host identity contracts; no database or live authorities."""
from test_host_contract import contract as contract, compose


def test_receiver_stores_and_collection_share_one_session_adapter(contract):
    host = compose(contract)
    session = contract.stores.pool
    assert host.stores is contract.stores
    assert host.collections._pool is session
    for name in ("activation", "permits", "reviews", "budget", "clearances", "governance", "heartbeats"):
        assert getattr(host.stores, name)._pool is session, name
    assert session._pool.role == "receiver"


def test_host_keeps_explicit_authority_objects(contract):
    host = compose(contract)
    configured = contract.authorities
    assert host.factory.trust is configured.trust
    assert host.factory.credential_verifier is configured.credential_verifier
    assert host.factory.host_verifiers is configured.host_verifiers
    assert host.factory.worm is configured.worm
    assert host.factory.verifier_signers == dict(configured.verifier_signers)
    for key, signer in configured.verifier_signers.items():
        assert host.factory.verifier_signers[key] is signer
    assert host.factory.engine._alerts is contract.alerts
    assert host.factory.engine._qualifications is contract.qualifications


def test_separate_write_duties_do_not_reuse_receiver_session(contract):
    host = compose(contract)
    session = host.stores.pool
    for name, role in (("recorder", "recorder"), ("grants", "delegation_issuer"), ("revocation", "governor")):
        writer = getattr(host.stores, name)._pool
        assert writer is not session
        assert writer._pool is not session._pool
        assert writer._pool.role == role
    allocator = host.stores.budget._allocator_pool
    assert allocator is not session and allocator is not session._pool
    assert allocator.role == "allocator"
