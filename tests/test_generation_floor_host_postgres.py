"""Guarded local floor admission; synthetic retirement evidence, no deployment claim.

Creates only fresh objects in the explicitly isolated loopback factory_test.
The retired fixture role is created NOLOGIN; no existing login is disabled or
re-enabled. Original generation-floor and target guards remain intact.
"""

from dataclasses import replace
import os
import uuid

import pytest
from psycopg import sql

from assurance_reference.generation_floor_admission import GenerationFloorAdmission
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import LocalPool, provision_local_roles
from factory.customer.generation_floor_pg import GenerationFloorVerifier, migrate_generation_floor
from regulated_core.identity_provider import CredentialError
from regulated_core.signing import Ed25519Signer
from regulated_core.target import Outcome
from test_reference_host import render_request


def test_host_floor_refuses_unqualified_history_then_holds_through_guarded_effect(tmp_path):
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    # provision_local_roles validates both the configured and connected boundary
    # before any object creation. All later connections use that same DSN.
    roles = provision_local_roles(dsn)
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    signer = Ed25519Signer("fixture:floor:" + uuid.uuid4().hex)
    authorities.trust.register_signer(signer)
    verifier = GenerationFloorVerifier(trust=authorities.trust, issuer_key_id=signer.key_id,
        installation_id="fixture:" + roles.schema, schema=roles.schema, minimum_generation=2)
    guard = GenerationFloorAdmission(verifier, roles.receiver, roles.domain, "factory_test", roles.receiver.role)
    owner = LocalPool(dsn, roles.schema, "fixture-provisioning-only")
    legacy = "fixture_retired_" + uuid.uuid4().hex
    try:
        with owner.connection() as connection:
            writer = connection.execute("SELECT session_user").fetchone()[0]
            connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT").format(sql.Identifier(legacy)))
            migrate_generation_floor(connection, schema=roles.schema, writer_logins=(writer,))
            connection.execute(sql.SQL("GRANT SELECT ON {}.application_generation_floor_v1 TO {}")
                .format(sql.Identifier(roles.schema), sql.Identifier(roles.receiver.role)))
        host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
                                      generation_floor=guard)
        engine, authorization, target, body = render_request(host, tmp_path)
        assert engine._generation_floor is guard
        with pytest.raises(CredentialError, match="not retired"):
            engine.commit(authorization, body, target)
        assert not target.path.exists()

        def append(state, head):
            with owner.connection() as connection, connection.transaction():
                return verifier.append_on(connection, signer=signer, generation=2, state=state,
                    retired_logins=(legacy,), deployment_evidence_digest="a" * 64,
                    expected_head=head, observation_pool=owner)

        # Fictional signed retirement history with real committed catalog checks.
        pending = append("retiring", "")
        with pytest.raises(CredentialError, match="not retired"):
            engine.commit(authorization, body, target)
        assert not target.path.exists()
        retired = append("retired", pending.digest)
        observed = []

        def observe_existing_floor_guard():
            # Observational lock contract only: the existing shared floor guard
            # must prevent an independent transaction taking the exclusive lock.
            with owner.connection() as connection, connection.transaction():
                acquired = connection.execute(
                    "SELECT pg_try_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
                    ("application-generation-floor:authentication",)).fetchone()[0]
                assert acquired is False
                observed.append("shared-floor-lock-held-at-target-check")

        guarded_target = replace(target, effect_check=observe_existing_floor_guard)
        result = engine.commit(authorization, body, guarded_target)
        assert result.outcome is Outcome.COMMITTED
        assert observed == ["shared-floor-lock-held-at-target-check"]
        assert target.path.read_bytes() == body
        assert target.status(authorization.permit).outcome is Outcome.COMMITTED
        assert stores.recorder.verify_chain("synthetic-host")
        with roles.receiver.connection() as connection, connection.transaction():
            assert verifier.require_on(connection) == retired
        with owner.connection() as connection, connection.transaction():
            assert connection.execute(
                "SELECT pg_try_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
                ("application-generation-floor:authentication",)).fetchone() == (True,)
    finally:
        owner.close()
        for value in vars(roles).values():
            if isinstance(value, LocalPool):
                value.close()
