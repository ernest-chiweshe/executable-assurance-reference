"""Queued real same-schema composition; requires the owned serial DB window."""

import os

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.role_contract import collect_access_matrix
from regulated_core.canonical import canonical_bytes
from three_application_fixture import compose_and_release, project_scope_observation


def test_three_applications_share_restricted_schema_without_cross_scope_state(tmp_path):
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    matrix = compose_and_release(roles, tmp_path)
    e, h, p = matrix.education, matrix.health, matrix.product_spec
    assert len({e.clock.domain, h.clock.domain, p.clock.domain}) == 1
    assert all(app.stores.pool._pool is roles.receiver for app in (e, h, p))
    assert len(e.stores.activation.pack_ids()) == 2
    assert p.domain_packs == ()
    assert e.workflow_state.load("geometry")["contract"] == e.contract
    assert p.state.load("geometry")["release_outcomes"][-1]["state"] == "committed"
    assert h.store.get(h.session.session_id, h.clinician.owner_id).document(h.document.doc_id).finalisation.state == "committed"
    assert h.lineage.get(h.release_outcome.nonce) == h.lineage_snapshot
    matrix_result = project_scope_observation(matrix)
    assert len(matrix_result) == 9 and sum(matrix_result.values()) == 3
    snapshots = []
    for app, tenant in ((e, "school-a"), (h, h.authenticated.tenant), (p, p.tenant)):
        assert app.stores.recorder.verify_chain(tenant)
        snapshots.append(canonical_bytes(app.stores.recorder.entries(tenant)))
    assert len(set(snapshots)) == 3
    roles_report = collect_access_matrix(roles, partitioned_lifecycle=True)
    assert roles_report["privilege_contract_matches"], roles_report["errors"]
    # Reconciliation of the neutral release remains idempotent with the other
    # applications and domain packs present in the same database schema.
    stamp = p.path.stat().st_mtime_ns
    p.engine.release("geometry", str(p.path), context=p.release_context)
    assert p.path.stat().st_mtime_ns == stamp
