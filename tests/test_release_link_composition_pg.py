"""X-22 end to end on actual restricted local logins; synthetic school, fictional people, isolated PostgreSQL.

The goal owner admits a reviewed delegation root, delegates one child to the host-derived executor, and the
executor's release contract (inheriting that authority) receives two signed reviews. Only the authenticated goal
owner can then link the release, inside one goal transaction that holds the material, chain and revocation fences
through publication. The executor's effect passes the complete receiving gates, whose delegated source check
requires that published link. Every refusal leaves no link and no artifact.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
import os
from types import SimpleNamespace

import pytest

from a08_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.release_link import GoalReleaseBinding, ReleaseLinkAdmission, ReleaseLinkRefused, ReleaseLinkRequest
from assurance_reference.release_link_authority import (ChainBoundReleaseMaterial, GoalOwnerAuthorization,
                                                        LinkedReleaseSource, provision_release_material,
                                                        reference_project_executor)
from assurance_reference.release_link_pg import PostgresGoalReleaseStore, provision_release_goal
from assurance_reference.release_link_reviews import StoredSignedReleaseReviews
from assurance_reference.session_credentials import SESSION_FIELD
from factory.projectos.governed_release import MISSION_FIELD, TARGET_FIELD
from factory.projectos.regulated import ReleaseAuthorityBinding
from regulated_core.approval_evidence import ReviewError
from regulated_core.authority_fence_pg import grant_revocation_key
from regulated_core.canonical import digest_hex
from regulated_core.delegation import RELEASE_AUTHORITY_FIELD, DelegationAuthority
from regulated_core.persistence_pg import PostgresGrantStore
from regulated_core.signing import Ed25519Signer, TrustDirectory
from synthetic_bounded_education import SYNTHETIC_PUBLISHER, build_bounded_education_fixture

TENANT, GOAL, INSTANCE = "school-a", "synthetic-goal", "synthetic-instance"
PASSWORD = "fictional-password-001"


def _admit_root(app):
    gate = app.gates["requester"]
    context = replace(app.context, nonce="x22-root-review", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    opened = gate.open_delegation_review(**common, context=context, destinations=(str(app.path),),
                                         expires_in_us=200_000_000, admit_within_us=60_000_000, delegable=True)
    request = dict(**common, delegation_review_id=opened["delegation_review_id"])
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        app.gates[principal].grant_delegation_review(
            **request, role=role, context=replace(context, actor_id=principal, now_us=app.clock.now_us()))
    admitted = gate.admit_delegation(**request, context=replace(context, now_us=app.clock.now_us()))
    assert admitted["status"] == "admitted" and admitted["root"]["subject"] == "requester"
    return admitted["root"]


@pytest.fixture
def scene(tmp_path):
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    source = {}
    try:
        publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
        bundle = tmp_path / "signed-budget-pack"
        build_bounded_education_fixture(bundle, publisher=publisher)
        delegation_signer = Ed25519Signer("fictional:x22-delegation")
        app = build_education_fixture(
            roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
            fixture_budget_limit=None, fixture_validity_us=300_000_000, delegation_signer=delegation_signer,
            delegation_source_status=lambda tenant, grant: source["status"](tenant, grant))
        # The receiving delegated source reads published links through the receiver's read-only duty.
        source["status"] = LinkedReleaseSource(pool=roles.receiver, clock_us=app.clock.now_us)
        root = _admit_root(app)
        executor = reference_project_executor(tenant_id=TENANT, goal_id=GOAL, vertical="education",
                                              project_instance_id=INSTANCE)
        delegation = app.gates["requester"]._engine.delegation
        child = delegation.issue_child(TENANT, root["root_digest"], actor="requester", subject=executor,
                                       operations=root["operations"], targets=root["targets"],
                                       expires_at_us=root["expires_at_us"] - 1_000_000, delegable=False,
                                       clock=app.clock.now_us)
        chain = delegation.resolve(TENANT, child.digest, now_us=app.clock.now_us())
        authority = ReleaseAuthorityBinding(child.digest, chain.digest, chain.root.digest(), chain.root.root_mission)
        app.sessions.provision_identity(TENANT, executor, "executor.local", PASSWORD)
        identity = app.sessions.authenticate(TENANT, app.sessions.login(TENANT, "executor.local", PASSWORD))
        gate = app.make_gate(identity)
        context = replace(app.context, actor_id=executor, nonce="x22-release", now_us=app.clock.now_us(),
                          not_after_us=identity.expires_at_us)
        contract = {**app.contract, SESSION_FIELD: identity.binding(), MISSION_FIELD: authority.mission,
                    RELEASE_AUTHORITY_FIELD: authority.as_fields(),
                    TARGET_FIELD: gate.describe_target(spec=app.spec, out_path=str(app.path), context=context)}
        opened = gate.open_review(spec=app.spec, contract=contract, context=context)
        for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
            state = app.gates[principal].grant_review(
                spec=app.spec, contract=contract, review_id=opened["review_id"], role=role,
                context=replace(context, actor_id=principal, now_us=app.clock.now_us()))
        assert state["status"] == "approved"
        reviewed = replace(context, approval=opened["review_id"], release_target=str(app.path))
        goal = GoalReleaseBinding(TENANT, GOAL, "requester", "a" * 64, "b" * 64,
                                  app.clock.now_us() + 200_000_000, "education", "geometry", INSTANCE, executor)
        provision_release_goal(owner, goal)
        provision_release_material(owner, goal_id=GOAL, review_id=opened["review_id"], contract=contract,
                                   context=reviewed)
        trust = TrustDirectory()
        trust.register_signer(delegation_signer)
        material = ChainBoundReleaseMaterial(pool=roles.release_linker, trust=trust,
                                             delegation_key_id=delegation_signer.key_id, clock=app.clock)
        reviews = StoredSignedReleaseReviews(exchange=gate._exchange(), material=material, clock=app.clock)
        request = ReleaseLinkRequest(GOAL, "task-1", "education", "geometry", opened["review_id"], str(app.path))

        def service(principal="requester", goals=None):
            return ReleaseLinkAdmission(
                authenticated=app.identities[principal], sessions=app.sessions,
                goals=goals or PostgresGoalReleaseStore(pool=roles.release_linker), reviews=reviews,
                authorize=GoalOwnerAuthorization(pool=roles.release_linker))

        def release():
            now = replace(reviewed, now_us=app.clock.now_us())
            decision = gate.authorize_release(spec=app.spec, contract=contract, out_path=str(app.path),
                                              context=now, artifact=app.body)
            if not decision.allowed:
                return decision
            return gate.commit_release(spec=app.spec, contract=contract, decision=decision,
                                       artifact=app.body, out_path=str(app.path), context=now)

        def links():
            with owner.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('app.release_tenant',%s,true)", (TENANT,))
                return conn.execute("SELECT count(*) FROM reference_release_links_v1").fetchone()[0]

        yield SimpleNamespace(app=app, roles=roles, owner=owner, goal=goal, child=child, chain=chain,
                              executor=executor, contract=contract, reviewed=reviewed, request=request,
                              material=material, reviews=reviews, service=service, release=release, links=links,
                              delegation_signer=delegation_signer, trust=trust)
    finally:
        owner.close()
        for f in fields(roles):
            value = getattr(roles, f.name)
            if isinstance(value, LocalPool):
                value.close()


def _revoke(s, digest):
    # Fixture withdrawal by the root's own subject, written through the provisioning pool: no runtime login of this
    # local profile holds the revocation append duty.
    DelegationAuthority(s.delegation_signer, s.trust, PostgresGrantStore(pool=s.owner)).revoke_authorized(
        TENANT, digest, actor="requester", reason="fixture withdrawal", now_us=s.app.clock.now_us())


def _goal_digest(goal):
    from dataclasses import asdict
    return digest_hex(asdict(goal))


def test_goal_owner_links_executor_review_and_the_effect_passes_receiving_gates(scene):
    s = scene
    link = s.service().admit(s.request)
    assert link.goal == s.goal and link.review.executor == s.executor
    assert link.review.authority == ReleaseAuthorityBinding(s.child.digest, s.chain.digest,
                                                            s.chain.root.digest(), s.chain.root.root_mission)
    assert s.service().admit(s.request) == link and s.links() == 1
    result = s.release()
    assert result.state == "committed", result
    assert s.app.path.read_bytes() == s.app.body
    assert s.app.stores.recorder.verify_chain(TENANT)


def test_executor_release_without_a_published_link_is_refused(scene):
    s = scene
    decision = s.release()
    assert not decision.allowed and not s.app.path.exists() and s.links() == 0


@pytest.mark.parametrize("principal", ["teacher", "executor-session-of-another-user"])
def test_non_owner_cannot_link(scene, principal):
    s = scene
    if principal != "teacher":
        s.app.sessions.provision_identity(TENANT, "other", "other.local", PASSWORD)
        s.app.identities[principal] = s.app.sessions.authenticate(
            TENANT, s.app.sessions.login(TENANT, "other.local", PASSWORD))
    with pytest.raises(ReleaseLinkRefused, match="goal owner"):
        s.service(principal).admit(s.request)
    assert s.links() == 0 and not s.release().allowed and not s.app.path.exists()


def test_missing_review_is_refused_without_creating_one(scene):
    s = scene
    absent = replace(s.request, review_id="review:absent")
    provision_release_material(s.owner, goal_id=GOAL, review_id=absent.review_id, contract=s.contract,
                               context=replace(s.reviewed, approval=absent.review_id))
    with pytest.raises(ReviewError):
        s.service().admit(absent)
    assert s.reviews.exchange.store.get(TENANT, absent.review_id) is None and s.links() == 0


def test_expired_review_is_refused(scene):
    s = scene
    state = s.reviews.exchange.store.get(TENANT, s.request.review_id)
    material = s.material.read(s.goal, s.request)
    review, *_ = s.reviews.exchange._validated(state, material.contract,
                                               replace(material.context, now_us=s.app.clock.now_us()),
                                               s.request.review_id)
    s.reviews.clock = SimpleNamespace(now_us=lambda: review.expires_at_us)
    with pytest.raises(ReviewError, match="expired"):
        s.service().admit(s.request)
    assert s.links() == 0


def test_revoked_inherited_grant_is_refused_before_linking(scene):
    s = scene
    _revoke(s, s.child.digest)
    with pytest.raises(ReleaseLinkRefused, match="revoked"):
        s.service().admit(s.request)
    assert s.links() == 0


def test_grant_revoked_after_preflight_is_refused_inside_the_goal_transaction(scene):
    s = scene

    class RevokingStore(PostgresGoalReleaseStore):
        def transact(self, tenant, request, mutation):
            _revoke(s, s.child.digest)  # Committed after the preflight read, before the goal transaction.
            return super().transact(tenant, request, mutation)

    with pytest.raises(ReleaseLinkRefused, match="revoked"):
        s.service(goals=RevokingStore(pool=s.roles.release_linker)).admit(s.request)
    assert s.links() == 0 and not s.release().allowed


def test_revocation_fences_are_held_through_publication(scene):
    s = scene
    observed = []
    material = s.material

    class Observing(ChainBoundReleaseMaterial):
        def locked_on(self, connection, goal, request):
            current = super().locked_on(connection, goal, request)

            def try_exclusive(digest):
                with s.owner.connection() as conn, conn.transaction():
                    return conn.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0))",
                                        (grant_revocation_key(TENANT, digest),)).fetchone()[0]

            # A revoker's exclusive grant lock is unavailable while this transaction holds its shared fences.
            with ThreadPoolExecutor(max_workers=1) as pool:
                observed.extend(pool.submit(try_exclusive, g.digest()).result() for g in s.chain.grants)
            return current

    s.reviews.material = Observing(pool=material.pool, trust=material.trust,
                                   delegation_key_id=material.delegation_key_id, clock=material.clock)
    s.service().admit(s.request)
    assert observed == [False] * len(s.chain.grants)
    with s.owner.connection() as conn, conn.transaction():
        assert conn.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0))",
                            (grant_revocation_key(TENANT, s.child.digest),)).fetchone() == (True,)


def test_ownership_change_inside_the_goal_transaction_is_refused(scene):
    s = scene

    class TransferringStore(PostgresGoalReleaseStore):
        def transact(self, tenant, request, mutation):
            provision_release_goal(s.owner, replace(s.goal, owner="teacher"), expected_digest=_goal_digest(s.goal))
            return super().transact(tenant, request, mutation)

    with pytest.raises(ReleaseLinkRefused, match="changed|owner"):
        s.service(goals=TransferringStore(pool=s.roles.release_linker)).admit(s.request)
    assert s.links() == 0 and not s.release().allowed


def test_goal_changed_after_linking_refuses_the_effect(scene):
    s = scene
    s.service().admit(s.request)
    provision_release_goal(s.owner, replace(s.goal, owner="teacher"), expected_digest=_goal_digest(s.goal))
    decision = s.release()
    assert not getattr(decision, "allowed", False) and not s.app.path.exists()


def test_expired_inherited_authority_is_refused(scene):
    s = scene
    # The trusted clock at the chain's expiry; the executor's review itself is still current on the real clock.
    s.material.clock = SimpleNamespace(now_us=lambda: s.chain.expires_at_us)
    with pytest.raises(ReleaseLinkRefused, match="expired"):
        s.service().admit(s.request)
    assert s.links() == 0


def test_grant_revoked_between_resolution_and_fences_is_refused(scene):
    s = scene

    class RevokedWhileWaiting(ChainBoundReleaseMaterial):
        revoked = False

        def _matches(self, chain, claim, goal):
            super()._matches(chain, claim, goal)
            # Inside the goal transaction: first resolution done, revocation fences not yet taken.
            if not self.revoked and len(chain.grants) > 1:
                type(self).revoked = True
                _revoke(s, s.child.digest)

    material = s.material
    s.reviews.material = RevokedWhileWaiting(pool=material.pool, trust=material.trust,
                                             delegation_key_id=material.delegation_key_id, clock=material.clock)
    s.reviews.material.read = material.read  # Preflight resolves before the revocation.
    with pytest.raises(ReleaseLinkRefused, match="revoked|changed while waiting"):
        s.service().admit(s.request)
    assert RevokedWhileWaiting.revoked and s.links() == 0


def test_release_material_row_is_share_locked_through_publication(scene):
    s = scene
    observed = []
    material = s.material

    class Observing(ChainBoundReleaseMaterial):
        def locked_on(self, connection, goal, request):
            current = super().locked_on(connection, goal, request)

            def try_update_lock():
                import psycopg
                with s.owner.connection() as conn, conn.transaction():
                    conn.execute("SELECT set_config('app.release_tenant',%s,true)", (TENANT,))
                    try:
                        conn.execute("SELECT 1 FROM reference_release_materials_v1 WHERE tenant=%s AND goal_id=%s"
                                     " AND review_id=%s FOR UPDATE NOWAIT", (TENANT, GOAL, request.review_id))
                    except psycopg.errors.LockNotAvailable:
                        return "locked"
                    return "free"

            with ThreadPoolExecutor(max_workers=1) as pool:
                observed.append(pool.submit(try_update_lock).result())
            return current

    s.reviews.material = Observing(pool=material.pool, trust=material.trust,
                                   delegation_key_id=material.delegation_key_id, clock=material.clock)
    s.service().admit(s.request)
    assert observed == ["locked"]
