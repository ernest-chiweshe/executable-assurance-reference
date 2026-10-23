"""X-3 on actual restricted local logins: sole-owner self-approval; synthetic school, fictional people.

The signed derivative lets one teacher approve feedback release, including their own request, only under the
explicit sole-owner term. The one shared check runs at the grant, at permit settlement and inside the receiving
admission, each over the retained review and the owner roster read through the dedicated owner_reader login.
Each loss of authority is refused independently at each point; a refusal leaves no artifact.
"""
from dataclasses import fields, replace
import os
from types import SimpleNamespace

import pytest

from a08_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.sole_owner_approval import set_tenant_owner, validate_self_approval_terms
from assurance_reference.sole_owner_composition import SoleOwnerApproval, SoleOwnerReleaseAdmission, SoleOwnerReviewGate
from factory.packs.registry import PackRegistry
from regulated_core.approval_evidence import ReviewError
from regulated_core.signing import Ed25519Signer
from synthetic_health_versions import fixture_trust
from synthetic_sole_owner_education import SYNTHETIC_PUBLISHER, build_sole_owner_education_fixture

TENANT = "school-a"
REFUSAL = {"second-owner": "sole tenant owner", "revoked": "sole tenant owner", "expired": "sole tenant owner",
           "membership-ended": "current tenant membership", "term-absent": "sole-owner self-approval term"}


def _pack(bundle, publisher):
    trust = fixture_trust()
    trust.register_signer(publisher)
    return PackRegistry(trust=trust).install(bundle, publisher_key_id=publisher.key_id, today="2026-10-14")


@pytest.fixture
def scene(tmp_path):
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    clock = {}
    try:
        publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
        bundle = tmp_path / "sole-owner-pack"
        build_sole_owner_education_fixture(bundle, publisher=publisher)
        approval = SoleOwnerApproval(pool=roles.owner_reader, pack=_pack(bundle, publisher),
                                     clock_us=lambda: clock["now"]())
        app = build_education_fixture(
            roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
            fixture_validity_us=300_000_000,
            credential_wrapper=lambda credentials: SoleOwnerReleaseAdmission(credentials, approval))
        clock["now"] = app.clock.now_us
        app.certify("requester", "teacher")
        set_tenant_owner(owner, tenant=TENANT, principal="requester", active_from_us=app.clock.now_us() - 1)
        gate = SoleOwnerReviewGate(app.gates["requester"], approval)
        context = replace(app.context, nonce="sole-owner-release", now_us=app.clock.now_us())
        common = dict(spec=app.spec, contract=app.contract)

        def opened():
            return gate.open_review(**common, context=context)["review_id"]

        def grant(review_id):
            return gate.grant_review(**common, context=replace(context, now_us=app.clock.now_us()),
                                     review_id=review_id, role="teacher")

        def authorize(review_id):
            return gate.authorize_release(**common, out_path=str(app.path), artifact=app.body,
                                          context=replace(context, approval=review_id, now_us=app.clock.now_us()))

        def commit(review_id, decision):
            return gate.commit_release(**common, decision=decision, artifact=app.body, out_path=str(app.path),
                                       context=replace(context, approval=review_id, now_us=app.clock.now_us()))

        def deactivate(principal):
            # Fixture membership withdrawal through the provisioning pool (no runtime login may deactivate).
            with owner.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)", (TENANT,))
                conn.execute("UPDATE reference_identities_v1 SET active=false WHERE tenant=%s AND principal=%s",
                             (TENANT, principal))

        def roster(principal, **change):
            set_tenant_owner(owner, tenant=TENANT, principal=principal,
                             active_from_us=change.pop("active_from_us", app.clock.now_us() - 1), **change)

        yield SimpleNamespace(app=app, approval=approval, gate=gate, opened=opened, grant=grant,
                              authorize=authorize, commit=commit, roster=roster, deactivate=deactivate, bundle=bundle, publisher=publisher)
    finally:
        owner.close()
        for f in fields(roles):
            value = getattr(roles, f.name)
            if isinstance(value, LocalPool):
                value.close()


def test_sole_current_owner_self_approval_releases(scene):
    s = scene
    review_id = s.opened()
    assert s.grant(review_id)["status"] == "approved"
    decision = s.authorize(review_id)
    assert decision.allowed, decision.reason
    assert s.commit(review_id, decision).state == "committed"
    assert s.app.path.read_bytes() == s.app.body


@pytest.mark.parametrize("loss", ["second-owner", "revoked", "expired", "membership-ended", "term-absent"])
def test_loss_of_sole_current_ownership_is_refused_at_grant(scene, loss):
    s = scene
    review_id = s.opened()
    _lose(s, loss)
    with pytest.raises(ReviewError, match=REFUSAL[loss]):
        s.grant(review_id)
    assert not s.app.path.exists()


@pytest.mark.parametrize("loss", ["second-owner", "revoked", "expired", "membership-ended", "term-absent"])
def test_loss_of_sole_current_ownership_is_refused_at_settlement(scene, loss):
    s = scene
    review_id = s.opened()
    s.grant(review_id)
    _lose(s, loss)
    with pytest.raises(Exception, match=REFUSAL[loss]):
        s.authorize(review_id)
    assert not s.app.path.exists()


@pytest.mark.parametrize("loss", ["second-owner", "revoked", "expired", "membership-ended", "term-absent"])
def test_loss_of_sole_current_ownership_is_refused_inside_the_receiver(scene, loss):
    s = scene
    review_id = s.opened()
    s.grant(review_id)
    decision = s.authorize(review_id)
    assert decision.allowed, decision.reason
    _lose(s, loss)
    result = s.commit(review_id, decision)
    assert result.state != "committed" and not s.app.path.exists()


def test_pending_owner_activation_bounds_the_release_window(scene):
    s = scene
    review_id = s.opened()
    s.grant(review_id)
    activation = s.app.clock.now_us() + 30_000_000
    s.roster("teacher", active_from_us=activation)
    decision = s.authorize(review_id)
    assert decision.allowed, decision.reason
    assert decision.permit.permit.permit.expires_at_us <= activation


def test_self_approval_without_the_signed_term_refuses_startup(tmp_path):
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    for name, change in (("no-term", {"term": None}), ("term-without-permission", {"requester_may_approve": False}),
                         ("other-term", {"term": "any-owner/v1"})):
        bundle = tmp_path / name
        build_sole_owner_education_fixture(bundle, publisher=publisher, **change)
        with pytest.raises(ValueError, match="sole-owner/v1"):
            validate_self_approval_terms(_pack(bundle, publisher))


def _without_term(pack):
    """The installed policy as it would read without the signed sole-owner term (and so without self-approval).

    A synthetic policy view: the recorded self-approval stays signed under the termed policy, while the check reads a
    rule that no longer carries the term. The guard itself is unchanged."""
    import copy
    content = copy.deepcopy(pack.rulebook.effective_content)
    for rule in content["rules"].values():
        approval = rule.get("approval")
        if approval is not None:
            approval.pop("self_approval_term", None)
            approval["requester_may_approve"] = False
    return SimpleNamespace(rulebook=SimpleNamespace(ref=pack.rulebook.ref, effective_content=content))


def _lose(s, loss):
    now = s.app.clock.now_us()
    if loss == "membership-ended":
        s.deactivate("requester")
    elif loss == "term-absent":
        s.approval.pack = _without_term(s.approval.pack)
    elif loss == "second-owner":
        s.roster("teacher")
    elif loss == "revoked":
        s.roster("requester", revoked_at_us=now)
    else:
        s.roster("requester", active_from_us=now - 2, expires_at_us=now - 1)
