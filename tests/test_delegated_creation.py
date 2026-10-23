"""Reviewed roots, durable host claims and reconstructed child issuance."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.delegated_creation import ChildRequest, ReviewedChildCreation
from regulated_core.canonical import canonical_bytes
from regulated_core.delegation import DelegationAuthority, MAX_DEPTH
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresGrantStore
from test_root_admission import TENANTS, canonical, reviewed_root_fixture


class FixtureCreations:
    """A provisioned synthetic host claim; caller authentication stays a host duty."""

    def verify_on(self, conn, request):
        row = conn.execute(
            "SELECT c.subject,m.revision FROM reference_child_claims c "
            "JOIN reference_root_members m ON m.tenant=c.tenant AND m.subject=c.actor "
            "WHERE c.tenant=%s AND c.creation_id=%s AND c.parent=%s AND c.actor=%s "
            "AND m.enabled AND m.role IN ('owner','executor') FOR SHARE OF c,m",
            (request.tenant, request.creation_id, request.parent_digest, request.actor),
        ).fetchone()
        if row is None:
            raise EmissionError("current host creation claim or actor membership is unavailable")
        return row


def test_creation_retries_and_withdrawal_preserve_exact_host_binding(tmp_path):
    fixture = reviewed_root_fixture(tmp_path)
    assemble = fixture["assemble"]
    pool, clock, _, _, _, _ = assemble(TENANTS[0])
    with pool.connection() as conn, conn.transaction():
        conn.execute("CREATE TABLE reference_child_claims "
                     "(tenant text,creation_id text,parent text,actor text,subject text,"
                     "PRIMARY KEY(tenant,creation_id),UNIQUE(tenant,subject))")
        for tenant in TENANTS:
            conn.execute("INSERT INTO reference_child_claims VALUES (%s,'draft-1',%s,'owner',%s)",
                         (tenant, fixture["roots"][tenant].digest, "executor:" + tenant + ":draft-1"))

    def service(tenant):
        pool, _, _, verifier, admission, _ = assemble(tenant)
        return ReviewedChildCreation(
            pool=pool, root_verifier=verifier, signer=fixture["signers"]["delegation"],
            creations=FixtureCreations(), alerts=admission.alerts,
        )

    requests = {tenant: ChildRequest(
        tenant=tenant, parent_digest=fixture["roots"][tenant].digest,
        creation_id="draft-1", actor="owner", operations=("course:save-draft",),
        targets=fixture["roots"][tenant].grant.targets,
        expires_at_us=fixture["expires"] - 1_000_000,
    ) for tenant in TENANTS}
    first = requests[TENANTS[0]]

    # Ordinary scope requests outside the approved parent refuse before any child is stored.
    refused_scope = []
    for request, reason in (
        (replace(first, operations=(*first.operations, "course:publish")),
         "a child cannot reach operations its parent cannot"),
        (replace(first, targets=(*first.targets, "f" * 64)),
         "a child cannot reach targets its parent cannot"),
        (replace(first, expires_at_us=fixture["expires"] + 1), "a child cannot outlive its parent"),
        (replace(first, policy_refs=("course:unrelated-policy",)), "a child keeps every policy its parent is bound by"),
    ):
        result = service(first.tenant).create(request)
        assert result.status == "refused" and result.grant is None and result.detail == reason
        refused_scope.append(result)
        with pool.connection() as conn:
            assert conn.execute("SELECT count(*) FROM regulated_delegation_grants_v1").fetchone()[0] == 2

    with pool.connection() as conn, conn.transaction():
        conn.execute("INSERT INTO reference_root_members VALUES (%s,'other-owner','owner','fixture-1',true,%s)",
                     (first.tenant, fixture["expires"]))
        conn.execute("INSERT INTO reference_child_claims VALUES (%s,'other-owner-claim',%s,'other-owner','executor:other')",
                     (first.tenant, first.parent_digest))
    nonholder = service(first.tenant).create(replace(first, actor="other-owner", creation_id="other-owner-claim"))
    assert nonholder.status == "refused" and nonholder.grant is None
    assert nonholder.detail == "only the authenticated parent holder may create its child"

    # Two separate composition instances race for the same retained host claim.
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: service(first.tenant).create(first), range(2)))
    assert all(result.status == "created" for result in results), results
    assert results[0].grant == results[1].grant
    child = results[0].grant
    assert child.grant.subject == "executor:" + first.tenant + ":draft-1"
    assert child.grant.parent_digest == first.parent_digest
    assert child.grant.root_mission == fixture["roots"][first.tenant].grant.root_mission
    assert child.grant.budget_limit == 1

    # A retry may not change even a still-narrower authority for this creation.
    changed = service(first.tenant).create(replace(first, expires_at_us=first.expires_at_us - 1))
    assert changed.status == "refused" and changed.grant is None
    missing = service(first.tenant).create(replace(first, creation_id="not-provisioned"))
    assert missing.status == "refused" and missing.grant is None
    with pool.connection() as conn, conn.transaction():
        conn.execute("UPDATE reference_root_members SET enabled=false "
                     "WHERE tenant=%s AND subject='owner'", (first.tenant,))
    disabled = service(first.tenant).create(first)
    assert disabled.status == "refused" and disabled.grant is None
    with pool.connection() as conn, conn.transaction():
        conn.execute("UPDATE reference_root_members SET enabled=true "
                     "WHERE tenant=%s AND subject='owner'", (first.tenant,))

    retry = service(first.tenant).create(first)
    assert retry.status == "created" and retry.grant == child
    other = service(TENANTS[1]).create(requests[TENANTS[1]])
    assert other.status == "created"

    # Exercise the inherited bound through this service, retaining every valid link.
    depth_grants = []
    parent = fixture["roots"][first.tenant]
    for generation in range(1, MAX_DEPTH + 1):
        creation = f"depth-{generation}"
        subject = "executor:" + creation
        with pool.connection() as conn, conn.transaction():
            conn.execute("INSERT INTO reference_child_claims VALUES (%s,%s,%s,%s,%s)",
                         (first.tenant, creation, parent.digest, parent.grant.subject, subject))
            conn.execute("INSERT INTO reference_root_members VALUES (%s,%s,'executor','fixture-1',true,%s)",
                         (first.tenant, subject, fixture["expires"]))
        request = replace(first, parent_digest=parent.digest, creation_id=creation,
                          actor=parent.grant.subject, delegable=True)
        result = service(first.tenant).create(request)
        if generation == MAX_DEPTH:
            assert result.status == "refused" and result.grant is None
            assert result.detail == f"delegation is limited to {MAX_DEPTH} generations"
            depth_refused = result
        else:
            assert result.status == "created", result
            parent = result.grant
            assert (parent.grant.root_mission, parent.grant.budget_limit) == ("one-draft", 1)
            depth_grants.append(parent)
    authority = DelegationAuthority(fixture["signers"]["delegation"], fixture["trust"],
                                    PostgresGrantStore(pool=pool))
    authority.revoke_authorized(first.tenant, first.parent_digest, actor="owner",
                                 reason="synthetic owner withdraws mission", now_us=clock.now_us())
    withdrawn = service(first.tenant).create(first)
    assert withdrawn.status == "refused" and withdrawn.grant is None
    other_retry = service(TENANTS[1]).create(requests[TENANTS[1]])
    assert other_retry.status == "created" and other_retry.grant == other.grant
    with pool.connection() as conn:
        counts = {name: conn.execute("SELECT count(*) FROM " + name).fetchone()[0] for name in (
            "regulated_delegation_grants_v1", "regulated_mission_budget_events_v1",
            "regulated_permit_uses_v1", "reference_child_claims",
        )}
    assert counts == {"regulated_delegation_grants_v1": 4 + MAX_DEPTH - 1, "regulated_mission_budget_events_v1": 0,
                      "regulated_permit_uses_v1": 0, "reference_child_claims": 3 + MAX_DEPTH}
    grants = [child, other.grant, *depth_grants]
    key = fixture["signers"]["delegation"].public_key_bytes
    for grant in grants:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(grant.signature.value), canonical(grant.grant.body()),
        )
    alerts = [service(first.tenant).alerts.read(r.alert_id, tenant_id=first.tenant)
              for r in (*refused_scope, nonholder, depth_refused, changed, missing, disabled, withdrawn)]
    for alert in alerts:
        Ed25519PublicKey.from_public_bytes(fixture["signers"]["alert"].public_key_bytes).verify(
            bytes.fromhex(alert["signature"]["value"]), canonical(alert["payload"]),
        )
        assert alert["payload"]["code"] == "ADMISSION_REFUSED"
    (tmp_path / "delegated-creation.json").write_bytes(canonical_bytes({
        "schema": fixture["schema"], "counts": counts, "grants": [asdict(g) for g in grants],
        "alerts": alerts, "public_key": key.hex(),
        "limits": ["Synthetic retained host claims and membership; no production session or RLS claim.",
                   "Concurrent child creation and object reconstruction; no process-kill recovery.",
                   "No effect permit, delivery or shared budget spending qualified here.",
                   "Physical G4 remains OPEN."],
    }) + b"\n")
