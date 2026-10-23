"""B-F7b: partitioned lifecycle retry receipts never place a tenant's request in the installation-shared store.

Uses the real restricted partitioned lifecycle (tests/test_partitioned_governance.py fixture): installation activations
and two signed cross-tenant pins are enacted with retained retry keys. Every receipt in
reference_pack_installation_retries_v1 is an installation operation (request_tenant None); each governed receipt
belongs to the governing tenant and lives only in that tenant's row of reference_pack_tenants_v1 under forced
row-level security (here both retries, none in the installation store). The governor-readable retry index holds
only hashes.
"""
import json
import re

from assurance_reference.lifecycle_partition import request_tenant
from regulated_core.target import Outcome

from test_partitioned_governance import governed, private_rows  # noqa: F401  (pytest fixture reuse)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_installation_retries_hold_only_tenantless_receipts(governed, monkeypatch):  # noqa: F811
    app = governed
    # Retained retry receipts are written by calling the unmodified guarded public operations with an idempotency
    # key (as in test_partitioned_governance); no guard context is entered or replaced.
    actual = app.packs.ledger.pin

    def keyed(tenant_id, *args, **kwargs):
        return actual(tenant_id, *args, **{**kwargs, "idempotency_key": "fixture-retry-pin-" + tenant_id})
    monkeypatch.setattr(app.packs.ledger, "pin", keyed)
    for school in ("school-a", "school-b"):
        result, *_ = app.enact("governance-office", {"pin": app.first, "tenant": school})
        assert result.outcome is Outcome.COMMITTED, result.detail
    with app.roles.governor.connection() as conn:
        retries = conn.execute("SELECT pack_id, requests FROM reference_pack_installation_retries_v1").fetchall()
        index = conn.execute("SELECT pack_id, key_digest, request_digest FROM reference_pack_retry_index_v1").fetchall()
    installation = [(pack, key, receipt) for pack, requests in retries
                    for key, receipt in (requests if isinstance(requests, dict) else json.loads(requests)).items()]
    assert all(request_tenant(pack, receipt["request"]) is None for pack, _, receipt in installation), installation
    tenant_receipts = {}
    for tenant in ("governance-office", "other-office", "school-a", "school-b"):
        for row in private_rows(app, tenant):
            for receipt in row[3]["requests"].values():
                assert request_tenant(row[0], receipt["request"]) == tenant
                tenant_receipts.setdefault(tenant, []).append(receipt)
    # Every retained receipt, installation or tenant, is indexed once; the index carries digests only.
    assert len(index) == len(installation) + sum(map(len, tenant_receipts.values()))
    assert all(HEX64.match(key) and HEX64.match(request) for _, key, request in index)
    # Not vacuous (C060-PRE-R1): both governed retries are retained, exactly as enacted, in the governing tenant's private
    # scope only. The installation store is empty by construction: every lawful governed operation carries its
    # governance receipt, so request_tenant attributes its retry to the governing tenant; a tenant-less installation
    # receipt can arise only from an ungoverned call, which the partitioned ledger's guard refuses.
    assert set(tenant_receipts) == {"governance-office"} and installation == []
    [office] = private_rows(app, "governance-office")
    keys = sorted(office[3]["requests"])
    assert keys == ["fixture-retry-pin-school-a", "fixture-retry-pin-school-b"], keys
    requests = sorted(json.loads(office[3]["requests"][key]["request"])[:2] for key in keys)
    assert [(method, args[0]) for method, args in requests] == [("pin", "school-a"), ("pin", "school-b")], requests
    assert len(index) == 2
    print(json.dumps({"installation_receipts": len(installation),
                      "tenant_receipts": {tenant: len(items) for tenant, items in tenant_receipts.items()}}))
