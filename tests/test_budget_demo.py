"""One retained schema checks database budget semantics with every guard active."""

import hashlib
import json
import os

from assurance_reference.budget_demo import run


def test_budget_store_concurrency_rollback_and_reconstruction(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped qualification"
    output = tmp_path / "budget"
    result = run(output, dsn)
    saved = json.loads((output / "budget.json").read_text(encoding="utf-8"))
    assert saved["status"] == result["status"] == "PASS"
    assert sorted(row[1] for row in saved["admissions"]) == ["refused", "reserved"]
    assert saved["rollback"] == {"effect_rows": 0, "consumed_units": 0}
    assert saved["committed_units"] == 1
    events = saved["events"]
    first_tenant = [row for row in events if row[0] == "budget-fixture-a"]
    assert sorted(row[3] for row in first_tenant) == ["consume", "reserve"]
    assert len({row[2] for row in first_tenant}) == 1
    expected = hashlib.sha256(
        b"Synthetic database receipt; not an authorized application release."
    ).hexdigest()
    assert saved["receipt_sha256"] == expected
    assert all(row[4:] == [1, 1, expected] for row in first_tenant)
    second_tenant = [row for row in events if row[0] == "budget-fixture-b"]
    assert sorted(row[3] for row in second_tenant) == ["release", "reserve", "reserve"]
    assert saved["replay_refused"] and saved["consumed_capacity_retained"]
