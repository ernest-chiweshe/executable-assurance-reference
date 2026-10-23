"""New reads, moved sites and unreviewed debt must not disappear from accounting."""
from hashlib import sha256
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_history_scans import check, identity, inventory


def fixture(root, text="def audit(recorder):\n    return recorder.entries('tenant')\n", debt=False):
    path = root / "src/sample.py"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    rows = inventory(root)
    for row in rows:
        row.update(classification="known_debt" if debt else "audit", reason="Reviewed synthetic fixture",
                   operational=debt)
        if debt:
            row["removal_phase"] = "2"
    baseline = [{"identity": list(identity(row)), "source_sha256": row["source_sha256"], "locus": row["locus"]}
                for row in rows] if debt else []
    pin = sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return path, {"schema": "reference/history-read-classifications/v1", "debt_baseline": baseline,
                  "sites": rows}, pin


def test_existing_catalog_integrity_is_distinct_from_scaling_closure():
    root = Path(__file__).resolve().parents[1]
    catalog = json.loads((root / "docs/provenance/history-read-classifications.json").read_bytes())
    report = check(root, catalog)
    assert report["guard_integrity"]
    if report["known_debt_sites"]:
        assert not report["history_scaling_closed"]
        with pytest.raises(ValueError, match="history debt remains"):
            check(root, catalog, require_closed=True)


def test_new_module_read_is_unclassified(tmp_path):
    _, catalog, pin = fixture(tmp_path)
    (tmp_path / "src/another.py").write_text("log.events('tenant')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unclassified=.*another"):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_changed_context_refuses_even_when_read_expression_is_same(tmp_path):
    path, catalog, pin = fixture(tmp_path)
    path.write_text(path.read_text() + "# Changed caller context\n", encoding="utf-8")
    with pytest.raises(ValueError, match="drift="):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_removed_read_leaves_stale_classification(tmp_path):
    path, catalog, pin = fixture(tmp_path)
    path.write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale="):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_debt_cannot_be_added_by_rehashing_the_catalog(tmp_path):
    _, catalog, pin = fixture(tmp_path, debt=True)
    assert check(tmp_path, catalog, debt_baseline_sha256=pin)["known_debt_sites"] == 1
    catalog["debt_baseline"][0]["locus"] = "different"
    with pytest.raises(ValueError, match="baseline changed"):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_operational_read_cannot_be_relabelled_as_audit(tmp_path):
    _, catalog, pin = fixture(tmp_path, debt=True)
    catalog["sites"][0]["classification"] = "audit"
    with pytest.raises(ValueError, match="pinned history debt"):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_debt_cannot_disappear_by_changing_class_and_operational_flag(tmp_path):
    _, catalog, pin = fixture(tmp_path, debt=True)
    catalog["sites"][0].update(classification="audit", operational=False)
    with pytest.raises(ValueError, match="pinned history debt"):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_unreviewed_resolution_cannot_launder_debt(tmp_path):
    _, catalog, pin = fixture(tmp_path, debt=True)
    row = catalog["sites"][0]
    resolution = dict(catalog["debt_baseline"][0], specification="invented", phase_evidence="unverified")
    row.update(classification="bounded", bound_basis="asserted", resolved_by=resolution)
    catalog["approved_resolutions"] = [resolution]
    with pytest.raises(ValueError, match="resolutions changed"):
        check(tmp_path, catalog, debt_baseline_sha256=pin)


def test_sql_parts_and_history_comprehension_are_seen_but_docstrings_are_not(tmp_path):
    text = '''"""SELECT * FROM regulated_decision_evidence_v1 is discussed here."""
def read(conn):
    return conn.execute("SELECT * FROM regulated_decision_evidence_v1 " + "WHERE tenant=%s")
def copy(self):
    return [item for item in self._log]
'''
    fixture(tmp_path, text)
    rows = inventory(tmp_path)
    assert [row["kind"] for row in rows] == ["history_sql", "history_storage"]


@pytest.mark.parametrize("table", ["regulated_egress_scope_v1", "collaboration_events",
    "regulated_mission_budget_events_v1", "regulated_revocation_events_v1",
    "regulated_governance_rosters_v1", "regulated_delegation_grants_v1",
    "regulated_delegation_revocations_v1", "regulated_decision_uses_v1",
    "regulated_permit_uses_v1", "reference_clock_floor_v1"])
def test_scope_and_collaboration_sql_are_in_the_inventory(tmp_path, table):
    fixture(tmp_path, f"QUERY = 'SELECT * FROM {table} WHERE tenant_id=%s'\n")
    rows = inventory(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "history_sql"


def test_history_inside_one_json_row_is_not_invisible(tmp_path):
    fixture(tmp_path, '''def read(conn, state):
    conn.execute("SELECT state FROM projectos_states WHERE project_id=%s")
    rows = state.get("emissions", ())
    state.setdefault("release_outcomes", []).append({})
    return state["emissions"]
''')
    rows = inventory(tmp_path)
    assert [row["kind"] for row in rows] == [
        "history_sql", "history_json_array", "history_json_array", "history_json_array"]
