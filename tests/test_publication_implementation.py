"""Protect the owner-directed restoration of existing implementation claims."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "docs/publication-corrections/corrected-20261014"
B_DIR = "executable-assurance/publication-package"


def test_original_implementation_conclusion_is_preserved():
    original = (ROOT / "docs/publication-corrections/retention" / B_DIR / "Executable-Assurance-v11.md").read_text(encoding="utf-8-sig")
    current = (BUNDLE / B_DIR / "Executable-Assurance-v13.md").read_text(encoding="utf-8")
    paragraph = next(p for p in original.splitlines() if p.startswith("Executable Assurance provides that foundation"))
    assert paragraph in current
    assert "Executable Assurance proposes that foundation" not in current


def test_platform_achievements_are_not_replaced_by_extraction_limits():
    text = (BUNDLE / B_DIR / "Executable-Assurance-v13.md").read_text(encoding="utf-8")
    assert "The architecture is implemented, deployed and in service" in text
    assert "**Established.** An enforceable authority path" in text
    assert "Eleven regulated domains have run on the one authority path" in text
    assert "without adding a single core abstraction" in text
    assert "DSSE attestations were independently verified" in text
    assert "The historical platform reports" not in text
    assert "**Physical G4 expiry prevention remains OPEN.**" in text


def test_figures_show_implemented_states_and_scope_new_deployment_limits():
    figures = BUNDLE / B_DIR / "figures"
    states = (figures / "paper-b-figure04-adopted.svg").read_text(encoding="utf-8")
    assert "Implemented decision states" in states
    assert "Designed decision states" not in states
    summary = (figures / "paper-b-figure08-adopted.svg").read_text(encoding="utf-8")
    assert "a new deployment needs its own qualification" in summary
    assert "Historical records and reported inventories do not qualify deployment" not in summary


def test_reference_readme_preserves_platform_history():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "was implemented and deployed before this" in text
    assert "their smaller scope does not redefine the platform as a proposal" in text


def test_established_achievements_and_operational_history_are_preserved():
    original = (ROOT / "docs/publication-corrections/retention" / B_DIR / "Executable-Assurance-v11.md").read_text(encoding="utf-8-sig")
    current = (BUNDLE / B_DIR / "Executable-Assurance-v13.md").read_text(encoding="utf-8")
    for prefix in ("**Established.**", "- **14–15 July 2026 (Operational Measurement"):
        assert next(p for p in original.splitlines() if p.startswith(prefix)) in current
    assert "Every decision traversed the full authority path" in current
    assert "the runtime aborted the release before any byte was emitted" in current


def test_deployment_figure_keeps_actual_drills_and_retention_distinction():
    path = BUNDLE / "capability-is-not-authority/Execution assurance thesis/figures/fig13-reference-deployment-v1.5.svg"
    text = path.read_text(encoding="utf-8")
    assert "Both times the door locked" in text
    assert "GOVERNANCE" in text and "COMPLIANCE" in text
