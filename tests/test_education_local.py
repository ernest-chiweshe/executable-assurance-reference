"""Execute the packaged local entry point with guards and database roles intact."""

import json
import os
import subprocess
import sys

import pytest

from assurance_reference.education_local import verify_owned_cluster


@pytest.mark.parametrize("teacher_only", [False, True])
def test_real_entrypoint_reports_receipt_or_refusal(tmp_path, teacher_only):
    output = tmp_path / "release"
    command = [sys.executable, "-m", "assurance_reference.education_local",
               "--fictional-fixture", "--output", str(output)]
    if teacher_only:
        command.append("--teacher-only")
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    evidence = json.loads((output / "evidence.json").read_bytes())
    assert evidence["fictional"] is True
    assert evidence["full_D1"] == "OPEN"
    assert evidence["chain_valid"] is True
    assert summary["status"] == ("REFUSED" if teacher_only else "COMMITTED")
    if teacher_only:
        assert not (output / "feedback.txt").exists()
        assert evidence["review_status"] == "awaiting-review"
        assert evidence["observation"] is None
        assert evidence["refusal"]["boundary"] == "stored-review-resolution"
        assert "required quorum" in evidence["refusal"]["reason"]
    else:
        assert (output / "feedback.txt").read_bytes()
        assert evidence["observation"]["receipt"]
        assert evidence["receipt_replay_unchanged"] is True
        assert evidence["scripted_reviewers"] == ["teacher", "head"]
    # Reports contain public evidence, never the migration login or bearer tokens.
    serialized = (output / "evidence.json").read_text()
    assert "fictional-password-001" not in serialized
    assert os.environ["FACTORY_TEST_DB_URL"] not in serialized


@pytest.mark.parametrize("dsn,port,directory", [
    ("", "", ""),
    ("host=127.0.0.1 port=55432 dbname=factory_test", "55433", "/owned"),
    ("host=remote port=55433 dbname=factory_test", "55433", "/owned"),
    ("host=127.0.0.1 port=55433 dbname=postgres", "55433", "/owned"),
    ("host=127.0.0.1 port=55433 dbname=factory_test", "55433", ""),
])
def test_invalid_launcher_metadata_refuses_before_connect(monkeypatch, dsn, port, directory):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid launcher metadata must not open a database connection")
    monkeypatch.setattr("assurance_reference.education_local.psycopg.connect", forbidden)
    with pytest.raises(ValueError, match="isolated"):
        verify_owned_cluster(dsn, port, directory)


def test_wrong_cluster_directory_refuses_before_output_or_provision(tmp_path):
    output = tmp_path / "must-not-exist"
    environment = dict(os.environ, REFERENCE_ISOLATED_PG_DATA=str(tmp_path / "not-cluster"))
    result = subprocess.run([sys.executable, "-m", "assurance_reference.education_local",
        "--fictional-fixture", "--output", str(output)], env=environment,
        capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert "not the launcher's owned cluster" in result.stderr
    assert not output.exists()


def test_fixture_consent_flag_is_required(tmp_path):
    result = subprocess.run([sys.executable, "-m", "assurance_reference.education_local",
        "--output", str(tmp_path / "not-created")], capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert "--fictional-fixture" in result.stderr
    assert not (tmp_path / "not-created").exists()


