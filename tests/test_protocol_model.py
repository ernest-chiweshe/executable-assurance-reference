"""Reproduce the pinned abstract model; no runtime service or target is exercised."""

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from importlib.resources import files

import pytest

from assurance_reference.protocol_model import check_protocol as model


def test_original_model_and_results_are_byte_identical():
    resources = files("assurance_reference.protocol_model")
    pins = {
        "check_protocol.py": "506ada42218ae7b209e566ecc9dc6c75f9515109d6f1c2d0aa97f671c9d48e3d",
        "results.json": "ac074a65e2ea1ef97ce90738808198fb351860a20e60c5607b7a2eb90da41b68",
    }
    for name, expected in pins.items():
        assert hashlib.sha256(resources.joinpath(name).read_bytes()).hexdigest() == expected


def test_module_entrypoint_reproduces_both_recorded_tables():
    result = subprocess.run(
        [sys.executable, "-B", "-m", "assurance_reference.protocol_model.check_protocol", "--json"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    expected = json.loads(files("assurance_reference.protocol_model").joinpath("results.json")
                          .read_text(encoding="utf-8"))
    assert result.stderr == ""
    assert json.loads(result.stdout) == expected
    assert len(expected["baseline"]) == 3
    assert len(expected["variants"]) == 7


@pytest.mark.parametrize(("changes", "budget", "expected"), [
    ({"permit": (False,)}, 1, "effect without permit"),
    ({"evidence": (False,)}, 1, "effect without prior evidence"),
    ({"effects": (2,)}, 2, "effect committed more than once"),
    ({"bad_payload": (True,)}, 1, "effect differs from permitted payload"),
    ({"late": (True,)}, 1, "effect after revocation or expiry"),
    ({}, 0, "mission budget exceeded"),
])
def test_inconsistent_synthetic_snapshots_are_detected(changes, budget, expected):
    state = model.S(
        phase=(model.DONE,), evidence=(True,), permit=(True,), nonce_used=(True,),
        effects=(1,), bad_payload=(False,), late=(False,), reserved=1,
        signer_up=True, vault_up=True, revoked=False, expired=False,
    )
    assert model.violations(state, 1) == []
    assert model.violations(replace(state, **changes), budget) == [expected]
