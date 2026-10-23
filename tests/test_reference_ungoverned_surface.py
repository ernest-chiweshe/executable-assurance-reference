"""Ordinary incomplete host configuration refuses at the public release entry."""

import pytest

from factory.projectos.engine import ProjectEngine, ProjectEngineError
from factory.projectos.regulated import EmissionContext
from factory.projectos.spec import RegulatedBlock, VerticalSpec


class NoStateAccess:
    def __getattr__(self, name):
        raise AssertionError("Ungoverned release must refuse before state access: " + name)


def test_pack_surface_without_emission_gate_refuses_before_export(tmp_path):
    calls = []

    def unavailable(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("Ungoverned release must not run, build or export")

    spec = VerticalSpec(
        "synthetic-pack-surface", "project", "synthetic", "project_id", (),
        regulated=RegulatedBlock(
            policy_ref="synthetic/policy", intended_use="local configuration contract",
            policy_digest="a" * 64, pack_version="synthetic.pack@1",
        ),
    )
    engine = ProjectEngine(
        spec, runner=unavailable, contract_builder=unavailable, exporter=unavailable,
        emission_gate=None, root=str(tmp_path / "state"), state_store=NoStateAccess(),
    )
    destination = tmp_path / "output.txt"
    context = EmissionContext(
        tenant="synthetic-tenant", actor_id="synthetic-owner", project_id="fixture",
        vertical_name=spec.name, action_id="release", nonce="missing-gate",
    )
    with pytest.raises(ProjectEngineError, match="no emission gate wired"):
        engine.release("fixture", str(destination), context=context)
    assert calls == []
    assert not destination.exists()
    assert not (tmp_path / "state").exists()
