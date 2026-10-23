"""Offline selection checks; no database or authenticated-grant qualification."""
from pathlib import Path
from types import SimpleNamespace
import pytest

from assurance_reference import local_clinical_fixture as fixture
from assurance_reference.packs import FIXTURES, PUBLISHER
from regulated_core.signing import Ed25519Signer


@pytest.mark.parametrize("directory,publisher", [
    ("separate-fixture", None),
    (None, SimpleNamespace(key_id="fixture:health-tier4-publisher")),
    ("separate-fixture", SimpleNamespace(key_id=PUBLISHER)),
    ("separate-fixture", object()),
])
def test_invalid_selection_refuses_before_configuration(monkeypatch, tmp_path, directory, publisher):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid selection reached host configuration")
    monkeypatch.setattr(fixture, "configuration", unexpected)
    with pytest.raises(ValueError):
        fixture.build_clinical_fixture(None, tmp_path, synthetic_pack_directory=directory,
                                       synthetic_publisher=publisher)


def test_default_selection_retains_historical_bundle():
    assert fixture._clinical_pack_selection(None, None) == (
        FIXTURES / "bundles" / "health-workspace-membership", PUBLISHER)


def test_explicit_selection_keeps_separate_path(tmp_path):
    publisher = Ed25519Signer("fixture:health-tier4-publisher")
    assert fixture._clinical_pack_selection(tmp_path, publisher) == (tmp_path, publisher.key_id)


@pytest.mark.parametrize("synthetic", [False, True])
def test_valid_selection_reaches_same_configuration_boundary(monkeypatch, tmp_path, synthetic):
    class AtConfiguration(Exception):
        pass
    calls = []
    def configuration(roles, path, **kwargs):
        calls.append((roles, path, kwargs))
        raise AtConfiguration
    monkeypatch.setattr(fixture, "configuration", configuration)
    kwargs = ({"synthetic_pack_directory": tmp_path / "synthetic",
               "synthetic_publisher": Ed25519Signer("fixture:health-tier4-publisher")}
              if synthetic else {})
    with pytest.raises(AtConfiguration):
        fixture.build_clinical_fixture(None, tmp_path, **kwargs)
    assert len(calls) == 1
    assert calls[0][1] == tmp_path
    assert calls[0][2]["tier4_directory"] is None
    assert calls[0][2]["tier4_cooling_off_us"] == 0
