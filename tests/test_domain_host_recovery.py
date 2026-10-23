"""Pinned host recovery and bounded declaration checks; no gate is emitted."""

from dataclasses import replace
from hashlib import sha1, sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory.domain_host import DomainAuthorityKeys, DomainBinding, DomainHost, UnboundDomain
from regulated_core.clock import ClockReading
from regulated_core.signing import Ed25519Signer, TrustDirectory


class FixtureClock:
    domain = "fixture:domain-host"

    def read(self):
        return ClockReading(self.domain, 100)

    def now_us(self):
        return self.read().now_us


def unused_credentials(request):
    raise AssertionError("declaration checks must not request credentials")


@pytest.fixture
def settings():
    signer = Ed25519Signer("fixture:domain-host")
    trust = TrustDirectory()
    trust.register_signer(signer)
    return dict(stores=object(), trust=trust, signer=signer, worm=object(), clock=FixtureClock())


def test_declared_domains_share_host_configuration_and_cannot_replace_each_other(settings):
    host = DomainHost(**settings)
    for use in ("education", "health", "product_spec"):
        binding = DomainBinding("fixture." + use, use, unused_credentials)
        host.bind(binding)
        assert host.binding(binding.pack_id) is binding
    assert host.domains == ("education", "health", "product_spec")
    assert host.stores is settings["stores"] and host.trust is settings["trust"]
    assert host.signer is settings["signer"] and host.worm is settings["worm"]
    with pytest.raises(ValueError, match="already served"):
        host.bind(DomainBinding("fixture.education", "replacement", unused_credentials))


@pytest.mark.parametrize("field", ["stores", "trust", "signer", "worm"])
def test_missing_shared_authority_configuration_refuses(settings, field):
    with pytest.raises(ValueError):
        DomainHost(**{**settings, field: None})


def test_unnamed_callable_clock_refuses(settings):
    with pytest.raises(ValueError, match="named trusted clock"):
        DomainHost(**{**settings, "clock": lambda: 100})


def test_unknown_pack_refuses_before_credential_or_gate_composition(settings):
    host = DomainHost(**settings)
    with pytest.raises(UnboundDomain):
        host.gate(SimpleNamespace(manifest=SimpleNamespace(id="fixture.unknown")), None, None)


@pytest.mark.parametrize("binding", [None, DomainBinding("", "fixture", unused_credentials),
                                     DomainBinding("fixture.id", "fixture", None)])
def test_invalid_binding_refuses(settings, binding):
    with pytest.raises(ValueError):
        DomainHost(**settings).bind(binding)


def test_unknown_credential_authority_refuses(settings):
    with pytest.raises(ValueError, match="not a trust anchor"):
        DomainHost(**settings).bind(DomainBinding(
            "fixture.id", "fixture", unused_credentials, credential_authority="unknown",
        ))


def test_explicit_keys_require_known_provider_map_and_preserve_immutable_copy(settings):
    signer = settings["signer"]
    keys = DomainAuthorityKeys(signer, signer, signer, signer.key_id, {})
    host = DomainHost(**settings, authority_keys=keys)
    binding = DomainBinding("fixture.id", "fixture", unused_credentials)
    with pytest.raises(ValueError, match="provider credential map"):
        host.bind(binding)
    with pytest.raises(ValueError, match="trusted keys"):
        host.bind(replace(binding, credential_authorities={"fixture-provider": "unknown"}))
    providers = {"fixture-provider": signer.key_id}
    bound = replace(binding, credential_authorities=providers)
    providers["fixture-provider"] = "changed-after-construction"
    host.bind(bound)
    assert bound.credential_authorities["fixture-provider"] == signer.key_id
    with pytest.raises(TypeError):
        bound.credential_authorities["fixture-provider"] = "replacement"


def test_provider_map_without_explicit_installation_keys_refuses(settings):
    with pytest.raises(ValueError, match="explicit installation"):
        DomainHost(**settings).bind(DomainBinding(
            "fixture.id", "fixture", unused_credentials,
            credential_authorities={"fixture-provider": settings["signer"].key_id},
        ))


def test_missing_verifier_signer_refuses_before_credentials(settings):
    signer = settings["signer"]
    host = DomainHost(**settings, authority_keys=DomainAuthorityKeys(
        signer, signer, signer, signer.key_id, {},
    ))
    host.bind(DomainBinding("fixture.id", "fixture", unused_credentials,
                           credential_authorities={"fixture-provider": signer.key_id}))
    pack = SimpleNamespace(manifest=SimpleNamespace(id="fixture.id"),
                           rulebook=SimpleNamespace(check_ids=lambda: ("fixture-check",)))
    with pytest.raises(ValueError, match="explicit verifier signing keys"):
        host.gate(pack, None, None)


def test_recovered_domain_host_is_the_exact_frozen_original(request):
    root = Path(__file__).resolve().parents[1]
    record = json.loads((root / "source-provenance-domain-host.json").read_bytes())
    entry, = record["files"]
    raw = (root / entry["path"]).read_bytes()
    if sha256(raw).hexdigest() != entry["sha256"]:
        # An explicitly qualified adaptation does not replace its frozen source.
        # Require both the retained original and the separately pinned live bytes.
        manifest_path = request.config.getoption("--source-adaptation-manifest")
        manifest_sha = request.config.getoption("--source-adaptation-sha256")
        assert manifest_path and manifest_sha, "adapted host requires explicit provenance"
        manifest_bytes = (root / manifest_path).read_bytes()
        assert sha256(manifest_bytes).hexdigest() == manifest_sha
        adaptation, = (item for item in json.loads(manifest_bytes)["files"]
                       if item["path"] == entry["path"])
        assert adaptation["source_path"] == "factory/domain_host.py"
        assert adaptation["original_sha256"] == entry["sha256"]
        assert adaptation["original_git_blob"] == entry["git_blob"]
        assert sha256(raw).hexdigest() == adaptation["adapted_sha256"]
        original = (root / adaptation["original_path"]).resolve()
        assert original.is_relative_to(root)
        assert original != (root / entry["path"]).resolve()
        raw = original.read_bytes()
    assert sha256(raw).hexdigest() == entry["sha256"]
    assert sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == entry["git_blob"]
    assert entry["git_blob"] == "aa4f4742ee4327d5096f52c5ce8d309b51dff541"
    assert record["changes"] == []
