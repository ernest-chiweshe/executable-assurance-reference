"""X-10 protected host configuration; no database mutations or network calls."""

import pytest

from assurance_reference.generation_floor import GenerationFloorConfigError, GenerationFloorVerifier
from factory.customer.generation_floor_pg import GenerationFloorVerifier as OriginalVerifier
from regulated_core.signing import Ed25519Signer, TrustDirectory

PREFIX = "REFERENCE_GENERATION_FLOOR"


@pytest.fixture
def trust():
    directory = TrustDirectory()
    directory.register_signer(Ed25519Signer("release-floor"))
    return directory


def configured():
    return {PREFIX + "_AUTHORITY": "release-floor", PREFIX + "_INSTALLATION": "local-fixture",
            PREFIX + "_MINIMUM": "4"}


def load(env, trust, **kwargs):
    return GenerationFloorVerifier.from_env(env, trust=trust, prefix=PREFIX,
                                           schema="factory_authority", **kwargs)


@pytest.mark.parametrize("env", [{}, {PREFIX + "_AUTHORITY": "  ",
                                     PREFIX + "_INSTALLATION": "", PREFIX + "_MINIMUM": "\t"}])
def test_absent_floor_refuses_without_explicit_non_use(trust, env, caplog):
    with pytest.raises(GenerationFloorConfigError, match="configuration is required"):
        load(env, trust)
    assert not caplog.records


def test_explicit_non_use_is_logged_before_returning_none(trust, caplog):
    assert load({}, trust, floor_not_used_reason="Detached offline qualification fixture") is None
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelname == "WARNING"
    assert record.generation_floor_mode == "not_used"
    assert record.generation_floor_prefix == PREFIX
    assert record.generation_floor_reason == "Detached offline qualification fixture"
    assert "generation_floor_not_used" in record.getMessage()


@pytest.mark.parametrize("reason", ["", " ", " leading", "trailing ", "line\nbreak",
                                    "tab\tvalue", "bidi\u202evalue", "x" * 257, True, 1])
def test_invalid_non_use_reason_refuses_without_log(trust, caplog, reason):
    with pytest.raises(GenerationFloorConfigError, match="reason is invalid"):
        load({}, trust, floor_not_used_reason=reason)
    assert not caplog.records


@pytest.mark.parametrize("fields", [("AUTHORITY",), ("INSTALLATION",), ("MINIMUM",),
                                   ("AUTHORITY", "INSTALLATION", "MINIMUM")])
def test_non_use_cannot_override_existing_configuration(trust, caplog, fields):
    env = {PREFIX + "_" + field: configured()[PREFIX + "_" + field] for field in fields}
    with pytest.raises(GenerationFloorConfigError, match="conflicts"):
        load(env, trust, floor_not_used_reason="Explicit fixture non-use")
    assert not caplog.records


@pytest.mark.parametrize("field", ["AUTHORITY", "INSTALLATION", "MINIMUM"])
def test_partial_configuration_refuses(trust, field):
    env = configured()
    del env[PREFIX + "_" + field]
    with pytest.raises(GenerationFloorConfigError, match="configured together"):
        load(env, trust)


@pytest.mark.parametrize("minimum", ["0", "-1", "1.5", "", str(2**31), "9" * 5000, "²", True])
def test_invalid_minimum_refuses(trust, minimum):
    env = configured()
    env[PREFIX + "_MINIMUM"] = minimum
    with pytest.raises(GenerationFloorConfigError):
        load(env, trust)


def test_unknown_authority_refuses(trust):
    env = configured()
    env[PREFIX + "_AUTHORITY"] = "unmanaged-release"
    with pytest.raises(GenerationFloorConfigError, match="trust anchor"):
        load(env, trust)


def test_exact_original_verifier_binding_without_io(trust, monkeypatch):
    import socket

    def no_network(*args, **kwargs):
        pytest.fail("configuration must not connect")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    floor = load(configured(), trust)
    assert isinstance(floor, OriginalVerifier)
    assert floor.trust is trust
    assert (floor.issuer_key_id, floor.installation_id, floor.schema, floor.minimum_generation) == (
        "release-floor", "local-fixture", "factory_authority", 4)
    assert GenerationFloorVerifier.require_on is OriginalVerifier.require_on
    assert GenerationFloorVerifier._history is OriginalVerifier._history


def test_host_prefix_selects_only_its_configuration(trust):
    env = configured()
    env.update({"OTHER_AUTHORITY": "unmanaged", "OTHER_INSTALLATION": "other", "OTHER_MINIMUM": "99"})
    assert load(env, trust).minimum_generation == 4
    with pytest.raises(GenerationFloorConfigError, match="trust anchor"):
        GenerationFloorVerifier.from_env(env, prefix="OTHER", trust=trust, schema="factory_authority")


@pytest.mark.parametrize("prefix", ["", " request", "REQUEST-FLOOR", "X" * 65])
def test_invalid_host_prefix_refuses(trust, prefix):
    with pytest.raises(GenerationFloorConfigError, match="prefix"):
        GenerationFloorVerifier.from_env(configured(), prefix=prefix, trust=trust, schema="authority")


@pytest.mark.parametrize("schema", ["", " authority", None])
def test_invalid_schema_refuses(trust, schema):
    with pytest.raises(GenerationFloorConfigError, match="binding"):
        GenerationFloorVerifier.from_env(configured(), prefix=PREFIX, trust=trust, schema=schema)


def test_installation_bound_and_maximum_generation(trust):
    env = configured()
    env[PREFIX + "_MINIMUM"] = str(2**31 - 1)
    assert load(env, trust).minimum_generation == 2**31 - 1
    env[PREFIX + "_INSTALLATION"] = "x" * 257
    with pytest.raises(GenerationFloorConfigError, match="binding"):
        load(env, trust)
