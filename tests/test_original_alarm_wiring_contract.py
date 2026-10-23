"""Exact reviewed original alarm-wiring function; other upstream tests not imported."""
import pytest
from regulated_core.outage import RecordingOutageAlarm

def test_the_host_runtime_hands_its_composed_alarm_to_every_pack_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The factory the host runtime composes passes its alarm to the gate builder, which passes it to the gate."""
    import inspect
    from types import SimpleNamespace as NS

    from regulated_core import pack_gate
    from regulated_core.host_runtime import RuntimeAuthorities

    assert "outage_alarm" in RuntimeAuthorities.__dataclass_fields__
    assert "outage_alarm" in inspect.signature(pack_gate.RulebookGate.__init__).parameters
    built: dict[str, Any] = {}
    monkeypatch.setattr(pack_gate, "build_pack_gate", lambda pack, **kw: built.update(kw))
    alarm = RecordingOutageAlarm()
    document = NS(vertical="v", policy_id="pid", digest=lambda: "d")
    pack = NS(reference="p#1", rulebook=NS(document=document))
    surface = NS(spec=NS(regulated=NS(pack_version="p#1", policy_ref="v/pid", policy_digest="d")))
    def unexpected_retention(*args, **kwargs):
        raise AssertionError("alarm wiring must not access retention")

    retention = NS(anchor=unexpected_retention, fetch=unexpected_retention,
                   verify=unexpected_retention)
    factory = pack_gate.PackGateFactory(trust=None, engine=None, host_verifiers=None,  # type: ignore[arg-type]
                                        verifier_signers={}, credential_verifier=None,  # type: ignore[arg-type]
                                        intended_uses=None, worm=retention, outage_alarm=alarm)  # type: ignore[arg-type]
    assert factory(pack, None, surface) is None  # type: ignore[arg-type]
    assert built["outage_alarm"] is alarm
