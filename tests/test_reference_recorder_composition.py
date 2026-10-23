"""Reference composition rejects a PostgreSQL recorder without lock-time guards."""
import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.engine import ReferenceEngine
from regulated_core import Ed25519Signer, TrustDirectory
from regulated_core.persistence_pg import PostgresDecisionRecorder
from test_prepermit_retention import FixtureClock
from test_reference_retention_contract import UnusedAlertPool


def test_plain_postgresql_recorder_is_refused_before_engine_composition():
    trust = TrustDirectory()
    signer = Ed25519Signer("fixture:composition")
    trust.register_signer(signer)
    pool = UnusedAlertPool()
    recorder = PostgresDecisionRecorder(signer, trust, pool=pool, clock=FixtureClock())
    alerts = AlertJournal(pool, signer, trust)
    with pytest.raises(TypeError, match="PostgreSQL reference composition requires ReferenceDecisionRecorder"):
        ReferenceEngine(alerts=alerts, recorder=recorder)
