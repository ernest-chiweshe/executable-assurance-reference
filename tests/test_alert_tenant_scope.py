"""Guarded alert contracts on fictional tenants and restricted logins only."""

from contextlib import nullcontext
from dataclasses import replace
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import psycopg
import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.role_contract import ROLES
from assurance_reference.timing_observations import TimingObservationRecorder
from regulated_core.canonical import canonical_bytes
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_local_roles import roles  # noqa: F401
from test_runtime_scope_cleanup import ReusedConnection, assert_idle_unscoped
from test_timing_observations import observation_case, signed  # noqa: F401
from test_alerts import alert_case, outcome_case  # noqa: F401

# pytest resolves the imported fixtures by argument name.
# ruff: noqa: F811


class NoConnection:
    def connection(self):
        raise AssertionError("invalid signed material must not reach storage")


def test_unverified_alert_is_rejected_before_storage():
    signer = Ed25519Signer("fixture:alert")
    trust = TrustDirectory()
    trust.register_signer(signer)
    journal = AlertJournal(NoConnection(), signer, trust)
    payload = {"alert_id": "fixture", "tenant_id": "school-a"}
    signature = signer.sign(payload)
    with pytest.raises(ValueError, match="not trusted"):
        journal.retain_signed({**payload, "tenant_id": "school-b"}, signature)
    other = Ed25519Signer("fixture:trusted-non-alert")
    trust.register_signer(other)
    with pytest.raises(ValueError, match="not trusted"):
        journal.retain_signed(payload, other.sign(payload))
    with pytest.raises(TypeError):
        journal.read("fixture")


@pytest.mark.parametrize("interrupted", [False, True])
def test_scoped_signed_alerts_and_reused_connection_cleanup(roles, interrupted):
    signer = Ed25519Signer("fixture:tenant-alert")
    trust = TrustDirectory()
    trust.register_signer(signer)
    with roles.alerts.connection() as conn:
        backend = conn.info.backend_pid
        timeouts = conn.execute(
            "SELECT current_setting('lock_timeout'),current_setting('statement_timeout')").fetchone()
        journal = AlertJournal(ReusedConnection(conn), signer, trust)
        expected = {}
        for tenant in ("school-a", "school-b"):
            # Only synthetic metadata is retained; no target is invoked.
            first = journal.append(tenant_id=tenant, decision_hash="a" * 64,
                permit_hash="b" * 64, code="TARGET_UNKNOWN", outcome="unknown")
            second = journal.append_refusal(tenant_id=tenant, request_hash="c" * 64,
                decision_hash=None, code="ADMISSION_REFUSED")
            expected[tenant] = {first, second}
            assert_idle_unscoped(conn, "app.alert_tenant")
        assert conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                            "WHERE oid='reference_alerts_v1'::regclass").fetchone() == (True, True)
        for tenant in ("school-a", "school-b", "school-a"):
            other = "school-b" if tenant == "school-a" else "school-a"
            # This module fixture can contain prior lawful alerts: retain exact new IDs.
            assert expected[tenant] <= set(journal.list_ids(tenant_id=tenant))
            assert not expected[other] & set(journal.list_ids(tenant_id=tenant))
            for identifier in expected[tenant]:
                assert journal.read(identifier, tenant_id=tenant)["payload"]["tenant_id"] == tenant
            with pytest.raises(KeyError):
                journal.read(next(iter(expected[other])), tenant_id=tenant)
            assert_idle_unscoped(conn, "app.alert_tenant")
            expectation = pytest.raises(RuntimeError, match="fixture interruption") if interrupted else nullcontext()
            with expectation:
                with conn.transaction():
                    journal._scope(conn, tenant)
                    visible = conn.execute("SELECT DISTINCT "
                        "convert_from(envelope,'UTF8')::jsonb->'payload'->>'tenant_id' "
                        "FROM reference_alerts_v1").fetchall()
                    assert visible == [(tenant,)]
                    if interrupted:
                        raise RuntimeError("fixture interruption after guarded read")
            assert conn.info.backend_pid == backend
            assert_idle_unscoped(conn, "app.alert_tenant")
            assert conn.execute("SELECT count(*) FROM reference_alerts_v1").fetchone() == (0,)
            assert conn.execute("SELECT current_setting('lock_timeout'),"
                                "current_setting('statement_timeout')").fetchone() == timeouts
        for tenant in (None, "", " "):
            with pytest.raises(ValueError, match="explicit alert tenant"):
                journal.list_ids(tenant_id=tenant)
            assert_idle_unscoped(conn, "app.alert_tenant")


def test_runtime_alert_duties_refuse_out_of_duty_reads_and_all_edits(roles):
    for role in ROLES:
        with getattr(roles, role).connection() as conn:
            if role != "alerts":
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute("SELECT * FROM reference_alerts_v1 LIMIT 0")
            # Empty predicates cannot mutate retained rows even if grants regress.
            for statement in (
                "UPDATE reference_alerts_v1 SET envelope=envelope WHERE false",
                "DELETE FROM reference_alerts_v1 WHERE false",
            ):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute(statement)


def test_write_policy_refuses_missing_or_mismatched_scope_and_preserves_exact_bytes(roles):
    signer = Ed25519Signer("fixture:write-scope-alert")
    trust = TrustDirectory()
    trust.register_signer(signer)
    payload = {
        "schema": "executable-assurance/refusal-alert/v1", "alert_id": uuid.uuid4().hex,
        "tenant_id": "write-scope-school", "request_hash": "d" * 64,
        "decision_hash": None, "permit_hash": None, "code": "ADMISSION_REFUSED",
        "outcome": "failed", "authority_time_us": None, "requires_reconciliation": False,
    }
    signature = signer.sign(payload)
    encoded = canonical_bytes({"payload": payload, "signature": signature})
    with roles.alerts.connection() as conn:
        journal = AlertJournal(ReusedConnection(conn), signer, trust)
        for scope in (None, "different-write-scope-school"):
            # Existing policy remains active; only this fictional signed row is attempted.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    if scope is not None:
                        journal._scope(conn, scope)
                    conn.execute("INSERT INTO reference_alerts_v1 VALUES (%s,%s)",
                                 (payload["alert_id"], encoded))
            assert_idle_unscoped(conn, "app.alert_tenant")
            assert payload["alert_id"] not in journal.list_ids(tenant_id=payload["tenant_id"])
        # A local transaction interruption also must not leave a row or tenant setting.
        with pytest.raises(RuntimeError, match="fixture write interruption"):
            with conn.transaction():
                journal._scope(conn, payload["tenant_id"])
                conn.execute("INSERT INTO reference_alerts_v1 VALUES (%s,%s)",
                             (payload["alert_id"], encoded))
                raise RuntimeError("fixture write interruption before commit")
        assert_idle_unscoped(conn, "app.alert_tenant")
        assert payload["alert_id"] not in journal.list_ids(tenant_id=payload["tenant_id"])
        journal.retain_signed(payload, signature)
        retained = journal.read(payload["alert_id"], tenant_id=payload["tenant_id"])
        assert retained["payload"] == payload
        with conn.transaction():
            journal._scope(conn, payload["tenant_id"])
            stored = conn.execute("SELECT envelope FROM reference_alerts_v1 WHERE alert_id=%s",
                                  (payload["alert_id"],)).fetchone()[0]
        assert bytes(stored) == encoded
        Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
            bytes.fromhex(retained["signature"]["value"]), canonical_bytes(retained["payload"]))
        assert_idle_unscoped(conn, "app.alert_tenant")


def test_signed_synthetic_timing_uses_restricted_tenant_journal(roles, observation_case):
    c = observation_case
    journal = AlertJournal(roles.alerts, c.journal.signer, c.journal.trust)
    reporter = TimingObservationRecorder(journal=journal,
        permit_key_ids={c.permit.signature.key_id}, observer_key_ids={c.observer.key_id})
    event = replace(c.event, earliest_completion_us=c.permit.permit.expires_at_us + 1,
                    latest_completion_us=c.permit.permit.expires_at_us + 2)
    identifier = reporter.record(c.permit, signed(c, event))
    payload = journal.read(identifier, tenant_id=event.tenant_id)["payload"]
    assert payload["classification"] == "LATE"
    assert payload["synthetic"] is True and payload["effect_invoked"] is False
    assert payload["observation"] == event.body()
    assert identifier in journal.list_ids(tenant_id=event.tenant_id)
    with pytest.raises(KeyError):
        journal.read(identifier, tenant_id="other-synthetic-school")
