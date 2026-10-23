"""Isolated PG compatibility of decoded keys and atomic authenticated flags."""
from dataclasses import replace
from types import SimpleNamespace
import json
import os
from contextlib import contextmanager
import psycopg

import pytest

from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.models import Annotation
from regulated_core.persistence_pg import decode_envelope, PersistenceError
from regulated_core.evidence_service import (
    EvidenceError, MemoryEvidenceService, UnhashableIdFlag, unhashable_id_key,
    require_hashable_history, verify_history_flag, verify_lookup,
)
from regulated_core.evidence_service_pg import stage_map_update_on
from assurance_reference.roster_authority import RosterAuthorityVerifier
from test_evidence_service_formats import case
from test_evidence_service_pg_core import service, append, counts, ALL_TABLES
from regulated_core import evidence_service_pg as pg
from regulated_core.persistence_pg import SCHEMA


@pytest.fixture(scope="module")
def database():
    assert os.environ.get("REFERENCE_ISOLATED_PG_DATA"), "requires owned isolated cluster"
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    with psycopg.connect(dsn) as conn:
        name, port = conn.execute("SELECT current_database(),inet_server_port()").fetchone()
        assert name == "factory_test" and port == int(os.environ["REFERENCE_ISOLATED_PG_PORT"])
        conn.execute(SCHEMA); conn.execute(pg.MAP_SCHEMA); conn.execute(pg.SERVICE_SCHEMA)
        conn.execute("CREATE ROLE evidence_compat_test_writer NOLOGIN NOSUPERUSER NOBYPASSRLS")
        for table in ALL_TABLES:
            conn.execute("GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON " + table + " TO evidence_compat_test_writer")
    return dsn


@contextmanager
def transaction(database, tenant):
    with psycopg.connect(database) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL ROLE evidence_compat_test_writer")
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            yield conn


def verification(store):
    return dict(tenant=store.tenant, clock_domain=store.clock.domain, trust=store.trust,
                allowed_head_keys=store.signing_keys, historical_head_keys=store.historical_head_keys)


def test_pg_decoded_keys_flags_and_memory_reference_agree(database, service):
    store, _, record, kwargs = service
    memory = MemoryEvidenceService(**kwargs)
    values = ["", 7, True, 1, None, "7", ["x"], {"k": True}, ("x",), b"x"]
    envelopes, heads = [], []
    with transaction(database, store.tenant) as conn:
        for value in values:
            changed = replace(record, record_id=value,
                decision=replace(record.decision, annotations=(Annotation("outcome-of-decision", value),) * 2))
            raw, head = append(conn, service, changed)
            expected = decode_envelope(canonical_bytes(raw))
            assert memory.append(raw) == head
            envelopes.append(expected); heads.append(head)
            assert canonical_bytes(raw) == canonical_bytes(expected)
            proof = store.history_flag_on(conn, head=head)
            assert proof == memory.history_flag(head=head)
        for head in heads:
            visible = envelopes[:head.tree_size]
            flag = verify_history_flag(store.history_flag_on(conn, head=head), expected_head=head, **verification(store))
            assert (flag is None) == (head.tree_size <= 6)
            if flag:
                assert flag.first_seq == 6
            for question in ["", 7, True, 1, None, "7", ["x"], {"k": True}, "78", "missing"]:
                for key_type in ("record_id", "outcome_of"):
                    matched = [e for e in visible if (e.record.record_id if key_type == "record_id"
                               else e.record.decision.annotations[0].message) == question]
                    for selection in ("count", "first", "latest"):
                        proof = store.lookup_on(conn, head=head, key_type=key_type, key=question, selection=selection)
                        assert proof == memory.lookup(head=head, key_type=key_type, key=question, selection=selection)
                        result = verify_lookup(proof, expected_head=head, key_type=key_type, key=question,
                            selection=selection, **verification(store),
                            allowed_envelope_keys=store.envelope_keys_allowed,
                            allowed_envelope_domains=store.envelope_domains)
                        assert (0 if result.summary is None else result.summary.count) == len(matched)
                        expected = None if not matched or selection == "count" else matched[0 if selection == "first" else -1]
                        assert result.envelope == expected
        assert conn.execute("SELECT count(*) FROM regulated_evidence_keys_v1 WHERE tenant=%s AND key_type='flag'",
                            (store.tenant,)).fetchone()[0] == 1
        # Compare exact legacy H5 dictionary failure with authenticated flag failure.
        legacy = SimpleNamespace(tenant=store.tenant,
            recorder=SimpleNamespace(entries=lambda tenant: envelopes))
        with pytest.raises(TypeError):
            RosterAuthorityVerifier._decisions(legacy)
        with pytest.raises(TypeError):
            require_hashable_history(store.history_flag_on(conn, head=heads[-1]),
                                     expected_head=heads[-1], **verification(store))


def test_pg_flag_cannot_be_replaced_and_rollback_leaves_no_flag(database, service):
    store, _, record, _ = service
    with transaction(database, store.tenant) as conn:
        _, first = append(conn, service, replace(record, record_id=["first"]))
        _, second = append(conn, service, replace(record, record_id=["second"]))
        proof = store.history_flag_on(conn, head=second)
        assert verify_history_flag(proof, expected_head=second, **verification(store)).first_seq == 0
        with pytest.raises(EvidenceError, match="cannot be replaced"):
            stage_map_update_on(conn, tenant=store.tenant, tree_size=3,
                previous_root=bytes.fromhex(second.map_root),
                updates={unhashable_id_key(store.tenant): ("flag", UnhashableIdFlag(1))})
    with transaction(database, store.tenant) as conn:
        before = counts(conn, store.tenant)
        with pytest.raises(RuntimeError, match="rollback"):
            with conn.transaction():
                append(conn, service, replace(record, record_id={"rollback": True}))
                raise RuntimeError("rollback after complete append")
        assert counts(conn, store.tenant) == before
        assert store.head_on(conn) == second


def test_pg_failed_first_flag_append_is_atomic(database, service):
    store, _, record, _ = service
    with transaction(database, store.tenant) as conn:
        _, head = append(conn, service)
        before = counts(conn, store.tenant)
        with pytest.raises(RuntimeError):
            with conn.transaction():
                append(conn, service, replace(record, record_id=[]))
                raise RuntimeError("rollback first flag")
        assert counts(conn, store.tenant) == before
        proof = store.history_flag_on(conn, head=head)
        assert verify_history_flag(proof, expected_head=head, **verification(store)) is None
        _, accepted = append(conn, service, replace(record, record_id=[]))
        assert verify_history_flag(store.history_flag_on(conn, head=accepted),
            expected_head=accepted, **verification(store)).first_seq == 1


def test_pg_eligible_keys_select_first_matching_scope_without_decoy_walk(database, service):
    from regulated_core.evidence_eligibility import decision_question, outcome_question, DECISION_ELIGIBLE, OUTCOME_ELIGIBLE
    from regulated_core.signing import Ed25519Signer
    store, recorder, record, kwargs = service
    other = Ed25519Signer("evidence:eligibility-other")
    store.trust.register_signer(other)
    store.envelope_keys_allowed = frozenset({store.signer.key_id, other.key_id})
    kwargs = kwargs | {"envelope_keys_allowed": store.envelope_keys_allowed}
    memory = MemoryEvidenceService(**kwargs)
    decision_hash = digest_hex(record)
    valid = replace(record, decision=replace(record.decision, reason_codes=("OUTCOME_COMMITTED",),
        annotations=(Annotation("outcome-of-decision", decision_hash),)))
    envelopes = []
    with transaction(database, store.tenant) as conn:
        for i, variant in enumerate([
            replace(valid, decision=replace(valid.decision, annotations=valid.decision.annotations * 2)),
            replace(valid, action=replace(valid.action, destination="wrong")), valid, valid, valid,
        ]):
            # Rotation explicitly configures both historical keys; the recorder's
            # original history integrity check remains in force.
            active = type(recorder)(other if i == 2 else store.signer, store.trust,
                pool=None, clock=store.clock,
                historical_evidence_key_ids=store.envelope_keys_allowed)
            env, head = store.append_record_on(conn, active, variant, digest_hex(variant))
            envelopes.append(decode_envelope(canonical_bytes(env)))
            assert memory.append(env) == head
        for signer, wanted in ((store.signer, 3), (other, 2)):
            questions = [(OUTCOME_ELIGIBLE, outcome_question(decision_hash, record.assertion_id, record.action,
                key_id=signer.key_id, clock_domain=store.clock.domain)),
                (DECISION_ELIGIBLE, decision_question(digest_hex(valid), key_id=signer.key_id,
                clock_domain=store.clock.domain))]
            for kind, q in questions:
                proof = store.lookup_on(conn, head=head, key_type=kind, key=q.value, selection="first")
                assert proof == memory.lookup(head=head, key_type=kind, key=q.value, selection="first")
                result = verify_lookup(proof, expected_head=head, key_type=kind, key=q.value, selection="first",
                    **verification(store), allowed_envelope_keys=store.envelope_keys_allowed,
                    allowed_envelope_domains=store.envelope_domains)
                assert result.envelope == envelopes[wanted]
        before = counts(conn, store.tenant)
        with pytest.raises(PersistenceError, match="record hash does not match"):
            store.append_record_on(conn, recorder, valid, "0" * 64)
        assert counts(conn, store.tenant) == before
        assert store.head_on(conn) == head


def test_pg_numeric_refusal_precedes_recorder_and_keeps_transaction_state(database, service):
    from regulated_core.evidence_encoding import TEN_D
    store, recorder, record, _ = service
    with transaction(database, store.tenant) as conn:
        before = counts(conn, store.tenant)
        with pytest.raises(EvidenceError, match="numeric domain"):
            store.append_record_on(conn, recorder, replace(record, record_id=TEN_D), "0" * 64)
        assert counts(conn, store.tenant) == before
        assert store.head_on(conn) is None


def test_pg_rotation_uses_cutoffs_for_stored_heads_and_current_key_for_new_heads(database, service):
    from regulated_core.signing import Ed25519Signer
    store, recorder, record, _ = service
    with transaction(database, store.tenant) as conn:
        _, first = append(conn, service)
        old = store.signer
        new = Ed25519Signer("evidence:009-new")
        store.trust.register_signer(new)
        store.signer = new
        store.signing_keys = frozenset({new.key_id})
        store.historical_head_keys = {old.key_id: {"retired_after_size": 1}}
        assert store.head_on(conn, 1) == first
        _, second = store.append_record_on(conn, recorder, record, digest_hex(record))
        assert second.key_id == new.key_id
        assert store.head_on(conn, 1) == first
        assert store.head_on(conn, 2) == second
        store.historical_head_keys = {old.key_id: {"retired_after_size": 0}}
        with pytest.raises(EvidenceError, match="signature or scope"):
            store.head_on(conn, 1)
