"""Postgres authority state behind the existing recorder and permit protocols.

The host supplies its existing pool and signing/trust objects. Nothing here opens
a database, creates a key or selects an authority. Explicit migration is separate
from construction. Appends serialize per tenant; permit consumption is an atomic
insert shared by every process. Production qualification still requires actual
database role/RLS and signing-authority evidence.
"""
from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from .clock import ConnectionClock
from .canonical import canonical_bytes, digest_hex
from .evidence import GENESIS, ClockedDecisionEnvelope, DecisionRecorder, SignedDecisionEnvelope, verify_envelope
from .models import Action, ActionEffect, Annotation, ApprovalRequirement, Decision, DecisionKind, DecisionRecord, PolicyRef
from .budget import BudgetError, Reservation
from .revocation import Revocation, RevocationError
from .delegation import DelegationGrant, GrantRevocation, SignedGrant
from .tier4 import CLEARANCE_SCHEMA, MonitorClearance
from .governance_targets import COMMITTED, NOT_COMMITTED, PREPARED, GovernanceEvent, GovernanceLog, attempt_key, event_body
from .permit import EmissionError
from .authority_fence_pg import grant_revocation_key
from .signing import Signature, Signer, TrustDirectory

if TYPE_CHECKING:
    from .delegated_effect_pg import DelegatedEffectVerifier
    from .input_evidence import InputVerifier
    from .approval import ApprovalWorkflow
    from .evidence_checkpoints_pg import PinnedVerifier
    from .preparation_pg import SignedPreparation
    from .registry import ConsequencePolicy
    from .target import TargetPermit


class PersistenceError(RuntimeError):
    """Stored authority evidence failed validation or a tenant was not supplied."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_decision_evidence_v1 (
    tenant TEXT NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    entry_hash TEXT NOT NULL CHECK (length(entry_hash) = 64),
    envelope JSONB NOT NULL,
    PRIMARY KEY (tenant, seq),
    UNIQUE (tenant, entry_hash)
);
CREATE TABLE IF NOT EXISTS regulated_permit_uses_v1 (
    tenant TEXT NOT NULL,
    nonce TEXT NOT NULL CHECK (length(nonce) > 0),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, nonce)
);
CREATE TABLE IF NOT EXISTS regulated_reviews_v1 (
    tenant TEXT NOT NULL,
    review_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 0),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant, review_id, version)
);
CREATE TABLE IF NOT EXISTS regulated_mission_budget_events_v1 (
    tenant TEXT NOT NULL,
    mission TEXT NOT NULL CHECK (length(mission) > 0),
    reservation_id TEXT NOT NULL CHECK (length(reservation_id) > 0),
    kind TEXT NOT NULL CHECK (kind IN ('reserve', 'consume', 'release')),
    units BIGINT NOT NULL CHECK (units > 0),
    limit_units BIGINT NOT NULL CHECK (limit_units >= 0),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, mission, reservation_id, kind)
);
ALTER TABLE regulated_mission_budget_events_v1
    ADD COLUMN IF NOT EXISTS subject_digest TEXT
    CHECK (subject_digest IS NULL OR subject_digest ~ '^[0-9a-f]{64}$');


CREATE TABLE IF NOT EXISTS regulated_preparations_v1 (
    tenant TEXT NOT NULL, nonce TEXT NOT NULL, mission TEXT NOT NULL,
    reservation_id TEXT NOT NULL, preparation_digest TEXT NOT NULL,
    body JSONB NOT NULL, signature JSONB NOT NULL,
    PRIMARY KEY(tenant,nonce), UNIQUE(tenant,mission,reservation_id)
);
CREATE TABLE IF NOT EXISTS regulated_preparation_writers_v1 (role_name TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS regulated_budget_writer_roles_v1 (
    role_name TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('reserve','consume','release')),
    PRIMARY KEY (role_name, kind)
);
CREATE OR REPLACE FUNCTION regulated_budget_insert_guard_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    reserved regulated_mission_budget_events_v1%ROWTYPE;
    active_units BIGINT;
    prepared_nonce TEXT;
    prepared_body JSONB;
    terminal_without_effect BOOLEAN;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed'
       OR NEW.tenant IS DISTINCT FROM current_setting('app.tenant', true) THEN
        RAISE EXCEPTION 'budget write requires matching READ COMMITTED tenant' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM regulated_budget_writer_roles_v1
        WHERE role_name=session_user::text AND kind=NEW.kind
    ) THEN
        RAISE EXCEPTION 'budget event kind not authorized for login' USING ERRCODE='42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'regulated-mission-budget:' || NEW.tenant || chr(31) || NEW.mission, 0));
    IF NEW.kind = 'reserve' THEN
        IF EXISTS (
            SELECT 1 FROM regulated_mission_budget_events_v1
            WHERE tenant=NEW.tenant AND mission=NEW.mission AND reservation_id=NEW.reservation_id
        ) THEN
            RAISE EXCEPTION 'reservation already exists' USING ERRCODE='23514';
        END IF;
        SELECT COALESCE(SUM(
            CASE WHEN spent > 0 THEN GREATEST(spent,allocated)
                 ELSE GREATEST(allocated-returned,0) END),0)
        INTO active_units FROM (
            SELECT reservation_id,
                COALESCE(SUM(units) FILTER (WHERE kind='reserve'),0) AS allocated,
                COALESCE(SUM(units) FILTER (WHERE kind='consume'),0) AS spent,
                COALESCE(SUM(units) FILTER (WHERE kind='release'),0) AS returned
            FROM regulated_mission_budget_events_v1
            WHERE tenant=NEW.tenant AND mission=NEW.mission GROUP BY reservation_id
        ) AS totals;
        IF NEW.units > NEW.limit_units OR active_units + NEW.units > NEW.limit_units THEN
            RAISE EXCEPTION 'mission budget exceeded' USING ERRCODE='23514';
        END IF;
    ELSE
        IF NEW.kind='release' THEN
            SELECT nonce,body INTO prepared_nonce,prepared_body
            FROM regulated_preparations_v1
            WHERE tenant=NEW.tenant AND mission=NEW.mission AND reservation_id=NEW.reservation_id;
            IF FOUND THEN
                terminal_without_effect := false;
                -- Other adapters and missing receiving evidence retain capacity.
                -- Resolve only this trigger's schema, never a session path.
                IF pg_catalog.to_regclass(pg_catalog.format(
                    '%I.regulated_database_receipts_v1', TG_TABLE_SCHEMA)) IS NOT NULL
                   AND pg_catalog.to_regclass(pg_catalog.format(
                    '%I.regulated_database_attempts_v1', TG_TABLE_SCHEMA)) IS NOT NULL THEN
                    EXECUTE pg_catalog.format(
                        'SELECT EXISTS (SELECT 1 FROM %I.regulated_database_receipts_v1 r '
                        'JOIN %I.regulated_database_attempts_v1 a '
                        'ON r.tenant=a.tenant AND r.nonce=a.nonce '
                        'WHERE r.tenant=$1 AND r.nonce=$2 AND r.outcome=''not_committed'' '
                        'AND r.permit_digest=a.permit_digest '
                        'AND a.output_digest=$3 AND a.target_digest=$4 AND a.operation=$5)',
                        TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
                    INTO terminal_without_effect
                    USING NEW.tenant, prepared_nonce, prepared_body->'draft'->>'output_digest',
                          prepared_body->'draft'->>'target_digest', prepared_body->'draft'->>'operation';
                END IF;
                IF NOT terminal_without_effect THEN
                    RAISE EXCEPTION 'prepared authority prevents reservation release' USING ERRCODE='23514';
                END IF;
            END IF;
        END IF;
        SELECT * INTO reserved FROM regulated_mission_budget_events_v1
        WHERE tenant=NEW.tenant AND mission=NEW.mission AND reservation_id=NEW.reservation_id
          AND kind='reserve';
        IF NOT FOUND OR NEW.units <> reserved.units THEN
            RAISE EXCEPTION 'no matching reservation' USING ERRCODE='23514';
        END IF;
        IF EXISTS (
            SELECT 1 FROM regulated_mission_budget_events_v1
            WHERE tenant=NEW.tenant AND mission=NEW.mission AND reservation_id=NEW.reservation_id
              AND kind IN ('consume','release')
        ) THEN
            RAISE EXCEPTION 'reservation is no longer live' USING ERRCODE='23514';
        END IF;
        IF NEW.kind='consume' AND (
            NEW.subject_digest IS DISTINCT FROM reserved.subject_digest
            OR (reserved.subject_digest IS NOT NULL AND NEW.limit_units <> reserved.limit_units)
        ) THEN
            RAISE EXCEPTION 'reservation subject or limit differs' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
DO $$
BEGIN
    EXECUTE format(
        'ALTER FUNCTION %I.regulated_budget_insert_guard_v1() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END $$;
DROP TRIGGER IF EXISTS regulated_budget_insert_guard_v1 ON regulated_mission_budget_events_v1;
CREATE TRIGGER regulated_budget_insert_guard_v1 BEFORE INSERT
    ON regulated_mission_budget_events_v1 FOR EACH ROW
    EXECUTE FUNCTION regulated_budget_insert_guard_v1();

CREATE TABLE IF NOT EXISTS regulated_revocation_events_v1 (
    tenant TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    actor TEXT NOT NULL CHECK (length(actor) > 0),
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    revoked_at_us BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, epoch)
);
CREATE TABLE IF NOT EXISTS regulated_delegation_grants_v1 (
    tenant TEXT NOT NULL,
    grant_digest TEXT NOT NULL CHECK (length(grant_digest) = 64),
    parent_digest TEXT NOT NULL,
    body TEXT NOT NULL,
    signature JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, grant_digest)
);
CREATE TABLE IF NOT EXISTS regulated_delegation_revocations_v1 (
    tenant TEXT NOT NULL,
    grant_digest TEXT NOT NULL CHECK (length(grant_digest) = 64),
    actor TEXT NOT NULL CHECK (length(actor) > 0),
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    revoked_at_us BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, grant_digest)
);
CREATE TABLE IF NOT EXISTS regulated_monitor_clearances_v1 (
    tenant TEXT NOT NULL,
    decision_record_id TEXT NOT NULL,
    body TEXT NOT NULL,
    signature JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, decision_record_id)
);
CREATE TABLE IF NOT EXISTS regulated_governance_events_v1 (
    tenant TEXT NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    nonce TEXT NOT NULL CHECK (length(nonce) > 0),
    phase TEXT NOT NULL CHECK (phase IN ('prepared', 'committed', 'not-committed')),
    scope TEXT NOT NULL CHECK (length(scope) > 0),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 64),
    body TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, seq),
    UNIQUE (tenant, nonce, phase)
);
CREATE UNIQUE INDEX IF NOT EXISTS regulated_governance_one_outcome_v1
    ON regulated_governance_events_v1 (tenant, nonce) WHERE phase <> 'prepared';
CREATE TABLE IF NOT EXISTS regulated_governance_fences_v1 (
    scope TEXT NOT NULL CHECK (length(scope) > 0),
    attempt TEXT NOT NULL CHECK (length(attempt) = 64),
    phase TEXT NOT NULL CHECK (phase IN ('open', 'closed')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (attempt, phase)
);
CREATE INDEX IF NOT EXISTS regulated_governance_fences_scope_v1 ON regulated_governance_fences_v1 (scope);
CREATE TABLE IF NOT EXISTS regulated_egress_scope_v1 (
    tenant TEXT NOT NULL CHECK (length(tenant) > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    kind TEXT NOT NULL CHECK (kind IN ('enrolled', 'inventoried')),
    pack_ref TEXT NOT NULL,
    packs JSONB NOT NULL,
    source TEXT NOT NULL CHECK (length(source) > 0),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant, revision),
    CHECK ((kind = 'enrolled' AND length(pack_ref) > 0) OR (kind = 'inventoried' AND pack_ref = ''))
);
CREATE UNIQUE INDEX IF NOT EXISTS regulated_egress_scope_enrolled_v1 ON regulated_egress_scope_v1 (tenant, pack_ref)
    WHERE kind = 'enrolled';
CREATE TABLE IF NOT EXISTS regulated_monitor_heartbeats_v2 (
    installation TEXT NOT NULL CHECK (length(installation) > 0),
    monitor_id TEXT NOT NULL CHECK (length(monitor_id) > 0),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    beat_at_us BIGINT NOT NULL,
    signature JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (installation, monitor_id, sequence)
);
CREATE TABLE IF NOT EXISTS regulated_governance_rosters_v1 (
    installation TEXT NOT NULL CHECK (length(installation) > 0),
    version BIGINT NOT NULL CHECK (version >= 1),
    roster_digest TEXT NOT NULL CHECK (length(roster_digest) = 64),
    body TEXT NOT NULL,
    tenant TEXT NOT NULL CHECK (length(tenant) > 0),
    operation TEXT NOT NULL CHECK (length(operation) > 0),
    nonce TEXT NOT NULL CHECK (length(nonce) > 0),
    change_digest TEXT NOT NULL CHECK (length(change_digest) = 64),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (installation, version),
    UNIQUE (tenant, operation, nonce, change_digest)
);
CREATE OR REPLACE FUNCTION regulated_authority_no_mutation_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN
    RAISE EXCEPTION 'regulated authority records are append-only';
END $$;
ALTER TABLE regulated_decision_evidence_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_decision_evidence_v1 FORCE ROW LEVEL SECURITY;
ALTER TABLE regulated_permit_uses_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_permit_uses_v1 FORCE ROW LEVEL SECURITY;
ALTER TABLE regulated_mission_budget_events_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_mission_budget_events_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_budget_tenant_v1 ON regulated_mission_budget_events_v1;
CREATE POLICY regulated_budget_tenant_v1 ON regulated_mission_budget_events_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_budget_immutable_v1 ON regulated_mission_budget_events_v1;
CREATE TRIGGER regulated_budget_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_mission_budget_events_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_budget_no_truncate_v1 ON regulated_mission_budget_events_v1;
CREATE TRIGGER regulated_budget_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_mission_budget_events_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_revocation_events_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_revocation_events_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_revocation_tenant_v1 ON regulated_revocation_events_v1;
CREATE POLICY regulated_revocation_tenant_v1 ON regulated_revocation_events_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_revocation_immutable_v1 ON regulated_revocation_events_v1;
CREATE TRIGGER regulated_revocation_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_revocation_events_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_revocation_no_truncate_v1 ON regulated_revocation_events_v1;
CREATE TRIGGER regulated_revocation_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_revocation_events_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_delegation_grants_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_delegation_grants_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_grants_tenant_v1 ON regulated_delegation_grants_v1;
CREATE POLICY regulated_grants_tenant_v1 ON regulated_delegation_grants_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_grants_immutable_v1 ON regulated_delegation_grants_v1;
CREATE TRIGGER regulated_grants_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_delegation_grants_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_grants_no_truncate_v1 ON regulated_delegation_grants_v1;
CREATE TRIGGER regulated_grants_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_delegation_grants_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_delegation_revocations_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_delegation_revocations_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_grant_revocations_tenant_v1 ON regulated_delegation_revocations_v1;
CREATE POLICY regulated_grant_revocations_tenant_v1 ON regulated_delegation_revocations_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_grant_revocations_immutable_v1 ON regulated_delegation_revocations_v1;
CREATE TRIGGER regulated_grant_revocations_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_delegation_revocations_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_grant_revocations_no_truncate_v1 ON regulated_delegation_revocations_v1;
CREATE TRIGGER regulated_grant_revocations_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_delegation_revocations_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_monitor_clearances_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_governance_events_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_governance_events_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_governance_tenant_v1 ON regulated_governance_events_v1;
CREATE POLICY regulated_governance_tenant_v1 ON regulated_governance_events_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_governance_immutable_v1 ON regulated_governance_events_v1;
CREATE TRIGGER regulated_governance_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_governance_events_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_governance_no_truncate_v1 ON regulated_governance_events_v1;
CREATE TRIGGER regulated_governance_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_governance_events_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_egress_scope_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_egress_scope_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_egress_scope_tenant_v1 ON regulated_egress_scope_v1;
CREATE POLICY regulated_egress_scope_tenant_v1 ON regulated_egress_scope_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_egress_scope_immutable_v1 ON regulated_egress_scope_v1;
CREATE TRIGGER regulated_egress_scope_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_egress_scope_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_egress_scope_no_truncate_v1 ON regulated_egress_scope_v1;
CREATE TRIGGER regulated_egress_scope_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_egress_scope_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_monitor_heartbeats_immutable_v2 ON regulated_monitor_heartbeats_v2;
CREATE TRIGGER regulated_monitor_heartbeats_immutable_v2 BEFORE UPDATE OR DELETE
    ON regulated_monitor_heartbeats_v2 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_monitor_heartbeats_no_truncate_v2 ON regulated_monitor_heartbeats_v2;
CREATE TRIGGER regulated_monitor_heartbeats_no_truncate_v2 BEFORE TRUNCATE
    ON regulated_monitor_heartbeats_v2 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_governance_rosters_immutable_v1 ON regulated_governance_rosters_v1;
CREATE TRIGGER regulated_governance_rosters_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_governance_rosters_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_governance_rosters_no_truncate_v1 ON regulated_governance_rosters_v1;
CREATE TRIGGER regulated_governance_rosters_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_governance_rosters_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_governance_fences_immutable_v1 ON regulated_governance_fences_v1;
CREATE TRIGGER regulated_governance_fences_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_governance_fences_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_governance_fences_no_truncate_v1 ON regulated_governance_fences_v1;
CREATE TRIGGER regulated_governance_fences_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_governance_fences_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_monitor_clearances_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_clearance_tenant_v1 ON regulated_monitor_clearances_v1;
CREATE POLICY regulated_clearance_tenant_v1 ON regulated_monitor_clearances_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_clearance_immutable_v1 ON regulated_monitor_clearances_v1;
CREATE TRIGGER regulated_clearance_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_monitor_clearances_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_clearance_no_truncate_v1 ON regulated_monitor_clearances_v1;
CREATE TRIGGER regulated_clearance_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_monitor_clearances_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
ALTER TABLE regulated_reviews_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_reviews_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_evidence_tenant_v1 ON regulated_decision_evidence_v1;
CREATE POLICY regulated_evidence_tenant_v1 ON regulated_decision_evidence_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP POLICY IF EXISTS regulated_permit_tenant_v1 ON regulated_permit_uses_v1;
CREATE POLICY regulated_permit_tenant_v1 ON regulated_permit_uses_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP POLICY IF EXISTS regulated_review_tenant_v1 ON regulated_reviews_v1;
CREATE POLICY regulated_review_tenant_v1 ON regulated_reviews_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS regulated_evidence_immutable_v1 ON regulated_decision_evidence_v1;
CREATE TRIGGER regulated_evidence_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_decision_evidence_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_permit_immutable_v1 ON regulated_permit_uses_v1;
CREATE TRIGGER regulated_permit_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_permit_uses_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_evidence_no_truncate_v1 ON regulated_decision_evidence_v1;
CREATE TRIGGER regulated_evidence_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_decision_evidence_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_permit_no_truncate_v1 ON regulated_permit_uses_v1;
CREATE TRIGGER regulated_permit_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_permit_uses_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_review_immutable_v1 ON regulated_reviews_v1;
CREATE TRIGGER regulated_review_immutable_v1 BEFORE UPDATE OR DELETE
    ON regulated_reviews_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_review_no_truncate_v1 ON regulated_reviews_v1;
CREATE TRIGGER regulated_review_no_truncate_v1 BEFORE TRUNCATE
    ON regulated_reviews_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();

CREATE OR REPLACE FUNCTION regulated_preparation_guard_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE reserved regulated_mission_budget_events_v1%ROWTYPE;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed'
       OR NEW.tenant IS DISTINCT FROM current_setting('app.tenant',true)
       OR NOT EXISTS(SELECT 1 FROM regulated_preparation_writers_v1 WHERE role_name=session_user::text) THEN
        RAISE EXCEPTION 'preparation writer or tenant not authorized' USING ERRCODE='42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'regulated-mission-budget:' || NEW.tenant || chr(31) || NEW.mission,0));
    SELECT * INTO reserved FROM regulated_mission_budget_events_v1
    WHERE tenant=NEW.tenant AND mission=NEW.mission AND reservation_id=NEW.reservation_id AND kind='reserve';
    IF NOT FOUND OR reserved.subject_digest IS NULL OR EXISTS(
        SELECT 1 FROM regulated_mission_budget_events_v1
        WHERE tenant=NEW.tenant AND mission=NEW.mission AND reservation_id=NEW.reservation_id
          AND kind IN ('consume','release')
    ) OR NEW.body->>'subject_digest' IS DISTINCT FROM reserved.subject_digest
      OR NEW.body->>'budget_units' IS DISTINCT FROM reserved.units::text
      OR NEW.body->>'budget_limit' IS DISTINCT FROM reserved.limit_units::text
      OR NEW.body->'draft'->>'tenant_id' IS DISTINCT FROM NEW.tenant
      OR NEW.body->'draft'->>'nonce' IS DISTINCT FROM NEW.nonce
      OR NEW.body->'draft'->>'mission' IS DISTINCT FROM NEW.mission
      OR NEW.body->'draft'->>'budget_reservation' IS DISTINCT FROM NEW.reservation_id THEN
        RAISE EXCEPTION 'preparation does not bind a live reservation' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.regulated_preparation_guard_v1() SET search_path=pg_catalog,%I,pg_temp',
                   current_schema(),current_schema());
END $$;
DROP TRIGGER IF EXISTS regulated_preparation_guard_v1 ON regulated_preparations_v1;
CREATE TRIGGER regulated_preparation_guard_v1 BEFORE INSERT ON regulated_preparations_v1
FOR EACH ROW EXECUTE FUNCTION regulated_preparation_guard_v1();
ALTER TABLE regulated_preparations_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_preparations_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS preparation_tenant ON regulated_preparations_v1;
CREATE POLICY preparation_tenant ON regulated_preparations_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS preparation_immutable ON regulated_preparations_v1;
CREATE TRIGGER preparation_immutable BEFORE UPDATE OR DELETE ON regulated_preparations_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS preparation_no_truncate ON regulated_preparations_v1;
CREATE TRIGGER preparation_no_truncate BEFORE TRUNCATE ON regulated_preparations_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


def migrate(pool: Any) -> None:
    """Install the adapter schema in one explicit, serialized transaction."""
    with pool.connection() as conn, conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("regulated-authority-schema-v1",))
        conn.execute(SCHEMA)


def _tenant(conn: Any, tenant: str) -> None:
    if not isinstance(tenant, str) or not tenant.strip():
        raise PersistenceError("explicit tenant required for regulated authority state")
    # Transaction-local: a pooled connection cannot leak its previous tenant.
    conn.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))


def _entry_hash(env: SignedDecisionEnvelope) -> str:
    return env.chain_hash()


def decode_envelope(raw: Any) -> SignedDecisionEnvelope:
    """Decode only the core's data model; never load executable/pickled state."""
    try:
        value = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        body = dict(value)
        record = dict(body.pop("record"))
        action = dict(record.pop("action"))
        action["effect"] = ActionEffect(action["effect"])
        decision = dict(record.pop("decision"))
        decision["kind"] = DecisionKind(decision["kind"])
        decision["reason_codes"] = tuple(decision["reason_codes"])
        decision["annotations"] = tuple(Annotation(**a) for a in decision["annotations"])
        approval = decision["approval"]
        if approval is not None:
            approval = dict(approval)
            approval["role_groups"] = tuple(frozenset(g) for g in approval["role_groups"])
            decision["approval"] = ApprovalRequirement(**approval)
        policy = PolicyRef(**record.pop("policy"))
        signature = Signature(**body.pop("signature"))
        envelope_type = ClockedDecisionEnvelope if "domain" in body else SignedDecisionEnvelope
        result = envelope_type(
            record=DecisionRecord(**record, action=Action(**action), policy=policy, decision=Decision(**decision)),
            signature=signature, **body,
        )
        if canonical_bytes(result) != canonical_bytes(value):
            raise ValueError("stored representation is not canonical core data")
        return result
    except (TypeError, ValueError, KeyError) as exc:
        raise PersistenceError("invalid stored regulated envelope") from exc


class PostgresDecisionRecorder(DecisionRecorder):
    """Signed per-tenant chains persist across processes and restarts."""

    durable = True

    def __init__(self, evidence_signer: Signer, trust: TrustDirectory, *, pool: Any,
                 historical_evidence_key_ids: frozenset[str] = frozenset(),
                 clock: ConnectionClock | None = None) -> None:
        super().__init__(evidence_signer, trust, clock=clock)
        if (not isinstance(historical_evidence_key_ids, frozenset)
                or any(not isinstance(key, str) or not key.strip() or not trust.is_known(key)
                       for key in historical_evidence_key_ids)):
            raise ValueError("historical evidence requires explicit trusted key identities")
        # Read old signed chain links after a host-authorized key transition. This
        # does NOT change verify_entry: old keys cannot authorize a new operation.
        self._history_keys = historical_evidence_key_ids | {evidence_signer.key_id}
        self._pool = pool

    def _checked(self, row: Any, tenant: str) -> SignedDecisionEnvelope:
        seq, entry_hash, raw = row
        env = decode_envelope(raw)
        if (env.record.tenant_id != tenant or env.seq != seq or _entry_hash(env) != entry_hash
                or env.signature.key_id not in self._history_keys or not verify_envelope(env, self._trust)):
            raise PersistenceError("stored regulated evidence failed integrity")
        return env

    def append(self, record: DecisionRecord, record_hash: str) -> SignedDecisionEnvelope:
        """Sign and persist the next entry, or roll back without advancing a head."""
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, record.tenant_id)
            return self._append_on(conn, record, record_hash)

    def _append_on(self, conn: Any, record: DecisionRecord, record_hash: str) -> SignedDecisionEnvelope:
        """Append on the recorder's transaction for atomic companion retention."""
        if record_hash != digest_hex(record):
            raise PersistenceError("record hash does not match the decision")
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                     ("regulated-evidence-v1:" + record.tenant_id,))
        row = conn.execute(
            "SELECT seq, entry_hash, envelope FROM regulated_decision_evidence_v1"
            " WHERE tenant = %s ORDER BY seq DESC LIMIT 1", (record.tenant_id,),
        ).fetchone()
        previous = self._checked(row, record.tenant_id) if row is not None else None
        seq, prev = (previous.seq + 1, _entry_hash(previous)) if previous is not None else (0, GENESIS)
        env = self._sign_entry(record, record_hash, prev, seq, connection=conn)
        if env.signature.key_id != self._signer.key_id or not verify_envelope(env, self._trust):
            raise PersistenceError("evidence signer is not the configured trusted authority")
        conn.execute(
            "INSERT INTO regulated_decision_evidence_v1 (tenant, seq, entry_hash, envelope)"
            " VALUES (%s, %s, %s, %s::jsonb)",
            (record.tenant_id, seq, _entry_hash(env), canonical_bytes(env).decode("utf-8")),
        )
        return env

    def prepare_target(
        self, draft: TargetPermit, *, issuer_key_id: str, policy: ConsequencePolicy,
        evidence_verifier: PinnedVerifier, max_decision_age_us: int,
        approval_authority: ApprovalWorkflow | None = None,
        input_verifier: InputVerifier | None = None,
        delegated_verifier: DelegatedEffectVerifier | None = None,
        clock: ConnectionClock | None = None,
    ) -> SignedPreparation:
        """Return preparation only after durable commit; no permit is signed."""
        from .preparation_pg import prepare_target_on

        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, draft.tenant_id)
            preparation = prepare_target_on(
                self, conn, draft, issuer_key_id=issuer_key_id, policy=policy,
                evidence_verifier=evidence_verifier,
                max_decision_age_us=max_decision_age_us,
                approval_authority=approval_authority, input_verifier=input_verifier,
                delegated_verifier=delegated_verifier, clock=clock,
            )
        return preparation

    def checkpoint(self, tenant: str, through_seq: int, *, previous: Any,
                   expected_previous_digest: str, profile: str, max_entries: int = 256) -> Any:
        """Retain a verified batch; publish its pin only after this transaction commits."""
        from .evidence_checkpoints_pg import checkpoint_on
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant)
            return checkpoint_on(
                conn, tenant=tenant, through_seq=through_seq, previous=previous,
                expected_previous_digest=expected_previous_digest, profile=profile,
                signer=self._signer, trust=self._trust, allowed_keys=self._history_keys,
                max_entries=max_entries,
            )

    def entries(self, tenant_id: str | None = None) -> tuple[SignedDecisionEnvelope, ...]:
        """Read one tenant only; there is no cross-tenant administrative shortcut."""
        if tenant_id is None:
            raise PersistenceError("explicit tenant required for durable evidence reads")
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            rows = conn.execute(
                "SELECT seq, entry_hash, envelope FROM regulated_decision_evidence_v1"
                " WHERE tenant = %s ORDER BY seq", (tenant_id,),
            ).fetchall()
        return tuple(self._checked(row, tenant_id) for row in rows)

    def verify_chain(self, tenant_id: str) -> bool:
        """Verify persisted signatures, record hashes and every predecessor link."""
        prev, seq = GENESIS, 0
        try:
            for env in self.entries(tenant_id):
                if env.seq != seq or env.prev_hash != prev:
                    return False
                prev, seq = _entry_hash(env), seq + 1
        except PersistenceError:
            return False
        return True


class PostgresMissionBudget:
    """The mission budget as append-only events, linearised per (tenant, mission) by a transaction advisory lock.

    Every worker and restart sees one ledger. A reservation is admitted only while live units (reserved minus
    released) plus the new units stay within the limit, checked and inserted under the same lock, so two workers
    can never both take the last unit. Consumption and release are single rows the primary key keeps unique; a
    release is refused once the reservation is consumed, so consumed authority is never returned.
    """

    durable = True

    def __init__(self, *, pool: Any, allocator_pool: Any = None) -> None:
        """Use explicit allocator and receiver logins over the same ledger.

        ``pool`` records consumption. ``allocator_pool`` reserves and releases;
        omission preserves existing single-pool callers. The host must bind
        both to the same database and schema. This in-process composition does
        not establish separate process or credential custody.
        """
        self._pool = pool
        self._allocator_pool = allocator_pool if allocator_pool is not None else pool

    @staticmethod
    def _lock(conn: Any, tenant_id: str, mission: str) -> None:
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                     ("regulated-mission-budget:" + tenant_id + "\x1f" + mission,))

    @staticmethod
    def _rows(conn: Any, tenant_id: str, mission: str, reservation_id: str) -> dict[str, int]:
        found = conn.execute(
            "SELECT kind, units FROM regulated_mission_budget_events_v1"
            " WHERE tenant = %s AND mission = %s AND reservation_id = %s", (tenant_id, mission, reservation_id),
        ).fetchall()
        return {str(kind): int(units) for kind, units in found}

    def reserve(
        self, tenant_id: str, mission: str, *, reservation_id: str,
        units: int, limit: int, subject_digest: str | None = None,
    ) -> Reservation:
        if subject_digest is not None:
            self._validate_subject(subject_digest)
        if type(units) is not int or type(limit) is not int or units < 1 or limit < 0:
            raise BudgetError("a reservation needs at least one unit against a non-negative limit")
        with self._allocator_pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            self._lock(conn, tenant_id, mission)
            if self._rows(conn, tenant_id, mission, reservation_id):
                raise BudgetError("reservation id already used")
            live = conn.execute(
                "SELECT COALESCE(SUM(CASE kind WHEN 'reserve' THEN units WHEN 'release' THEN -units ELSE 0 END), 0)"
                " FROM regulated_mission_budget_events_v1 WHERE tenant = %s AND mission = %s", (tenant_id, mission),
            ).fetchone()[0]
            if int(live) + units > limit:
                raise BudgetError(f"mission budget exceeded: {limit} unit(s) allowed")
            conn.execute("INSERT INTO regulated_mission_budget_events_v1"
                         " (tenant, mission, reservation_id, kind, units, limit_units, subject_digest)"
                         " VALUES (%s, %s, %s, 'reserve', %s, %s, %s)",
                         (tenant_id, mission, reservation_id, units, limit, subject_digest))
        return Reservation(tenant_id, mission, reservation_id, units, limit)

    @staticmethod
    def _validate_subject(subject_digest: str) -> None:
        if (
            not isinstance(subject_digest, str)
            or len(subject_digest) != 64
            or any(c not in "0123456789abcdef" for c in subject_digest)
        ):
            raise BudgetError("a bound reservation requires a canonical subject digest")

    def require_live_on(
        self, conn: Any, tenant_id: str, mission: str, reservation_id: str,
        *, subject_digest: str, units: int, limit: int,
    ) -> Reservation:
        """Check an exact bound reservation inside the caller's transaction.

        Derive the subject from authenticated retained evidence and expected
        units/limit from trusted policy and delegation. This method does not
        authenticate those inputs. Acquire authority and target locks before
        this mission lock. Legacy unbound reservations are refused.
        """
        from psycopg.pq import TransactionStatus

        self._validate_subject(subject_digest)
        if type(units) is not int or type(limit) is not int or units < 1 or limit < units:
            raise BudgetError("invalid expected reservation amount")
        if conn.info.transaction_status != TransactionStatus.INTRANS:
            raise BudgetError("bound consumption requires an active transaction")
        isolation, scoped_tenant = conn.execute(
            "SELECT current_setting('transaction_isolation'), current_setting('app.tenant', true)"
        ).fetchone()
        if isolation != "read committed":
            raise BudgetError("bound consumption requires READ COMMITTED isolation")
        if not tenant_id or scoped_tenant != tenant_id:
            raise BudgetError("reservation tenant differs from transaction tenant")
        self._lock(conn, tenant_id, mission)
        rows = conn.execute(
            "SELECT kind, units, limit_units, subject_digest"
            " FROM regulated_mission_budget_events_v1"
            " WHERE tenant=%s AND mission=%s AND reservation_id=%s",
            (tenant_id, mission, reservation_id),
        ).fetchall()
        if len(rows) != 1 or rows[0] != ("reserve", units, limit, subject_digest):
            raise BudgetError("no matching live bound reservation backs this effect")
        return Reservation(tenant_id, mission, reservation_id, units, limit)

    def consume_on(
        self, conn: Any, tenant_id: str, mission: str, reservation_id: str,
        *, subject_digest: str, units: int, limit: int,
    ) -> None:
        """Consume with the caller's database effect and receipt atomically.

        Neither commits nor opens a connection. External effects cannot be
        made atomic by this database transaction.
        """
        self.require_live_on(
            conn, tenant_id, mission, reservation_id,
            subject_digest=subject_digest, units=units, limit=limit,
        )
        conn.execute(
            "INSERT INTO regulated_mission_budget_events_v1"
            " (tenant,mission,reservation_id,kind,units,limit_units,subject_digest)"
            " VALUES (%s,%s,%s,'consume',%s,%s,%s)",
            (tenant_id, mission, reservation_id, units, limit, subject_digest),
        )

    def consume(self, tenant_id: str, mission: str, reservation_id: str) -> None:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            self._lock(conn, tenant_id, mission)
            bound = conn.execute(
                "SELECT subject_digest FROM regulated_mission_budget_events_v1"
                " WHERE tenant=%s AND mission=%s AND reservation_id=%s AND kind='reserve'",
                (tenant_id, mission, reservation_id),
            ).fetchone()
            if bound is not None and bound[0] is not None:
                raise BudgetError("bound reservation requires transaction-owned consume_on")
            rows = self._rows(conn, tenant_id, mission, reservation_id)
            if "reserve" not in rows or "release" in rows or "consume" in rows:
                raise BudgetError("no live reservation backs this effect")
            conn.execute("INSERT INTO regulated_mission_budget_events_v1"
                         " (tenant, mission, reservation_id, kind, units, limit_units) VALUES (%s, %s, %s, 'consume', %s, 0)",
                         (tenant_id, mission, reservation_id, rows["reserve"]))

    def release(self, tenant_id: str, mission: str, reservation_id: str) -> None:
        with self._allocator_pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            self._lock(conn, tenant_id, mission)
            rows = self._rows(conn, tenant_id, mission, reservation_id)
            if "reserve" in rows and "consume" not in rows and "release" not in rows:
                conn.execute("INSERT INTO regulated_mission_budget_events_v1"
                             " (tenant, mission, reservation_id, kind, units, limit_units) VALUES (%s, %s, %s, 'release', %s, 0)",
                             (tenant_id, mission, reservation_id, rows["reserve"]))

    def committed(self, tenant_id: str, mission: str) -> int:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            total = conn.execute(
                "SELECT COALESCE(SUM(units), 0) FROM regulated_mission_budget_events_v1"
                " WHERE tenant = %s AND mission = %s AND kind = 'consume'", (tenant_id, mission),
            ).fetchone()[0]
        return int(total)


class PostgresPermitUseStore:
    """An atomic unique insert refuses replay across workers and restarts."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def consume(self, tenant_id: str, nonce: str) -> None:
        """Consume once within the supplied tenant, with no update/delete route."""
        if not isinstance(nonce, str) or not nonce.strip():
            raise EmissionError("permit nonce must not be empty")
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            row = conn.execute(
                "INSERT INTO regulated_permit_uses_v1 (tenant, nonce) VALUES (%s, %s)"
                " ON CONFLICT (tenant, nonce) DO NOTHING RETURNING nonce", (tenant_id, nonce),
            ).fetchone()
            if row is None:
                raise EmissionError("permit already used (single-use)")

    def used(self, tenant_id: str, nonce: str) -> bool:
        """Whether the nonce is already consumed within the tenant: a read, never a claim. The atomic insert in
        `consume` stays the only thing that spends a nonce, so a race between this read and it is still safe."""
        with self._pool.connection() as conn, conn.transaction():
            return self.used_on(conn, tenant_id, nonce)

    @staticmethod
    def used_on(conn: Any, tenant_id: str, nonce: str) -> bool:
        """Read a claim on an already owned session, inside its caller's transaction."""
        _tenant(conn, tenant_id)
        row = conn.execute(
            "SELECT 1 FROM regulated_permit_uses_v1 WHERE tenant = %s AND nonce = %s", (tenant_id, nonce),
        ).fetchone()
        return row is not None


def _decode_grant(raw_body: Any, raw_signature: Any) -> SignedGrant:
    body = json.loads(raw_body)
    signature = raw_signature if isinstance(raw_signature, dict) else json.loads(raw_signature)
    if body.pop("schema", None) != "regulated/delegation-grant/v1":
        raise PersistenceError("stored delegation grant has an unknown schema")
    for name in ("operations", "targets", "policy_refs"):
        body[name] = tuple(body[name])
    return SignedGrant(DelegationGrant(**body), Signature(**signature))


class PostgresGrantStore:
    """Delegation grants and their revocations, append-only per tenant (docs/ARCHITECTURE-OF-RECORD/13).

    The stored body is the grant's canonical signed body, so a resolver re-derives the digest and re-verifies the
    signature on every read; nothing here is trusted because it was stored. Rows are never updated or deleted."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def put(self, signed: SignedGrant) -> None:
        grant = signed.grant
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, grant.tenant_id)
            conn.execute("INSERT INTO regulated_delegation_grants_v1 (tenant, grant_digest, parent_digest, body, signature)"
                         " VALUES (%s, %s, %s, %s, %s::jsonb) ON CONFLICT (tenant, grant_digest) DO NOTHING",
                         (grant.tenant_id, signed.digest, grant.parent_digest,
                          canonical_bytes(grant.body()).decode("utf-8"),
                          json.dumps({"key_id": signed.signature.key_id, "value": signed.signature.value,
                                      "alg": signed.signature.alg})))

    def get(self, tenant_id: str, digest: str) -> SignedGrant | None:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            row = conn.execute("SELECT body, signature FROM regulated_delegation_grants_v1"
                               " WHERE tenant = %s AND grant_digest = %s", (tenant_id, digest)).fetchone()
        if row is None:
            return None
        return _decode_grant(row[0], row[1])

    def revoke(self, tenant_id: str, revocation: GrantRevocation) -> None:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (grant_revocation_key(tenant_id, revocation.grant_digest),),
            )
            conn.execute("INSERT INTO regulated_delegation_revocations_v1"
                         " (tenant, grant_digest, actor, reason, revoked_at_us) VALUES (%s, %s, %s, %s, %s)"
                         " ON CONFLICT (tenant, grant_digest) DO NOTHING",
                         (tenant_id, revocation.grant_digest, revocation.actor, revocation.reason, revocation.at_us))

    def delegated_to(self, tenant_id: str, subject: str) -> tuple[SignedGrant, ...]:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            rows = conn.execute("SELECT grant_digest FROM regulated_delegation_grants_v1 WHERE tenant = %s"
                                " AND parent_digest <> '' AND (body::jsonb ->> 'subject') = %s",
                                (tenant_id, subject)).fetchall()
        found = (self.get(tenant_id, str(r[0])) for r in rows)
        return tuple(g for g in found if g is not None)

    def stored_child(self, tenant_id: str, parent_digest: str, subject: str) -> SignedGrant | None:
        """The one stored child of this parent for this subject, or None (read without a lock)."""
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            rows = self._children(conn, tenant_id, parent_digest, subject)
        if len(rows) > 1:
            raise PersistenceError("more than one child is stored for this parent and executor")
        return _decode_grant(rows[0][0], rows[0][1]) if rows else None

    @staticmethod
    def _children(conn: Any, tenant_id: str, parent_digest: str, subject: str) -> list[Any]:
        return list(conn.execute("SELECT body, signature FROM regulated_delegation_grants_v1 WHERE tenant = %s"
                                 " AND parent_digest = %s AND (body::jsonb ->> 'subject') = %s",
                                 (tenant_id, parent_digest, subject)).fetchall())

    def ensure_child(self, tenant_id: str, parent_digest: str, subject: str, candidate: SignedGrant) -> SignedGrant:
        """One stored child per (tenant, parent, subject), across processes (see GrantStore.ensure_child). Nothing
        but this key's rows is read while the lock and the connection are held."""
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         (canonical_bytes(["delegation-child", tenant_id, parent_digest, subject]).decode("utf-8"),))
            rows = self._children(conn, tenant_id, parent_digest, subject)
            if len(rows) > 1:
                raise PersistenceError("more than one child is stored for this parent and executor")
            if rows:
                return _decode_grant(rows[0][0], rows[0][1])
            signed = candidate
            grant = signed.grant
            if (grant.tenant_id, grant.parent_digest, grant.subject) != (tenant_id, parent_digest, subject):
                raise PersistenceError("the issued child is not for this parent and executor")
            conn.execute("INSERT INTO regulated_delegation_grants_v1 (tenant, grant_digest, parent_digest, body, signature)"
                         " VALUES (%s, %s, %s, %s, %s::jsonb)",
                         (grant.tenant_id, signed.digest, grant.parent_digest,
                          canonical_bytes(grant.body()).decode("utf-8"),
                          json.dumps({"key_id": signed.signature.key_id, "value": signed.signature.value,
                                      "alg": signed.signature.alg})))
            return signed

    def revoked(self, tenant_id: str, digests: Any) -> frozenset[str]:
        wanted = list(digests)
        if not wanted:
            return frozenset()
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            rows = conn.execute("SELECT grant_digest FROM regulated_delegation_revocations_v1"
                                " WHERE tenant = %s AND grant_digest = ANY(%s)", (tenant_id, wanted)).fetchall()
        return frozenset(str(r[0]) for r in rows)


class PostgresEgressScopeStore:
    """Tenant egress scope history (regulated_core/egress_admission.py), durable, append-only and untruncatable.
    Writes for one tenant are serialised by a transaction-scoped advisory lock, so revisions are contiguous across
    hosts; an enrolment is recorded once per pack (a unique partial index backs the check)."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    @staticmethod
    def _lock(conn: Any, tenant: str) -> None:
        # The tenant's scope lock: every write takes it, and so does a guarded send, for its whole transaction.
        _tenant(conn, tenant)
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("regulated-egress-scope:" + tenant,))

    @staticmethod
    def _read(conn: Any, tenant: str) -> Any:
        from .egress_admission import ScopeEvent

        rows = conn.execute("SELECT revision, kind, pack_ref, packs, source FROM regulated_egress_scope_v1"
                            " WHERE tenant = %s ORDER BY revision", (tenant,)).fetchall()
        return tuple(ScopeEvent(tenant, int(r[0]), str(r[1]), str(r[2]),
                                tuple(r[3] if isinstance(r[3], list) else json.loads(r[3])), str(r[4])) for r in rows)

    def _append(self, tenant: str, kind: str, pack_ref: str, packs: tuple[str, ...], source: str) -> int:
        with self._pool.connection() as conn, conn.transaction():
            self._lock(conn, tenant)
            if kind == "enrolled":
                exists = conn.execute("SELECT 1 FROM regulated_egress_scope_v1 WHERE tenant = %s AND kind = 'enrolled'"
                                      " AND pack_ref = %s", (tenant, pack_ref)).fetchone()
                if exists is not None:
                    row = conn.execute("SELECT max(revision) FROM regulated_egress_scope_v1 WHERE tenant = %s",
                                       (tenant,)).fetchone()
                    return int(row[0])
            row = conn.execute("SELECT coalesce(max(revision), 0) FROM regulated_egress_scope_v1 WHERE tenant = %s",
                               (tenant,)).fetchone()
            revision = int(row[0]) + 1
            conn.execute("INSERT INTO regulated_egress_scope_v1 (tenant, revision, kind, pack_ref, packs, source)"
                         " VALUES (%s, %s, %s, %s, %s::jsonb, %s)",
                         (tenant, revision, kind, pack_ref, json.dumps(list(packs)), source))
            return revision

    def enroll(self, tenant: str, pack_ref: str, *, source: str) -> int:
        from .egress_admission import ENROLLED, _checked_text

        return self._append(_checked_text(tenant, "tenant"), ENROLLED, _checked_text(pack_ref, "pack reference"), (),
                            _checked_text(source, "enrolment source"))

    def record_inventory(self, tenant: str, packs: frozenset[str], *, evidence: str) -> int:
        from .egress_admission import INVENTORIED, _checked_text

        found = tuple(sorted(_checked_text(p, "pack reference") for p in packs))
        return self._append(_checked_text(tenant, "tenant"), INVENTORIED, "", found,
                            _checked_text(evidence, "inventory evidence"))

    def events(self, tenant: str) -> Any:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant)
            return self._read(conn, tenant)

    @contextmanager
    def guard(self, tenant: str) -> Iterator[Callable[[], Any]]:
        """One connection and transaction holding the tenant's advisory scope lock for the block: an enrolment on any
        host waits. It takes a single pool connection and nothing inside it needs another from this store, so it cannot
        deadlock the pool on itself; acquiring that connection is bounded by the pool's own timeout, and a failure is a
        refusal. The transaction ends, and the lock is released, when the block ends or raises."""
        with self._pool.connection() as conn, conn.transaction():
            self._lock(conn, tenant)
            yield lambda: self._read(conn, tenant)


class PostgresHeartbeatStore:
    """Monitor heartbeats, durable and append-only (A17; regulated_core/heartbeat.py). Each monitor's latest is its
    own highest sequence, so a retired monitor's high sequence never hides its replacement's beats; a repeated sequence
    is ignored, never replaced. Only the verifying ingress writes here, and nothing is trusted because it was stored:
    the heartbeat gate re-verifies the signature and the monitor key in force on every read."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def put(self, beat: Any) -> None:
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("INSERT INTO regulated_monitor_heartbeats_v2 (installation, sequence, monitor_id, beat_at_us,"
                         " signature) VALUES (%s, %s, %s, %s, %s::jsonb)"
                         " ON CONFLICT (installation, monitor_id, sequence) DO NOTHING",
                         (beat.installation, beat.sequence, beat.monitor_id, beat.beat_at_us,
                          json.dumps({"key_id": beat.signature.key_id, "value": beat.signature.value,
                                      "alg": beat.signature.alg})))

    def latest(self, installation: str, monitor_id: str) -> Any:
        from .heartbeat import MonitorHeartbeat

        with self._pool.connection() as conn, conn.transaction():
            row = conn.execute("SELECT sequence, monitor_id, beat_at_us, signature FROM regulated_monitor_heartbeats_v2"
                               " WHERE installation = %s AND monitor_id = %s ORDER BY sequence DESC LIMIT 1",
                               (installation, monitor_id)).fetchone()
        if row is None:
            return None
        signature = row[3] if isinstance(row[3], dict) else json.loads(row[3])
        return MonitorHeartbeat(installation, str(row[1]), int(row[0]), int(row[2]), Signature(**signature))


class PostgresRosterStore:
    """The governance roster, durable and append-only (A09; regulated_core/governance_roster.py).

    Installation-level like the governance fences: one roster governs the whole installation. Each version is one
    immutable row, and the row IS the receiving receipt (tenant, operation, nonce, change digest), written in the same
    transaction as the roster under the installation's advisory lock. The stored body is re-parsed and its digest
    re-derived on every read; nothing is trusted because it was stored."""

    durable = True

    def __init__(self, *, pool: Any, guard: Any = None) -> None:
        self._pool, self._guard = pool, guard

    def current(self, installation: str) -> Any:
        from .governance_roster import roster_from_fields

        with self._pool.connection() as conn, conn.transaction():
            row = conn.execute("SELECT roster_digest, body FROM regulated_governance_rosters_v1 WHERE installation = %s"
                               " ORDER BY version DESC LIMIT 1", (installation,)).fetchone()
        if row is None:
            return None
        roster = roster_from_fields(json.loads(row[1]))
        if roster.digest() != row[0] or roster.installation != installation:
            raise PersistenceError("the stored governance roster does not match its digest")
        return roster

    def apply(self, change: Any) -> None:
        from .governance_roster import ROSTER_KIND, roster_from_fields
        from .governance_targets import FinalCheckRefused

        roster = roster_from_fields(change.change["roster"])
        if self._guard is not None:
            self._guard.require(ROSTER_KIND, change.subject)
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         ("regulated-governance-roster:" + change.subject,))
            row = conn.execute("SELECT version, roster_digest FROM regulated_governance_rosters_v1 WHERE installation = %s"
                               " ORDER BY version DESC LIMIT 1", (change.subject,)).fetchone()
            prior = str(row[1]) if row is not None else "absent"
            if prior != change.approved_prior:
                raise FinalCheckRefused("the roster changed since this change was approved; nothing written")
            if roster.installation != change.subject or roster.version != (int(row[0]) + 1 if row is not None else 1):
                raise FinalCheckRefused("a roster change must advance this installation's version by exactly one")
            change.final_check()
            conn.execute("INSERT INTO regulated_governance_rosters_v1 (installation, version, roster_digest, body, tenant,"
                         " operation, nonce, change_digest) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                         (roster.installation, roster.version, roster.digest(),
                          canonical_bytes(roster.as_fields()).decode("utf-8"), change.tenant_id, change.operation,
                          change.nonce, change.change_digest))

    def receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Any:
        from .target import Outcome

        with self._pool.connection() as conn, conn.transaction():
            row = conn.execute("SELECT 1 FROM regulated_governance_rosters_v1 WHERE tenant = %s AND operation = %s"
                               " AND nonce = %s AND change_digest = %s",
                               (tenant_id, operation, nonce, change_digest)).fetchone()
        return Outcome.COMMITTED if row is not None else Outcome.UNKNOWN


class PostgresClearanceStore:
    """Tier-4 monitor clearances, append-only per tenant (A03). The stored body is the signed body, so the controls
    re-verify the monitor's signature on every read; the first clearance of a decision is the only one."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def put(self, clearance: MonitorClearance) -> None:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, clearance.tenant_id)
            conn.execute("INSERT INTO regulated_monitor_clearances_v1 (tenant, decision_record_id, body, signature)"
                         " VALUES (%s, %s, %s, %s::jsonb) ON CONFLICT (tenant, decision_record_id) DO NOTHING",
                         (clearance.tenant_id, clearance.decision_record_id,
                          canonical_bytes(clearance.signed_body()).decode("utf-8"),
                          json.dumps({"key_id": clearance.signature.key_id, "value": clearance.signature.value,
                                      "alg": clearance.signature.alg})))

    def get(self, tenant_id: str, decision_record_id: str) -> MonitorClearance | None:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            row = conn.execute("SELECT body, signature FROM regulated_monitor_clearances_v1"
                               " WHERE tenant = %s AND decision_record_id = %s", (tenant_id, decision_record_id)).fetchone()
        if row is None:
            return None
        body = json.loads(row[0])
        signature = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        if body.pop("schema", None) != CLEARANCE_SCHEMA:
            raise PersistenceError("stored monitor clearance has an unknown schema")
        return MonitorClearance(**body, signature=Signature(**signature))


class PostgresGovernanceLog(GovernanceLog):
    """The governance log, durable and shared by every host (A09).

    Events are append-only per tenant under row-level security and triggers that refuse any rewrite; each row carries
    its event digest, re-checked on every read, so the Merkle root a host publishes is reproduced from the stored rows.
    The scope fence is installation-level, because a pack registry is global: it holds only the scope and an opaque
    attempt key, never a tenant's change. Compare-and-apply on a scope is serialised across processes by a session
    advisory lock held for the whole receiving transaction; a process that dies releases it, and its prepared attempt
    stays fenced until reconciled.

    The lock lives on one owned session, and a session whose lock state is uncertain is never returned to a pool
    (source review 3146): a lost acquisition or commit acknowledgement, a failed or refused unlock, an exception or a
    cancellation inside the section all close the session, which is the one release PostgreSQL guarantees. Log
    operations inside the section reuse that session, so a bounded pool is never asked for a second connection."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        super().__init__()
        self._pool = pool
        self._owned = threading.local()

    @contextmanager
    def _session(self) -> Iterator[Any]:
        owned = getattr(self._owned, "conn", None)
        if owned is not None:
            yield owned
            return
        with self._pool.connection() as conn:
            yield conn

    @contextmanager
    def connection(self) -> Iterator[Any]:
        """Join the scope-owned session, or borrow one outside a governed operation.

        Related stores use this connection port to avoid nested pool checkouts.
        They own their transactions; the governance log retains session custody.
        """
        with self._session() as conn:
            yield conn

    def permit_claimed(self, uses: Any, tenant_id: str, nonce: str) -> bool:
        """Observe a claim without borrowing twice from the same bounded pool."""
        if isinstance(uses, PostgresPermitUseStore) and uses._pool is self._pool:
            with self._session() as conn, conn.transaction():
                return uses.used_on(conn, tenant_id, nonce)
        return super().permit_claimed(uses, tenant_id, nonce)

    @contextmanager
    def governing(self, scope: str) -> Iterator[None]:
        key = "regulated-governance:" + scope
        with self._pool.connection() as conn:
            released = False
            try:
                conn.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (key,))
                conn.commit()
                prior = getattr(self._owned, "conn", None)
                self._owned.conn = conn
                try:
                    yield
                finally:
                    self._owned.conn = prior
                row = conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (key,)).fetchone()
                conn.commit()
                released = row is not None and row[0] is True
            finally:
                if not released:
                    try:
                        conn.close()
                    except Exception:           # already broken: the pool discards it either way
                        pass

    def append(self, event: GovernanceEvent) -> str:
        if event.phase not in (PREPARED, COMMITTED, NOT_COMMITTED) or not event.scope:
            raise PersistenceError("a governance event needs a known phase and a scope")
        with self._session() as conn, conn.transaction():
            _tenant(conn, event.tenant_id)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         ("regulated-governance-log:" + event.tenant_id,))
            row = conn.execute("SELECT COALESCE(MAX(seq) + 1, 0) FROM regulated_governance_events_v1 WHERE tenant = %s",
                               (event.tenant_id,)).fetchone()
            conn.execute("INSERT INTO regulated_governance_events_v1 (tenant, seq, nonce, phase, scope, event_digest, body)"
                         " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                         (event.tenant_id, row[0], event.nonce, event.phase, event.scope, event.digest(),
                          canonical_bytes(event_body(event)).decode("utf-8")))
            conn.execute("INSERT INTO regulated_governance_fences_v1 (scope, attempt, phase) VALUES (%s, %s, %s)"
                         " ON CONFLICT DO NOTHING",
                         (event.scope, attempt_key(event.tenant_id, event.nonce),
                          "open" if event.phase == PREPARED else "closed"))
        return self.root(event.tenant_id)

    def events(self, tenant_id: str) -> tuple[GovernanceEvent, ...]:
        with self._session() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            rows = conn.execute("SELECT event_digest, body FROM regulated_governance_events_v1 WHERE tenant = %s"
                                " ORDER BY seq", (tenant_id,)).fetchall()
        out = []
        for digest, body in rows:
            event = GovernanceEvent(**json.loads(body))
            if event.digest() != digest or event.tenant_id != tenant_id:
                raise PersistenceError("a stored governance event does not match its digest")
            out.append(event)
        return tuple(out)

    def unresolved(self, scope: str) -> str | None:
        with self._session() as conn, conn.transaction():
            row = conn.execute("SELECT o.attempt FROM regulated_governance_fences_v1 o WHERE o.scope = %s"
                               " AND o.phase = 'open' AND NOT EXISTS (SELECT 1 FROM regulated_governance_fences_v1 c"
                               " WHERE c.attempt = o.attempt AND c.phase = 'closed') LIMIT 1", (scope,)).fetchone()
        return None if row is None else str(row[0])


class PostgresRevocationLedger:
    """The tenant revocation epoch as append-only events, linearised per tenant by a transaction advisory lock.

    Every host and every restart reads one epoch, so a revocation reaches outstanding permits wherever they are
    held. Rows are never updated or deleted (triggers refuse it); the epoch is the number of revocations."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def epoch(self, tenant_id: str) -> int:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            found = conn.execute("SELECT COALESCE(MAX(epoch), 0) FROM regulated_revocation_events_v1"
                                 " WHERE tenant = %s", (tenant_id,)).fetchone()[0]
        return int(found)

    def revoke(self, tenant_id: str, *, actor: str, reason: str, now_us: int) -> Revocation:
        if not tenant_id.strip() or not actor.strip() or not reason.strip():
            raise RevocationError("a revocation names its tenant, the revoking actor and the reason")
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         ("regulated-revocation:" + tenant_id,))
            current = int(conn.execute("SELECT COALESCE(MAX(epoch), 0) FROM regulated_revocation_events_v1"
                                       " WHERE tenant = %s", (tenant_id,)).fetchone()[0])
            conn.execute("INSERT INTO regulated_revocation_events_v1 (tenant, epoch, actor, reason, revoked_at_us)"
                         " VALUES (%s, %s, %s, %s, %s)", (tenant_id, current + 1, actor, reason, now_us))
        return Revocation(tenant_id, current + 1, actor, reason, now_us)
