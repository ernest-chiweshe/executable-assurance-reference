"""Retained supervisor reviews loaded under the receiving transaction's locks."""
from collections.abc import Mapping
from dataclasses import dataclass
import json

from assurance_reference.clock_floor import DurableClock
from assurance_reference.roster_authority import RosterAuthorityVerifier
from regulated_core.approval import ApprovalCertificate, ApprovedDecision, ApprovalWorkflow
from regulated_core.canonical import canonical_bytes
from regulated_core.identity_provider import CredentialReceipt
from regulated_core.persistence_pg import (
    PersistenceError, PostgresDecisionRecorder, PostgresRosterStore, decode_envelope,
)
from regulated_core.review_store import PostgresReviewStore
from regulated_core.signing import Signature

from assurance_reference.epoch_withdrawal_admission import checked_change, verify_supervisor_approval

SCHEMA = "reference/epoch-withdrawal-review/v1"


def encode_review(tenant_id, change, approved):
    """Serialize original signatures; serialization does not authorize a review."""
    if not isinstance(approved, ApprovedDecision):
        raise PersistenceError("withdrawal review requires an approved decision")
    return json.loads(canonical_bytes({
        "schema": SCHEMA, "change": checked_change(tenant_id, change), "approved": approved,
    }))


def decode_review(tenant_id, value):
    """Decode only the pinned data types, preserving canonical signed bytes."""
    try:
        if not isinstance(value, Mapping) or set(value) != {"schema", "change", "approved"}:
            raise ValueError("withdrawal review fields differ")
        if value["schema"] != SCHEMA:
            raise ValueError("unsupported withdrawal review schema")
        change = checked_change(tenant_id, value["change"])
        body = value["approved"]
        if not isinstance(body, Mapping) or set(body) != {"certificate", "envelope", "credential_receipts"}:
            raise ValueError("approved decision fields differ")
        certificate = dict(body["certificate"])
        signature = Signature(**certificate.pop("signature"))
        certificate["approver_ids"] = tuple(certificate["approver_ids"])
        certificate["credential_receipt_digests"] = tuple(certificate["credential_receipt_digests"])
        certificate = ApprovalCertificate(signature=signature, **certificate)
        if not isinstance(body["credential_receipts"], list):
            raise ValueError("review receipts must be a list")
        receipts = []
        for receipt in body["credential_receipts"]:
            fields = dict(receipt)
            seal = Signature(**fields.pop("signature"))
            receipts.append(CredentialReceipt(signature=seal, **fields))
        approved = ApprovedDecision(certificate, decode_envelope(body["envelope"]), tuple(receipts))
        if canonical_bytes(encode_review(tenant_id, change, approved)) != canonical_bytes(value):
            raise ValueError("withdrawal review is not canonical core data")
        return change, approved
    except (TypeError, ValueError, KeyError) as error:
        raise PersistenceError("invalid stored withdrawal review") from error


@dataclass(frozen=True)
class _LockedRosterObservation:
    installation: str
    roster: object

    def current(self, installation):
        if installation != self.installation:
            raise PersistenceError("withdrawal roster installation differs")
        return self.roster


@dataclass(frozen=True)
class AdmittedWithdrawalReview:
    approved: ApprovedDecision
    supervisor_ids: tuple[str, ...]
    roster_digest: str
    at_us: int


class EpochWithdrawalReviewLoader:
    """Host-configured stores and authority; construction performs no I/O.

    Lock order is roster then review. A caller must acquire these before its
    epoch and budget locks, and call load_on again after all blocking work.
    Holding the transaction preserves both locks through the epoch write.
    """
    def __init__(self, *, reviews, roster, installation, workflow, recorder, clock):
        if (not isinstance(reviews, PostgresReviewStore)
                or not isinstance(roster, PostgresRosterStore)
                or not isinstance(workflow, ApprovalWorkflow) or not workflow.requires_credentials
                or not isinstance(recorder, PostgresDecisionRecorder)
                or not isinstance(clock, DurableClock)
                or recorder.clock is not clock):
            raise TypeError("withdrawal loader requires durable configured stores and shared trusted clock")
        verifier = roster._proof_verifier
        if not isinstance(verifier, RosterAuthorityVerifier) or verifier.installation != installation:
            raise TypeError("withdrawal loader requires matching persisted roster authority")
        self.reviews, self.roster, self.installation = reviews, roster, installation
        self.workflow, self.recorder, self.clock = workflow, recorder, clock

    def load_on(self, connection, *, tenant_id, review_id, change, requester_id):
        """Authenticate the exact stored approval after owned shared locks.

        Caller tenant scope and READ COMMITTED are checked before any lock.
        The store's pool is deliberately not borrowed: all reads use the
        receiving connection, which must have explicit access to both stores.
        """
        from psycopg.pq import TransactionStatus
        if connection.info.transaction_status != TransactionStatus.INTRANS:
            raise PersistenceError("withdrawal review requires an active receiving transaction")
        if tenant_id != self.roster._proof_verifier.tenant:
            raise PersistenceError("withdrawal tenant differs from configured roster authority")
        scope, isolation = connection.execute(
            "SELECT current_setting('app.tenant',true),current_setting('transaction_isolation')"
        ).fetchone()
        if scope != tenant_id or isolation != "read committed":
            raise PersistenceError("withdrawal review requires matching READ COMMITTED tenant")
        connection.execute("SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))",
                           ("regulated-governance-roster:" + self.installation,))
        raw = PostgresReviewStore.read_locked_on(connection, tenant_id, review_id)
        if raw is None:
            raise PersistenceError("withdrawal approval review is absent")
        stored_change, approved = decode_review(tenant_id, raw)
        if (stored_change != checked_change(tenant_id, change)
                or approved.certificate.request_id != review_id):
            raise PersistenceError("withdrawal retained review differs from exact request")
        history = self.roster._verified_history(connection, self.installation)
        if not history:
            raise PersistenceError("withdrawal requires a verified persisted roster")
        roster = history[-1][0]
        # A local view of verified rows held stable by the shared roster lock.
        observation = _LockedRosterObservation(self.installation, roster)
        reading = self.clock.read_on(connection)
        supervisors = verify_supervisor_approval(approved, workflow=self.workflow,
            recorder=self.recorder, roster_store=observation, installation=self.installation,
            tenant_id=tenant_id, change=stored_change, requester_id=requester_id,
            now_us=reading.now_us)
        return AdmittedWithdrawalReview(approved, supervisors, roster.digest(), reading.now_us)
