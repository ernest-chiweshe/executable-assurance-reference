"""Clinical finalisation through the door (C4): docs/ARCHITECTURE-OF-RECORD/09-clinical-finalisation.md.

A clinician signing a document is a request to FINALISE exactly one version of it. This component runs that
request through the clinical-writing pack's gate, the same door every regulated release passes:

1. **Freeze.** The document's exact version is recorded as a pending finalisation and saved before any authority
   is sought; while pending, the workspace refuses every edit (`Document.is_frozen`).
2. **Render once.** The final record is rendered once, carrying the verified clinician's name and the signing
   time it will bear, and retained content-addressed per tenant. The docx export is not byte-deterministic, so
   these retained bytes, never a later render, are what is approved and committed.
3. **Approve.** The governed contract names the session, document and version, the retained digest, the
   finalised-record target and its prior state, and the mission for this version. The clinician's approval is
   verified against their live workspace membership at that instant.
4. **Decide and commit.** The pack gate runs the four host checks against the frozen version, decides, issues a
   permit, and the target adapter writes the retained bytes once into the tenant's finalised-record store.
5. **Settle from the receipt.** Only a COMMITTED outcome makes the document SIGNED, with exactly the rendered name
   and time. FAILED releases the document with the reason. UNKNOWN stays frozen until `resolve` reads the
   target's receipt; nothing ever signs again to find out.

There is no fallback: a workspace without this component composed cannot sign (see `factory/health_ui/app.py`).
Finalisation grants no send, print or external delivery.
"""
from __future__ import annotations

import copy
import secrets
from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from factory.health_ui import documents as doc_mod
from factory.health_ui import export as export_mod
from factory.health_ui.identity import ClinicianIdentity
from factory.health_ui.session_release import SESSION_FIELD, SESSION_SCHEMA
from factory.health_ui.store import SessionStore, StaleSession
from factory.ledger import ArtifactStore
from factory.projectos.governed_release import GovernedContract, PreparedArtifact, ReleaseTarget
from regulated_core.target import ABSENT
from factory.projectos.regulated import EmissionContext, RegulatedEmissionGate, ReleaseOutcome
from factory.projectos.spec import VerticalSpec
from factory.tenant import TenantContext
from regulated_core.approval import ApprovalError
from regulated_core.identity_provider import CredentialError, IdentityProviderUnavailable, LicenceRegistryUnavailable
from regulated_core.models import Actor

CLINICIAN_ROLE = "clinician"
_REFUSALS = (ApprovalError, CredentialError, ValueError)
_UNAVAILABLE = (IdentityProviderUnavailable, LicenceRegistryUnavailable)
#: Opens the recorded detail of a finalisation refused because a credential service could not be reached.
CREDENTIAL_SERVICE_UNAVAILABLE = "credential service unavailable"


class ClinicalGate(RegulatedEmissionGate, Protocol):
    """The release gate, plus the direct approval request a clinician's own finalisation uses."""

    def request_approval(self, contract: dict[str, Any], context: EmissionContext,
                         approvers: tuple[Actor, ...]) -> Any: ...


class FinalisationRefused(ValueError):
    """The document cannot be finalised now; nothing was approved or written."""


def owner_of(context: EmissionContext) -> str:
    """The health store owner an authenticated release context may read: the clinician in that workspace."""
    return f"{context.tenant}:{context.actor_id}" if context.tenant and context.actor_id else ""


def record_path(root: Path, workspace_id: str, record: doc_mod.Finalisation) -> Path:
    """Where one finalised record lives: its workspace, then the digest of its own signed render. Unique per document
    and attempt, because the render carries the document's title, subject, signer and signing time."""
    return root / workspace_id / f"{record.artifact_sha256}.docx"


class ClinicalRecords:
    """Read-only access to one workspace's finalised clinical records, with no signing authority at all.

    A signed record must stay readable to its clinician even while signing is paused or off: reading needs only the
    records store and the committed finalisation's digest, never the gate."""

    def __init__(self, finalised_root: Path, workspace_id: str) -> None:
        if not workspace_id:
            raise ValueError("clinical records are read per workspace")
        self._root, self._workspace = finalised_root, workspace_id

    def committed_bytes(self, document: doc_mod.Document) -> bytes:
        """The finalised record's bytes as committed, checked against the finalisation; never a re-render."""
        record = document.finalisation
        if document.status != doc_mod.SIGNED or record is None or record.state != doc_mod.FINALISATION_COMMITTED:
            raise FinalisationRefused("this document has no committed final record")
        try:
            content = record_path(self._root, self._workspace, record).read_bytes()
        except OSError as missing:
            raise FinalisationRefused("the finalised record cannot be read from its store") from missing
        if sha256(content).hexdigest() != record.artifact_sha256:
            raise FinalisationRefused("the finalised record no longer holds the committed bytes")
        return content


class ClinicalFinalisation:
    """Finalises clinical documents through the clinical-writing pack's gate, for one workspace."""

    def __init__(self, *, gate: ClinicalGate, spec: VerticalSpec, store: SessionStore,
                 artifacts: ArtifactStore, finalised_root: Path, workspace_id: str,
                 now_us: Callable[[], int], clock_utc: Callable[[], str],
                 nonce: Callable[[], str] = lambda: secrets.token_hex(16),
                 authorisation_window_us: int = 3_600_000_000) -> None:
        if spec.regulated is None or not workspace_id:
            raise ValueError("clinical finalisation needs the regulated clinical spec and its workspace")
        self._gate, self._spec, self._store, self._artifacts = gate, spec, store, artifacts
        self._root, self._workspace = finalised_root, workspace_id
        self._now_us, self._clock_utc, self._nonce = now_us, clock_utc, nonce
        # The longest an attempt's authority can live (the gate's permit lifetime). Past it, nothing issued for the
        # attempt can still commit, so the target's receipts are its final answer.
        self._window_us = authorisation_window_us

    # ── the request ──

    def finalise(self, session: doc_mod.Session, document: doc_mod.Document,
                 clinician: ClinicianIdentity) -> doc_mod.Finalisation:
        """Finalise this exact version, or refuse; returns how the attempt settled."""
        if clinician.workspace_id != self._workspace or session.owner_id != clinician.owner_id:
            raise FinalisationRefused("only the document's own clinician, in this workspace, can finalise it")
        if document.is_frozen:
            raise FinalisationRefused("this document is already signed or being finalised")
        version = document.digest()
        signed_utc = self._clock_utc()
        content = export_mod.docx_bytes(self._as_signed(document, clinician.display_name, signed_utc, version))
        # A signed record is created once and never replaced (pre-release audit, 2026-09-28: two documents with the same
        # clinician text once shared an address and the second signing replaced the first patient's record). The
        # address is the signed render's own digest, and an address already taken refuses before anything is frozen;
        # the target is then written in create mode, which fails on anything present.
        if (self._root / self._workspace / f"{sha256(content).hexdigest()}.docx").exists():
            raise FinalisationRefused("a finalised record already holds this address; nothing is replaced")
        address = self._artifacts.put(self._tenant, content)
        record = doc_mod.Finalisation(
            state=doc_mod.FINALISATION_PENDING, document_digest=version, artifact_address=address,
            artifact_sha256=sha256(content).hexdigest(), signer=clinician.display_name, signed_utc=signed_utc,
            nonce=self._nonce(), started_us=self._now_us())
        document.finalisation = record
        self._store.save(session)                       # frozen before any authority is sought
        context = self._context(session, document, clinician, record)
        contract = self._contract(session, document, record, content, context, clinician)
        try:
            certificate = self._gate.request_approval(
                contract, context, (Actor(clinician.user_id, self._workspace, frozenset({CLINICIAN_ROLE})),))
            approved = replace(context, approval=certificate)
            decision = self._gate.authorize_release(spec=self._spec, contract=contract, out_path=self._target(record),
                                                    context=approved, artifact=content)
        except _REFUSALS as refused:
            return self._settle(session, document, ReleaseOutcome("failed", str(refused)))
        except _UNAVAILABLE as down:
            # Fail closed, explicitly and on the record (source review 3054): no approval without a verified credential,
            # and no fallback to a weaker source. The document returns to draft; signing again is safe.
            return self._settle(session, document, ReleaseOutcome(
                "failed", f"{CREDENTIAL_SERVICE_UNAVAILABLE}: {down}; nothing was approved or written"))
        if not decision.allowed:
            return self._settle(session, document, ReleaseOutcome("failed", decision.reason))
        # The effect is judged at the time it actually happens, on the host's trusted clock, never at the time the
        # request began: a worker delayed past the permit's expiry is refused at the target (source review 3028).
        outcome = self._gate.commit_release(spec=self._spec, contract=contract, decision=decision, artifact=content,
                                            out_path=self._target(record),
                                            context=replace(approved, now_us=self._now_us()))
        return self._settle(session, document, outcome)

    def resolve(self, session: doc_mod.Session, document: doc_mod.Document,
                clinician: ClinicianIdentity) -> doc_mod.Finalisation:
        """Settle a finalisation from the target's receipt, never by finalising again.

        An UNKNOWN outcome can be resolved at any time. A PENDING one, left by a process that stopped between
        freezing and settling (source review 3017), is resolved only after its authorisation window, when no permit issued
        for it can still commit; until then the attempt may yet complete, and the receipt is not final."""
        record = document.finalisation
        if record is None or record.state not in (doc_mod.FINALISATION_UNKNOWN, doc_mod.FINALISATION_PENDING):
            raise FinalisationRefused("there is no unsettled finalisation to resolve")
        if (record.state == doc_mod.FINALISATION_PENDING
                and self._now_us() - record.started_us < self._window_us):
            raise FinalisationRefused("this finalisation is still within its authorisation window and may yet "
                                      "complete; resolve it after the window closes")
        if session.owner_id != clinician.owner_id:
            raise FinalisationRefused("only the document's own clinician can resolve its finalisation")
        found = self._gate.reconcile_release(spec=self._spec, artifact_sha256=record.artifact_sha256,
                                             out_path=self._target(record),
                                             context=self._context(session, document, clinician, record),
                                             nonce=record.nonce)
        if found.state == "committed" and found.evidence.get("target_holds") is not True:
            found = ReleaseOutcome("unknown", "committed earlier, but the record no longer holds the final bytes")
        return self._settle(session, document, found)

    def committed_bytes(self, document: doc_mod.Document) -> bytes:
        """The finalised record's bytes as committed, checked against the finalisation; never a re-render."""
        return ClinicalRecords(self._root, self._workspace).committed_bytes(document)

    # ── composition ──

    @property
    def _tenant(self) -> TenantContext:
        return TenantContext(tenant_id=self._workspace, display_name=self._workspace)

    def _target(self, record: doc_mod.Finalisation) -> str:
        """One file per finalised record, addressed by its own signed render, in the workspace's record store."""
        return str(record_path(self._root, self._workspace, record))

    def _context(self, session: doc_mod.Session, document: doc_mod.Document, clinician: ClinicianIdentity,
                 record: doc_mod.Finalisation) -> EmissionContext:
        # Every permit issued for this attempt expires by its recovery deadline, so recovery after the deadline can
        # never race a delayed worker still holding usable authority (source review 3028).
        return EmissionContext(tenant=self._workspace, actor_id=clinician.user_id, now_us=self._now_us(),
                               nonce=record.nonce, action_id=f"finalise:{record.document_digest}",
                               project_id=f"{session.session_id}:{document.doc_id}",
                               vertical_name=self._spec.name, release_target=self._target(record),
                               not_after_us=record.started_us + self._window_us)

    def _contract(self, session: doc_mod.Session, document: doc_mod.Document, record: doc_mod.Finalisation,
                  content: bytes, context: EmissionContext, clinician: ClinicianIdentity) -> dict[str, Any]:
        base = {
            SESSION_FIELD: {"schema": SESSION_SCHEMA, "user_id": clinician.user_id,
                            "username": clinician.username, "workspace_id": clinician.workspace_id,
                            "reference": clinician.session_reference, "expires_at": clinician.session_expires_at},
            "body": "\n".join(p.text for s in document.sections for p in s.paragraphs),
            "session_id": session.session_id, "doc_id": document.doc_id, "document_digest": record.document_digest,
            "payload_ref": f"health://{self._workspace}/{session.session_id}/{document.doc_id}",
            "provenance": {"run_id": f"clinical:{session.session_id}:{document.doc_id}",
                           "model_id": "clinician-authored"},
        }
        prepared = PreparedArtifact({"schema": "health.final-record/v1", "artifact_address": record.artifact_address,
                                     "artifact_sha256": record.artifact_sha256,
                                     "document_digest": record.document_digest, "signer": record.signer,
                                     "signed_utc": record.signed_utc}, content)
        target = ReleaseTarget.from_description(
            self._gate.describe_target(spec=self._spec, out_path=self._target(record), context=context))
        if target.expected_state != ABSENT:
            # Create-only: the permit binds an absent prior state, so the target adapter creates and never replaces.
            raise FinalisationRefused("a finalised record already holds this address; nothing is replaced")
        mission = f"clinical-writing:{session.session_id}:{document.doc_id}@{record.document_digest}"
        return GovernedContract(base, prepared, target, mission=mission).for_approval()

    @staticmethod
    def _as_signed(document: doc_mod.Document, signer: str, signed_utc: str, version: str) -> doc_mod.Document:
        """The document exactly as it will stand once finalisation commits, for the one render."""
        final = copy.deepcopy(document)
        final.status, final.signed_by, final.signed_utc = doc_mod.SIGNED, signer, signed_utc
        final.frozen_digest = version
        final.frozen_export_digest_version = 3
        final.frozen_export_digest = final.export_digest(3)
        return final

    def _settle(self, session: doc_mod.Session, document: doc_mod.Document,
                outcome: ReleaseOutcome) -> doc_mod.Finalisation:
        """Record how the attempt ended, against the stored session as it is NOW: re-read, apply, compare-and-set,
        so an unrelated change to the consultation meanwhile is kept, never overwritten. Only a committed outcome
        signs the document, exactly as it was rendered."""
        record = document.finalisation
        assert record is not None
        state = {"committed": doc_mod.FINALISATION_COMMITTED, "failed": doc_mod.FINALISATION_FAILED,
                 "not_committed": doc_mod.FINALISATION_FAILED}.get(outcome.state, doc_mod.FINALISATION_UNKNOWN)
        for _attempt in range(8):
            current = self._store.get(session.session_id, session.owner_id)
            stored = current.document(document.doc_id) if current is not None else None
            if current is None or stored is None or stored.finalisation is None                     or stored.finalisation.nonce != record.nonce:
                raise FinalisationRefused("the attempt being settled is no longer the document's finalisation")
            stored.finalisation = replace(stored.finalisation, state=state, detail=outcome.detail)
            if state == doc_mod.FINALISATION_COMMITTED:
                signed = self._as_signed(stored, record.signer, record.signed_utc, record.document_digest)
                stored.status, stored.signed_by, stored.signed_utc = signed.status, signed.signed_by, signed.signed_utc
                stored.frozen_digest = signed.frozen_digest
                stored.frozen_export_digest_version = signed.frozen_export_digest_version
                stored.frozen_export_digest = signed.frozen_export_digest
                stored.snapshot(f"finalised by {record.signer}")
            try:
                self._store.save(current)
            except StaleSession:
                continue
            document.finalisation = stored.finalisation
            return stored.finalisation
        raise FinalisationRefused("the consultation kept changing; the outcome is recorded by the target's receipt "
                                  "and can be settled with resolve")
