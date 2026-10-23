"""The Project OS choreography engine: runs ANY vertical's stage graph, and owns no truth.

Given a `VerticalSpec` (the declaration) and a few injected seams (a runner that executes a stage, a contract
builder, an exporter), the engine provides the universal choreography both the book and the course pipelines
hand-rolled: per-project state, stage execution with declarative input chaining, item iteration, hand-edit,
assemble, and export. It coordinates; it decides nothing about truth.

The boundary it must keep (pinned by `tests/test_projectos_conformance.py`, Project OS T1-T5):
  - it imports no renderer and never renders (export is an injected seam);
  - it never writes knowledge or sets a confidence (a knowledge-backed stage's runner does the gated write);
  - a stage record's `accepted` is COPIED from the runner's `StageOutcome`, never authored here;
  - every stage executes through the injected runner; the engine bypasses no gate.
"""
from __future__ import annotations

from copy import deepcopy

import json
import ntpath
import os
import tempfile
import time
from hashlib import sha256
from dataclasses import replace
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from factory.projectos.spec import (
    KIND_ASSEMBLE,
    SCOPE_ITEM,
    Runner,
    StageOutcome,
    StageRun,
    StageSpec,
    VerticalSpec,
)
from factory.ledger import ArtifactStore, FileArtifactStore
from factory.projectos.errors import ProjectEngineError as ProjectEngineError  # re-exported: callers import it here
from factory.projectos.governed_release import GovernedRelease
from factory.projectos.regulated import (
    EmissionContext, ReceiptPinSource, RegulatedEmissionGate, ReleaseAuthoritySource, ReleaseObservation,
    ReleaseOutcome,
)
from factory.runtime import resolve_tenant
from factory.tenant import SELF

# The synthetic stage used to drive the readiness gate at assemble time, so assembling goes through the SAME
# runner as every other stage (the runner dispatches on kind == "assemble" to the vertical's readiness gate).
_ASSEMBLE_STAGE = StageSpec(id="assemble", title="Assemble", kind=KIND_ASSEMBLE)

# The revision prompt for `ProjectEngine.revise`. Generic by design: it revises the ARTIFACT against the
# editor's comment, so one prompt serves every vertical and no per-stage template is touched. The comment is
# quarantined by the caller (untrusted input); this only asks the model to apply it and return the artifact.
_REVISE_PROMPT = (
    "You are revising an existing artifact based on an editor's comment. Apply the comment faithfully and "
    "return ONLY the revised artifact, in the same format, structure, and voice as the original. Do not add "
    "any commentary, preamble, or explanation.\n\n"
    "EDITOR'S COMMENT:\n{feedback}\n\n"
    "CURRENT ARTIFACT:\n{previous}\n"
)




class ProjectStateStore(Protocol):
    """Durable authority for Project OS choreography state only.

    Vertical-owned source media, exports, settings, and other workspace files
    are deliberately outside this port; their surfaces must select their own
    durable blob/data stores before a task can be treated as replaceable.
    """

    def create(self, project_id: str, state: dict[str, Any]) -> None: ...

    def load(self, project_id: str) -> dict[str, Any]: ...

    def save(self, project_id: str, state: dict[str, Any]) -> None: ...

    def list_projects(self) -> list[str]: ...

    def delete(self, project_id: str) -> None: ...


class FileProjectStateStore:
    """The existing local/EC2 project.json authority."""

    def __init__(self, root: str) -> None:
        self._root = root

    def create(self, project_id: str, state: dict[str, Any]) -> None:
        directory = self._dir(project_id)
        if os.path.exists(directory):
            raise ProjectEngineError(f"project {project_id!r} already exists")
        os.makedirs(directory)
        self._write(project_id, state)

    def load(self, project_id: str) -> dict[str, Any]:
        path = self._path(project_id)
        if not os.path.isfile(path):
            raise ProjectEngineError(f"no project {project_id!r}")
        with open(path, encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
        return data

    def save(self, project_id: str, state: dict[str, Any]) -> None:
        if not os.path.isfile(self._path(project_id)):
            raise ProjectEngineError(f"no project {project_id!r}")
        self._write(project_id, state)

    def list_projects(self) -> list[str]:
        if not os.path.isdir(self._root):
            return []
        out: list[tuple[float, str]] = []
        for project_id in os.listdir(self._root):
            if not os.path.isfile(self._path(project_id)):
                continue
            try:
                out.append((float(self.load(project_id).get("created", 0.0)), project_id))
            except (ProjectEngineError, TypeError, ValueError):
                continue
        return [project_id for _created, project_id in sorted(out, reverse=True)]

    def delete(self, project_id: str) -> None:
        import shutil

        if not os.path.isfile(self._path(project_id)):
            raise ProjectEngineError(f"no project {project_id!r}")
        shutil.rmtree(self._dir(project_id), ignore_errors=True)

    def _write(self, project_id: str, state: dict[str, Any]) -> None:
        directory = self._dir(project_id)
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".project-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, self._path(project_id))
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _path(self, project_id: str) -> str:
        return os.path.join(self._dir(project_id), "project.json")

    def _dir(self, project_id: str) -> str:
        _validate_project_id(project_id)
        return os.path.join(self._root, project_id)


def build_project_state_store(
    root: str,
    namespace: str,
    *,
    env: Mapping[str, str] = os.environ,
    pool: Any = None,
) -> ProjectStateStore:
    """Select PostgreSQL only through the explicit managed authority flag."""
    mode = env.get("FACTORY_PROJECTOS", "file").strip().casefold() or "file"
    if mode == "file":
        return FileProjectStateStore(root)
    if mode != "pg":
        raise RuntimeError("FACTORY_PROJECTOS must be file or pg")
    dsn = env.get("FACTORY_DB_URL", "").strip()
    if not dsn:
        raise RuntimeError("FACTORY_PROJECTOS=pg requires FACTORY_DB_URL")
    schema_mode = env.get(
        "FACTORY_PROJECTOS_SCHEMA_MODE",
        env.get("FACTORY_PRODUCT_SCHEMA_MODE", "bootstrap-on-start"),
    ).strip()
    if schema_mode not in {"bootstrap-on-start", "external-migration-task"}:
        raise RuntimeError(
            "FACTORY_PROJECTOS_SCHEMA_MODE must be bootstrap-on-start or "
            "external-migration-task"
        )
    from factory.projectos.pg_store import PostgresProjectStateStore

    return PostgresProjectStateStore(
        dsn,
        namespace=namespace,
        tenant_id=(
            env.get("FACTORY_PROJECTOS_TENANT_ID", "").strip()
            or resolve_tenant(SELF).tenant_id
        ),
        ensure_schema=schema_mode == "bootstrap-on-start",
        pool=pool,
    )


class ProjectEngine:
    """Run one vertical's projects. Construct with the `VerticalSpec` and the seams it needs."""

    def __init__(
        self,
        spec: VerticalSpec,
        *,
        runner: Runner,
        contract_builder: Callable[[dict[str, Any], bool], dict[str, Any]] | None = None,
        exporter: Callable[[dict[str, Any], str], str] | None = None,
        emission_gate: RegulatedEmissionGate | None = None,
        receipt_pins: ReceiptPinSource | None = None,
        root: str | None = None,
        clock: Callable[[], float] = time.time,
        state_store: ProjectStateStore | None = None,
        env: Mapping[str, str] = os.environ,
        store_pool: Any = None,
        artifact_store: ArtifactStore | None = None,
        release_authority: ReleaseAuthoritySource | None = None,
        regulated_scope: Callable[[str, str], None] | None = None,
    ) -> None:
        self._spec = spec
        # Egress scope (docs/ARCHITECTURE-OF-RECORD/14): the host's enrolment of this tenant into regulated scope,
        # called with (pack reference, project id) BEFORE a regulated project's state exists. A plain callable, so
        # the engine stays independent of the authority plane.
        self._regulated_scope = regulated_scope
        self._runner = runner                  # executes a stage and returns its gate verdict; never bypassed
        self._build_contract = contract_builder  # builds the gate-checkable "X as Code" from state
        self._exporter = exporter              # projects the contract to an asset; the engine renders nothing
        self._emission_gate = emission_gate    # authority-plane gate for REGULATED verticals (else unused)
        self._receipt_pins = receipt_pins
        self._release_authority = release_authority
        self._root = root or os.path.join(os.getcwd(), ".factory", spec.state_dir)
        self._clock = clock
        # Prepared release artifacts are content-addressed and tenant-scoped, and every read re-verifies them.
        # The composition root may inject an object-store implementation; the core default is on local disk.
        self._artifact_store = artifact_store
        self._state_store = (
            state_store
            if state_store is not None
            else build_project_state_store(
                self._root, spec.state_dir, env=env, pool=store_pool
            )
        )

    # --- lifecycle ---------------------------------------------------------------

    def new(self, project_id: str, **fields: Any) -> dict[str, Any]:
        """Create a project and persist its starting state. `fields` are the vertical's own top-level values
        (topic, audience, domain, ...), referenced by `field:` bindings."""
        _validate_project_id(project_id)
        state: dict[str, Any] = {self._spec.id_field: project_id, **fields,
                                 "stages": {}, "items": {}, "created": self._clock()}
        self._enrol_regulated_scope(project_id)
        self._state_store.create(project_id, state)
        return state

    def get(self, project_id: str) -> dict[str, Any]:
        """The project's stored state (a free read)."""
        return self._load(project_id)

    def set_field(self, project_id: str, **fields: Any) -> dict[str, Any]:
        """Merge top-level fields into a project's state and persist (e.g. a `media_path` set after an
        upload). This is project METADATA the operator owns, not a stage output or a gate verdict, so it does
        not touch the `stages`/`items` records or author any acceptance (Project OS T3). Returns the new
        state."""
        state = self._load(project_id)
        state.update(fields)
        self._save(project_id, state)
        return state

    def replace_inputs(self, project_id: str, **fields: Any) -> dict[str, Any]:
        """Replace a declared complete source and retire its derived analysis atomically.

        Ordinary metadata still uses set_field. Only opted-in, non-regulated
        single-source verticals use this operation. Keep previous source fields,
        stage output bytes and verdicts as historical evidence, not current work.
        The same store's revision check prevents an older in-flight stage from
        saving over the replacement. No automatic conflict retry is performed.
        """
        reserved = {self._spec.id_field, "id", "created", "stages", "items", "approved",
                    "assembled", "invalidated_assemblies", "input_revisions", "output_objects"}
        declared = set(self._spec.source_fields)
        if (self._spec.regulated is not None or not declared or declared & reserved
                or set(fields) != declared):
            raise ProjectEngineError("replace_inputs requires every declared source field and no state/authority fields on an opted-in ordinary vertical")
        state = self._load(project_id)
        prior_fields = {key: deepcopy(state[key]) for key in fields if key in state}
        if any(prior_fields.values()) or state.get("stages") or state.get("items"):
            state.setdefault("input_revisions", []).append({
                "fields": prior_fields, "stages": deepcopy(state.get("stages", {})),
                "items": deepcopy(state.get("items", {})), "replaced_at": self._clock(),
            })
        self._invalidate_assembly(state, {"reason": "source-replaced"})
        state.update(fields)
        state["stages"] = {}
        state["items"] = {}
        self._save(project_id, state)
        return state

    def new_from_state(self, project_id: str, state: dict[str, Any]) -> dict[str, Any]:
        """Create a project from a PREBUILT state (the document-import path, where the chapters and their
        synthetic draft results are derived from an uploaded file rather than generated stage by stage). The
        caller assembles the full state (including the id field, `stages`, and `items`); the engine validates
        the id and persists it, refusing to overwrite an existing project."""
        _validate_project_id(project_id)
        self._enrol_regulated_scope(project_id)
        self._state_store.create(project_id, state)
        return state

    def _enrol_regulated_scope(self, project_id: str) -> None:
        """A regulated project's tenant is enrolled in regulated scope before its content can exist. A failed
        enrolment refuses the creation: governed content never lands in a tenant its egress scope does not know."""
        regulated = self._spec.regulated
        if regulated is None or self._regulated_scope is None:
            return
        pack_ref = regulated.pack_version or ("policy:" + regulated.policy_ref)
        try:
            self._regulated_scope(pack_ref, project_id)
        except Exception as exc:  # noqa: BLE001 - whatever failed, the project must not be created unenrolled
            raise ProjectEngineError(
                "the tenant's regulated scope could not be recorded; the project was not created") from exc

    def preview_inputs(self, project_id: str, stage_id: str, *,
                       item_id: str | None = None) -> dict[str, str] | None:
        """Resolve the inputs a stage WOULD run with, WITHOUT running it (a free read for a driving surface
        that prefills a stage's form). Returns None when a prerequisite is not yet met (so the UI shows the
        stage as not-yet-runnable instead of erroring), or when an item-scoped stage has no item id."""
        stage = self._stage(stage_id)
        state = self._load(project_id)
        item: dict[str, Any] | None = None
        if stage.scope == SCOPE_ITEM:
            if item_id is None:
                return None
            try:
                item = self._find_item(state, item_id)
            except ProjectEngineError:
                return None
        try:
            return self._resolve_inputs(state, stage, item_id, item)
        except ProjectEngineError:
            return None

    def list_projects(self) -> list[str]:
        """The ids of every project of this vertical, newest first."""
        return self._state_store.list_projects()

    def delete(self, project_id: str) -> None:
        """Remove a project and all its state. Raises when absent, so a caller can 404 honestly."""
        _validate_project_id(project_id)
        self._state_store.delete(project_id)

    def items(self, project_id: str) -> list[dict[str, Any]]:
        """The item-scoped work units (chapters/lessons), enumerated from state by the vertical."""
        return self._spec.item_enumerator(self._load(project_id))

    # --- the core: run a stage ---------------------------------------------------

    def run_stage(self, project_id: str, stage_id: str, *, tenant: Any, item_id: str | None = None,
                  overrides: dict[str, str] | None = None,
                  options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one stage: resolve its inputs from the declarative bindings, apply any operator `overrides`,
        execute it through the injected runner, and RECORD the verdict the runner returns (the engine authors
        none of it). For an item-scoped stage, `item_id` selects the chapter/lesson. `options` carries per-run
        knobs the engine does not interpret (a model tier, say); they ride the `StageRun` to the runner. A
        runner's `StageOutcome.extra` is written through to the record verbatim."""
        stage = self._stage(stage_id)
        state = self._load(project_id)
        item: dict[str, Any] | None = None
        if stage.scope == SCOPE_ITEM:
            if item_id is None:
                raise ProjectEngineError(f"stage {stage_id!r} is item-scoped; pass an item_id")
            item = self._find_item(state, item_id)

        params = self._resolve_inputs(state, stage, item_id, item)
        if overrides:
            params.update({k: str(v) for k, v in overrides.items()})
        outcome = self._runner(StageRun(stage, params, item, tenant, options or {}))
        if not isinstance(outcome, StageOutcome):
            raise ProjectEngineError("a runner must return a StageOutcome")
        # Copy the verdict; never author acceptance here. The runner's extra fields are written through as-is
        # (a vertical's own surface reads them); the core verdict keys win on any collision.
        record = {**dict(outcome.extra), "output": outcome.output, "accepted": bool(outcome.accepted),
                  "reason": outcome.reason, "run_id": outcome.run_id, "at": self._clock(),
                  "inputs": params, "edited": False}
        self._store(state, stage, item_id, record)
        self._save(project_id, state)
        return record

    def set_output(self, project_id: str, stage_id: str, output: str, *,
                   item_id: str | None = None) -> dict[str, Any]:
        """Replace a stored stage output with a human-edited version before it feeds downstream. The operator's
        edit is recorded as such; the gate verdict on the prior run is kept (a hand-edit is the operator's
        authority)."""
        stage = self._stage(stage_id)
        state = self._load(project_id)
        # A hand-edit carries the OPERATOR's authority, not a gate verdict: when there is no prior run to
        # inherit a verdict from, the edited output is accepted on the operator's say-so. Built with dict()
        # rather than a JSON-style verdict literal precisely because this is operator authority, not the
        # engine authoring a gate decision (Project OS T3 forbids the latter, not this).
        prior = self._record(state, stage, item_id) or dict(accepted=True, reason="edited", run_id="", inputs={})
        record = {**prior, "output": output, "edited": True, "at": self._clock()}
        self._store(state, stage, item_id, record)
        self._save(project_id, state)
        return record

    def revise(self, project_id: str, stage_id: str, *, feedback: str, tenant: Any, provider: Any,
               item_id: str | None = None, harness: str = "") -> dict[str, Any]:
        """Revise a stage's stored output per an operator's COMMENT, the Project OS parallel of the studio's
        `iterate`: the comment is the instruction, the current output is what it revises, and the model returns
        a revised artifact that OVERWRITES the stage's output (a re-run is the latest truth). Operator-initiated,
        so the record is marked `edited`, but the model still runs through the gate and the verdict is kept
        honest. Requires the stage to have produced an output already (there is nothing to revise otherwise)
        and a `provider` (the Factory) to run the model. Universal: it revises the ARTIFACT, so it needs no
        per-vertical prompt and works for any stage's text output."""
        from factory.gate.guardrails import quarantine   # the untrusted-input boundary
        from factory.profile import ProjectProfile

        if not feedback.strip():
            raise ProjectEngineError("a revision needs a comment to act on")
        stage = self._stage(stage_id)
        state = self._load(project_id)
        if stage.scope == SCOPE_ITEM and item_id is None:
            raise ProjectEngineError(f"stage {stage_id!r} is item-scoped; pass an item_id")
        prior = self._record(state, stage, item_id)
        if not prior or not prior.get("output"):
            raise ProjectEngineError(f"stage {stage_id!r} has no output to revise; run it first")
        # The comment folds into a model prompt, so it rides inside quarantine() as untrusted data and the
        # input-guardrail check screens it, exactly like any other ingested text.
        task = _REVISE_PROMPT.format(feedback=quarantine(feedback.strip(), "EDITOR COMMENT"),
                                     previous=str(prior["output"]))
        profile = ProjectProfile("revise", gate_checks=frozenset({"input-guardrail"}),
                                 pinned_harness=harness or None)
        report = provider.run(task, profile, tenant)
        record = {
            **prior,
            "output": str(getattr(report, "output", "")),
            "accepted": bool(getattr(report, "accepted", False)),
            "reason": str(getattr(report, "gate_reason", "")) or "revised per comment",
            "run_id": str(getattr(report, "run_id", "")),
            "edited": True, "revised_from_comment": feedback.strip(),
            "cost_usd": float(getattr(report, "cost_usd", 0.0)),
            "harness": str(getattr(report, "harness_name", "") or harness or "auto"),
            "at": self._clock(),
        }
        self._store(state, stage, item_id, record)
        self._save(project_id, state)
        return record

    # --- assemble + export -------------------------------------------------------

    def assemble(self, project_id: str, *, tenant: Any, approve: bool = False,
                 context: EmissionContext | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
        """Build the contract artifact from state and run it through the readiness gate (the same injected
        runner, dispatched on the synthetic assemble stage). Records the verdict. Returns the contract and the
        verdict record.

        For a REGULATED vertical, the authority plane also reviews the DRAFT here (defense in depth): the
        content verifiers run at assemble time, so unsafe content is blocked before it becomes a governed
        draft, not only at release. Fail-closed if no gate/context is wired for a regulated vertical."""
        if self._build_contract is None:
            raise ProjectEngineError("no contract builder configured for this vertical")
        state = self._load(project_id)
        state["approved"] = bool(approve)
        contract = self._build_contract(state, bool(approve))
        outcome = self._runner(StageRun(_ASSEMBLE_STAGE, {"contract": json.dumps(contract)}, None, tenant, {}))
        record = {"accepted": bool(outcome.accepted), "reason": outcome.reason, "at": self._clock()}
        if self._spec.regulated is not None:
            if self._emission_gate is None:
                raise ProjectEngineError(f"regulated vertical {self._spec.name!r}: no emission gate wired (fail-closed)")
            if context is None:
                raise ProjectEngineError("regulated assemble requires a review context")
            context = self._review_production_context(project_id, contract, context, state=state)
            draft = self._emission_gate.review_draft(spec=self._spec, contract=contract, context=context)
            record["regulated_draft"] = {"allowed": bool(draft.allowed), "reason": draft.reason,
                                         "evidence": dict(draft.evidence)}
            if not draft.allowed:                     # unsafe content: the draft is not governed/acceptable
                record["accepted"] = False
                record["reason"] = f"regulated draft blocked: {draft.reason}"
        state["assembled"] = record
        self._save(project_id, state)
        return contract, record

    def contract(self, project_id: str) -> dict[str, Any]:
        """Rebuild the contract artifact from current state (a free read), reflecting the stored approval."""
        if self._build_contract is None:
            raise ProjectEngineError("no contract builder configured for this vertical")
        state = self._load(project_id)
        return self._build_contract(state, bool(state.get("approved", False)))

    def _review_production_context(self, project_id: str, contract: dict[str, Any],
                                   context: EmissionContext, *, state: dict[str, Any] | None = None) -> EmissionContext:
        """Bind a producing run only from a declared, accepted and unedited stage.

        The human remains the release actor. A hand-edit, imported result, missing
        run or ambiguous record cannot stand in as an independent producer.
        """
        state = self._load(project_id) if state is None else state
        provenance = contract.get("provenance")
        run_id = provenance.get("run_id") if isinstance(provenance, dict) else None
        producer = ""
        if isinstance(run_id, str) and run_id.strip():
            candidates = []
            for stage in self._spec.stages:
                if stage.scope == SCOPE_ITEM:
                    continue
                record = state.get("stages", {}).get(stage.id)
                if (isinstance(record, dict) and record.get("run_id") == run_id
                        and record.get("accepted") is True and record.get("edited") is False
                        and isinstance(record.get("output"), str) and record["output"].strip()):
                    candidates.append(stage.id)
            if len(candidates) == 1:
                producer = "production-run:" + sha256(json.dumps(
                    [context.tenant, self._spec.name, project_id, candidates[0], run_id],
                    separators=(",", ":"),
                ).encode()).hexdigest()
        return replace(context, review_producer_id=producer, retained_state=deepcopy(state))

    def _review(self, method: str, project_id: str, context: EmissionContext, **kwargs: Any) -> dict[str, Any]:
        if context.project_id != project_id or context.vertical_name != self._spec.name:
            raise ProjectEngineError("human review context does not match this project")
        operation = getattr(self._emission_gate, method, None)
        if self._spec.regulated is None or operation is None:
            raise ProjectEngineError("governed human review is not configured for this vertical")
        if self._build_contract is None:
            raise ProjectEngineError("no contract builder configured for this vertical")
        state = self._load(project_id)
        # An existing stored review is judged as the identity that OPENED it: a delegated project's executor, whose
        # inherited authority the contract resolves. The human caller keeps their own identity for the credential
        # grant; they never execute as the delegate, and release still requires the original requester (review 3179).
        contract_context = context
        requester = getattr(self._emission_gate, "review_requester", None)
        if "review_id" in kwargs and callable(requester):
            try:
                opened_by = requester(spec=self._spec, context=context, review_id=kwargs["review_id"])
            except ValueError as exc:
                raise ProjectEngineError(str(exc)) from exc
            contract_context = replace(context, actor_id=opened_by)
        contract = self._governed_release().contract(project_id, tenant=context.tenant, context=contract_context,
                                                     state=state).for_approval()
        context = self._review_production_context(project_id, contract, context, state=state)
        result: dict[str, Any] = operation(spec=self._spec, contract=contract, context=context, **kwargs)
        return result

    def get_source_review(self, project_id: str, *, context: EmissionContext) -> dict[str, Any]:
        return self._review("get_source_review", project_id, context)

    def confirm_source_review(self, project_id: str, *, context: EmissionContext,
                              expected_material_digest: str, confirmed: bool, request_id: str) -> dict[str, Any]:
        return self._review("confirm_source_review", project_id, context,
                            expected_material_digest=expected_material_digest, confirmed=confirmed, request_id=request_id)

    def open_review(self, project_id: str, *, context: EmissionContext) -> dict[str, Any]:
        """Prepare the current contract for authenticated human review."""
        return self._review("open_review", project_id, context)

    def get_review(self, project_id: str, review_id: str, *, context: EmissionContext) -> dict[str, Any]:
        """Read this project's verified stored-review status."""
        return self._review("get_review", project_id, context, review_id=review_id)

    def grant_review(self, project_id: str, review_id: str, role: str, *, context: EmissionContext) -> dict[str, Any]:
        """Grant only through the authority gate as the authenticated caller."""
        return self._review("grant_review", project_id, context, review_id=review_id, role=role)

    # Delegating a project's release (regulated_core/delegation_review.py): the host drives the root lifecycle with
    # its authenticated context and plain values only. `delegation_review_id` is deliberately not `review_id`, so a
    # delegation review is never mistaken for a release review's requester lookup.

    def open_delegation_review(self, project_id: str, *, context: EmissionContext, destinations: tuple[str, ...],
                               expires_in_us: int, admit_within_us: int, delegable: bool = True) -> dict[str, Any]:
        """The authenticated owner proposes delegating this project's release; humans then review it."""
        return self._review("open_delegation_review", project_id, context, destinations=tuple(destinations),
                            expires_in_us=expires_in_us, admit_within_us=admit_within_us, delegable=delegable)

    def get_delegation_review(self, project_id: str, delegation_review_id: str, *,
                              context: EmissionContext) -> dict[str, Any]:
        return self._review("get_delegation_review", project_id, context, delegation_review_id=delegation_review_id)

    def grant_delegation_review(self, project_id: str, delegation_review_id: str, role: str, *,
                                context: EmissionContext) -> dict[str, Any]:
        return self._review("grant_delegation_review", project_id, context,
                            delegation_review_id=delegation_review_id, role=role)

    def admit_delegation(self, project_id: str, delegation_review_id: str, *, context: EmissionContext) -> dict[str, Any]:
        return self._review("admit_delegation", project_id, context, delegation_review_id=delegation_review_id)

    def delegation_root(self, project_id: str, delegation_review_id: str, *, context: EmissionContext) -> dict[str, Any]:
        return self._review("delegation_root", project_id, context, delegation_review_id=delegation_review_id)

    def export(self, project_id: str, out_path: str) -> str:
        """Project the contract to an asset through the injected exporter. The engine renders nothing itself
        (Project OS T1); it hands the contract to the vertical's exporter and returns the path written.

        For an ORDINARY vertical this is unchanged. A REGULATED vertical must NOT export directly — its
        emission is a consequential action that requires the authority plane's permission, so it fails
        closed here and must go through `release()`."""
        if self._spec.regulated is not None or self._release_authority is not None:
            boundary = "regulated" if self._spec.regulated is not None else "delegated"
            reason = f"vertical {self._spec.name!r} is {boundary}: emit via release() with an approval context, not export()"
            self._record_export_refusal(project_id, out_path, reason)
            raise ProjectEngineError(reason)
        if self._exporter is None:
            raise ProjectEngineError("no exporter configured for this vertical")
        return self._exporter(self.contract(project_id), out_path)

    def release(self, project_id: str, out_path: str, *, context: EmissionContext | None = None) -> str:
        """The AUTHORIZED emission path. For an ordinary vertical it is a plain export. For a REGULATED vertical the
        whole protocol, prepare once, freeze and bind, decide, commit through the target adapter, record the
        outcome and answer replays from receipts, belongs to `GovernedRelease`; the engine only hands it over."""
        if self._spec.regulated is None and self._release_authority is None:
            if self._exporter is None:
                raise ProjectEngineError("no exporter configured for this vertical")
            return self._exporter(self.contract(project_id), out_path)
        if context is None:
            raise ProjectEngineError("regulated release requires an approval context")
        return self._governed_release().release(project_id, out_path, context)

    def reconcile_release(self, project_id: str, out_path: str, *, context: EmissionContext) -> ReleaseOutcome:
        """Read-only: the outcome of one exact recorded regulated release attempt, from the target's receipts.
        Never authorizes, commits or resends (see GovernedRelease.reconcile)."""
        if self._spec.regulated is None and self._release_authority is None:
            raise ProjectEngineError("only a regulated release has an attempt to reconcile")
        return self._governed_release().reconcile(project_id, out_path, context)

    def observe_release(self, project_id: str, out_path: str, *, context: EmissionContext) -> ReleaseObservation:
        """Read-only evidence of one exact allowed release attempt (see GovernedRelease.observe)."""
        if self._spec.regulated is None and self._release_authority is None:
            raise ProjectEngineError("only a regulated release has evidence to observe")
        return self._governed_release().observe(project_id, out_path, context)

    def _record_export_refusal(self, project_id: str, out_path: str, reason: str) -> None:
        """Paper A 3 (claims row A01): a refused attempt at a regulated effect is signed evidence, whichever entrance
        it came through. export() has no authenticated caller, so the attempt is recorded as unattributed; the gate
        writes it to the same signed chain as every decision. The refusal stands even if the record cannot be made,
        and a gate without the recording seam still refuses."""
        record = getattr(self._emission_gate, "record_entrance_refusal", None)
        if not callable(record):
            return
        try:
            contract: dict[str, Any] = self.contract(project_id)
        except Exception:
            contract = {"project_id": project_id}
        record(spec=self._spec, contract=contract,
               context=EmissionContext(tenant=resolve_tenant(SELF).tenant_id, actor_id="unattributed-export",
                                       project_id=project_id, vertical_name=self._spec.name,
                                       release_target=os.path.abspath(out_path)),
               code="EXPORT_REFUSED", reason=reason)

    def governed_contract(self, project_id: str, *, tenant: str, destination: str = "",
                          context: EmissionContext | None = None) -> dict[str, Any]:
        """The contract review, approval and release all bind for a regulated vertical: the vertical's contract,
        the digest of the prepared artifact, and the declared target with its prior state."""
        if context is None:
            context = EmissionContext(tenant=tenant, actor_id="", release_target=destination)
        else:
            if destination and context.release_target and os.path.abspath(destination) != os.path.abspath(context.release_target):
                raise ProjectEngineError("review destination differs from its authenticated context")
            context = replace(context, release_target=destination or context.release_target)
        return self._governed_release().contract(project_id, tenant=tenant, context=context).for_approval()

    def _governed_release(self) -> GovernedRelease:
        """The regulated release protocol for this vertical, built from the seams the engine already holds."""
        if self._emission_gate is None:
            raise ProjectEngineError(f"regulated vertical {self._spec.name!r}: no emission gate wired (fail-closed)")
        if self._exporter is None:
            raise ProjectEngineError("no exporter configured for this vertical")
        if self._build_contract is None:
            raise ProjectEngineError("no contract builder configured for this vertical")
        if self._artifact_store is None:
            self._artifact_store = FileArtifactStore(os.path.join(self._root, "release-artifacts"))
        return GovernedRelease(
            spec=self._spec, gate=self._emission_gate, build_contract=self._build_contract, exporter=self._exporter,
            artifacts=self._artifact_store, state=_EngineState(self), clock=self._clock,
            review_context=lambda pid, contract, ctx, state: self._review_production_context(
                pid, contract, ctx, state=state),
            receipt_pins=self._receipt_pins, release_authority=self._release_authority)

    def latest_emission(self, project_id: str) -> dict[str, Any] | None:
        emissions = self._load(project_id).get("emissions", ())
        return dict(emissions[-1]) if emissions else None

    # --- declarative input resolution (the chaining) -----------------------------

    def _resolve_inputs(self, state: dict[str, Any], stage: StageSpec, item_id: str | None,
                        item: dict[str, Any] | None) -> dict[str, str]:
        params: dict[str, str] = {}
        for binding in stage.inputs:
            kind, _, arg = binding.source.partition(":")
            if kind == "field":
                params[binding.param] = str(state.get(arg, ""))
            elif kind == "item":
                params[binding.param] = str((item or {}).get(arg, ""))
            elif kind == "stage":
                sid, _, json_field = arg.partition(".")
                output = self._stage_output(state, sid, item_id)
                params[binding.param] = self._json_field(output, json_field) if json_field else output
            elif kind == "fn":
                fn = self._spec.computed_inputs.get(arg)
                if fn is None:
                    raise ProjectEngineError(f"no computed-input function {arg!r} registered for {self._spec.name}")
                params[binding.param] = fn(state, item)
            else:
                raise ProjectEngineError(f"unknown binding source {binding.source!r}")
        return params

    def _stage_output(self, state: dict[str, Any], sid: str, item_id: str | None) -> str:
        src = self._stage(sid)
        if src.scope == SCOPE_ITEM:
            rec = state.get("items", {}).get(item_id, {}).get(sid)
        else:
            rec = state.get("stages", {}).get(sid)
        if not rec or not rec.get("output"):
            raise ProjectEngineError(f"prerequisite stage {sid!r} has not run; run it first")
        return str(rec["output"])

    @staticmethod
    def _json_field(output: str, json_field: str) -> str:
        try:
            data = json.loads(output)
        except Exception:  # noqa: BLE001 - a non-JSON prior output means the field is simply absent
            return ""
        return str(data.get(json_field, "")) if isinstance(data, dict) else ""

    # --- helpers -----------------------------------------------------------------

    def _stage(self, stage_id: str) -> StageSpec:
        try:
            return self._spec.stage(stage_id)
        except KeyError:
            known = ", ".join(s.id for s in self._spec.stages)
            raise ProjectEngineError(f"unknown stage {stage_id!r} (have: {known})") from None

    def _find_item(self, state: dict[str, Any], item_id: str) -> dict[str, Any]:
        for item in self._spec.item_enumerator(state):
            if str(item.get("id")) == item_id:
                return item
        raise ProjectEngineError(f"no item {item_id!r}; the stage that produces items must run first")

    def _store(self, state: dict[str, Any], stage: StageSpec, item_id: str | None,
               record: dict[str, Any]) -> None:
        if stage.scope == SCOPE_ITEM:
            state.setdefault("items", {}).setdefault(str(item_id), {})[stage.id] = record
        else:
            state.setdefault("stages", {})[stage.id] = record
        self._invalidate_assembly(state, {"stage": stage.id, "item_id": item_id})

    def _invalidate_assembly(self, state: dict[str, Any], origin: dict[str, Any]) -> None:
        # Revoke authority without authoring a verdict. The historical record is
        # unchanged for stage writes; source replacement names its own reason.
        previous = state.pop("assembled", None)
        if previous is not None:
            state.setdefault("invalidated_assemblies", []).append({
                "assembly": previous, "approved": bool(state.get("approved", False)),
                "invalidated_at": self._clock(), **origin,
            })
        if "approved" in state:
            state["approved"] = False

    def _record(self, state: dict[str, Any], stage: StageSpec, item_id: str | None) -> dict[str, Any] | None:
        if stage.scope == SCOPE_ITEM:
            rec = state.get("items", {}).get(str(item_id), {}).get(stage.id)
        else:
            rec = state.get("stages", {}).get(stage.id)
        return rec if isinstance(rec, dict) else None

    def _save(self, project_id: str, state: dict[str, Any]) -> None:
        _validate_project_id(project_id)
        self._state_store.save(project_id, state)

    def _load(self, project_id: str) -> dict[str, Any]:
        _validate_project_id(project_id)
        return self._state_store.load(project_id)


def _validate_project_id(project_id: str) -> None:
    """Apply the same cross-platform identifier boundary to every backend."""
    if (
        not project_id
        or "/" in project_id
        or "\\" in project_id
        or project_id in (".", "..")
        or os.path.isabs(project_id)
        or ntpath.splitdrive(project_id)[0]
    ):
        raise ProjectEngineError(f"invalid project id {project_id!r}")


class _EngineState:
    """The engine's project state as the `ProjectState` port `GovernedRelease` reads and appends to."""

    def __init__(self, engine: ProjectEngine) -> None:
        self._engine = engine

    def load(self, project_id: str) -> dict[str, Any]:
        return self._engine._load(project_id)

    def save(self, project_id: str, state: dict[str, Any]) -> None:
        self._engine._save(project_id, state)

