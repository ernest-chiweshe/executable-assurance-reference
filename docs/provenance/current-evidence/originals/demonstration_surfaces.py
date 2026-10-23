"""D5 pack projections over the existing generic Project OS customer surface.

Only a host-injected reader supplies evidence. This module grants no credentials,
installs no packs and activates nothing. The host must bind the same current reader
into its verifier and hold its source guard through release; surface construction
alone is not a managed deployment or a production qualification.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol

from factory.projectos.regulated import EmissionContext, ReleaseAuthoritySource
from factory.projectos.spec import (
    AXIS_KNOWLEDGE_BACKED, KIND_PROJECT, Binding, RegulatedBlock, StageOutcome,
    StageRun, StageSpec, VerticalSpec,
)
from factory.runtime import resolve_tenant
from factory.tenant import SELF
from factory.verticals.plugins import PluginSurface

from .composition import sdk_binding
from .demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from .demonstrations import EVIDENCE_CHECK, USES
from .registry import InstalledPack


class EvidenceUnavailable(ValueError):
    """A current host-reviewed case is unavailable; draft fields are never a fallback."""


class HostEvidence(Protocol):
    def current(self, tenant: str, use: str, case_id: str) -> EvidenceSnapshot: ...


def current_snapshot(source: HostEvidence, tenant: str, use: str, case_id: str) -> EvidenceSnapshot:
    if not tenant or use not in USES or not isinstance(case_id, str) or not case_id.strip():
        raise EvidenceUnavailable("A tenant and an existing reviewed case are required")
    try:
        snapshot = source.current(tenant, use, case_id)
    except Exception as exc:
        raise EvidenceUnavailable("The host-reviewed case is unavailable; contact its evidence custodian") from exc
    if not isinstance(snapshot, EvidenceSnapshot) or (snapshot.tenant, snapshot.case_id) != (tenant, case_id):
        raise EvidenceUnavailable("The host evidence does not match this tenant and case")
    return snapshot


class CurrentSnapshotVerifier:
    """Reread host custody on every check; never retain an earlier accepted revision."""
    def __init__(self, source: HostEvidence, use: str) -> None:
        if use not in USES:
            raise ValueError("Unknown D5 domain")
        self.source, self.use = source, use

    def __call__(self, draft: str, contract: Mapping[str, object]) -> Any:
        return SnapshotVerifier(()).__call__(draft, contract)

    def verify_context(self, draft: str, contract: Mapping[str, object], context: EmissionContext | None) -> Any:
        if context is None:
            return self(draft, contract)
        try:
            case_id = contract.get("case_id")
            if not isinstance(case_id, str):
                raise EvidenceUnavailable("Existing case required")
            snapshot = current_snapshot(self.source, context.tenant, self.use, case_id)
        except EvidenceUnavailable:
            # The existing verifier supplies the fail-closed unavailable verdict.
            return SnapshotVerifier(()).verify_context(draft, contract, context)
        return SnapshotVerifier((snapshot,)).verify_context(draft, contract, context)


def _contract(state: dict[str, Any], approved: bool) -> dict[str, Any]:
    stages = state.get("stages", {})
    record = stages.get("draft", {}) if isinstance(stages, dict) else {}
    pinned = record.get("source_contract") if isinstance(record, dict) else None
    if not isinstance(pinned, dict) or pinned.get("case_id") != state.get("case_id"):
        raise EvidenceUnavailable("Load the reviewed case before preparing this packet")
    # Keep the projection's original evidence pins. A later source revision requires
    # another load, never an invisible update while an approver reads the packet.
    return {**pinned, "body": record.get("output", ""),
            "provenance": {"run_id": record.get("run_id", ""), "model_id": "none"}}


def _render(contract: dict[str, Any], destination: str) -> str:
    # ProjectEngine calls this renderer in its private preparation workspace; the
    # governed target owns the final customer effect and checks the exact bytes.
    Path(destination).write_bytes(str(contract["body"]).encode("utf-8"))
    return destination


def demonstration_surface(pack: InstalledPack, *, source: HostEvidence, clock_us: Callable[[], int],
                          release_authority_factory: Callable[[str], ReleaseAuthoritySource] | None = None,
                          regulated_scope_factory: Callable[[str], Callable[[str, str], None]] | None = None,
                          ) -> PluginSurface:
    use = pack.manifest.capability
    if use not in USES or not (pack.manifest.id == "lumiwright.demo." + use or
                               pack.manifest.id.startswith("lumiwright.demo." + use + ".")):
        raise ValueError("An explicitly installed D5 pack is required")
    actions = pack.rulebook.actions("external")
    if len(actions) != 1 or EVIDENCE_CHECK not in pack.rulebook.check_ids():
        raise ValueError("The pack must declare its evidence check and one release action")
    rule = pack.rulebook.effective_content["rules"][actions[0]]
    roles = tuple(sorted({r for group in rule["approval"]["role_groups"] for r in group}))
    binding = sdk_binding(pack)
    # Overlay routes are distinct, and keep their exact effective pack binding.
    name = pack.manifest.id.removeprefix("lumiwright.demo.").replace(".", "-")
    spec = VerticalSpec(name=name, axis=AXIS_KNOWLEDGE_BACKED, state_dir=name, id_field="case_id",
        domain=pack.manifest.domain,
        stages=(StageSpec("draft", "Load reviewed source packet", kind=KIND_PROJECT,
                          inputs=(Binding("case_id", "field:case_id"),)),),
        regulated=RegulatedBlock(policy_ref=binding["policy_ref"], policy_digest=binding["policy_digest"],
            pack_version=pack.reference, intended_use=str(USES[use]["purpose"]),
            required_verifiers=tuple(pack.rulebook.check_ids()), approver_roles=roles,
            prohibited_uses=tuple(USES[use]["prohibited"])))

    def make_runner(provider: Any) -> Callable[[StageRun], StageOutcome]:
        def run(stage: StageRun) -> StageOutcome:
            if stage.stage.id == "assemble":
                return StageOutcome("", True, "Packet prepared; authority checks are still required")
            if stage.stage.id != "draft":
                raise EvidenceUnavailable("Unsupported packet stage")
            tenant = resolve_tenant(SELF).tenant_id
            snapshot = current_snapshot(source, tenant, use, stage.params.get("case_id", ""))
            context = EmissionContext(tenant=tenant, actor_id="host-projection", now_us=clock_us(), nonce="projection")
            verdict, reasons = SnapshotVerifier((snapshot,)).verify_context(snapshot.render(), snapshot.contract(), context)
            return StageOutcome(snapshot.render(), verdict.value == "pass", ", ".join(reasons),
                run_id="host-evidence:" + snapshot.digest, extra={"source_contract": snapshot.contract()})
        return run

    plugin = SimpleNamespace(spec=spec, title=pack.manifest.title, audience="customer",
        new_fields=({"name": "case_id", "label": "Reviewed case ID", "type": "text", "required": True},),
        stage_descriptors=({"stage": "draft", "title": "Load reviewed source packet",
                            "scope": "project", "spends": False,
                            "hint": "Project the host-reviewed case; no model call or release occurs."},),
        make_runner=make_runner, contract_builder=_contract, exporter=_render)
    return PluginSurface(name, plugin, release_authority_factory=release_authority_factory,
                         regulated_scope_factory=regulated_scope_factory)
