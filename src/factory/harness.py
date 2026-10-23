"""The harness seam, the keystone of the factory's portability.

Two layers live here, and the distinction is the whole point:

  • A *harness* (the `Harness` protocol) is a **disposable driver**. It knows how to
    run exactly one provider. Providers churn, terms change, APIs break, tools get
    retired, so harnesses get rewritten and thrown away. That's expected.

  • A *harness adapter* (`HarnessAdapter`) is the **permanent interface**. It wraps a
    disposable harness with stable, descriptive metadata, a name, a default model,
    a set of capabilities, so the factory core can choose and call a provider
    WITHOUT ever naming one. The adapter is what survives the churn.

This closes the first crack Module 06 exposed: the per-provider *model* now lives in
`HarnessInfo.default_model`, so the core never hardcodes it, and per-provider
*capabilities* let the core select by what a task needs rather than by who makes it.
(The per-provider *key* crack is closed next, in Module 09.)

Note we GROW the seam by addition: `Harness` and `RunResult` are unchanged from
Module 05, so every existing driver and test still works. The adapter wraps a
driver from the outside, the disposable thing stays disposable.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from factory.tenant import TenantContext


@dataclass(frozen=True, slots=True)
class RunResult:
    """One harness run, normalized so the rest of the factory never sees provider shapes."""

    output: str
    cost_usd: float
    succeeded: bool
    artifacts: tuple[str, ...] = ()
    # Provider-specific extras, stored but never interpreted by the core; object
    # values keep the field honest under strict typing.
    raw: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class Harness(Protocol):
    """The disposable execution contract: run a task for a tenant, return a result."""

    def run(self, task: str, tenant: TenantContext) -> RunResult: ...


class Capability(str, Enum):
    """What a harness can do. The core selects on these, never on provider names."""

    # WORKSPACE_EDIT means the COMPLETE adapter/model/runtime tuple can inspect and modify the ambient repository
    # -- it is an agentic coding agent, not merely a model that returns text. It is deliberately NOT inferred from
    # SANDBOX, a model family, or a provider name: a Chat-Completions call and a bare local text model both run()
    # but cannot edit a workspace, so the Studio must require this to admit a coding agent. STRUCTURED_REVIEW marks
    # a bounded text/JSON reviewer, so an agentic coding CLI is not used as a reviewer merely because both run().
    WORKSPACE_EDIT = "workspace_edit"
    STRUCTURED_REVIEW = "structured_review"
    PARALLEL_SUBAGENTS = "parallel_subagents"
    ADVERSARIAL_CRITIC = "adversarial_critic"
    RESUMABLE = "resumable"
    BROWSER = "browser"
    SANDBOX = "sandbox"
    # A one-shot text lane with fresh provider state, no tools, no filesystem, and no workspace.
    # Session advisory seats require this explicit qualification; WORKSPACE_EDIT never implies it.
    ADVISORY_SAFE = "advisory_safe"
    # A tool-capable lane whose actions run only through the provider-neutral
    # isolated Artifact cell. The complete tuple (adapter, runner, image and
    # grants) must carry an ArtifactQualification; WORKSPACE_EDIT and SANDBOX
    # never imply it.
    ARTIFACT_EXECUTION = "artifact_execution"
    DATA_API = "data_api"          # may call typed external data APIs (YouTube Data/Analytics)
    MEDIA_RENDER = "media_render"  # may shell ffmpeg / image tooling / NLE-adjacent media tools
    # Content Factory media-generation capabilities. The core depends on these verbs, not
    # on the products that satisfy them: a recipe asks for IMAGE_GENERATOR, and whichever
    # harness advertises it (Gemini/Nano Banana today, another model tomorrow) is selected.
    # Kept distinct because their cost, latency, and failure modes differ: a still image is
    # not a video clip, and editing an existing frame is not generating one from scratch.
    IMAGE_GENERATOR = "image_generator"    # text -> still image (Nano Banana / Gemini image models)
    IMAGE_EDITOR = "image_editor"          # image + instruction -> edited image (multi-image consistency)
    VIDEO_GENERATOR = "video_generator"    # text/image -> video clip (Veo, Kling, Runway)
    AVATAR_GENERATOR = "avatar_generator"  # script -> talking-head clip (a presenter, not Nano Banana)
    VOICE_GENERATOR = "voice_generator"    # text -> narration audio (TTS; Gemini speech models)
    SPEECH_TO_TEXT = "speech_to_text"      # prepared audio -> word-timed transcript


@dataclass(frozen=True, slots=True)
class AdvisoryQualification:
    """Auditable proof claims required before a lane may enter an advisory session.

    `ADVISORY_SAFE` used to be a bare capability bit.  That let a composition-root
    edit confer trust without carrying the properties the Courier contract actually
    requires.  This record makes every property explicit and names the provider-shape
    test that proves it.  `HarnessInfo` rejects incomplete claims at construction.
    """

    one_shot: bool
    fresh_state: bool
    no_tools: bool
    no_filesystem: bool
    no_workspace: bool
    proof: str
    billing: str

    @property
    def complete(self) -> bool:
        return (
            self.one_shot and self.fresh_state and self.no_tools
            and self.no_filesystem and self.no_workspace and bool(self.proof.strip())
            and bool(self.billing.strip())
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "one_shot": self.one_shot,
            "fresh_state": self.fresh_state,
            "no_tools": self.no_tools,
            "no_filesystem": self.no_filesystem,
            "no_workspace": self.no_workspace,
            "proof": self.proof,
            "billing": self.billing,
        }


def advisory_qualification(*, proof: str, billing: str) -> AdvisoryQualification:
    """Construct the common fully-isolated qualification after a provider-shape test."""
    return AdvisoryQualification(True, True, True, True, True, proof, billing)


class ArtifactGrant(str, Enum):
    """Composable authority inside the Artifact tool cell; roles are presets, not grants."""

    SNAPSHOT_READ = "snapshot_read"
    PRIVATE_SCRATCH_WRITE = "private_scratch_write"
    APPROVED_TOOL_EXECUTE = "approved_tool_execute"
    ARTIFACT_EMIT = "artifact_emit"


_ARTIFACT_BASE_GRANTS = frozenset({
    ArtifactGrant.SNAPSHOT_READ,
    ArtifactGrant.PRIVATE_SCRATCH_WRITE,
    ArtifactGrant.APPROVED_TOOL_EXECUTE,
})
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ArtifactQualification:
    """Typed proof required before a lane may use contained Artifact tools.

    Version one deliberately admits only the network-off, secret-free tool
    cell. Provider interaction stays outside this boundary. The receipt names
    the non-author reviewer and conformance proof; it cannot be conferred by a
    capability bit or provider name.
    """

    schema_version: str
    runner: str
    runner_version: str
    image_digest: str
    grants: tuple[ArtifactGrant, ...]
    network_policy: str
    secret_policy: str
    promotion_policy: str
    proof: str
    billing: str
    reviewer: str

    @property
    def complete(self) -> bool:
        grant_set = frozenset(self.grants)
        return (
            self.schema_version == "artifact-qualification/v1"
            # The local Docker cell (unchanged), or the same cell on the managed estate (N10), which is billed as
            # managed compute and never claims local-none.
            and (self.runner == "docker-tool-cell"
                 or (self.runner == "ecs-tool-cell" and self.billing == "managed-compute"))
            and self.runner_version == "1"
            and _SHA256.fullmatch(self.image_digest) is not None
            and len(grant_set) == len(self.grants)
            and _ARTIFACT_BASE_GRANTS <= grant_set
            and self.network_policy == "none"
            and self.secret_policy == "none"
            and self.promotion_policy == "none"
            and bool(self.proof.strip())
            and bool(self.billing.strip())
            and bool(self.reviewer.strip())
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "runner": self.runner,
            "runner_version": self.runner_version,
            "image_digest": self.image_digest,
            "grants": [grant.value for grant in self.grants],
            "network_policy": self.network_policy,
            "secret_policy": self.secret_policy,
            "promotion_policy": self.promotion_policy,
            "proof": self.proof,
            "billing": self.billing,
            "reviewer": self.reviewer,
        }

    @property
    def digest(self) -> str:
        raw = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def artifact_qualification(*, image_digest: str, grants: tuple[ArtifactGrant, ...],
                           proof: str, billing: str, reviewer: str) -> ArtifactQualification:
    """Construct the v1 provider-neutral, network-off tool-cell receipt."""
    return ArtifactQualification(
        schema_version="artifact-qualification/v1",
        runner="docker-tool-cell",
        runner_version="1",
        image_digest=image_digest,
        grants=grants,
        network_policy="none",
        secret_policy="none",
        promotion_policy="none",
        proof=proof,
        billing=billing,
        reviewer=reviewer,
    )


@dataclass(frozen=True, slots=True)
class HarnessInfo:
    """Stable description of a harness, the only provider detail the core may see."""

    name: str
    default_model: str
    capabilities: frozenset[Capability]
    advisory: AdvisoryQualification | None = None
    artifact: ArtifactQualification | None = None
    # How a run on this lane is PAID FOR, in the operator's terms: "api-key" (metered),
    # "oauth-subscription" (the operator's plan, no per-call charge), or "" when the lane
    # has not declared one. Deliberately separate from the advisory receipt, which only
    # exists for ADVISORY_SAFE lanes - a structured reviewer must be able to state its
    # billing truthfully without claiming a contract it does not meet.
    billing: str = ""

    def __post_init__(self) -> None:
        claims_safe = Capability.ADVISORY_SAFE in self.capabilities
        if claims_safe and (self.advisory is None or not self.advisory.complete):
            raise ValueError(
                f"harness {self.name!r} claims ADVISORY_SAFE without a complete qualification receipt"
            )
        if self.advisory is not None and not claims_safe:
            raise ValueError(
                f"harness {self.name!r} carries an advisory receipt but does not claim ADVISORY_SAFE"
            )
        claims_artifact = Capability.ARTIFACT_EXECUTION in self.capabilities
        if claims_artifact and (self.artifact is None or not self.artifact.complete):
            raise ValueError(
                f"harness {self.name!r} claims ARTIFACT_EXECUTION without a complete qualification receipt"
            )
        if self.artifact is not None and not claims_artifact:
            raise ValueError(
                f"harness {self.name!r} carries an artifact receipt but does not claim ARTIFACT_EXECUTION"
            )


@dataclass(frozen=True, slots=True)
class HarnessAdapter:
    """The permanent interface: stable metadata wrapping a disposable harness.

    The factory core holds adapters, reads `info`, and calls `run`. It never
    imports a driver, never names a provider, never sees a provider's model.
    An adapter also satisfies `Harness` (it has `run`), so anything that takes a
    harness, like `run_headless`, takes an adapter too.
    """

    info: HarnessInfo
    harness: Harness

    def run(self, task: str, tenant: TenantContext) -> RunResult:
        return self.harness.run(task, tenant)

    def supports(self, required: frozenset[Capability]) -> bool:
        if Capability.ADVISORY_SAFE in required:
            advisory = self.info.advisory
            if advisory is None or not advisory.complete:
                return False
        if Capability.ARTIFACT_EXECUTION in required:
            artifact = self.info.artifact
            if artifact is None or not artifact.complete:
                return False
        return required <= self.info.capabilities
