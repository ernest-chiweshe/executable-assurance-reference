"""Install a pack from its directory, by declaration only, fail-closed per pack; then activate it.

The install order is the trust order: the content index, the signature over it, the provenance, the
declared dependencies (an overlay's base among them), the schema, the rulebook (signed, digest-pinned
by the manifest, validated against the schema; for an overlay, applied over the base under the
tighten-only law), the sources lock, the workflow, the verifier bindings (host capabilities with
validated parameters; a custom module only when the host allows it), every conformance case, the
collections with their migration chains, the scopes, the kit, and the expert attestations. A pack
that fails any step is refused with the reason and the platform keeps running; a pack that passes is
INSTALLED, which is not yet trust: ``activate`` makes one installed version the active one for its
pack id, and only after the collections a tenant already holds can migrate to it. Rollback,
revocation and tenant pinning are the ledger's (``lifecycle``). The fourth pack needs nothing but
its directory; the eleventh domain installs and activates without modifying an existing file.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from threading import RLock
from typing import Any

from regulated_core.target import Outcome
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.policy_document import PolicyDocument, verify_document
from regulated_core.signing import Signature, TrustDirectory

from .attestations import AttestationError, ExpertAttestation, coverage, load_attestations
from .checks import CaseReport, CheckError, load_cases, load_custom_module, run_cases
from .collections import (
    CollectionError,
    CollectionSpec,
    PackCollectionStore,
    PackDocument,
    collections_from_list,
    compatible,
    document_key,
    migrate_payload,
)
from .lifecycle import (
    ActivationLedger, ActivationRecord, DependencyRequirements, GovernanceReceipt, LifecycleError, dependency_requirements,
)
from .manifest import ManifestError, PackManifest, file_digest, load_manifest
from .receipt import PIN_FIELDS
from .rulebook import RulebookError, RulebookPolicy, apply_overlay
from .schema import PackSchema, SchemaError, schema_from_dict
from .signing import SignatureError, VerifiedProvenance, VerifiedSignature, verify_pack_signature, verify_provenance
from .sources import SourceError, SourceLock, sources_digest, sources_from_list, vocabulary_problems
from .verifiers import HOST_CATALOG, BoundCheck, VerifierCatalog, VerifierError, verifier_profile_digest
from .workflow import Stage, WorkflowError, workflow_digest, workflow_from_dict

KIT_HEADINGS = ("## Journey", "## Rulebook sources", "## Approvers", "## Evidence", "## Expert validation")
CUSTOM_QUALIFICATION = "pack-supplied executable; host-allowed; standard-library imports only; NOT sandboxed (stated gap)"


class PackRefused(RuntimeError):
    """One pack, one reason. Other packs are unaffected."""


def load_rulebook_document(pack_dir: Path, name: str = "rulebook.json") -> PolicyDocument:
    path = pack_dir / "rulebook" / name
    if not path.is_file():
        raise RulebookError(f"rulebook/{name} is missing")
    raw = json.loads(path.read_text(encoding="utf-8"))
    sig = raw.get("signature") or {}
    return PolicyDocument(
        vertical=str(raw["vertical"]), policy_id=str(raw["policy_id"]), version=str(raw["version"]),
        content=dict(raw["content"]), jurisdictions=tuple(str(j) for j in raw["jurisdictions"]),
        effective_from_us=int(raw["effective_from_us"]), effective_until_us=int(raw.get("effective_until_us", 0)),
        issued_by=str(raw["issued_by"]), supersedes=str(raw.get("supersedes", "")),
        signature=Signature(key_id=str(sig.get("key_id", "")), value=str(sig.get("value", "")), alg=str(sig.get("alg", ""))),
    )


def load_schema(pack_dir: Path) -> PackSchema:
    path = pack_dir / "schema" / "schema.json"
    if not path.is_file():
        raise SchemaError("schema/schema.json is missing")
    return schema_from_dict(json.loads(path.read_text(encoding="utf-8")))


def schema_digest(schema: PackSchema) -> str:
    encoded = json.dumps(schema.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def kit_problems(pack_dir: Path) -> list[str]:
    kit = pack_dir / "kit" / "README.md"
    if not kit.is_file():
        return ["kit/README.md is missing (the domain starting kit is part of the pack)"]
    text = kit.read_text(encoding="utf-8")
    return [f"kit/README.md lacks section {h!r}" for h in KIT_HEADINGS if h not in text]


@dataclass(frozen=True)
class InstalledPack:
    root: Path
    manifest: PackManifest
    schema: PackSchema
    rulebook: RulebookPolicy
    checks: Mapping[str, BoundCheck]
    cases: tuple[CaseReport, ...]
    collections: tuple[CollectionSpec, ...]
    stages: tuple[Stage, ...]
    sources: tuple[SourceLock, ...]
    signature: VerifiedSignature
    provenance: VerifiedProvenance
    attestations: tuple[ExpertAttestation, ...] = ()
    expert_coverage: Mapping[str, str] = field(default_factory=dict)
    surface_digests: Mapping[str, str] = field(default_factory=dict)
    dependency_digests: DependencyRequirements = ()

    @property
    def reference(self) -> str:
        return self.manifest.reference

    @property
    def expert_validated(self) -> bool:
        roles = self.manifest.required_expert_roles
        return bool(roles) and all(self.expert_coverage.get(r, "").startswith("ok:") for r in roles)

    def collection(self, name: str) -> CollectionSpec:
        for spec in self.collections:
            if spec.name == name:
                return spec
        raise CollectionError(f"{self.reference} declares no collection {name!r}")

    def collection_or_none(self, name: str) -> CollectionSpec | None:
        return next((s for s in self.collections if s.name == name), None)

    def summary(self) -> dict[str, Any]:
        return {
            "pack": self.reference, "kind": self.manifest.kind, "pack_digest": self.manifest.digest, "domain": self.manifest.domain,
            "capability": self.manifest.capability, "rulebook": self.rulebook.reference,
            "rulebook_digest": self.rulebook.effective_digest, "checks": {r.check_id: r.to_dict() for r in self.cases},
            "verifiers": {k: v.capability for k, v in self.checks.items()}, "collections": [c.name for c in self.collections],
            "stages": [s.id for s in self.stages], "sources": [s.id for s in self.sources], "signed_by": self.signature.key_id,
            "builder": self.provenance.builder_id, "jurisdictions": list(self.manifest.jurisdictions),
            "expert_coverage": dict(self.expert_coverage), "expert_validated": self.expert_validated,
            "surface_digests": dict(self.surface_digests),
        }


@dataclass(frozen=True)
class InstallReport:
    installed: tuple[str, ...] = ()
    refused: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"installed": list(self.installed), "refused": [list(r) for r in self.refused]}


class PackRegistry:
    # The pins every receipt this registry builds is guaranteed to carry; the composition root hands them
    # to Project OS so its completeness check needs no pack import.
    receipt_pin_fields: tuple[str, ...] = (*PIN_FIELDS, "contributing_packs", "contributing_digest")

    def __init__(self, *, trust: TrustDirectory, collections: PackCollectionStore | None = None,
                 verifiers: VerifierCatalog = HOST_CATALOG, allow_custom_verifiers: bool = False,
                 activation: ActivationLedger | None = None, guard: GovernanceGuard | None = None,
                 known_data_classes: Iterable[str] = ("public", "internal", "confidential", "pii", "phi", "financial", "pci")) -> None:
        self._trust = trust
        self._store = collections
        self._catalog = verifiers
        self._allow_custom = allow_custom_verifiers
        if activation is not None and guard is not None and activation.governance_guard is not guard:
            raise ValueError("pack registry and activation ledger must share one governance guard")
        self._ledger = activation if activation is not None else ActivationLedger(guard=guard)
        self._governance_guard = self._ledger.governance_guard
        self._known = frozenset(known_data_classes)
        self._packs: dict[str, InstalledPack] = {}
        self._installed_digests: dict[str, str] = {}
        self._install_lock = RLock()

    @property
    def governance_guard(self) -> GovernanceGuard | None:
        """The same receiving guard protects the registry and its underlying authority store."""
        return self._governance_guard

    def _require_governance(self, pack_id: str) -> None:
        if self._governance_guard is not None:
            self._governance_guard.require("pack-activation", pack_id)

    # -- reads ----------------------------------------------------------------------------------------

    @property
    def ledger(self) -> ActivationLedger:
        return self._ledger

    def installed(self) -> tuple[InstalledPack, ...]:
        return tuple(self._packs[k] for k in sorted(self._packs))

    def get(self, reference: str) -> InstalledPack | None:
        return self._packs.get(reference)

    def versions(self, pack_id: str) -> tuple[str, ...]:
        return tuple(sorted(p.manifest.version for p in self._packs.values() if p.manifest.id == pack_id))

    def active(self, pack_id: str) -> InstalledPack | None:
        record = self._ledger.active(pack_id)
        return self._installed_record(record)

    def _installed_record(self, record: ActivationRecord | None) -> InstalledPack | None:
        if record is None:
            return None
        pack = self._packs.get(record.reference)
        if pack is not None and pack.manifest.digest != record.pack_digest:
            raise LifecycleError("installed artifact does not match its activation digest")
        return pack

    def _dependency_closure(self, manifest: PackManifest) -> DependencyRequirements:
        """Resolve declarations to immutable installed identities, refusing cycles and version conflicts."""
        visiting = {manifest.reference}
        found: dict[str, str] = {}

        def visit(reference: str) -> None:
            if reference in visiting:
                raise PackRefused("pack dependency cycle")
            if reference in found:
                return
            pack = self._packs.get(reference)
            if pack is None:
                raise PackRefused(f"dependency {reference} is not installed")
            digest = self._installed_digests.get(reference)
            if digest is None or pack.manifest.digest != digest:
                raise PackRefused(f"dependency {reference} changed its installed digest")
            visiting.add(reference)
            for dependency in pack.manifest.dependencies:
                visit(dependency)
            visiting.remove(reference)
            found[reference] = digest

        for reference in manifest.dependencies:
            visit(reference)
        try:
            return dependency_requirements(manifest.id, tuple(found.items()))
        except LifecycleError as exc:
            raise PackRefused(str(exc)) from exc

    def dependency_pins(self, reference: str) -> DependencyRequirements:
        pack = self._packs.get(reference)
        if pack is None:
            raise LifecycleError(f"{reference} is not installed")
        if self._installed_digests.get(reference) != pack.manifest.digest:
            raise LifecycleError("installed artifact changed its digest")
        try:
            pins = self._dependency_closure(pack.manifest)
        except PackRefused as exc:
            raise LifecycleError(str(exc)) from exc
        if pins != pack.dependency_digests:
            raise LifecycleError("installed dependency closure changed its digest")
        return pins

    @contextmanager
    def resolution_guard(self, tenant_id: str, pack_id: str, *, now_us: int,
                         expected_reference: str | None = None) -> Iterator[ActivationRecord | None]:
        """Hold the complete installed authority closure through a decision or target recheck."""
        prior = self._ledger.resolve_record(tenant_id, pack_id)
        if prior is None or (expected_reference is not None and prior.reference != expected_reference):
            yield None
            return
        pack = self._installed_record(prior)
        if pack is None:
            yield None
            return
        try:
            dependencies = self.dependency_pins(pack.reference)
        except LifecycleError:
            # Invalid installed authority is a refusal, just like revoked authority.
            # Let the caller follow its normal denial/evidence path; do not escape
            # before it can record the attempted action. Admission still raises.
            yield None
            return
        contributors = (pack, *(self._packs[reference] for reference, _ in dependencies))
        if type(now_us) is not int or not all(p.rulebook.document.effective_at(now_us) for p in contributors):
            yield None
            return
        with self._ledger.resolution_guard(tenant_id, pack_id, required_dependencies=dependencies) as record:
            # The target may have changed while its closure was being resolved. Never use locks for an old graph.
            if record is None or record.reference != pack.reference or record.pack_digest != pack.manifest.digest:
                yield None
            else:
                yield record

    def for_tenant(self, tenant_id: str, pack_id: str) -> InstalledPack | None:
        return self._installed_record(self._ledger.resolve_record(tenant_id, pack_id))

    def active_packs(self) -> tuple[InstalledPack, ...]:
        return tuple(p for p in self.installed() if (r := self._ledger.active(p.manifest.id)) is not None
                     and r.reference == p.reference)

    def capabilities(self) -> frozenset[str]:
        """The entitlement names ACTIVE packs sell: the plan catalog's vocabulary, derived, never listed by hand."""
        return frozenset(p.manifest.capability for p in self.active_packs())

    def domains(self) -> frozenset[str]:
        return frozenset(p.manifest.domain for p in self.active_packs())

    # -- install ----------------------------------------------------------------------------------------

    def install(self, pack_dir: Path, *, publisher_key_id: str | None = None, today: str | None = None) -> InstalledPack:
        with self._install_lock:
            return self._install(pack_dir, publisher_key_id=publisher_key_id, today=today)

    def _install(self, pack_dir: Path, *, publisher_key_id: str | None, today: str | None) -> InstalledPack:
        today = today or date.today().isoformat()
        try:
            manifest = load_manifest(pack_dir)
        except ManifestError as exc:
            raise PackRefused(f"manifest: {exc}") from exc
        ref = manifest.reference
        prior_digest = self._installed_digests.get(ref)
        if prior_digest is not None and prior_digest != manifest.digest:
            raise PackRefused(f"{ref}: an installed version cannot change its digest")
        try:
            signature = verify_pack_signature(pack_dir, manifest, self._trust, publisher_key_id=publisher_key_id)
            provenance = verify_provenance(pack_dir, manifest, self._trust)
        except SignatureError as exc:
            raise PackRefused(f"{ref}: {exc}") from exc
        dependencies = self._dependency_closure(manifest)
        base = self._packs.get(manifest.base) if manifest.base else None
        if manifest.kind != "base":
            if base is None:
                raise PackRefused(f"{ref}: a {manifest.kind} pack needs its installed base as first dependency")
            if base.manifest.kind != "base" and not (manifest.kind == "overlay" and base.manifest.kind == "overlay"):
                raise PackRefused(f"{ref}: first dependency must be a base pack, not {base.manifest.kind}")
            if base.manifest.domain != manifest.domain:
                raise PackRefused(f"{ref}: base {base.reference} is a {base.manifest.domain} pack, not {manifest.domain}")
        # schema and rulebook
        if manifest.kind == "overlay":
            assert base is not None
            schema = base.schema
            rulebook = self._overlay_rulebook(pack_dir, manifest, base)
        else:
            try:
                schema = load_schema(pack_dir)
            except (SchemaError, ValueError, KeyError) as exc:
                raise PackRefused(f"{ref}: schema: {exc}") from exc
            rulebook = self._base_rulebook(pack_dir, manifest, schema)
        # sources lock and vocabularies
        try:
            sources = sources_from_list((manifest.section("knowledge") or {}).get("sources"), required=manifest.kind == "base")
        except SourceError as exc:
            raise PackRefused(f"{ref}: knowledge: {exc}") from exc
        source_map: dict[str, SourceLock] = {}
        for source in sources + (base.sources if base is not None else ()):
            if source.id in source_map and source_map[source.id] != source:
                raise PackRefused(f"{ref}: inherited source {source.id} cannot change its edition or digest")
            source_map[source.id] = source
        known_sources = tuple(source_map.values())
        vocab = vocabulary_problems(manifest.vocabularies, known_sources)
        if vocab:
            raise PackRefused(f"{ref}: " + "; ".join(vocab))
        # workflow
        workflow_raw = manifest.section("workflow") or {}
        if manifest.kind == "overlay" and workflow_raw.get("inherits"):
            assert base is not None
            stages = base.stages
            workflow_raw = base.manifest.section("workflow") or {}
        else:
            try:
                stages = workflow_from_dict(workflow_raw, schema)
            except WorkflowError as exc:
                raise PackRefused(f"{ref}: workflow: {exc}") from exc
        # verifiers and cases
        if manifest.kind == "overlay":
            assert base is not None
            checks: dict[str, BoundCheck] = dict(base.checks)
            cases: tuple[CaseReport, ...] = ()
        else:
            checks, cases = self._bind_and_case(pack_dir, ref, rulebook)
        # collections
        try:
            collections = collections_from_list(list(manifest.section("collections") or []))
        except CollectionError as exc:
            raise PackRefused(f"{ref}: collections: {exc}") from exc
        if manifest.kind == "overlay" and collections:
            raise PackRefused(f"{ref}: an overlay declares no collections; durable data belongs to the base pack")
        # scopes
        rulebook_classes = {str(c).lower() for c in rulebook.effective_content.get("data_classes", ()) or ()}
        for scope in manifest.scopes:
            if scope.data_class not in self._known:
                raise PackRefused(f"{ref}: scope {scope.name} names unknown data class {scope.data_class}")
            if scope.data_class in {"pii", "phi", "financial", "pci"} and scope.data_class not in rulebook_classes:
                raise PackRefused(f"{ref}: scope {scope.name} requests {scope.data_class} data the rulebook does not classify")
        # kit
        problems = kit_problems(pack_dir)
        if problems:
            raise PackRefused(f"{ref}: " + "; ".join(problems))
        # attestations over the surfaces as they are now
        surfaces = {
            "rulebook": rulebook.effective_digest, "schema": schema_digest(schema),
            "kit": file_digest((pack_dir / "kit" / "README.md").read_bytes()), "sources": sources_digest(known_sources),
            "workflow": (base.surface_digests["workflow"] if manifest.kind == "overlay" and base is not None
                         and (manifest.section("workflow") or {}).get("inherits") else workflow_digest(workflow_raw)),
        }
        try:
            attestations = load_attestations(pack_dir)
        except (AttestationError, ValueError) as exc:
            raise PackRefused(f"{ref}: attestations: {exc}") from exc
        expert_coverage = coverage(attestations, required_roles=manifest.required_expert_roles, trust=self._trust,
                                   pack_id=manifest.id, surface_digests=surfaces, today=today)
        pack = InstalledPack(pack_dir, manifest, schema, rulebook, checks, cases, collections, stages, known_sources, signature,
                             provenance, attestations, expert_coverage, surfaces, dependencies)
        self._packs[ref] = pack
        self._installed_digests[ref] = manifest.digest
        return pack

    def _base_rulebook(self, pack_dir: Path, manifest: PackManifest, schema: PackSchema) -> RulebookPolicy:
        ref = manifest.reference
        try:
            document = load_rulebook_document(pack_dir)
        except (RulebookError, ValueError, KeyError) as exc:
            raise PackRefused(f"{ref}: rulebook: {exc}") from exc
        if not verify_document(self._trust, document):
            raise PackRefused(f"{ref}: rulebook signature does not verify")
        self._check_pin(manifest, document)
        try:
            return RulebookPolicy(document, schema)
        except RulebookError as exc:
            raise PackRefused(f"{ref}: rulebook: {exc}") from exc

    def _overlay_rulebook(self, pack_dir: Path, manifest: PackManifest, base: InstalledPack) -> RulebookPolicy:
        ref = manifest.reference
        try:
            document = load_rulebook_document(pack_dir, "overlay.json")
        except (RulebookError, ValueError, KeyError) as exc:
            raise PackRefused(f"{ref}: overlay: {exc}") from exc
        if not verify_document(self._trust, document):
            raise PackRefused(f"{ref}: overlay signature does not verify")
        self._check_pin(manifest, document)
        if str(document.content.get("base", "")) != base.rulebook.reference:
            raise PackRefused(f"{ref}: overlay tailors {document.content.get('base')!r}, but the base in force is {base.rulebook.reference}")
        try:
            merged = apply_overlay(base.rulebook.effective_content, document.content)
            return RulebookPolicy(document, base.schema, content=merged)
        except RulebookError as exc:
            raise PackRefused(f"{ref}: overlay: {exc}") from exc

    @staticmethod
    def _check_pin(manifest: PackManifest, document: PolicyDocument) -> None:
        declared = str((manifest.section("rulebook") or {}).get("digest", ""))
        if not declared:
            raise PackRefused(f"{manifest.reference}: the manifest declares no rulebook digest; a pack pins the rulebook it was tested against")
        if document.digest() != declared:
            raise PackRefused(f"{manifest.reference}: rulebook digest {document.digest()[:12]} is not the declared {declared[:12]}")

    def _bind_and_case(self, pack_dir: Path, ref: str, rulebook: RulebookPolicy) -> tuple[dict[str, BoundCheck], tuple[CaseReport, ...]]:
        checks: dict[str, BoundCheck] = {}
        reports: list[CaseReport] = []
        for check_id in rulebook.check_ids():
            spec = rulebook.check_spec(check_id)
            kind = str(spec["kind"])
            if kind == "deterministic":
                try:
                    checks[check_id] = self._catalog.bind(check_id, spec)
                except VerifierError as exc:
                    raise PackRefused(f"{ref}: verifiers: {exc}") from exc
            elif kind == "custom":
                try:
                    module = load_custom_module(pack_dir, str(spec["module"]), verified=True, allowed=self._allow_custom)
                except CheckError as exc:
                    raise PackRefused(f"{ref}: verifiers: check {check_id!r}: {exc}") from exc
                fn = module.get(check_id)
                if fn is None:
                    raise PackRefused(f"{ref}: verifiers: {spec['module']} does not define check {check_id!r}")
                checks[check_id] = BoundCheck(check_id, f"custom:{spec['module']}", str(spec["version"]), {}, fn, CUSTOM_QUALIFICATION)
            else:
                continue                                    # platform/model/human checks are bound at composition
            try:
                cases = load_cases(pack_dir, check_id)
            except CheckError as exc:
                raise PackRefused(f"{ref}: cases: {exc}") from exc
            report = run_cases(check_id, checks[check_id].run, cases)
            if not report.ok:
                detail = "no golden cases" if not report.by_category.get("golden") else "; ".join(str(f) for f in report.failures)
                raise PackRefused(f"{ref}: check {check_id!r}: {detail}")
            reports.append(report)
        return checks, tuple(reports)

    def install_all(self, pack_dirs: Iterable[Path], *, publisher_keys: Mapping[str, str] | None = None,
                    today: str | None = None) -> InstallReport:
        installed: list[str] = []
        refused: list[tuple[str, str]] = []
        for pack_dir in pack_dirs:
            key = None if publisher_keys is None else publisher_keys.get(pack_dir.name)
            try:
                installed.append(self.install(pack_dir, publisher_key_id=key, today=today).reference)
            except PackRefused as exc:
                refused.append((pack_dir.name, str(exc)))
        return InstallReport(tuple(installed), tuple(refused))

    # -- lifecycle --------------------------------------------------------------------------------------

    def activate(self, reference: str, *, at: str, reason: str = "", approved_prior: str | None = None,
                 before_commit: Callable[[], None] | None = None,
                 receipt: tuple[str, str, str, str] | None = None, first_state_only: bool = False) -> ActivationRecord:
        """Make an installed version the active one. Refused, with the previous version left active, when a
        collection tenants already hold cannot migrate to it, or when an overlay's base is not the active base."""
        self._require_governance(reference.partition("#")[0])
        pack = self._packs.get(reference)
        if pack is None:
            raise LifecycleError(f"{reference} is not installed")
        if pack.manifest.kind == "overlay":
            base_ref = pack.manifest.base or ""
            base_id = base_ref.partition("#")[0]
            active_base = self._ledger.active(base_id)
            if active_base is None or active_base.reference != base_ref:
                raise LifecycleError(f"{reference}: its base {base_ref} is not the active {base_id}")
        expected = self._ledger.active(pack.manifest.id)
        expected_id = self._expected_id(pack.manifest.id, expected)
        current = self._installed_record(expected)
        if expected is not None and current is None:
            raise LifecycleError("active artifact is not installed; cannot validate compatibility")
        if current is not None and current.reference != reference:
            problems: list[str] = []
            removed = {spec.name for spec in current.collections} - {spec.name for spec in pack.collections}
            if removed:
                problems.append("existing collections cannot be removed: " + ", ".join(sorted(removed)))
            for spec in pack.collections:
                previous = current.collection_or_none(spec.name)
                if previous is not None:
                    problems.extend(compatible(previous, spec))
            if problems:
                raise LifecycleError(f"{reference}: cannot supersede {current.reference}: " + "; ".join(problems))
        self._check_stored_compatibility(pack)
        return self._ledger.activate(pack.manifest.id, pack.manifest.version, pack.manifest.digest, at=at, reason=reason,
                                     expected_activation_id=expected_id,
                                     required_base_reference=pack.manifest.base if pack.manifest.kind == "overlay" else None,
                                     required_dependencies=self.dependency_pins(reference),
                                     approved_prior=approved_prior, before_commit=before_commit, receipt=receipt,
                                     **({"first_state_only": True} if first_state_only else {}))

    def governance_receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Outcome:
        """Recover only an exact receiving receipt; absence cannot exclude delayed delivery."""
        receipt = (tenant_id, operation, nonce, change_digest)
        for pack_id in sorted({pack.manifest.id for pack in self._packs.values()}):
            if self._ledger.governance_receipt(pack_id, receipt):
                return Outcome.COMMITTED
        return Outcome.UNKNOWN

    def _expected_id(self, pack_id: str, current: ActivationRecord | None) -> str:
        if current is not None:
            return current.activation_id
        history = self._ledger.history(pack_id)
        return "inactive:" + (history[-1].activation_id if history else "")

    def _check_stored_compatibility(self, target: InstalledPack) -> None:
        """Conservative schema high-water mark: any activated schema may have durable tenant data.

        Until a separately governed data rollback exists, do not infer that an older schema is safe
        just because its activation was retired or revoked. This can refuse an unmigrated rollback.
        """
        if self._store is None:
            return
        for record in self._ledger.history(target.manifest.id):
            previous = self._installed_record(record)
            if previous is None:
                raise LifecycleError(f"{record.reference}: historical artifact unavailable for collection compatibility")
            problems = []
            removed = {s.name for s in previous.collections} - {s.name for s in target.collections}
            if removed:
                problems.append("existing collections cannot be removed: " + ", ".join(sorted(removed)))
            for spec in target.collections:
                old = previous.collection_or_none(spec.name)
                if old is not None:
                    problems.extend(compatible(old, spec))
            if problems:
                raise LifecycleError(f"{target.reference}: unsafe durable collection transition from {record.reference}: " + "; ".join(problems))

    def _fallback(self, pack_id: str, current: ActivationRecord | None) -> ActivationRecord | None:
        if current is None:
            return None
        records = self._ledger.history(pack_id)
        prior = []
        for record in records:
            if record.activation_id == current.activation_id:
                break
            prior.append(record)
        return next((r for r in reversed(prior) if not self._ledger.is_revoked(pack_id, r.version)), None)

    def rollback(self, pack_id: str, *, at: str, reason: str, approved_prior: str | None = None,
                 before_commit: Callable[[], None] | None = None, receipt: GovernanceReceipt | None = None,
                 approved_target: str | None = None) -> ActivationRecord:
        self._require_governance(pack_id)
        current = self._ledger.active(pack_id)
        expected_id = self._expected_id(pack_id, current)
        target = self._fallback(pack_id, current)
        if approved_target is not None and (target is None or target.reference != approved_target):
            raise LifecycleError("rollback target differs from approved target")
        if target is not None and self._store is not None:
            installed = self._installed_record(target)
            if installed is None:
                raise LifecycleError("rollback artifact is not installed")
            self._check_stored_compatibility(installed)
        return self._ledger.rollback(pack_id, at=at, reason=reason,
                                     expected_activation_id=expected_id,
                                     expected_target_reference=None if target is None else target.reference,
                                     approved_prior=approved_prior, before_commit=before_commit, receipt=receipt)

    @staticmethod
    def _same_fallback_authority(current: InstalledPack, target: InstalledPack) -> bool:
        """Automatic recovery is not permission to change policy or its supporting artifacts.

        A distinct release version may carry identical signed authority material. Anything
        else needs a separately governed selection, even if its collections are compatible.
        Compare the complete indexed contract, rather than attempting to prove equivalence
        of arbitrary verifier code or to rank domain-specific credential requirements.
        """
        before, after = current.manifest.canonical(), target.manifest.canonical()
        before.pop("version")
        after.pop("version")
        return (before == after and current.signature.key_id == target.signature.key_id
                and current.provenance.builder_id == target.provenance.builder_id
                and current.rulebook.ref == target.rulebook.ref
                and current.rulebook.effective_digest == target.rulebook.effective_digest
                and current.dependency_digests == target.dependency_digests)

    def revoke(self, reference: str, *, at: str, reason: str, approved_prior: str | None = None,
               before_commit: Callable[[], None] | None = None, receipt: GovernanceReceipt | None = None
               ) -> tuple[ActivationRecord | None, ActivationRecord | None]:
        """Withdraw authority without implicitly replacing it with a different authority.

        Revocation always proceeds. An automatic fallback must preserve the signed contract
        and durable collection compatibility, and the ledger rechecks the observed activation
        and exact candidate under its write lock. Otherwise the pack stays inactive.
        """
        self._require_governance(reference.partition("#")[0])
        pack_id, _, version = reference.partition("#")
        current = self._ledger.active(pack_id)
        expected_id = self._expected_id(pack_id, current)
        target = self._fallback(pack_id, current)
        fallback_reference = ""
        try:
            previous = self._installed_record(current)
            installed = self._installed_record(target)
            if (previous is not None and installed is not None
                    and self._same_fallback_authority(previous, installed)):
                self._check_stored_compatibility(installed)
                fallback_reference = installed.reference
        except LifecycleError:
            # Unavailable or mismatched local artifacts cannot prove a safe fallback.
            # They must not prevent withdrawal of the authority held by the ledger.
            pass
        return self._ledger.revoke(pack_id, version, at=at, reason=reason, fallback_reference=fallback_reference,
                                   expected_activation_id=expected_id, approved_prior=approved_prior,
                                   before_commit=before_commit, receipt=receipt)

    def pin_tenant(self, tenant_id: str, reference: str, *, approved_prior: str | None = None,
                   before_commit: Callable[[], None] | None = None, receipt: GovernanceReceipt | None = None) -> None:
        self._require_governance(reference.partition("#")[0])
        if reference not in self._packs:
            raise LifecycleError(f"{reference} is not installed")
        pack_id, _, version = reference.partition("#")
        current = self._ledger.active(pack_id)
        expected_id = self._expected_id(pack_id, current)
        self._check_stored_compatibility(self._packs[reference])
        self._ledger.pin(tenant_id, pack_id, version,
                         expected_activation_id=expected_id, approved_prior=approved_prior,
                         before_commit=before_commit, receipt=receipt)

    def activation_for(self, tenant_id: str, pack_id: str) -> ActivationRecord | None:
        """The activation record a tenant's releases cite: its pinned version's latest activation, else the active one."""
        return self._ledger.resolve_record(tenant_id, pack_id)

    def receipt_pins(self, tenant_id: str, pack_id: str) -> dict[str, str]:
        """The original authority pins plus the complete contributing-pack evidence (research gate 9)."""
        record = self.activation_for(tenant_id, pack_id)
        if record is None:
            raise LifecycleError(f"{pack_id}: no active or pinned version is activated for tenant {tenant_id}")
        return self.receipt_pins_for_record(record)

    def receipt_pins_for_record(self, record: ActivationRecord) -> dict[str, str]:
        """Build pins from the exact record held by a lifecycle resolution guard."""
        pack = self._installed_record(record)
        if pack is None:
            raise LifecycleError(f"{record.reference}: activated artifact is not installed")
        dependencies = self.dependency_pins(pack.reference)
        contributors = [self._packs[reference] for reference in sorted([pack.reference, *(ref for ref, _ in dependencies)])]
        contributing = json.dumps([
            {"pack": p.reference, "pack_digest": p.manifest.digest, "rulebook_ref": p.rulebook.reference,
             "rulebook_digest": p.rulebook.effective_digest} for p in contributors
        ], sort_keys=True, separators=(",", ":"))
        return {
            "pack": pack.reference, "pack_digest": pack.manifest.digest, "activation_id": record.activation_id,
            "rulebook_ref": pack.rulebook.reference, "rulebook_digest": pack.rulebook.effective_digest,
            "schema_digest": pack.surface_digests["schema"], "sources_digest": pack.surface_digests["sources"],
            "verifier_profile_digest": verifier_profile_digest(pack.rulebook.effective_content["checks"]),
            "builder_id": pack.provenance.builder_id,
            "contributing_packs": contributing,
            "contributing_digest": hashlib.sha256(contributing.encode("utf-8")).hexdigest(),
        }

    # -- collections ------------------------------------------------------------------------------------

    def put_document(self, document: PackDocument, *, expected_version: int | None) -> PackDocument:
        if self._store is None:
            raise CollectionError("no collection store is composed")
        pack = self.for_tenant(document.tenant_id, document.pack_id)
        if pack is None:
            raise CollectionError(f"pack {document.pack_id} has no active or pinned version for tenant {document.tenant_id}")
        return self._store.put(pack.collection(document.collection), document, expected_version=expected_version)

    def get_document(self, pack_id: str, collection: str, tenant_id: str, key: str) -> PackDocument | None:
        if self._store is None:
            raise CollectionError("no collection store is composed")
        pack = self.for_tenant(tenant_id, pack_id)
        if pack is None:
            raise CollectionError(f"pack {pack_id} has no active or pinned version for tenant {tenant_id}")
        spec = pack.collection(collection)
        document = self._store.get(pack_id, collection, tenant_id, key)
        if document is None or document.schema_version == spec.version:
            return document
        # Migrate on read as a CAS write: concurrent readers cannot overwrite newer
        # work, and the stored schema is distinct from its edit revision. A pinned
        # older pack cannot reinterpret a document migrated by a newer pack.
        payload = migrate_payload(spec, document.payload, document.schema_version)
        if document_key(spec, payload) != document.key:
            raise CollectionError("schema migration may not change a document key")
        from datetime import datetime, timezone
        migrated = PackDocument(pack_id, collection, tenant_id, key, document.version + 1,
                                payload, datetime.now(timezone.utc), spec.version)
        return self._store.put(spec, migrated, expected_version=document.version)


__all__ = ["CUSTOM_QUALIFICATION", "KIT_HEADINGS", "InstallReport", "InstalledPack", "PackRefused", "PackRegistry",
           "kit_problems", "load_rulebook_document", "load_schema", "schema_digest"]
