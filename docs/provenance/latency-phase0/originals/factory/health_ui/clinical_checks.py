"""The clinical-writing pack's four host verifiers, run over the PERSISTED document version (C4).

The clinical-writing pack (declared in `factory/packs/clinical_writing.py`) names four checks and leaves their
implementation to the host that owns the documents. These are those implementations. Each one reads the
document from the health store and judges only what is stored: a claim that "there are no pending suggestions"
is never evidence, the stored session is.

Whose document it is never comes from the contract. The contract names a session, a document and the exact
version (`document_digest`); the OWNER is resolved from the trusted, authenticated release context by the
host's `owner_of`, so a caller who names another clinician's real session, document and digest reads nothing of
theirs (source review 3000). The gate runs these through its contextual seam (`verify_context`); called without a
context, every check fails, as the Education source witness does.

The checks are the sign route's own rules, now expressed once as verifiers the door runs and signs:

* ``clinical:no-pending-suggestions``: every model suggestion for the document has been accepted or rejected;
* ``clinical:authorship``: every section the template leaves to the clinician carries the clinician's own words;
* ``clinical:traceability``: every paragraph has a source or an author;
* ``clinical:rubric``: a medico-legal report carries a current clinician rubric validation marked ready to sign.
  For any other profile the rubric is not required, and the check says so rather than passing silently.

A document that cannot be found for the authenticated owner, or is not the version the contract names, fails
(fail closed); a degraded store is indeterminate, never a pass.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from factory.health_ui import documents as doc_mod
from factory.health_ui import templates as tpl_mod
from factory.health_ui.store import SessionStore
from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome

NO_PENDING_SUGGESTIONS = "clinical:no-pending-suggestions"
AUTHORSHIP = "clinical:authorship"
TRACEABILITY = "clinical:traceability"
RUBRIC = "clinical:rubric"
CHECK_IDS = (NO_PENDING_SUGGESTIONS, AUTHORSHIP, TRACEABILITY, RUBRIC)

# The governed contract names the document by these fields and nothing else; the owner is never among them.
CONTRACT_FIELDS = ("session_id", "doc_id", "document_digest")

VerifierResult = tuple[Outcome, tuple[str, ...]]
Rule = Callable[[doc_mod.Session, doc_mod.Document], VerifierResult]
OwnerOf = Callable[[EmissionContext], "str | None"]


class ClinicalCheck:
    """One clinical host verifier: a rule over the stored document the trusted context's owner holds."""

    def __init__(self, store: SessionStore, owner_of: OwnerOf, rule: Rule) -> None:
        self._store, self._owner_of, self._rule = store, owner_of, rule

    def __call__(self, draft: str, contract: Mapping[str, Any]) -> VerifierResult:
        return Outcome.FAIL, ("CLINICAL_CHECK_CONTEXT_REQUIRED",)

    def verify_context(self, draft: str, contract: Mapping[str, Any], context: EmissionContext) -> VerifierResult:
        named = {name: contract.get(name) for name in CONTRACT_FIELDS}
        if not all(isinstance(value, str) and value for value in named.values()):
            return Outcome.FAIL, ("CONTRACT_NAMES_NO_DOCUMENT",)
        owner = self._owner_of(context)
        if not owner:
            return Outcome.FAIL, ("NO_AUTHENTICATED_OWNER",)
        if self._store.degraded:
            return Outcome.INDETERMINATE, ("STORE_DEGRADED",)
        session = self._store.get(str(named["session_id"]), owner)
        document = session.document(str(named["doc_id"])) if session is not None else None
        if session is None or document is None:
            return Outcome.FAIL, ("DOCUMENT_NOT_FOUND",)
        if document.digest() != named["document_digest"]:
            return Outcome.FAIL, ("DOCUMENT_VERSION_CHANGED",)
        return self._rule(session, document)


def _no_pending_suggestions(session: doc_mod.Session, document: doc_mod.Document) -> VerifierResult:
    pending = [item for item in session.model_suggestions
               if item.doc_id == document.doc_id and item.status == "pending"]
    return (Outcome.FAIL, ("MODEL_SUGGESTIONS_PENDING",)) if pending else (Outcome.PASS, ())


def _authorship(_session: doc_mod.Session, document: doc_mod.Document) -> VerifierResult:
    blank = doc_mod.unwritten_sections(document, tpl_mod.TEMPLATES[document.template_id])
    return (Outcome.FAIL, ("CLINICIAN_SECTIONS_UNWRITTEN",)) if blank else (Outcome.PASS, ())


def _traceability(_session: doc_mod.Session, document: doc_mod.Document) -> VerifierResult:
    return (Outcome.FAIL, ("PARAGRAPHS_UNTRACEABLE",)) if document.untraceable() else (Outcome.PASS, ())


def _rubric(_session: doc_mod.Session, document: doc_mod.Document) -> VerifierResult:
    if not doc_mod.requires_rubric_validation(document):
        return Outcome.PASS, ("RUBRIC_NOT_REQUIRED_FOR_PROFILE",)
    validation = doc_mod.current_validation(document)
    if validation is None or validation.decision != "ready-to-sign":
        return Outcome.FAIL, ("RUBRIC_VALIDATION_NOT_READY",)
    return Outcome.PASS, ()


def clinical_checks(store: SessionStore, owner_of: OwnerOf) -> dict[str, ClinicalCheck]:
    """The four verifiers, by check id, for the host verifier registry the clinical pack gate resolves.

    `owner_of` is the host's binding from an authenticated release context to the health store owner it may
    read; it is the only source of ownership these checks accept."""
    rules: dict[str, Rule] = {NO_PENDING_SUGGESTIONS: _no_pending_suggestions, AUTHORSHIP: _authorship,
                              TRACEABILITY: _traceability, RUBRIC: _rubric}
    return {check: ClinicalCheck(store, owner_of, rule) for check, rule in rules.items()}
