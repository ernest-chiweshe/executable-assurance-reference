"""X-12 on the retained local Health path: fictional data, isolated PostgreSQL.

The host verifier judges only the persisted version the authenticated owner holds,
by exact digest. A store that cannot be read (synthetic connection failure or a
refused session) yields a signed INDETERMINATE at the pack gate, never PASS.
"""

import psycopg

from factory.health_ui.clinical_checks import CHECK_IDS
from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome
from test_clinical_finalisation import clinical, roles  # noqa: F401


class _UnavailablePool:
    """Synthetic store-unavailable condition: the retained store's own connection port fails."""

    def __init__(self, pool):
        self.authenticated = pool.authenticated

    def connection(self):
        raise psycopg.OperationalError("synthetic retained store outage")


def _named(c, **changes):
    contract = {"session_id": c.session.session_id, "doc_id": c.document.doc_id,
                "document_digest": c.document.digest()}
    return {**contract, **changes}


def _context(c, actor=None):
    return EmissionContext(tenant=c.clinician.workspace_id, actor_id=actor or c.clinician.user_id,
                           now_us=c.clock.now_us())


def _outcomes(c, contract, context):
    return {check: c.verifiers.resolve(check).verify_context("", contract, context) for check in CHECK_IDS}


def _gate_outcomes(c, contract, context):
    signed = c.gate._gate._verify_for_context("fictional draft", contract, assertion_id="fixture:x12",
                                              content_digest="0" * 64, context=context)
    # Only the four store-reading clinical checks; the pack's content checks do not read the store.
    return {item.result.verification_class: (item.result.outcome, item.result.reason_codes)
            for item in signed if item.result.verification_class in CHECK_IDS}


def test_persisted_owned_exact_version_is_judged(clinical):  # noqa: F811
    c = clinical
    outcomes = _outcomes(c, _named(c), _context(c))
    assert set(outcomes) == set(CHECK_IDS)
    assert {outcome for outcome, _ in outcomes.values()} == {Outcome.PASS}
    assert _gate_outcomes(c, _named(c), _context(c)) == outcomes


def test_changed_digest_and_other_owner_are_refused_on_the_retained_path(clinical):  # noqa: F811
    c = clinical
    changed = _outcomes(c, _named(c, document_digest="f" * 64), _context(c))
    assert set(changed.values()) == {(Outcome.FAIL, ("DOCUMENT_VERSION_CHANGED",))}
    other = _outcomes(c, _named(c), _context(c, actor="fictional-other-clinician"))
    assert set(other.values()) == {(Outcome.FAIL, ("DOCUMENT_NOT_FOUND",))}


def test_unavailable_retained_store_yields_signed_indeterminate_at_the_gate(clinical):  # noqa: F811
    c = clinical
    c.store._pool = _UnavailablePool(c.store._pool)
    expected = {check: (Outcome.INDETERMINATE, ("STORE_DEGRADED",)) for check in CHECK_IDS}
    assert _outcomes(c, _named(c), _context(c)) == expected
    assert _gate_outcomes(c, _named(c), _context(c)) == expected


def test_refused_session_yields_indeterminate_never_pass(clinical):  # noqa: F811
    c = clinical
    c.sessions.revoke(c.authenticated)
    expected = {check: (Outcome.INDETERMINATE, ("STORE_DEGRADED",)) for check in CHECK_IDS}
    assert _outcomes(c, _named(c), _context(c)) == expected
