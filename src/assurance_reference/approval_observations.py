"""Purpose-limited, audited observations of supplied approval workflow events.

This host port neither grants releases nor assigns, ranks or penalizes reviewers.
Signed observer assertions do not prove completeness, consent or human behavior.
"""

from dataclasses import asdict
import json
import uuid

from assurance_reference.alerts import AlertUnavailable
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from regulated_core.canonical import digest_hex
from regulated_core.signing import Signature


PURPOSE = "approval-workflow-quality"
SCHEMA = "reference/approval-workflow-observation/v1"
FIELDS = {"schema", "tenant", "review_id", "reviewer", "decision_sha256",
          "display_sha256", "outcome", "clock_domain", "presented_us", "decided_us", "synthetic"}


def _text(value):
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def _validate(event):
    if type(event) is not dict or set(event) != FIELDS or event["schema"] != SCHEMA:
        raise ValueError("fixed-schema approval observation required")
    if not all(_text(event[k]) for k in ("tenant", "review_id", "reviewer", "clock_domain")):
        raise ValueError("bounded observation identity required")
    for key in ("decision_sha256", "display_sha256"):
        value = event[key]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("exact decision and display references required")
    if (event["outcome"] not in ("approved", "refused", "escalated")
            or type(event["synthetic"]) is not bool
            or any(type(event[k]) is not int for k in ("presented_us", "decided_us"))
            or not 0 <= event["presented_us"] <= event["decided_us"] <= 2**63 - 1):
        raise ValueError("explicit outcome and ordered observation times required")


class ApprovalObservations:
    """Host-scoped collection and authenticated aggregate reads with signed audit.

    The host owns the observer keys, immutable reader allowlist, session authority
    and restricted journal credentials. Do not expose the underlying journal to
    clients. Policy updates require replacing this host object; no dynamic ACL
    revocation, universal routing or database privilege boundary is claimed here.
    """

    def __init__(self, *, tenant, journal, sessions, observer_key_ids, reader_principals,
                 cohorts=(), minimum_reviewers=5):
        if (not _text(tenant) or type(observer_key_ids) not in (tuple, frozenset)
                or not 1 <= len(observer_key_ids) <= 32
                or not all(_text(k) for k in observer_key_ids)
                or type(reader_principals) not in (tuple, frozenset)
                or not 1 <= len(reader_principals) <= 128
                or not all(_text(k) for k in reader_principals)
                or not callable(getattr(sessions, "admit", None))
                or not all(callable(getattr(journal, k, None)) for k in ("read", "retain_signed"))):
            raise ValueError("explicit bounded host observation policy and ports required")
        if (journal.signer.key_id in observer_key_ids
                or not all(journal.trust.is_known(k) for k in observer_key_ids)):
            raise ValueError("trusted observer keys distinct from journal signer required")
        self._tenant, self._journal, self._sessions = tenant, journal, sessions
        self._observers, self._readers = frozenset(observer_key_ids), frozenset(reader_principals)
        if (type(minimum_reviewers) is not int or not 5 <= minimum_reviewers <= 256
                or type(cohorts) is not tuple or len(cohorts) > 32):
            raise ValueError("host cohorts require a reviewer floor of at least five")
        self._cohorts = {}
        periods, references = [], set()
        for cohort in cohorts:
            if (type(cohort) is not dict
                    or set(cohort) != {"cohort_id", "clock_domain", "evidence_kind",
                                       "start_us", "end_us", "observation_ids"}
                    or not _text(cohort["clock_domain"])
                    or cohort["evidence_kind"] not in ("observed", "synthetic-fixture")
                    or not _text(cohort["cohort_id"]) or cohort["cohort_id"] in self._cohorts
                    or type(cohort["start_us"]) is not int or type(cohort["end_us"]) is not int
                    or not 0 <= cohort["start_us"] < cohort["end_us"] <= 2**63 - 1):
                raise ValueError("fixed host cohort identity and period required")
            ids = cohort["observation_ids"]
            if (type(ids) is not tuple or not 1 <= len(ids) <= 256
                    or not all(type(i) is str and i.startswith("approval-observation:")
                               and len(i) == 85 and all(c in "0123456789abcdef" for c in i[21:])
                               for i in ids) or len(set(ids)) != len(ids)
                    or references.intersection(ids)
                    or any(cohort["start_us"] < end and start < cohort["end_us"]
                           for start, end in periods)):
                raise ValueError("host cohorts must have distinct references and disjoint fixed periods")
            self._cohorts[cohort["cohort_id"]] = {**cohort, "observation_ids": tuple(sorted(ids))}
            periods.append((cohort["start_us"], cohort["end_us"]))
            references.update(ids)
        self._minimum = minimum_reviewers
        self._policy = digest_hex({"tenant": tenant, "purpose": PURPOSE,
            "observer_key_ids": sorted(self._observers), "reader_principals": sorted(self._readers),
            "minimum_reviewers": self._minimum, "cohorts": self._cohorts})

    def _verified(self, event, signature):
        _validate(event)
        if (event["tenant"] != self._tenant or not isinstance(signature, Signature)
                or signature.key_id not in self._observers
                or not self._journal.trust.verify(event, signature)):
            raise ValueError("authorized tenant-bound observer signature required")

    def _retain(self, payload):
        try:
            signature = self._journal.signer.sign(payload)
            if not self._journal.trust.verify(payload, signature):
                raise ValueError("journal signature unavailable")
            self._journal.retain_signed(payload, signature)
        except Exception as exc:
            raise AlertUnavailable("observation or access audit was not confirmed durable") from exc

    def validate_signed(self, event, signature):
        """Check host observation binding without retaining or granting anything.

        A capture route can reject misconfigured signing before asking the original
        gate for a grant. This does not promise that later retention will succeed.
        """
        self._verified(event, signature)

    def record(self, event, signature):
        """Retain an exact signed host observation; no release authority is inferred.

        Duplicate appends can fail; the deterministic returned identity supports
        host reconciliation. The caller must never turn a failed append into an
        assertion that an approval or refusal did not occur.
        """
        _validate(event)
        event = json.loads(json.dumps(event, ensure_ascii=True, allow_nan=False))
        self._verified(event, signature)
        identifier = "approval-observation:" + digest_hex(event)
        self._retain({"schema": "reference/retained-approval-observation/v1",
            "tenant_id": self._tenant, "alert_id": identifier, "event": event,
            "observer_signature": asdict(signature)})
        return identifier

    def report(self, *, authenticated, purpose, cohort_id):
        """Audit an authorized read before touching observations and before return.

        Report only an immutable host-defined cohort. No individual rates, refusal
        penalties, performance grades or automatic decisions are produced. Small
        samples are not anonymous; the host must protect reports and audit logs.
        """
        if (not isinstance(authenticated, AuthenticatedSession)
                or authenticated.tenant != self._tenant or purpose != PURPOSE
                or authenticated.principal not in self._readers):
            raise SessionRefused("observation access is not authorized for this purpose")
        if not _text(cohort_id) or cohort_id not in self._cohorts:
            raise ValueError("a configured host cohort is required")
        cohort = self._cohorts[cohort_id]
        identifiers = cohort["observation_ids"]
        request_id = uuid.uuid4().hex

        def audit(stage, result=None):
            self._retain({"schema": "reference/approval-observation-access/v1",
                "tenant_id": self._tenant, "alert_id": uuid.uuid4().hex,
                "request_id": request_id, "stage": stage, "principal": authenticated.principal,
                "purpose": PURPOSE, "policy_sha256": self._policy,
                "cohort_id": cohort_id,
                "sample_sha256": digest_hex(identifiers), "sample_size": len(identifiers),
                "report_sha256": None if result is None else digest_hex(result)})

        with self._sessions.admit(authenticated) as current:
            current()
            audit("READ_REQUESTED")
            counts = {outcome: 0 for outcome in ("approved", "refused", "escalated")}
            durations, seen, domains, reviewer_counts = [], set(), set(), {}
            synthetic_count = 0
            for identifier in identifiers:
                current()
                envelope = self._journal.read(identifier, tenant_id=self._tenant)
                payload = envelope["payload"]
                retained_signature = Signature(**envelope["signature"])
                if (payload.get("schema") != "reference/retained-approval-observation/v1"
                        or payload.get("tenant_id") != self._tenant
                        or payload.get("alert_id") != identifier
                        or retained_signature.key_id != self._journal.signer.key_id
                        or not self._journal.trust.verify(payload, retained_signature)):
                    raise ValueError("retained observation binding differs")
                event = payload["event"]
                self._verified(event, Signature(**payload["observer_signature"]))
                if event["synthetic"] != (cohort["evidence_kind"] == "synthetic-fixture"):
                    raise ValueError("observations must match the host cohort evidence kind; no mixed cohorts")
                if (event["clock_domain"] != cohort["clock_domain"]
                        or not cohort["start_us"] <= event["decided_us"] < cohort["end_us"]):
                    raise ValueError("observation is outside the fixed cohort period")
                if identifier != "approval-observation:" + digest_hex(event):
                    raise ValueError("observation identity differs")
                logical = (event["review_id"], event["reviewer"], event["decision_sha256"])
                if logical in seen:
                    raise ValueError("multiple observations for one review require reconciliation")
                seen.add(logical)
                reviewer = event["reviewer"]
                reviewer_counts[reviewer] = reviewer_counts.get(reviewer, 0) + 1
                counts[event["outcome"]] += 1
                durations.append(event["decided_us"] - event["presented_us"])
                domains.add(event["clock_domain"])
                synthetic_count += event["synthetic"]
            if len(reviewer_counts) < self._minimum:
                raise ValueError("cohort has fewer than the host minimum distinct reviewers")
            # Exact integer comparison: each reviewer contributes at most 1/K.
            # The host may raise K, but cannot weaken the five-person floor/cap.
            if any(count * self._minimum > len(identifiers) for count in reviewer_counts.values()):
                raise ValueError("cohort exceeds the maximum record share per reviewer")
            result = {"schema": "reference/approval-observation-summary/v1",
                "tenant": self._tenant, "purpose": PURPOSE, "sample_size": len(identifiers),
                "cohort_id": cohort_id, "start_us": cohort["start_us"], "end_us": cohort["end_us"],
                "evidence_kind": cohort["evidence_kind"],
                "maximum_reviewer_share": {"numerator": 1, "denominator": self._minimum},
                "outcome_counts": counts,
                "approved_fraction": {"numerator": counts["approved"], "denominator": len(identifiers)},
                "duration_us": {"sum": sum(durations), "count": len(durations)},
                "clock_domains": sorted(domains), "synthetic_count": synthetic_count,
                "coverage": "supplied completed-choice observations only; abandoned, expired or lost "
                            "presentations are not observed; approval fraction is conditional on "
                            "completion, not a population approval rate",
                "abandoned_presentations_measured": False,
                "all_presentations_count": None,
                "population_approval_rate_established": False,
                "timing_accuracy_established": False, "institutional_protection_established": False,
                "automatic_consequences": [], "request_id": request_id}
            current()
            audit("REPORT_PREPARED", result)
            current()
            return result
