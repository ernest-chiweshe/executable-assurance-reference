"""Bounded host-roster rotation as an additional approval precondition.

Assignment never grants credentials or substitutes for the original quorum,
reporting-line, cooling-off or receiving guards. The host owns the roster,
directory and per-review rotation index; request data selects none of them.
"""

import json

from assurance_reference.approval_screening import ScreenedMaterialReview
from assurance_reference.review_material import _digest, _json
from regulated_core.approval_evidence import ReviewError


def _identifier(value):
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and value == value.strip() and value.isprintable())


class ReviewAssignmentPolicy:
    """A host-selected, single-review roster snapshot and rotation position.

    The bounded greedy selection may escalate when another allocation could
    exist. It does not search indefinitely or relax independence. Persistence,
    atomic rotation allocation and directory withdrawal locking are separate.
    """

    def __init__(self, *, tenant, review_id, decision_record_hash, roster,
                 directory, rotation_index, excluded_principals, escalation_route):
        if (not all(_identifier(x) for x in (tenant, review_id, escalation_route))
                or not isinstance(decision_record_hash, str) or len(decision_record_hash) != 64
                or any(x not in "0123456789abcdef" for x in decision_record_hash)
                or type(rotation_index) is not int or not 0 <= rotation_index <= 2**63 - 1
                or not callable(getattr(directory, "reporting_line", None))):
            raise ValueError("assignment requires explicit host review, directory and rotation bindings")
        if type(roster) is not dict or not 1 <= len(roster) <= 16:
            raise ValueError("assignment requires one to 16 host role rosters")
        snapshot = {}
        for role, candidates in roster.items():
            if (not _identifier(role) or type(candidates) not in (tuple, list)
                    or not 1 <= len(candidates) <= 64
                    or not all(_identifier(x) for x in candidates)
                    or len(set(candidates)) != len(candidates)):
                raise ValueError("assignment roster requires bounded distinct principals")
            snapshot[role] = tuple(candidates)
        if (type(excluded_principals) not in (tuple, list, frozenset)
                or len(excluded_principals) > 128
                or not all(_identifier(x) for x in excluded_principals)):
            raise ValueError("assignment exclusions must be explicit bounded principals")
        self._tenant, self._review, self._decision = tenant, review_id, decision_record_hash
        self._roster, self._directory, self._rotation = snapshot, directory, rotation_index
        self._excluded, self._route = frozenset(excluded_principals), escalation_route
        self._policy_digest = _digest(_json({"tenant": tenant, "review_id": review_id,
            "decision_record_hash": decision_record_hash, "roster": snapshot,
            "rotation_index": rotation_index, "excluded_principals": sorted(self._excluded),
            "escalation_route": escalation_route}).encode("ascii"))

    def assess(self, bound):
        """Use only the verified MaterialReview payload, never caller role claims."""
        result = {"schema": "reference/review-assignment/v1", "status": "ESCALATE",
            "policy_sha256": self._policy_digest, "rotation_index": self._rotation,
            "tenant": self._tenant, "review_id": self._review, "decision_record_hash": self._decision,
            "escalation_route": self._route, "selected": [],
            "institutional_independence_established": False}
        if (bound.get("tenant"), bound.get("review_id"), bound.get("decision_record_hash")) != (
                self._tenant, self._review, self._decision):
            return {**result, "reason": "review-binding-differs"}
        groups, minimum = bound.get("required_role_groups"), bound.get("minimum_approvers")
        if (type(groups) is not list or not 1 <= len(groups) <= 8
                or type(minimum) is not int or not 1 <= minimum <= len(groups)
                or any(type(group) is not list or not 1 <= len(group) <= 16
                       or not all(_identifier(role) for role in group) for group in groups)
                or not _identifier(bound.get("requester"))):
            return {**result, "reason": "unsupported-or-incomplete-review-requirements"}
        selected, principals, lines = [], set(self._excluded) | {bound["requester"]}, set()
        line_cache = {}
        for index, group in enumerate(groups):
            chosen = None
            for role in sorted(set(group)):
                candidates = self._roster.get(role, ())
                if not candidates:
                    continue
                offset = (self._rotation + index) % len(candidates)
                for principal in candidates[offset:] + candidates[:offset]:
                    if principal in principals:
                        continue
                    try:
                        if principal not in line_cache:
                            line_cache[principal] = self._directory.reporting_line(self._tenant, principal)
                        line = line_cache[principal]
                    except Exception:
                        return {**result, "reason": "directory-unavailable"}
                    if _identifier(line) and line not in lines:
                        chosen = {"principal": principal, "role": role, "reporting_line": line}
                        break
                if chosen is not None:
                    break
            if chosen is None:
                return {**result, "reason": "no-distinct-host-roster-assignment"}
            selected.append(chosen)
            principals.add(chosen["principal"])
            lines.add(chosen["reporting_line"])
        return {**result, "status": "ASSIGNED_BY_HOST_POLICY", "selected": selected,
                "reason": "distinct-directory-lines-and-explicit-roster"}


class AssignedScreenedMaterialReview(ScreenedMaterialReview):
    """Opt-in route: assignment, screening, display and original grant all apply."""

    def __init__(self, gate, *, screening, assignment):
        super().__init__(gate, screening=screening)
        if not isinstance(assignment, ReviewAssignmentPolicy):
            raise TypeError("host review assignment policy is required")
        self._assignment = assignment

    def view(self, **request):
        result = super().view(**request)
        bound = {**result["bound"], "assignment": self._assignment.assess(result["bound"])}
        return {**result, "bound": bound, "display_sha256": _digest(_json(bound).encode("ascii"))}

    def grant(self, **request):
        contract = json.loads(_json(request["contract"]))
        view_request = {key: value for key, value in request.items() if key not in {"role", "displayed_sha256"}}
        view = self.view(**{**view_request, "contract": contract})
        assignment = view["bound"]["assignment"]
        if (assignment["status"] != "ASSIGNED_BY_HOST_POLICY"
                or not any(entry["principal"] == request["context"].actor_id
                           and entry["role"] == request["role"] for entry in assignment["selected"])):
            raise ReviewError("assignment requires escalation or a different assigned reviewer")
        return super().grant(**{**request, "contract": contract})
