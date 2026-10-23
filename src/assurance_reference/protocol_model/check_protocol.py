"""Bounded state exploration of the execution-assurance commitment protocol.

Dependency-free (Python 3.9+ standard library). Explores every reachable state of a small abstract
model of the authority path by breadth-first search, checks safety invariants in each state, and
re-runs the search with each protection removed to show that every guard is load-bearing.

    python model/check_protocol.py            # baseline configurations + guard-removal variants
    python model/check_protocol.py --json     # machine-readable results

What is modelled: one mission; N distinguishable unit-cost actions; a shared mission budget;
reservation, evidence, permit, commit and acknowledgement per action; nonce use; a substituted-payload
attempt; signer and vault outages (both directions); revocation and expiry (monotone, immediately
visible); lost acknowledgements, retries and reconciliation.
What is not modelled: clocks and network delay, cryptography, key compromise, reservation reclamation,
heterogeneous target APIs, or model cognition. Results check sequencing and guard interactions at small
bounds; they are not evidence of adversarial robustness or of any deployment's safety.
"""
from __future__ import annotations

import json
import sys
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any

IDLE, RESERVED, EVIDENCED, PERMITTED, SENT, DONE = range(6)
PHASE = ["IDLE", "RESERVED", "EVIDENCED", "PERMITTED", "SENT(UNKNOWN)", "COMMITTED"]


@dataclass(frozen=True)
class S:
    phase: tuple[Any, ...]        # per action
    evidence: tuple[Any, ...]     # per action: authorisation evidence retained
    permit: tuple[Any, ...]       # per action: permit issued
    nonce_used: tuple[Any, ...]   # per action: target has consumed this permit's nonce
    effects: tuple[Any, ...]      # per action: ground-truth count of effects at the target (oracle)
    bad_payload: tuple[Any, ...]  # per action: an effect committed with a payload that did not match the permit
    late: tuple[Any, ...]         # per action: an effect committed after revocation or expiry
    reserved: int       # units reserved from the mission budget
    signer_up: bool
    vault_up: bool
    revoked: bool
    expired: bool


GUARDS = ["mandatory_path", "evidence_prerequisite", "revocation_check", "expiry_check",
          "payload_match", "durable_replay", "aggregate_reservation"]


def successors(s: S, budget: int, off: frozenset[str]) -> Iterator[tuple[str, S]]:
    n = len(s.phase)

    def setv(t: tuple[Any, ...], i: int, v: Any) -> tuple[Any, ...]:
        return t[:i] + (v,) + t[i + 1:]

    # environment
    yield "signer_toggle", replace(s, signer_up=not s.signer_up)
    yield "vault_toggle", replace(s, vault_up=not s.vault_up)
    if not s.revoked:
        yield "revoke", replace(s, revoked=True)
    if not s.expired:
        yield "expire", replace(s, expired=True)

    for i in range(n):
        ph = s.phase[i]
        # 1. reserve budget (aggregate guard)
        if ph == IDLE and not s.revoked and not s.expired and (
                "aggregate_reservation" in off or s.reserved < budget):
            yield f"reserve[{i}]", replace(s, phase=setv(s.phase, i, RESERVED), reserved=s.reserved + 1)
        # 2. retain authorisation evidence (requires the vault)
        if ph == RESERVED and s.vault_up:
            yield f"record[{i}]", replace(s, phase=setv(s.phase, i, EVIDENCED), evidence=setv(s.evidence, i, True))
        # 3. issue permit (requires signer; evidence prerequisite)
        if ph == EVIDENCED or ("evidence_prerequisite" in off and ph == RESERVED):
            if s.signer_up and not s.revoked and not s.expired:
                yield f"permit[{i}]", replace(s, phase=setv(s.phase, i, PERMITTED), permit=setv(s.permit, i, True))
        # 4. target commit, with the permit's payload or a substituted one; retries allowed after SENT
        if ph in (PERMITTED, SENT):
            for substituted in (False, True):
                ok = s.permit[i]
                if "evidence_prerequisite" not in off:
                    ok = ok and s.evidence[i]
                if "revocation_check" not in off:
                    ok = ok and not s.revoked
                if "expiry_check" not in off:
                    ok = ok and not s.expired
                if "payload_match" not in off:
                    ok = ok and not substituted
                if not ok:
                    continue
                duplicate = s.nonce_used[i] and "durable_replay" not in off
                if duplicate:  # target deduplicates: returns the recorded result, no new effect
                    yield f"retry_dedup[{i}]", s
                    continue
                yield (f"commit{'_substituted' if substituted else ''}[{i}]",
                       replace(s, phase=setv(s.phase, i, SENT),
                               nonce_used=setv(s.nonce_used, i, True),
                               effects=setv(s.effects, i, s.effects[i] + 1),
                               bad_payload=setv(s.bad_payload, i, s.bad_payload[i] or substituted),
                               late=setv(s.late, i, s.late[i] or s.revoked or s.expired)))
        # 5. reconciliation supplies the missing acknowledgement
        if ph == SENT:
            yield f"reconcile[{i}]", replace(s, phase=setv(s.phase, i, DONE))
        # 6. an alternative effect path around the door (exists only if the mandatory path is removed)
        if "mandatory_path" in off and s.effects[i] == 0:
            yield f"bypass[{i}]", replace(s, effects=setv(s.effects, i, 1))


def violations(s: S, budget: int) -> list[str]:
    v: list[str] = []
    for i, e in enumerate(s.effects):
        if e and not s.permit[i]:
            v.append("effect without permit")
        if e and not s.evidence[i]:
            v.append("effect without prior evidence")
        if e > 1:
            v.append("effect committed more than once")
        if s.bad_payload[i]:
            v.append("effect differs from permitted payload")
        if s.late[i]:
            v.append("effect after revocation or expiry")
    if sum(1 for e in s.effects if e) > budget or sum(s.effects) > budget:
        v.append("mission budget exceeded")
    return v


def explore(actions: int, budget: int, off: frozenset[str] = frozenset()) -> dict[str, Any]:
    z = (False,) * actions
    init = S((IDLE,) * actions, z, z, z, (0,) * actions, z, z, 0, True, True, False, False)
    parent: dict[S, tuple[S, str] | None] = {init: None}
    q = deque([init])
    transitions = 0
    while q:
        s = q.popleft()
        bad = violations(s, budget)
        if bad:
            trace: list[str] = []
            cur = s
            step = parent[cur]
            while step is not None:
                cur, label = step
                trace.append(label)
                step = parent[cur]
            return {"states": len(parent), "transitions": transitions, "violation": bad[0],
                    "trace": list(reversed(trace))}
        for label, t in successors(s, budget, off):
            transitions += 1
            if t not in parent:
                parent[t] = (s, label)
                q.append(t)
    return {"states": len(parent), "transitions": transitions, "violation": None, "trace": []}


def main() -> None:
    out: dict[str, list[dict[str, Any]]] = {"baseline": [], "variants": []}
    for a, b in [(2, 1), (2, 2), (3, 2)]:
        r = explore(a, b)
        out["baseline"].append({"actions": a, "budget": b, **{k: r[k] for k in ("states", "transitions", "violation")}})
    for g in GUARDS:
        r = explore(2, 1, frozenset([g]))
        out["variants"].append({"removed": g, "violation": r["violation"], "trace_length": len(r["trace"]),
                                "trace": r["trace"]})
    if "--json" in sys.argv:
        print(json.dumps(out, indent=2))
        return
    print("Baseline (exhaustive):")
    for r in out["baseline"]:
        print(f"  actions={r['actions']} budget={r['budget']}: {r['states']:,} states, "
              f"{r['transitions']:,} transitions, violations: {r['violation'] or 0}")
    print("Guard-removal variants (actions=2, budget=1), shortest counterexample:")
    for r in out["variants"]:
        print(f"  without {r['removed']:<22} -> {r['violation']} in {r['trace_length']} steps: {' > '.join(r['trace'])}")


if __name__ == "__main__":
    main()
