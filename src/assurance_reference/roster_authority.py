"""Verify persisted roster authority from configured trust and signed history."""
from dataclasses import asdict
from hashlib import sha256
import json

from regulated_core.evidence import GENESIS
from regulated_core.governance_roster import ROSTER_KIND, ROSTER_OPERATION, roster_change_bytes, roster_from_fields
from regulated_core.governance_targets import SignedBootstrap
from regulated_core.models import DecisionKind
from regulated_core.persistence_pg import PersistenceError, PostgresDecisionRecorder
from regulated_core.signing import Signature, TrustDirectory
from regulated_core.target import SignedTargetPermit, TargetAuthority, TargetPermit, TargetRef, effect_of


SCHEMA = "reference/authorized-roster/v1"


class RosterAuthorityVerifier:
    def __init__(self, *, tenant, installation, authority, recorder, bootstrap_trust, bootstrap_key_ids):
        if (not tenant or not installation or not isinstance(authority, TargetAuthority)
                or not isinstance(recorder, PostgresDecisionRecorder)
                or not isinstance(bootstrap_trust, TrustDirectory)
                or not isinstance(bootstrap_key_ids, frozenset)
                or not bootstrap_key_ids
                or any(not bootstrap_trust.is_known(key) for key in bootstrap_key_ids)):
            raise TypeError("roster verification requires configured authority, evidence and bootstrap trust")
        self.tenant, self.installation = tenant, installation
        self.authority, self.recorder = authority, recorder
        self.bootstrap_trust, self.bootstrap_key_ids = bootstrap_trust, bootstrap_key_ids

    def _decisions(self):
        entries = self.recorder.entries(self.tenant)  # adapter verifies signatures and configured key identities
        previous = GENESIS
        for seq, env in enumerate(entries):
            if env.seq != seq or env.prev_hash != previous:
                raise PersistenceError("roster decision chain is incomplete or inconsistent")
            previous = env.chain_hash()
        return {env.record.record_id: env for env in entries}

    def encode(self, change):
        proof = change.authority_proof
        if isinstance(proof, SignedBootstrap):
            authority = {"type": "bootstrap", "fields": asdict(proof)}
        elif isinstance(proof, SignedTargetPermit):
            authority = {"type": "permit", "fields": asdict(proof)}
        else:
            raise PersistenceError("roster change requires original signed authority")
        return {"schema": SCHEMA, "roster": dict(change.change["roster"]), "authority": authority}

    def verify_rows(self, rows, installation):
        if installation != self.installation:
            raise PersistenceError("roster installation differs from configured authority")
        verified, prior, decisions = [], "absent", None
        try:
            for index, row in enumerate(rows):
                version, digest, raw, tenant, operation, nonce, change_digest = row
                body = json.loads(raw)
                if set(body) != {"schema", "roster", "authority"} or body["schema"] != SCHEMA:
                    raise PersistenceError("roster has no supported signed authority envelope")
                roster = roster_from_fields(body["roster"])
                output_digest = sha256(roster_change_bytes(roster)).hexdigest()
                if (version != index + 1 or roster.version != version or roster.installation != installation
                        or roster.digest() != digest or tenant != self.tenant or operation != ROSTER_OPERATION
                        or output_digest != change_digest):
                    raise PersistenceError("roster state or receipt binding differs")
                proof = body["authority"]
                if set(proof) != {"type", "fields"}:
                    raise PersistenceError("roster authority envelope differs")
                fields = dict(proof["fields"])
                signature = Signature(**fields.pop("signature"))
                if index == 0:
                    if proof["type"] != "bootstrap":
                        raise PersistenceError("first roster state requires signed bootstrap")
                    signed = SignedBootstrap(signature=signature, **fields)
                    if (signature.key_id not in self.bootstrap_key_ids
                            or not self.bootstrap_trust.verify(signed.body(), signature)
                            or (signed.tenant_id, signed.kind, signed.subject, signed.change_digest) !=
                            (tenant, ROSTER_KIND, installation, change_digest)
                            or nonce != "bootstrap:" + change_digest):
                        raise PersistenceError("roster bootstrap authority does not verify")
                else:
                    if proof["type"] != "permit":
                        raise PersistenceError("roster revision requires signed permit")
                    if set(fields) != {"permit"}:
                        raise PersistenceError("roster permit envelope differs")
                    fields["permit"]["qualification_digests"] = tuple(fields["permit"]["qualification_digests"])
                    signed = SignedTargetPermit(TargetPermit(**fields["permit"]), signature)
                    p = signed.permit
                    target = TargetRef("governance", ROSTER_KIND + ":" + installation)
                    # Authenticate historical evidence without applying current expiry/revocation.
                    self.authority.authenticate(signed, tenant_id=tenant, target=target, operation=operation)
                    if (p.nonce != nonce or p.output_digest != change_digest
                            or p.expected_target_state != prior or not p.approval_ref):
                        raise PersistenceError("roster permit does not bind this revision")
                    if decisions is None:
                        decisions = self._decisions()
                    env = decisions.get(p.decision_record_id)
                    if env is None or env.record_hash != p.decision_record_hash:
                        raise PersistenceError("roster permit decision is absent or differs")
                    record = env.record
                    bound = effect_of(record.action.destination)
                    if (record.tenant_id != tenant or record.action.action_id != operation
                            or record.assertion_id != p.assertion_id or record.assertion_digest != change_digest
                            or record.actor_id != p.principal
                            or record.decision.kind is not DecisionKind.REQUIRE_APPROVAL
                            or record.decision.approval is None
                            or record.decision.approval.minimum_approvers < 2
                            or record.decision.approval.requester_may_approve
                            or bound is None or bound.target != target or bound.target_state != prior
                            or bound.output_digest != change_digest or bound.mission != p.mission):
                        raise PersistenceError("roster signed decision does not bind governed effect")
                prior = digest
                verified.append((roster, (tenant, operation, nonce, change_digest)))
        except PersistenceError:
            raise
        except Exception as error:
            raise PersistenceError("stored roster authority failed verification") from error
        return verified
