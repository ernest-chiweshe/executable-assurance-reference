"""Exact decision inputs authenticated by an independently configured ingress.

An ingress signature attests the source of an exact request, not the truth of its
content or policy outcome. The host must authenticate the session and authorize
the request before signing. A fresh host currentness check remains mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .canonical import canonical_bytes, digest_hex
from .clock import ClockError, ConnectionClock, TrustedClock, read_clock
from .identity import IdentityVerifier
from .models import (
    Action, ActionEffect, Actor, Assertion, ConfidenceEvidence, Credential,
    DataClass, Outcome, PolicyContext, PolicyRef, ProducerLineage,
    SignedVerification, VerificationResult,
)
from .permit import EmissionError
from .signing import Signature, Signer, TrustDirectory
from .verification import VerificationTrustStore


@dataclass(frozen=True)
class DecisionInputs:
    """All policy inputs; the legacy decision record remains unchanged."""

    assertion: Assertion
    action: Action
    context: PolicyContext
    policy: PolicyRef

    def body(self) -> dict[str, Any]:
        # Version 1 explicitly names its fields so later dataclass additions do
        # not silently alter historical signed bytes.
        a, c = self.assertion, self.context
        def project(value: Any, names: tuple[str, ...]) -> dict[str, Any]:
            return {name: getattr(value, name) for name in names}
        def signature(value: Signature) -> dict[str, Any]:
            return project(value, ("key_id", "value", "alg"))
        verifications = []
        for v in a.verifications:
            body = project(v, ("assertion_id", "content_digest", "tenant_id", "verified_at_us"))
            body["result"] = project(v.result, (
                "verification_class", "outcome", "verifier_id", "verifier_version", "reason_codes"))
            body["signature"] = signature(v.signature)
            verifications.append(body)
        credentials = []
        for cred in c.actor.credentials:
            value = project(cred, ("kind", "jurisdiction", "scope", "subject_actor_id",
                                   "tenant_id", "expires_at_us"))
            value["signature"] = signature(cred.signature)
            credentials.append(value)
        assertion = project(a, ("assertion_id", "tenant_id", "content_type", "content_digest",
                                "data_classes", "payload_ref", "attributes"))
        assertion.update(verifications=verifications,
            lineage=None if a.lineage is None else project(a.lineage, (
                "producer", "run_id", "model_id", "prompt_digest", "policy_digest", "gate_digest")),
            confidence=None if a.confidence is None else project(a.confidence, (
                "score", "method_id", "calibration_set_id", "calibrated_at_us")))
        context = project(c, ("tenant_id", "purpose", "correlation_id", "now_us", "requested_scope"))
        context["actor"] = {**project(c.actor, ("actor_id", "tenant_id", "roles", "producer")),
                            "credentials": credentials}
        return {"schema": "regulated/decision-inputs/v1", "assertion": assertion,
                "action": project(self.action, ("action_id", "effect", "destination")),
                "context": context,
                "policy": project(self.policy, ("vertical", "policy_id", "version", "digest"))}

    def digest(self) -> str:
        return digest_hex(self.body())

    @classmethod
    def decode(cls, raw: dict[str, Any]) -> DecisionInputs:
        """Decode only typed core data and require canonical round-trip equality."""
        try:
            data = dict(raw)
            if data.pop("schema") != "regulated/decision-inputs/v1":
                raise ValueError("input schema")
            a = dict(data.pop("assertion"))
            a["data_classes"] = frozenset(DataClass(x) for x in a["data_classes"])
            verifications = []
            for value in a["verifications"]:
                v = dict(value)
                result = dict(v.pop("result"))
                result["outcome"] = Outcome(result["outcome"])
                result["reason_codes"] = tuple(result["reason_codes"])
                verifications.append(SignedVerification(
                    **{k: v[k] for k in v if k != "signature"},
                    result=VerificationResult(**result), signature=Signature(**v["signature"])))
            a["verifications"] = tuple(verifications)
            for name, kind in (("lineage", ProducerLineage), ("confidence", ConfidenceEvidence)):
                if a[name] is not None:
                    a[name] = kind(**a[name])
            c = dict(data.pop("context"))
            actor = dict(c.pop("actor"))
            if type(actor["producer"]) is not bool:
                raise ValueError("producer classification must be boolean")
            actor["roles"] = frozenset(actor["roles"])
            actor["credentials"] = tuple(
                Credential(**{k: v[k] for k in v if k != "signature"},
                           signature=Signature(**v["signature"])) for v in actor["credentials"]
            )
            c["requested_scope"] = frozenset(c["requested_scope"])
            action = dict(data.pop("action"))
            action["effect"] = ActionEffect(action["effect"])
            result_inputs = cls(Assertion(**a), Action(**action),
                                PolicyContext(**c, actor=Actor(**actor)),
                                PolicyRef(**data.pop("policy")))
            if data or canonical_bytes(result_inputs.body()) != canonical_bytes(raw):
                raise ValueError("noncanonical or unrecognized input fields")
            return result_inputs
        except (KeyError, TypeError, ValueError) as exc:
            raise EmissionError("invalid decision input evidence") from exc


@dataclass(frozen=True)
class InputAdmission:
    """Ingress attestation over one exact request and its host identity revision."""

    request_id: str
    permit_nonce: str
    correlation_id: str
    input_digest: str
    tenant: str
    principal: str
    identity_revision: str
    issued_at_us: int
    expires_at_us: int
    signature: Signature
    clock_domain: str = ""

    def signed_body(self) -> dict[str, Any]:
        body = {"schema": "regulated/input-admission/v1", **{
            name: getattr(self, name) for name in ("request_id", "permit_nonce", "correlation_id",
                "input_digest", "tenant", "principal", "identity_revision", "issued_at_us", "expires_at_us")}}
        if self.clock_domain:
            body.update(schema="regulated/input-admission/v2", clock_domain=self.clock_domain)
        return body

    def digest(self) -> str:
        return digest_hex({"body": self.signed_body(), "signature": self.signature})

    @classmethod
    def issue(cls, signer: Signer, inputs: DecisionInputs, *, request_id: str, permit_nonce: str,
              identity_revision: str, issued_at_us: int, expires_at_us: int,
              clock: TrustedClock, connection: Any = None) -> InputAdmission:
        """Attest a host-authenticated request; this does not authenticate a session.

        Only the trusted ingress owns this signer and invokes this method after
        deriving tenant, principal, roles and producer classification server-side.
        """
        body: dict[str, Any] = {"schema": "regulated/input-admission/v1", "request_id": request_id,
                "permit_nonce": permit_nonce, "correlation_id": inputs.context.correlation_id,
                "input_digest": inputs.digest(), "tenant": inputs.context.tenant_id,
                "principal": inputs.context.actor.actor_id, "identity_revision": identity_revision,
                "issued_at_us": issued_at_us, "expires_at_us": expires_at_us}
        if not isinstance(clock, TrustedClock):
            raise EmissionError("input admission requires an explicit trusted clock")
        try:
            reading = read_clock(clock, connection=connection)
            reading.require_live(domain=clock.domain, issued_at_us=issued_at_us,
                                 expires_at_us=expires_at_us)
            if not issued_at_us <= inputs.context.now_us <= reading.now_us:
                raise ClockError("input decision time differs from the admission window")
        except ClockError as exc:
            raise EmissionError("input admission clock invalid") from exc
        body.update(schema="regulated/input-admission/v2", clock_domain=reading.domain)
        signature = signer.sign(body)
        try:
            read_clock(clock, connection=connection).require_live(
                domain=body["clock_domain"], issued_at_us=issued_at_us, expires_at_us=expires_at_us)
        except ClockError as exc:
            raise EmissionError("input admission clock changed during signing") from exc
        return cls(**{k: v for k, v in body.items() if k != "schema"}, signature=signature)

    @classmethod
    def decode(cls, raw: dict[str, Any]) -> InputAdmission:
        try:
            values = dict(raw)
            signature = Signature(**values.pop("signature"))
            result = cls(**values, signature=signature)
            if canonical_bytes({**{k: v for k, v in result.signed_body().items() if k != "schema"},
                                "signature": result.signature}) != canonical_bytes(raw):
                raise ValueError("noncanonical admission")
            return result
        except (KeyError, TypeError, ValueError) as exc:
            raise EmissionError("invalid input admission") from exc


class AdmissionCurrentness(Protocol):
    """Host-owned current identity, membership, classification and scope checks."""

    def verify_on(self, connection: Any, admission: InputAdmission,
                  inputs: DecisionInputs, now_us: int) -> None:
        """Raise on stale/revoked/unauthorized identity or unavailable authority.

        Use the caller's transaction; do not acquire another pooled connection.
        The implementation must authenticate the identity revision and current
        request authorization, including producer classification and scope.
        """
        ...


@dataclass(frozen=True)
class InputVerifier:
    """Pinned ingress/identity authorities, independent of the evidence signer."""

    trust: TrustDirectory
    ingress_key_id: str
    identity_key_id: str
    currentness: AdmissionCurrentness
    permit_key_id: str
    approval_key_id: str
    delegation_key_id: str
    max_age_us: int
    clock: ConnectionClock

    def now_on(self, conn: Any) -> int:
        """Read the configured authority clock on the caller's transaction."""
        if not isinstance(self.clock, ConnectionClock):
            raise EmissionError("input verification requires an explicit connection-bound clock")
        try:
            return read_clock(self.clock, connection=conn).now_us
        except ClockError as exc:
            raise EmissionError("input verification clock unavailable") from exc

    def verify_on(self, conn: Any, inputs: DecisionInputs, admission: InputAdmission,
                  *, evidence_key_id: str, now_us: int) -> None:
        """Check current host authority between fresh transaction-bound reads."""
        now_us = self.now_on(conn)
        self.verify_at(inputs, admission, evidence_key_id=evidence_key_id, now_us=now_us)
        self.currentness.verify_on(conn, admission, inputs, now_us)
        self.verify_at(inputs, admission, evidence_key_id=evidence_key_id, now_us=self.now_on(conn))

    def verify_at(self, inputs: DecisionInputs, admission: InputAdmission,
                  *, evidence_key_id: str, now_us: int) -> None:
        """Check signed authority at a fresh trusted instant without host callbacks."""
        if (not isinstance(self.clock, ConnectionClock)
                or not admission.clock_domain or admission.clock_domain != self.clock.domain):
            raise EmissionError("input admission clock domain differs")
        if (self.currentness is None or self.max_age_us <= 0
                or admission.signature.key_id != self.ingress_key_id
                or not all((self.ingress_key_id, self.identity_key_id, evidence_key_id,
                            self.permit_key_id, self.approval_key_id, self.delegation_key_id))
                or self.identity_key_id in {self.ingress_key_id, evidence_key_id,
                                            self.permit_key_id, self.approval_key_id,
                                            self.delegation_key_id}
                or self.ingress_key_id in {evidence_key_id, self.permit_key_id,
                                           self.approval_key_id, self.delegation_key_id}
                or not self.trust.verify(admission.signed_body(), admission.signature)):
            raise EmissionError("input admission authority invalid")
        c = inputs.context
        if (not admission.request_id or not admission.permit_nonce or not admission.identity_revision
                or admission.correlation_id != c.correlation_id
                or admission.input_digest != inputs.digest()
                or admission.tenant != c.tenant_id or admission.principal != c.actor.actor_id
                or inputs.assertion.tenant_id != c.tenant_id):
            raise EmissionError("input admission binding mismatch")
        if (type(now_us) is not int or type(admission.issued_at_us) is not int
                or type(admission.expires_at_us) is not int
                or not admission.issued_at_us <= c.now_us <= now_us < admission.expires_at_us
                or admission.expires_at_us - admission.issued_at_us > self.max_age_us):
            raise EmissionError("input admission validity window invalid")
        identity = IdentityVerifier(self.trust, self.identity_key_id)
        if (type(c.actor.producer) is not bool
                or any(not identity.credential_valid(c.actor, cred, now_us)
                       for cred in c.actor.credentials)
                or set(c.actor.roles) != identity.verified_roles(c.actor, now_us)):
            raise EmissionError("actor roles or credentials are not authenticated and current")
        if not VerificationTrustStore(self.trust).authenticate(inputs.assertion):
            raise EmissionError("assertion verification authenticity failed")


def input_json(inputs: DecisionInputs) -> str:
    """Canonical representation suitable for retained JSONB storage."""
    return canonical_bytes(inputs.body()).decode("utf-8")
