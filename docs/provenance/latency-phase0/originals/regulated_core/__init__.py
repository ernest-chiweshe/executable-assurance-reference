"""regulated_core (consolidated) — one authority core for regulated and non-regulated verticals.

source review substrate (real Ed25519, data-class + calibration-provenance modelling, real Factory reuse)
+ integration review grafts (single enforced `authorize_and_emit`, `requirement_digest` binding, lean base
`Assertion`) + the five security fixes. See README.md and COMPLIANCE-BOUNDARY.md.
"""
from .canonical import canonical_bytes, digest_hex, CanonicalizationError
from .signing import (
    ALG_ECDSA_P384, ALG_ED25519, EcdsaP384Signer, Ed25519Signer, Signature, Signer, TrustDirectory,
)
from .models import (
    Action, ActionEffect, Annotation, ApprovalRequirement, Assertion, Actor, ConfidenceEvidence,
    Credential, DataClass, Decision, DecisionKind, DecisionRecord, Outcome, PolicyContext,
    PolicyRef, ProducerLineage, SignedVerification, VerificationResult,
)
from .verification import VerificationTrustStore, sign_verification
from .identity import IdentityVerifier, issue_credential
from .registry import ConsequencePolicy, PolicyRegistry
from .evidence import DecisionRecorder, SignedDecisionEnvelope, verify_envelope
from .approval import ApprovalWorkflow, ApprovalCertificate, ApprovalGrant, ApprovalRequest, ApprovalError
from .permit import EmissionAuthority, EmissionPermit, SignedEmissionPermit, InMemoryPermitUseStore, EmissionError
from .preflight import IntendedUse, IntendedUseRegistry, PreflightAuthority, GenerationCapability, PreflightError
from .production_gate import AssuranceEvidence, ProductionGate, ProductionReadinessError, MANDATORY
from .engine import RegulatedEngine, EmissionOutcome
from .verticals import HealthPolicy, FinancePolicy, CoursePolicy

__all__ = [
    "canonical_bytes", "digest_hex", "CanonicalizationError", "Signature", "Signer", "Ed25519Signer",
    "EcdsaP384Signer", "ALG_ED25519", "ALG_ECDSA_P384",
    "TrustDirectory", "Action", "ActionEffect", "Annotation", "ApprovalRequirement", "Assertion", "Actor",
    "ConfidenceEvidence", "Credential", "DataClass", "Decision", "DecisionKind", "DecisionRecord", "Outcome",
    "PolicyContext", "PolicyRef", "ProducerLineage", "SignedVerification", "VerificationResult",
    "VerificationTrustStore", "sign_verification", "IdentityVerifier", "issue_credential", "ConsequencePolicy",
    "PolicyRegistry", "DecisionRecorder", "SignedDecisionEnvelope", "verify_envelope", "ApprovalWorkflow",
    "ApprovalCertificate", "ApprovalGrant", "ApprovalRequest", "ApprovalError", "EmissionAuthority", "EmissionPermit",
    "SignedEmissionPermit", "InMemoryPermitUseStore", "EmissionError", "IntendedUse", "IntendedUseRegistry",
    "PreflightAuthority", "GenerationCapability", "PreflightError", "AssuranceEvidence", "ProductionGate",
    "ProductionReadinessError", "MANDATORY", "RegulatedEngine", "EmissionOutcome", "HealthPolicy", "FinancePolicy",
    "CoursePolicy",
]
