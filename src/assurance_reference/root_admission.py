"""Commit an approved delegation root, or retain a request-bound refusal."""

from dataclasses import dataclass

from assurance_reference.alerts import AlertJournal
from regulated_core.canonical import digest_hex
from regulated_core.delegation import SignedGrant
from regulated_core.permit import EmissionError
from regulated_core.root_admission_pg import RootAdmissionVerifier, admit_root_on


@dataclass(frozen=True)
class RootAdmissionResult:
    status: str
    grant: SignedGrant | None = None
    alert_id: str | None = None


class ReviewedRootAdmission:
    """Host composition over retained core verification; no migration or policy override.

    The host supplies authenticated tenant/review/nonce references and all pinned
    authorities. A root grants no effect permit. Receipt loss at commit is UNKNOWN;
    a later authenticated retry must consult the retained admission. Alert-storage
    failure propagates rather than claiming that an alert reached an operator.
    """

    def __init__(self, *, pool, verifier: RootAdmissionVerifier, evidence_signer,
                 delegation_signer, alerts: AlertJournal):
        self.pool = pool
        self.verifier = verifier
        self.evidence_signer = evidence_signer
        self.delegation_signer = delegation_signer
        self.alerts = alerts

    def admit(self, *, tenant: str, review_id: str, nonce: str) -> RootAdmissionResult:
        request_hash = digest_hex({
            "schema": "executable-assurance/root-admission-request/v1",
            "tenant": tenant, "review_id": review_id, "nonce": nonce,
        })
        try:
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
                conn.execute("SET LOCAL lock_timeout = '5s'")
                conn.execute("SET LOCAL statement_timeout = '10s'")
                grant = admit_root_on(
                    conn, tenant, review_id, nonce=nonce, verifier=self.verifier,
                    evidence_signer=self.evidence_signer,
                    delegation_signer=self.delegation_signer,
                )
            return RootAdmissionResult("admitted", grant=grant)
        except EmissionError:
            code, status = "ADMISSION_REFUSED", "refused"
        except Exception:
            code, status = "AUTHORIZATION_UNCERTAIN", "unknown"
        alert_id = self.alerts.append_refusal(
            tenant_id=tenant, request_hash=request_hash, decision_hash=None, code=code,
        )
        return RootAdmissionResult(status, alert_id=alert_id)
