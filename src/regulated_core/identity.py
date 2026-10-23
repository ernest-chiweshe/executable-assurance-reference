"""Credentialed identity: roles/licences are SIGNED attestations, not claims on an object.

An actor's effective roles come only from credentials that (a) are signed by the trusted
identity authority, (b) are bound to that actor and tenant, and (c) have not expired. This is
what makes "a clinician approved" mean a verified clinician, not a string in a form.
"""
from __future__ import annotations

from .models import Actor, Credential
from .signing import Signer, TrustDirectory


def issue_credential(
    identity_signer: Signer, *, actor_id: str, tenant_id: str, kind: str,
    expires_at_us: int, jurisdiction: str = "*", scope: str = "*",
) -> Credential:
    body = {
        "schema": "regulated/credential/v1", "kind": kind, "jurisdiction": jurisdiction,
        "scope": scope, "subject_actor_id": actor_id, "tenant_id": tenant_id,
        "expires_at_us": expires_at_us,
    }
    return Credential(
        kind=kind, jurisdiction=jurisdiction, scope=scope, subject_actor_id=actor_id,
        tenant_id=tenant_id, expires_at_us=expires_at_us, signature=identity_signer.sign(body),
    )


class IdentityVerifier:
    def __init__(self, trust: TrustDirectory, identity_key_id: str) -> None:
        self._trust = trust
        self._identity = identity_key_id

    def _credential_ok(self, actor: Actor, c: Credential, now_us: int) -> bool:
        return self.credential_valid(actor, c, now_us)

    def credential_valid(self, actor: Actor, c: Credential, now_us: int) -> bool:
        """Verify the credential signature, exact principal/tenant and expiry."""
        return (
            c.subject_actor_id == actor.actor_id
            and c.tenant_id == actor.tenant_id
            and now_us < c.expires_at_us
            and c.signature.key_id == self._identity
            and self._trust.verify(c.signed_body(), c.signature)
        )

    def verified_roles(self, actor: Actor, now_us: int) -> set[str]:
        roles: set[str] = set()
        for c in actor.credentials:
            if self.credential_valid(actor, c, now_us) and c.kind.startswith("role:"):
                roles.add(c.kind[len("role:"):])
        return roles
