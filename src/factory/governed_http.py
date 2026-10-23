"""Receipt-bound HTTP delivery behind the existing governed egress target.

A registered destination implements the explicit receipt-v1 contract. Its
acknowledgement binds the key, endpoint configuration, approved request and
payload. Uncertainty is retained; neither this adapter nor status lookup retries
POST. Ordinary webhooks are not treated as receipt-capable destinations.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit

from factory.public_fetch.drivers.application import WEBHOOK_MAX_BYTES, public_response
from factory.public_fetch.url_policy import parse_public_transport_url
from regulated_core.canonical import canonical_bytes
from regulated_core.choke_points import EGRESS_OPERATION, idempotency_key
from regulated_core.governance_targets import FinalCheckRefused, GovernedChange
from regulated_core.target import Outcome

PROFILE = "factory/http-receipt/v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class HttpEndpoint:
    """Host-registered immutable destination and its same-origin receipt API."""

    tenant_id: str
    endpoint_id: str
    delivery_url: str
    receipt_url: str
    max_payload_bytes: int = WEBHOOK_MAX_BYTES

    def __post_init__(self) -> None:
        if any(
            not value or value != value.strip() or len(value) > 256
            for value in (self.tenant_id, self.endpoint_id)
        ):
            raise ValueError("endpoint needs bounded tenant and endpoint identities")
        urls = [
            parse_public_transport_url(value) for value in (self.delivery_url, self.receipt_url)
        ]
        if any(url.scheme != "https" for url in urls) or urls[0].origin != urls[1].origin:
            raise ValueError("receipt endpoints require one HTTPS origin")
        if any(urlsplit(url.value).query or urlsplit(url.value).fragment for url in urls):
            raise ValueError("endpoint configuration must not contain query authority")
        if (
            type(self.max_payload_bytes) is not int
            or not 0 < self.max_payload_bytes <= WEBHOOK_MAX_BYTES
        ):
            raise ValueError("invalid endpoint payload bound")

    @property
    def digest(self) -> str:
        return sha256(canonical_bytes({"profile": PROFILE, **asdict(self)})).hexdigest()


@dataclass(frozen=True)
class HttpAttempt:
    """Retained request identity; no credentials or payload bytes are stored here."""

    tenant_id: str
    key: str
    endpoint_id: str
    endpoint_digest: str
    request_digest: str
    payload_digest: str
    nonce: str

    def __post_init__(self) -> None:
        if not all(
            _HEX.fullmatch(value)
            for value in (self.key, self.endpoint_digest, self.request_digest, self.payload_digest)
        ):
            raise ValueError("delivery identity needs canonical digests")
        if not self.tenant_id or not self.endpoint_id or not self.nonce:
            raise ValueError("delivery identity is incomplete")


class AttemptStore(Protocol):
    def record(self, attempt: HttpAttempt) -> bool:
        """Retain once after matching the prepared governance event."""
        ...

    def get(self, tenant_id: str, key: str) -> HttpAttempt | None: ...


@dataclass(frozen=True)
class HttpReply:
    status: int
    body: bytes


class RequestPort(Protocol):
    def __call__(
        self,
        url: str,
        *,
        method: str,
        body: bytes | None,
        headers: Mapping[str, str],
        before_send: Callable[[], None] | None,
    ) -> HttpReply: ...


def public_http_request(
    url: str,
    *,
    method: str,
    body: bytes | None,
    headers: Mapping[str, str],
    before_send: Callable[[], None] | None,
) -> HttpReply:
    """Use the existing public-address policy, peer pinning and bounded transport."""
    with public_response(
        url,
        method=method,
        body=body,
        headers=headers,
        before_send=before_send,
        follow_redirects=False,
        max_bytes=16_384,
        timeout=10.0,
    ) as response:
        return HttpReply(response.status, response.read())


class DeliveryUnconfirmed(RuntimeError):
    """An attempt may have reached the destination; preserve UNKNOWN."""


def _receipt_matches(reply: HttpReply, attempt: HttpAttempt) -> bool:
    if not 200 <= reply.status < 300 or len(reply.body) > 16_384:
        return False
    try:
        value: object = json.loads(reply.body)
    except (ValueError, UnicodeDecodeError):
        return False
    return value == {
        "schema": PROFILE,
        "key": attempt.key,
        "endpoint_digest": attempt.endpoint_digest,
        "request_digest": attempt.request_digest,
        "payload_digest": attempt.payload_digest,
        "outcome": "committed",
    }


class HttpEgressTransport:
    """One immutable receipt-capable destination, invoked by egress_target only.

    The store anchors a key to the original configuration across restarts. A
    changed configuration cannot resolve an older attempt. Receipt absence,
    malformed replies and unavailable status all remain UNKNOWN; only a bound
    durable destination receipt establishes COMMITTED.
    """

    def __init__(
        self,
        endpoint: HttpEndpoint,
        store: AttemptStore,
        request: RequestPort = public_http_request,
    ) -> None:
        self._endpoint, self._store, self._request = endpoint, store, request

    def endpoint(self, tenant_id: str, endpoint_id: str) -> str:
        value = self._endpoint
        return (
            value.digest
            if (tenant_id, endpoint_id) == (value.tenant_id, value.endpoint_id)
            else "absent"
        )

    def send(self, change: GovernedChange, key: str) -> None:
        endpoint = self._endpoint
        if (change.tenant_id, change.subject, change.approved_prior, change.operation) != (
            endpoint.tenant_id,
            endpoint.endpoint_id,
            endpoint.digest,
            EGRESS_OPERATION,
        ):
            raise FinalCheckRefused("endpoint registration does not match the approved request")
        if key != idempotency_key(
            change.tenant_id, change.operation, change.nonce, change.change_digest
        ):
            raise FinalCheckRefused("delivery identity differs from the prepared request")
        payload = change.change.get("payload")
        media_type = change.change.get("media_type")
        if not isinstance(payload, str) or not isinstance(media_type, str):
            raise FinalCheckRefused("delivery requires text bytes and an explicit media type")
        body = payload.encode("utf-8")
        if not body or len(body) > endpoint.max_payload_bytes:
            raise FinalCheckRefused("payload exceeds the registered endpoint bound")
        attempt = HttpAttempt(
            change.tenant_id,
            key,
            endpoint.endpoint_id,
            endpoint.digest,
            change.change_digest,
            sha256(body).hexdigest(),
            change.nonce,
        )
        change.final_check()
        if not self._store.record(attempt):
            raise DeliveryUnconfirmed("delivery is already recorded or preparation is unavailable")
        reply = self._request(
            endpoint.delivery_url,
            method="POST",
            body=body,
            headers={
                "Content-Type": media_type,
                "Idempotency-Key": key,
                "X-Factory-Request-Digest": attempt.request_digest,
                "X-Factory-Endpoint-Digest": attempt.endpoint_digest,
            },
            before_send=change.final_check,
        )
        if not _receipt_matches(reply, attempt):
            raise DeliveryUnconfirmed("destination has not supplied a bound committed receipt")

    def status(self, tenant_id: str, key: str) -> Outcome:
        endpoint = self._endpoint
        if tenant_id != endpoint.tenant_id or not _HEX.fullmatch(key):
            return Outcome.UNKNOWN
        try:
            attempt = self._store.get(tenant_id, key)
            if attempt is None or (attempt.endpoint_id, attempt.endpoint_digest) != (
                endpoint.endpoint_id,
                endpoint.digest,
            ):
                return Outcome.UNKNOWN
            reply = self._request(
                endpoint.receipt_url.rstrip("/") + "/" + key,
                method="GET",
                body=None,
                headers={},
                before_send=None,
            )
            return Outcome.COMMITTED if _receipt_matches(reply, attempt) else Outcome.UNKNOWN
        except Exception:
            # Status is an observation, never permission to resend after a failure.
            return Outcome.UNKNOWN
