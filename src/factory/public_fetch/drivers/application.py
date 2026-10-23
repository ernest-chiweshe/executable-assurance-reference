"""Bounded public HTTP transport for binary media and signed webhooks.

The address policy and pinned connection are shared with CAP-3. Application
requests preserve signed URL bytes and do not apply robots or text-page rules.
All tests inject channels and resolvers; no live destination is needed.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from threading import Timer
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urljoin, urlsplit

from ..contracts import DeadlineBudget
from ..url_policy import (
    URLPolicyError, freeze_public_addresses, parse_public_transport_url,
    require_public_address,
)
from .resolver import DeadlineBoundResolver, os_resolver_worker_factory
from .stdlib import StdlibHttpConnectionFactory

_REDIRECTS = {301, 302, 303, 307, 308}
MEDIA_MAX_BYTES = 512 * 1024 * 1024
WEBHOOK_MAX_BYTES = 1024 * 1024


def _remaining(deadline: DeadlineBudget) -> float:
    value = deadline.remaining_seconds()
    if value <= 0:
        raise TimeoutError("public HTTP deadline exceeded")
    return value


class PublicResponse:
    """File-like response that refuses truncation, oversized bodies and deadlines."""

    def __init__(self, channel: Any, deadline: DeadlineBudget, status: int,
                 declared: int | None, maximum: int) -> None:
        self.status = status
        self._channel = channel
        self._deadline = deadline
        self._declared = declared
        self._maximum = maximum
        self._received = 0
        self._eof = False

    def read(self, size: int = -1) -> bytes:
        """Return a bounded chunk, or refuse before a partial object is adopted."""
        if size == 0 or self._eof:
            return b""
        if size < 0:
            chunks = []
            while chunk := self.read(65536):
                chunks.append(chunk)
            return b"".join(chunks)
        limit = min(size,
                    self._maximum - self._received + 1, 65536)
        chunk = self._channel.read_chunk(
            max_bytes=limit, read_timeout=min(10.0, _remaining(self._deadline)))
        _remaining(self._deadline)
        if not isinstance(chunk, bytes) or len(chunk) > limit:
            raise URLPolicyError("transport exceeded its read allowance")
        self._received += len(chunk)
        if self._received > self._maximum:
            raise URLPolicyError("response exceeds byte limit")
        if self._declared is not None and self._received > self._declared:
            raise URLPolicyError("response exceeds declared length")
        if not chunk:
            self._eof = True
            if self._declared is not None and self._received != self._declared:
                raise URLPolicyError("response ended before declared length")
        return chunk


def _response_length(pairs: tuple[tuple[str, str], ...], maximum: int) -> int | None:
    lengths = [v.strip() for k, v in pairs if k.lower() == "content-length"]
    encodings = [v.strip().lower() for k, v in pairs if k.lower() == "content-encoding"]
    transfers = [v.strip().lower() for k, v in pairs if k.lower() == "transfer-encoding"]
    if len(lengths) > 1 or any(not v.isascii() or not v.isdecimal() for v in lengths):
        raise URLPolicyError("ambiguous response length")
    if len(encodings) > 1 or any(v != "identity" for v in encodings):
        raise URLPolicyError("encoded responses are not supported")
    if transfers and (transfers != ["chunked"] or lengths):
        raise URLPolicyError("ambiguous response framing")
    length = int(lengths[0]) if lengths else None
    if length is not None and length > maximum:
        raise URLPolicyError("response exceeds byte limit")
    return length


@contextmanager
def public_response(url: str, *, method: str = "GET", body: bytes | None = None,
                    headers: Mapping[str, str] | None = None,
                    max_bytes: int = MEDIA_MAX_BYTES, timeout: float = 120.0,
                    resolver: Any = None, connections: Any = None,
                    clock: Any = time.monotonic,
                    before_send: Callable[[], None] | None = None,
                    follow_redirects: bool = True) -> Iterator[PublicResponse]:
    """Open one bounded response using only verified public peers.

    GET redirects are revalidated at each hop, with five hops maximum and no
    HTTPS downgrade. POST redirects are returned without forwarding signed
    payloads. No automatic retry or ambient proxy/authentication is used.
    A supplied final authority check runs after peer validation, immediately
    before each application request is sent.
    """
    if method not in {"GET", "POST"} or max_bytes <= 0:
        raise ValueError("invalid public HTTP request bounds")
    if body is not None and len(body) > WEBHOOK_MAX_BYTES:
        raise URLPolicyError("request exceeds byte limit")
    deadline = DeadlineBudget(timeout, clock)
    resolver = resolver or DeadlineBoundResolver(os_resolver_worker_factory, max_addresses=16)
    connections = connections or StdlibHttpConnectionFactory()
    target = parse_public_transport_url(url)
    for hop in range(6):
        result = resolver.resolve(target.ascii_host, deadline)
        if result.failure:
            raise URLPolicyError("public destination resolution failed")
        approved = freeze_public_addresses(result.addresses, 16)
        channel = connections.open(
            scheme=target.scheme, host=target.ascii_host, port=target.effective_port,
            address=approved[0], connect_timeout=min(5.0, _remaining(deadline)))
        watchdog = None
        try:
            # Observe the real peer before sending any application data.
            if require_public_address(channel.peer_address()) != approved[0]:
                raise URLPolicyError("connected peer differs from approved address")
            watchdog = Timer(_remaining(deadline), channel.abort)
            watchdog.daemon = True
            watchdog.start()
            outbound = {"Host": urlsplit(target.origin).netloc,
                        "User-Agent": "agent-factory-public-http/1",
                        "Accept-Encoding": "identity", "Connection": "close"}
            for key, value in (headers or {}).items():
                receipt_headers = {"idempotency-key", "x-factory-request-digest",
                                   "x-factory-endpoint-digest"}
                if key.lower() in receipt_headers:
                    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                        raise URLPolicyError("receipt header must be a canonical digest")
                elif key.lower() not in {"content-type", "x-factory-signature"}:
                    raise URLPolicyError("header is outside application policy")
                outbound[key] = value
            parts = urlsplit(target.value)
            path = parts.path + ("?" + parts.query if parts.query else "")
            if before_send is not None:
                before_send()
            status, pairs, _ = channel.request_payload(
                method=method, path_and_query=path, body=body, headers=outbound,
                read_timeout=min(10.0, _remaining(deadline)))
            _remaining(deadline)
            declared = _response_length(pairs, max_bytes)
            if method == "GET" and status in _REDIRECTS:
                if not follow_redirects:
                    raise URLPolicyError("redirect is outside this endpoint contract")
                locations = [value for key, value in pairs if key.lower() == "location"]
                if len(locations) != 1 or not locations[0] or hop == 5:
                    raise URLPolicyError("invalid or excessive redirect")
                next_target = parse_public_transport_url(urljoin(target.value, locations[0]))
                if target.scheme == "https" and next_target.scheme != "https":
                    raise URLPolicyError("HTTPS downgrade refused")
                target = next_target
                continue
            if method == "GET" and not 200 <= status < 300:
                raise URLPolicyError("media server returned an unsuccessful status")
            yield PublicResponse(channel, deadline, status, declared, max_bytes)
            return
        finally:
            if watchdog is not None:
                watchdog.cancel()
                watchdog.join()
            channel.close()
    raise URLPolicyError("redirect limit exceeded")
