"""CAP-3 §5.1/§5.2: the qualified stdlib HTTP driver and RFC 9309 robots policy.

This is the ONLY driver that touches the network, and even here every socket is
behind an injected `HttpConnectionFactory` seam so free tests open nothing. The
driver orchestrates the Half A security primitives — `require_public_address`,
`freeze_public_addresses`, `canonicalize_redirect_url`/`redirect_allowed`,
`robots_target_digest` — rather than re-implementing them, and emits one fully
cross-bound `DriverObservation` per fetch.

Per external hop (initial body, robots, each redirect) it: (1) takes the canonical
URL + policy; (2) resolves the host once through the deadline-bound resolver;
(3) refuses the whole hop if any answer is non-public; (4) connects one pinned
approved address while preserving the canonical host for HTTP `Host`/HTTPS SNI;
(5) reads back and records the actual peer BEFORE accepting data; (6) disables
redirects/proxies/env-proxy/netrc/cookies/ambient auth in the connection factory
contract; (7) sends only fixed server headers; (8) sends `Accept-Encoding:
identity` and rejects any other content coding; (9) uses fixed GET and follows
only 301/302/303/307/308 under the law-19 origin rules; (10) streams under
independent declared-length, actual-wire and aggregate bounds and never adopts a
partial body.

Robots (§5.2) is fetched through the same qualified path before any ordinary
body, parsed under RFC 9309 with the exact line/rule/group ceilings, and mapped
to a closed decision; a missing body maps through the exact status→absence
matrix (`unavailable_allow` for 404/410, `access_refused_disallow` for 401/403,
`rate_limited_disallow` for 429, `unreachable_disallow` for 5xx/network, etc.).
Robots content is untrusted bytes: it can never supply a URL, header or code
path.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, cast

from ..contracts import (
    DeadlineBudget,
    DriverObservation,
    InfrastructureMeteringState,
    InitialPacingGrant,
    OperationEvidence,
    OperationKind,
    OriginPacer,
    PeerEvidence,
    PublicFetchInvocation,
    PublicFetchOutcome,
    RedirectHop,
    ResourcePurpose,
    RobotsAbsenceReason,
    RobotsCacheReader,
    RobotsCacheUse,
    RobotsDecision,
    RobotsObservation,
    RobotsOutcome,
)
from ..url_policy import (
    CanonicalURL,
    URLPolicyError,
    canonicalize_observed_url,
    canonicalize_redirect_url,
    freeze_public_addresses,
)
from ..url_policy import robots_target_digest as _robots_target_digest
from .resolver import DeadlineBoundResolver

# The fixed, server-owned request headers. NEVER Authorization, Cookie,
# Proxy-Authorization or any caller header; Accept-Encoding is identity-only so
# no v1 decompressor or transparent client decoding ever exists.
# v1 hard per-resource buffer maxima (WO §5.1): a text/page body may never
# exceed 2 MiB nor an image 8 MiB on the WIRE, whatever the policy ceiling says.
_PAGE_HARD_MAX = 2 * 1024 * 1024
_IMAGE_HARD_MAX = 8 * 1024 * 1024
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class DriverRefused(Exception):
    """A bounded, safe pre/mid-transport refusal carrying one closed outcome.

    A refusal that prevents a connection (non-public address, wrong peer, DNS
    failure, deadline) fails the WHOLE fetch with this outcome and produces no
    robots evidence — a `RobotsObservation` can only exist for a hop that
    actually connected and returned a status.
    """

    def __init__(self, outcome: PublicFetchOutcome, safe_detail_code: str) -> None:
        super().__init__(safe_detail_code)
        self.outcome = outcome
        self.safe_detail_code = safe_detail_code


@dataclass(frozen=True, slots=True)
class WireResponse:
    """One already-read HTTP response from the qualified connection seam.

    `connected_address` is the peer the factory ACTUALLY connected to — the
    driver verifies it is inside the frozen approved set BEFORE accepting any
    of `body`. `headers` is a case-insensitive multimap flattened to a tuple of
    (lowercase-name, value) pairs so duplicate fields (e.g. two Content-Encoding)
    are visible, never silently merged.
    """

    status: int
    header_pairs: tuple[tuple[str, str], ...]
    connected_address: str
    body_chunks: tuple[bytes, ...] = ()
    declared_length: int | None = None
    # the EXACT number of bytes pulled off the wire for this response — charged
    # to the aggregate byte authority whatever the validation outcome (R11).
    observed_wire_bytes: int = 0
    # a size-bound breach the driver DETECTED without reading past authority
    # (resource ceiling exceeded, or an unframed body that filled the exact
    # remaining aggregate without a proven EOF) — a closed TOO_LARGE detail code.
    overflow_code: str | None = None

    def header_values(self, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(value for key, value in self.header_pairs if key == lowered)


class HttpConnection(Protocol):
    """One qualified, already-opened connection to ONE approved address.

    The contract is TWO-PHASE so the driver can enforce every pre-body bound at
    the honest moment:

    - `peer_address()` reports the ACTUAL connected peer of the ACTIVE socket
      (the TLS socket for https) the instant the connection is open — BEFORE any
      request is sent — so a DNS rebinding that repoints the socket is caught
      before data. An unobservable peer raises `OSError` (never a guess).
    - `request()` sends the one bodyless GET and returns status + header pairs +
      declared length WITHOUT reading a single body byte, so the driver can
      close the header set against the policy ceilings first.
    - `read_body()` then streams at most `max_bytes` (+1 to detect overflow).

    Each phase takes its own freshly-sampled `read_timeout`, so no phase can
    outlive the remaining total deadline sampled BEFORE that phase started.
    """

    def peer_address(self) -> str: ...

    def request(self, *, host: str, path_and_query: str,
                headers: Mapping[str, str], read_timeout: float,
                ) -> tuple[int, tuple[tuple[str, str], ...], int | None]: ...

    def read_body(self, *, max_bytes: int, read_timeout: float) -> bytes: ...

    def close(self) -> None: ...


class HttpConnectionFactory(Protocol):
    """Opens one connection to an EXACT approved address, preserving the
    canonical host for `Host`/SNI. Implementations MUST disable automatic
    redirects, proxies, environment proxy discovery, netrc, cookies and every
    ambient credential. Free tests inject a fake that opens no socket."""

    def open(self, *, scheme: str, host: str, port: int, address: str,
             connect_timeout: float) -> HttpConnection: ...


# -- the ONE live-transport path (C1: networking lives under drivers/) --------
# `StdlibHttpConnectionFactory` is the only socket path; it lives here in the
# already-pinned driver module. Free tests inject a fake `_RawChannel` (or the
# fake `HttpConnection` above), so no test opens a socket (THE STOP).

# A hard read backstop; the driver additionally bounds every read by the response
# ceiling AND the remaining byte authority via `max_bytes`.
_MAX_WIRE_READ = 64 * 1024 * 1024
# Body is pulled in bounded chunks so a mid-body failure keeps its partial count.
_READ_CHUNK = 64 * 1024


class LiveTransportError(RuntimeError):
    """An invariant on the live socket path was violated (never on the happy
    path: the driver only ever hands this factory an http/https scheme)."""


class TransportInterrupted(Exception):
    """A read failed PART-WAY through the body. Carries the exact count of bytes
    already pulled off the wire so the driver charges the aggregate byte
    authority for them (R11) even though no artifact is adoptable."""

    def __init__(self, observed_bytes: int) -> None:
        super().__init__(f"transport interrupted after {observed_bytes} bytes")
        self.observed_bytes = observed_bytes


class _SocketChannel:
    """The real socket+TLS+http.client channel implementing `HttpConnection`.

    `sock` is the ACTIVE socket — the TLS-wrapped socket for https (the pre-wrap
    raw socket is DETACHED by `wrap_socket` and can no longer answer
    `getpeername`), the raw socket for http. The peer is therefore always read
    from the socket that will actually carry bytes; if the OS cannot report it,
    the `OSError` propagates and the driver refuses before any request."""

    def __init__(self, sock: object, conn: object) -> None:
        self._sock = sock
        self._conn = conn
        self._pending: object | None = None

    def peer_address(self) -> str:
        return str(self._sock.getpeername()[0])  # type: ignore[attr-defined]

    def request(self, *, host: str, path_and_query: str,
                headers: Mapping[str, str], read_timeout: float,
                ) -> tuple[int, tuple[tuple[str, str], ...], int | None]:
        # `_conn` is an `http.client.HTTP(S)Connection` in production (duck-typed
        # so the channel's logic is provable with stubs and no socket).
        # the head phase gets its own freshly-sampled deadline slice
        self._sock.settimeout(read_timeout)  # type: ignore[attr-defined]
        # http.client never follows redirects, reads netrc/cookies or discovers
        # proxies; only the fixed headers and a bodyless GET are sent.
        # `getresponse()` parses status + headers ONLY — no body byte is read
        # until the driver has closed the header set against the policy.
        self._conn.request(  # type: ignore[attr-defined]
            "GET", path_and_query or "/", headers=dict(headers))
        response = self._conn.getresponse()  # type: ignore[attr-defined]
        self._pending = response
        header_pairs = tuple(
            (name.lower(), value) for name, value in response.getheaders())
        declared = response.getheader("Content-Length")
        declared_length = (int(declared.strip())
                           if declared is not None and declared.strip().isdigit()
                           else None)
        return int(response.status), header_pairs, declared_length

    def request_payload(self, *, method: str, path_and_query: str,
                        headers: Mapping[str, str], body: bytes | None,
                        read_timeout: float,
                        ) -> tuple[int, tuple[tuple[str, str], ...], int | None]:
        """Send one explicit application request without redirects or proxies."""
        if method not in {"GET", "POST"}:
            raise LiveTransportError("unsupported application method")
        cast(Any, self._sock).settimeout(read_timeout)
        cast(Any, self._conn).request(method, path_and_query or "/", body=body,
                           headers=dict(headers))
        response = cast(Any, self._conn).getresponse()
        self._pending = response
        pairs = tuple((name.lower(), value) for name, value in response.getheaders())
        length = response.getheader("Content-Length")
        return int(response.status), pairs, int(length) if length and length.isdigit() else None

    def read_chunk(self, *, max_bytes: int, read_timeout: float) -> bytes:
        """Read at most one bounded chunk so the caller can resample its deadline."""
        if self._pending is None:
            raise LiveTransportError("body read before response headers")
        cast(Any, self._sock).settimeout(read_timeout)
        return bytes(cast(Any, self._pending).read1(min(max_bytes, _READ_CHUNK)))

    def abort(self) -> None:
        """Interrupt blocked reads at an application's absolute deadline."""
        try:
            cast(Any, self._sock).shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            self.close()

    def read_body(self, *, max_bytes: int, read_timeout: float) -> bytes:
        assert self._pending is not None, "read_body before request"
        # the body phase re-samples its own deadline slice; +1 so the driver
        # detects overflow instead of silently truncating at the bound. Read in
        # chunks so a mid-body failure preserves the partial count (R11): the
        # bytes already on the wire are charged, but the partial is never
        # returned as an adoptable artifact.
        import http.client

        # Read EXACTLY up to `max_bytes` — no hidden +1. The DRIVER decides
        # whether to ask for an overflow-detection sentinel byte (by passing
        # cap+1) based on which bound binds, so an aggregate-bound read never
        # pulls an unauthorized byte off the wire.
        self._sock.settimeout(read_timeout)  # type: ignore[attr-defined]
        limit = min(max_bytes, _MAX_WIRE_READ)
        chunks: list[bytes] = []
        got = 0
        while got < limit:
            try:
                chunk = self._pending.read(  # type: ignore[attr-defined]
                    min(_READ_CHUNK, limit - got))
            except http.client.IncompleteRead as exc:
                # a truncated Content-Length transfer: the already-received bytes
                # live in `.partial` and DID touch the wire — charge them.
                raise TransportInterrupted(got + len(exc.partial)) from exc
            except OSError as exc:
                raise TransportInterrupted(got) from exc
            if not chunk:
                break
            chunks.append(bytes(chunk))
            got += len(chunk)
        return b"".join(chunks)

    def close(self) -> None:
        try:
            self._conn.close()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass


class StdlibHttpConnectionFactory(HttpConnectionFactory):
    """Live `http.client` transport pinned to one approved address. Connects the
    socket to the EXACT approved address, then (for HTTPS) wraps it with the
    canonical host as SNI + `CERT_REQUIRED`, so DNS rebinding cannot repoint the
    connection while cert verification still binds the real host. No proxy /
    env-proxy / netrc / cookie / redirect behavior exists. `connect` is an
    injectable low-level connector (a test supplies a fake `HttpConnection`;
    production uses the real socket wiring)."""

    def __init__(self,
                 connect: "Callable[..., HttpConnection] | None" = None) -> None:
        self._connect = connect or self._connect_socket

    def open(self, *, scheme: str, host: str, port: int, address: str,
             connect_timeout: float) -> HttpConnection:
        return self._connect(scheme=scheme, host=host, port=port,
                             address=address, connect_timeout=connect_timeout)

    @staticmethod
    def _connect_socket(*, scheme: str, host: str, port: int, address: str,
                        connect_timeout: float) -> HttpConnection:
        import http.client

        if scheme not in ("http", "https"):
            raise LiveTransportError("unsupported scheme for transport")
        expires = time.monotonic() + connect_timeout
        raw = socket.create_connection((address, port), timeout=connect_timeout)
        conn: http.client.HTTPConnection
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            try:
                remaining = expires - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("pinned connection deadline exceeded")
                raw.settimeout(remaining)
                tls = context.wrap_socket(raw, server_hostname=host)
            except BaseException:
                raw.close()
                raise
            conn = http.client.HTTPSConnection(host, port)
            conn.auto_open = 0
            conn.sock = tls
            # the ACTIVE socket is the TLS socket: peer + timeouts live there
            return _SocketChannel(tls, conn)
        conn = http.client.HTTPConnection(host, port)
        conn.auto_open = 0
        conn.sock = raw
        return _SocketChannel(raw, conn)


# -- RFC 9309 robots parsing (§5.2) -------------------------------------------


@dataclass(frozen=True, slots=True)
class _RobotsRule:
    allow: bool
    pattern: str


@dataclass(frozen=True, slots=True)
class RobotsRuleset:
    """The parsed groups applicable to our product token, or a parse refusal."""

    rules: tuple[_RobotsRule, ...]
    parsed: bool  # False => structural exhaustion/invalid => uncertain_disallow


def parse_robots(content: bytes, product_token: str, *,
                 max_lines: int, max_bytes_per_line: int,
                 max_rules: int, max_groups: int) -> RobotsRuleset:
    """Parse RFC 9309 bytes under the closed ceilings. Any bound breach or
    invalid UTF-8 returns `parsed=False` (the caller maps that to
    `uncertain_disallow`). Unknown directives are ignored while structure holds.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return RobotsRuleset((), False)
    lines = text.splitlines()
    if len(lines) > max_lines:
        return RobotsRuleset((), False)
    token = product_token.lower()
    groups = 0
    # A group is one or more consecutive user-agent lines followed by rules.
    # RFC 9309 §2.2.1 group SELECTION: if any group names our specific product
    # token, ONLY the specific group(s) apply; wildcard (`*`) groups are the
    # FALLBACK when no specific group matched — their rules never merge with a
    # specific group's (a merged pool would let a longer wildcard prohibition
    # override a specific allow via longest-match).
    current_agents: list[str] = []
    starting_group = False
    group_specific = False
    group_wildcard = False
    specific_matched = False
    specific_rules: list[_RobotsRule] = []
    wildcard_rules: list[_RobotsRule] = []
    rule_count = 0
    for raw_line in lines:
        if len(raw_line.encode("utf-8")) > max_bytes_per_line:
            return RobotsRuleset((), False)
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue  # unknown/structureless directive: ignore, structure holds
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()
        if field_name == "user-agent":
            if not starting_group:
                # a user-agent line begins a fresh group boundary
                current_agents = []
                starting_group = True
                groups += 1
                if groups > max_groups:
                    return RobotsRuleset((), False)
            current_agents.append(value.lower())
            group_specific = any(agent and agent != "*" and agent in token
                                 for agent in current_agents)
            group_wildcard = any(agent == "*" for agent in current_agents)
            if group_specific:
                # a matched specific group SELECTS the specific tier even when
                # it carries no rules (an empty specific group = allow all)
                specific_matched = True
            continue
        starting_group = False
        if field_name in ("allow", "disallow"):
            rule_count += 1
            if rule_count > max_rules:
                return RobotsRuleset((), False)
            # RFC 9309 §2.2.2: an EMPTY Allow/Disallow value imposes no rule (an
            # empty Disallow means "allow all", never "disallow everything"); it
            # is counted but never collected as a zero-length match.
            if value:
                if group_specific:
                    specific_rules.append(_RobotsRule(field_name == "allow", value))
                elif group_wildcard:
                    wildcard_rules.append(_RobotsRule(field_name == "allow", value))
        # every other directive is ignored while structure stays valid
    chosen = specific_rules if specific_matched else wildcard_rules
    return RobotsRuleset(tuple(chosen), True)


# RFC 3986 unreserved octets: a percent-encoding of any of these is equivalent to
# the literal character and MUST be decoded before matching (RFC 9309 §2.2.2).
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _percent_normalize(value: str) -> str:
    """RFC 9309 §2.2.2 octet normalization: a percent-encoded UNRESERVED octet is
    decoded to its literal character, and every other valid escape is upper-cased,
    so equivalent encodings compare equal (`%7E` == `~`, `%2f` == `%2F`). A
    malformed `%` sequence is left verbatim."""
    out: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if (char == "%" and index + 3 <= length
                and value[index + 1] in _HEX_DIGITS
                and value[index + 2] in _HEX_DIGITS):
            decoded = chr(int(value[index + 1:index + 3], 16))
            if decoded in _UNRESERVED:
                out.append(decoded)
            else:
                out.append("%" + value[index + 1:index + 3].upper())
            index += 3
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _rule_matches(pattern: str, target: str) -> int:
    """Return the match length (RFC 9309 longest-match precedence), or -1."""
    pattern = _percent_normalize(pattern)
    target = _percent_normalize(target)
    must_end = pattern.endswith("$")
    core = pattern[:-1] if must_end else pattern
    segments = core.split("*")
    pos = 0
    first = True
    for segment in segments:
        if segment == "":
            first = False
            continue
        if first:
            if not target.startswith(segment):
                return -1
            pos = len(segment)
            first = False
        else:
            found = target.find(segment, pos)
            if found < 0:
                return -1
            pos = found + len(segment)
    if must_end and pos != len(target):
        return -1
    return len(core.replace("*", ""))


def robots_decision(ruleset: RobotsRuleset, path_and_query: str) -> RobotsDecision:
    """Apply RFC 9309 longest-match precedence; ties resolve to ALLOW."""
    if not ruleset.parsed:
        return RobotsDecision.DISALLOW
    best_len = -1
    best_allow = True
    for rule in ruleset.rules:
        matched = _rule_matches(rule.pattern, path_and_query)
        if matched > best_len or (matched == best_len and rule.allow):
            if matched >= 0:
                best_len = matched
                best_allow = rule.allow
    if best_len < 0:
        return RobotsDecision.ALLOW  # no rule matches => allowed
    return RobotsDecision.ALLOW if best_allow else RobotsDecision.DISALLOW


# -- the status → robots absence/outcome mapping (§5.2) -----------------------

def _robots_absence(status: int | None) -> tuple[RobotsAbsenceReason, RobotsOutcome,
                                                 RobotsDecision]:
    if status in (404, 410):
        return (RobotsAbsenceReason.UNAVAILABLE_NO_BODY,
                RobotsOutcome.UNAVAILABLE_ALLOW, RobotsDecision.ALLOW)
    if status in (401, 403):
        return (RobotsAbsenceReason.ACCESS_REFUSED,
                RobotsOutcome.ACCESS_REFUSED_DISALLOW, RobotsDecision.DISALLOW)
    if status == 429:
        return (RobotsAbsenceReason.RATE_LIMITED,
                RobotsOutcome.RATE_LIMITED_DISALLOW, RobotsDecision.DISALLOW)
    if status in (204, 304):
        return (RobotsAbsenceReason.NO_BODY_STATUS,
                RobotsOutcome.UNCERTAIN_DISALLOW, RobotsDecision.DISALLOW)
    if status is not None and 500 <= status <= 599:
        return (RobotsAbsenceReason.SERVER_ERROR,
                RobotsOutcome.SERVER_ERROR_DISALLOW, RobotsDecision.DISALLOW)
    if status is not None and 100 <= status <= 499:
        # any other observed HTTP status (e.g. 300/305/306/418/451): a real
        # response with no usable robots body — a closed uncertain-disallow bound
        # to the exact status, never mislabelled as a network failure (which the
        # contract requires to carry a null status).
        return (RobotsAbsenceReason.OTHER_HTTP_STATUS,
                RobotsOutcome.UNCERTAIN_DISALLOW, RobotsDecision.DISALLOW)
    return (RobotsAbsenceReason.NETWORK_UNREACHABLE,
            RobotsOutcome.UNREACHABLE_DISALLOW, RobotsDecision.DISALLOW)



def _path_and_query(url: CanonicalURL) -> str:
    from urllib.parse import urlsplit
    parts = urlsplit(url.value)
    return parts.path + (f"?{parts.query}" if parts.query else "")


def _robots_url(url: CanonicalURL) -> str:
    # §5.2: the robots URL is the authority's lowercase /robots.txt.
    return f"{url.scheme}://{url.ascii_host}:{url.effective_port}/robots.txt"


class StdlibPublicFetchDriver:
    """The qualified `PublicFetchDriver`. Injected resolver/clock/connection
    factory make every free test socketless."""

    driver_id: str
    driver_revision: str
    qualification_digest: str

    def __init__(self, *, driver_id: str, driver_revision: str,
                 qualification_digest: str,
                 resolver: DeadlineBoundResolver,
                 connection_factory: HttpConnectionFactory,
                 clock: Callable[[], datetime]) -> None:
        self.driver_id = driver_id
        self.driver_revision = driver_revision
        self.qualification_digest = qualification_digest
        self._resolver = resolver
        self._factory = connection_factory
        self._clock = clock

    # -- request shaping -----------------------------------------------------

    @staticmethod
    def _accept_header(purpose: ResourcePurpose) -> str:
        if purpose is ResourcePurpose.IMAGE:
            return "image/png,image/jpeg,image/gif,image/webp"
        return "text/html,text/plain"

    def _fixed_headers(self, host: str, purpose: ResourcePurpose,
                       product_token: str) -> dict[str, str]:
        # ONLY server-owned headers. The product token is a substring of the
        # UA (RFC 9309 matching). No Authorization/Cookie/Proxy-Authorization
        # or any caller-provided header can appear.
        return {
            "Host": host,
            "User-Agent": product_token,
            "Accept": self._accept_header(purpose),
            "Accept-Encoding": "identity",
        }

    @staticmethod
    def _lease_digest(lease: object) -> str:
        return str(getattr(lease, "lease_id_digest"))

    @staticmethod
    def _content_type(response: "WireResponse") -> str:
        values = response.header_values("content-type")
        if len(values) != 1:
            return ""
        return values[0].split(";", 1)[0].strip().lower()

    def _check_encoding(self, response: "WireResponse") -> None:
        # §5.1 step 8: Accept-Encoding identity was sent; the response may carry
        # no Content-Encoding or exactly the single token `identity`. Multiple
        # fields or any other coding refuses — there is no v1 decompressor.
        encodings = response.header_values("content-encoding")
        if len(encodings) > 1:
            raise DriverRefused(PublicFetchOutcome.UNSUPPORTED_ENCODING,
                                "multiple_content_encoding")
        if encodings and encodings[0].strip().lower() != "identity":
            raise DriverRefused(PublicFetchOutcome.UNSUPPORTED_ENCODING,
                                "non_identity_content_encoding")

    @staticmethod
    def _declared_length(response: "WireResponse") -> int | None:
        lengths = response.header_values("content-length")
        if not lengths:
            return None
        if len(lengths) > 1 or len(set(lengths)) != 1:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "conflicting_content_length")
        try:
            value = int(lengths[0].strip())
        except ValueError as exc:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "invalid_content_length") from exc
        if value < 0:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "invalid_content_length")
        return value

    def _read_body(self, response: "WireResponse") -> bytes:
        # §5.1 step 10: VALIDATION only — the size-bound decision was already made
        # in `_dispatch` (which never overreads), and the hop's observed wire
        # bytes are already charged by `_run_hop` (R11), so a refusal here never
        # loses the bytes that touched the wire and never overreads. A partial
        # body is never adopted.
        if response.overflow_code is not None:
            raise DriverRefused(PublicFetchOutcome.TOO_LARGE,
                                response.overflow_code)
        declared = self._declared_length(response)
        body = b"".join(response.body_chunks)
        # R1 declared/actual truth: a body shorter than its declared length is a
        # truncated transfer (disconnect mid-body); longer is a lying server.
        # Neither is ever adopted as a success artifact.
        if declared is not None and len(body) != declared:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "declared_length_mismatch")
        return body

    # -- one qualified external hop -----------------------------------------

    @staticmethod
    def _phase_timeout(ceiling: float, deadline: DeadlineBudget,
                       exhausted_code: str) -> float:
        # R1: EVERY phase (connect/head/body) re-samples the remaining total
        # deadline immediately before it starts, so no phase can outlive it.
        remaining = deadline.remaining_seconds()
        if remaining <= 0.0:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR, exhausted_code)
        return min(ceiling, remaining)

    def _dispatch(self, *, url: CanonicalURL, deadline: DeadlineBudget,
                  policy_max_dns: int, headers: Mapping[str, str],
                  ceiling_connect: float, ceiling_read: float,
                  resource_bound: int, aggregate_headroom: int,
                  max_header_fields: int, max_header_bytes: int,
                  ) -> tuple["WireResponse", tuple[str, ...], float, float, float]:
        """Resolve → refuse-non-public → connect one approved address → verify the
        ACTUAL peer BEFORE any request byte → bounded GET head → close the header
        set against the policy ceilings → read the body (2xx only) under the
        remaining authority. Returns the raw response plus the frozen approved set
        and this hop's timing; the caller records the operation with the kind it
        determines from the status."""
        elapsed_start = deadline.elapsed_seconds()
        remaining_start = deadline.remaining_seconds()
        if remaining_start <= 0.0:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "deadline_before_hop")
        # (2)(3) resolve once; refuse the WHOLE hop if any answer is non-public.
        resolution = self._resolver.resolve(url.ascii_host, deadline)
        if resolution.failure:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                resolution.failure)
        try:
            approved = freeze_public_addresses(resolution.addresses, policy_max_dns)
        except URLPolicyError as exc:
            # a non-public answer is a CAP-3 security-policy refusal
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "address_not_public") from exc
        # (4) connect ONE pinned approved address, preserving the canonical host.
        # The connect timeout is sampled AFTER DNS so it reflects what the
        # resolver already consumed. A connect failure has no request side.
        try:
            connection = self._factory.open(
                scheme=url.scheme, host=url.ascii_host, port=url.effective_port,
                address=approved[0],
                connect_timeout=self._phase_timeout(
                    ceiling_connect, deadline, "deadline_before_connect"))
        except OSError as exc:
            raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                "connect_failed") from exc
        try:
            # (5) the ACTUAL connected peer must belong to the frozen approved set
            # BEFORE the request is sent or any response byte is read — a rebound
            # socket is caught here, not after its bytes were buffered. A peer the
            # OS cannot report is a refusal, never a pass-through.
            try:
                peer = connection.peer_address()
            except OSError as exc:
                raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                    "peer_unobservable") from exc
            if peer not in approved:
                raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR, "wrong_peer")
            # (6) head phase: once the GET is on the wire, a failure is genuinely
            # ambiguous (the server may have processed it) — typed UNKNOWN.
            try:
                status, header_pairs, declared = connection.request(
                    host=url.ascii_host, path_and_query=_path_and_query(url),
                    headers=headers,
                    read_timeout=self._phase_timeout(
                        ceiling_read, deadline, "deadline_before_request"))
            except OSError as exc:
                raise _AmbiguousDispatch("request_interrupted") from exc
            # (7) R1: the response header set is closed against the policy
            # field/byte ceilings BEFORE a single body byte is requested.
            if len(header_pairs) > max_header_fields:
                raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                    "too_many_response_headers")
            if sum(len(n) + len(v) for n, v in header_pairs) > max_header_bytes:
                raise DriverRefused(PublicFetchOutcome.NETWORK_ERROR,
                                    "response_headers_too_large")
            # (8) body phase: ONLY a 2xx body is ever read. The read size is
            # chosen so the wire NEVER yields an unauthorized byte (R11):
            #   * when the per-resource bound is strictly below the remaining
            #     aggregate, ask for `resource_bound + 1` — the +1 detection
            #     sentinel still fits inside the aggregate authority;
            #   * when the aggregate binds and a trustworthy Content-Length proves
            #     exact fit, read exactly `declared` (a complete framed read
            #     proves the body fits — no sentinel needed);
            #   * when the aggregate binds and the transfer is unframed (or a
            #     declared length that itself overflows), read at most the exact
            #     remaining aggregate; filling it without a proven EOF is a
            #     conservative TOO_LARGE, never a one-byte overread.
            body_chunks: tuple[bytes, ...] = ()
            observed = 0
            overflow_code: str | None = None
            if 200 <= status <= 299:
                authorized = min(resource_bound, aggregate_headroom)
                if declared is not None and declared > authorized:
                    # provably too large from the header alone — read nothing
                    overflow_code = "declared_too_large"
                    want = 0
                elif resource_bound < aggregate_headroom:
                    want = resource_bound + 1  # sentinel fits inside the aggregate
                elif declared is not None:
                    want = declared            # framed exact fit under the aggregate
                else:
                    want = aggregate_headroom   # unframed: fill the exact remainder
                if want > 0:
                    try:
                        body = connection.read_body(
                            max_bytes=want,
                            read_timeout=self._phase_timeout(
                                ceiling_read, deadline, "deadline_before_body"))
                    except TransportInterrupted as exc:
                        # partial bytes were on the wire — charge them, adopt none
                        raise _AmbiguousDispatch(
                            "body_read_interrupted", exc.observed_bytes) from exc
                    except OSError as exc:
                        raise _AmbiguousDispatch("body_read_interrupted", 0) from exc
                    observed = len(body)
                    body_chunks = (body,) if body else ()
                    if overflow_code is None:
                        if resource_bound < aggregate_headroom:
                            if observed > resource_bound:
                                overflow_code = "response_too_large"
                        elif declared is None and observed >= aggregate_headroom:
                            # unframed body filled the exact remaining aggregate:
                            # EOF is unproven, so refuse rather than overread
                            overflow_code = "aggregate_too_large"
        finally:
            connection.close()
        response = WireResponse(
            status=status, header_pairs=header_pairs, connected_address=peer,
            body_chunks=body_chunks, declared_length=declared,
            observed_wire_bytes=observed, overflow_code=overflow_code)
        return (response, approved, elapsed_start, deadline.elapsed_seconds(),
                remaining_start)

    # -- the public fetch orchestration -------------------------------------

    def fetch(self, invocation: PublicFetchInvocation, canonical_url: str,
              initial_grant: InitialPacingGrant, deadline: DeadlineBudget,
              pacer: OriginPacer, robots_cache: RobotsCacheReader,
              ) -> DriverObservation:
        """Robots-gate → body → bounded redirects, emitting one fully
        cross-bound observation. Known refusals carry their closed outcome;
        post-dispatch ambiguity settles UNKNOWN and is never retried."""
        run = _FetchRun(self, invocation, initial_grant, deadline, pacer,
                        robots_cache)
        try:
            return run.execute(canonical_url)
        except DriverRefused as refused:
            return run.observation(refused.outcome, refused.safe_detail_code)
        except _AmbiguousDispatch as ambiguous:
            return run.observation(PublicFetchOutcome.UNKNOWN,
                                   ambiguous.safe_detail_code)


class _AmbiguousDispatch(Exception):
    """A post-dispatch disconnect/timeout: the outcome is genuinely UNKNOWN.

    `observed_bytes` is any partial body already pulled off the wire before the
    interruption — charged to the aggregate byte authority (R11), never adopted."""

    def __init__(self, safe_detail_code: str, observed_bytes: int = 0) -> None:
        super().__init__(safe_detail_code)
        self.safe_detail_code = safe_detail_code
        self.observed_bytes = observed_bytes


class _FetchRun:
    """One fetch's mutable accumulators + the cross-bound assembly."""

    def __init__(self, driver: StdlibPublicFetchDriver,
                 invocation: PublicFetchInvocation,
                 initial_grant: InitialPacingGrant, deadline: DeadlineBudget,
                 pacer: OriginPacer, robots_cache: RobotsCacheReader) -> None:
        self._d = driver
        self._inv = invocation
        self._policy = invocation.policy
        self._tenant = invocation.tenant_id
        self._purpose = invocation.request.purpose
        self._grant = initial_grant
        self._deadline = deadline
        self._pacer = pacer
        self._cache = robots_cache
        self._token = invocation.policy.user_agent_product_token
        self._ops: list[OperationEvidence] = []
        self._peers: list[PeerEvidence] = []
        self._redirects: list[RedirectHop] = []
        self._robots_obs: list[RobotsObservation] = []
        self._robots_bodies: list[bytes | None] = []
        self._cache_uses: list[RobotsCacheUse] = []
        self._wire_bytes = 0
        self._pre_hop_wire = 0
        self._retrieved_at = driver._clock()
        self._final_url = ""

    # -- lease acquisition ---------------------------------------------------

    def _lease(self, origin: str) -> object:
        # The FIRST external operation consumes the one-time initial grant; all
        # later hops (redirects, upgraded-origin robots, assets) pace fresh.
        if not self._grant.consumed:
            return self._grant.consume(self._tenant, origin)
        return self._pacer.acquire_origin(origin)

    def _resource_cap(self) -> int:
        # item-5 hard maxima: what THIS fetch's terminal resource may buffer
        return (_IMAGE_HARD_MAX if self._purpose is ResourcePurpose.IMAGE
                else _PAGE_HARD_MAX)

    def _charge_wire(self, observed: int) -> None:
        # Charge the EXACT bytes that touched the wire (R11) — no truncation. The
        # dispatch never authorizes a read past the remaining aggregate (the +1
        # detection sentinel is only used when a lower per-resource bound binds,
        # so it still fits inside the aggregate), so charging the exact count can
        # never push `wire_bytes` above `remaining_byte_authority`.
        self._wire_bytes += observed

    def _run_hop(self, url: CanonicalURL,
                 kind_for: Callable[[int], OperationKind], *,
                 resource_bound: int) -> WireResponse:
        # The op's KIND is chosen from the response status (a 3xx is a REDIRECT
        # op, a terminal status a BODY op) so redirect evidence binds a
        # REDIRECT-kind operation exactly. The lease is released whether the
        # dispatch succeeds or refuses.
        ceiling = self._policy.ceiling
        # R4a/R11: the remaining aggregate authority for THIS hop, refused before
        # any external op if already spent.
        aggregate_headroom = self._inv.remaining_byte_authority - self._wire_bytes
        if aggregate_headroom <= 0:
            raise DriverRefused(PublicFetchOutcome.TOO_LARGE,
                                "aggregate_exhausted_before_hop")
        lease = self._lease(url.origin)
        lease_digest = self._d._lease_digest(lease)
        # R11: the baseline for THIS hop's aggregate check is what earlier hops
        # already charged. The hop's own observed wire bytes are charged the
        # instant the dispatch resolves — success, validation-refusal OR a
        # mid-body interrupt — so no bytes that touched the wire go uncounted.
        self._pre_hop_wire = self._wire_bytes
        try:
            response, approved, start, finish, remaining = self._d._dispatch(
                url=url, deadline=self._deadline,
                policy_max_dns=self._policy.max_dns_addresses,
                headers=self._d._fixed_headers(url.ascii_host, self._purpose,
                                               self._token),
                ceiling_connect=ceiling.connect_timeout_seconds,
                ceiling_read=ceiling.read_timeout_seconds,
                # R1/R4a/item-5/R11: the dispatch chooses the exact read size from
                # the per-resource bound and the remaining aggregate so the wire
                # never yields an unauthorized byte; header field/byte ceilings
                # are enforced pre-body inside the dispatch.
                resource_bound=min(resource_bound, ceiling.max_response_bytes),
                aggregate_headroom=aggregate_headroom,
                max_header_fields=self._policy.max_header_fields,
                max_header_bytes=self._policy.max_header_bytes)
        except _AmbiguousDispatch as exc:
            # a partial body reached the wire before the disconnect — charge it
            self._charge_wire(exc.observed_bytes)
            raise
        finally:
            self._pacer.release_origin(lease_digest)
        self._charge_wire(response.observed_wire_bytes)
        index = len(self._ops)
        self._ops.append(OperationEvidence(
            index=index, kind=kind_for(response.status), origin=url.origin,
            lease_id_digest=lease_digest, elapsed_start_seconds=start,
            elapsed_finish_seconds=finish, remaining_start_seconds=remaining))
        self._peers.append(PeerEvidence(
            operation_index=index, url=url.value, origin=url.origin,
            lease_id_digest=lease_digest, approved_addresses=approved,
            connected_address=response.connected_address))
        self._final_url = url.value
        return response

    # -- robots (§5.2) -------------------------------------------------------

    def _robots_gate(self, body_url: CanonicalURL) -> RobotsDecision:
        _, target_digest = _robots_target_digest(body_url.value, self._policy)
        cached = self._cache.get_robots(body_url.value)
        if cached is not None:
            self._cache_uses.append(cached)
            return cached.decision
        current = canonicalize_observed_url(_robots_url(body_url), self._policy)
        # §5.2/R2b: robots.txt may itself redirect (e.g. an http->https upgrade).
        # Follow up to the policy bound, recording each hop as ROBOTS-kind
        # operation evidence + a canonical redirect graph; a hop that fails to
        # CONNECT (non-public/wrong-peer/DNS/deadline) fails the whole fetch, and
        # an off-authority Location refuses. The redirect chain is bound onto the
        # terminal RobotsObservation so the service can re-validate it.
        robots_redirects: list[RedirectHop] = []
        seen = {current.value}
        while True:
            # item 5: a robots hop may never buffer more than the robots cap
            response = self._run_hop(
                current, lambda status: OperationKind.ROBOTS,
                resource_bound=self._policy.max_robots_body_bytes)
            status = response.status
            if status in _REDIRECT_STATUSES:
                # at the policy bound (or a loop) the current over-limit 3xx op
                # terminates a bounded REDIRECT_EXHAUSTED disallow carrying the
                # graph so far and the TERMINAL 3xx status (no terminal robots
                # resource was reached — the redirect itself is the evidence).
                if (len(robots_redirects) >= self._policy.max_robots_redirects):
                    return self._record_robots_redirect_exhausted(
                        body_url, target_digest, status,
                        tuple(robots_redirects))
                target, hop = self._follow_robots_redirect(current, response)
                if target.value in seen:
                    return self._record_robots_redirect_exhausted(
                        body_url, target_digest, status,
                        tuple(robots_redirects))
                robots_redirects.append(hop)
                seen.add(target.value)
                current = target
                continue
            if 200 <= status <= 299:
                self._d._check_encoding(response)
                # R4a/R11: dispatch already bounded the read by the robots cap AND
                # the remaining aggregate without overreading; _read_body only
                # validates the size verdict + declared/actual truth.
                body = self._d._read_body(response)
                ruleset = parse_robots(
                    body, self._token,
                    max_lines=self._policy.max_robots_lines,
                    max_bytes_per_line=self._policy.max_robots_bytes_per_line,
                    max_rules=self._policy.max_robots_rules,
                    max_groups=self._policy.max_robots_groups)
                path_decision = robots_decision(ruleset, _path_and_query(body_url))
                # A PARSED 2xx ruleset is a DETERMINISTIC decision: RULES_APPLIED+
                # ALLOW or RULES_DISALLOW+DISALLOW (source review-confirmed distinction).
                # Only an unparseable 2xx body is genuinely UNCERTAIN_DISALLOW.
                if not ruleset.parsed:
                    decision = RobotsDecision.DISALLOW
                    outcome = RobotsOutcome.UNCERTAIN_DISALLOW
                elif path_decision is RobotsDecision.ALLOW:
                    decision = RobotsDecision.ALLOW
                    outcome = RobotsOutcome.RULES_APPLIED
                else:
                    decision = RobotsDecision.DISALLOW
                    outcome = RobotsOutcome.RULES_DISALLOW
                artifact_digest = hashlib.sha256(body).hexdigest()
                self._robots_obs.append(RobotsObservation(
                    origin=body_url.origin, robots_target_digest=target_digest,
                    operation_index=self._ops[-1].index,
                    lease_id_digest=self._ops[-1].lease_id_digest,
                    decision=decision, outcome_class=outcome,
                    policy_revision=self._policy.revision,
                    product_token=self._token,
                    observed_at=self._retrieved_at,
                    expires_at=_plus_seconds(
                        self._retrieved_at,
                        self._policy.robots_success_ttl_seconds),
                    status=status, artifact_digest=artifact_digest,
                    artifact_size=len(body), redirects=tuple(robots_redirects)))
                self._robots_bodies.append(body)
                return decision
            return self._record_robots_absence(
                body_url, target_digest, status,
                redirects=tuple(robots_redirects))

    def _record_robots_absence(self, body_url: CanonicalURL,
                               target_digest: str, status: int | None,
                               *, redirects: tuple[RedirectHop, ...] = (),
                               ) -> RobotsDecision:
        reason, outcome, decision = _robots_absence(status)
        ttl = (self._policy.robots_success_ttl_seconds
               if outcome is RobotsOutcome.UNAVAILABLE_ALLOW
               else self._policy.robots_failure_cooldown_seconds)
        self._robots_obs.append(RobotsObservation(
            origin=body_url.origin, robots_target_digest=target_digest,
            operation_index=self._ops[-1].index,
            lease_id_digest=self._ops[-1].lease_id_digest,
            decision=decision, outcome_class=outcome,
            policy_revision=self._policy.revision, product_token=self._token,
            observed_at=self._retrieved_at,
            expires_at=_plus_seconds(self._retrieved_at, ttl),
            status=status, absence_reason=reason, redirects=redirects))
        self._robots_bodies.append(None)
        return decision

    def _record_robots_redirect_exhausted(
            self, body_url: CanonicalURL, target_digest: str,
            terminal_status: int,
            redirects: tuple[RedirectHop, ...]) -> RobotsDecision:
        """A robots redirect bound/loop is REDIRECT_EXHAUSTED: the terminal 3xx
        status IS the evidence (a redirect was observed, no robots body reached),
        so the observation carries that exact 3xx status and an uncertain-disallow
        that blocks the body — never a null-status policy flag."""
        self._robots_obs.append(RobotsObservation(
            origin=body_url.origin, robots_target_digest=target_digest,
            operation_index=self._ops[-1].index,
            lease_id_digest=self._ops[-1].lease_id_digest,
            decision=RobotsDecision.DISALLOW,
            outcome_class=RobotsOutcome.UNCERTAIN_DISALLOW,
            policy_revision=self._policy.revision, product_token=self._token,
            observed_at=self._retrieved_at,
            expires_at=_plus_seconds(
                self._retrieved_at, self._policy.robots_failure_cooldown_seconds),
            status=terminal_status,
            absence_reason=RobotsAbsenceReason.REDIRECT_EXHAUSTED,
            redirects=redirects))
        self._robots_bodies.append(None)
        return RobotsDecision.DISALLOW

    def _follow_robots_redirect(
            self, current: CanonicalURL,
            response: WireResponse) -> tuple[CanonicalURL, RedirectHop]:
        """Canonicalize a robots 3xx Location under law-19 (same authority) and
        build the hop bound to the operation that produced it. Ambiguous/absent
        Location or an off-authority target refuses the whole fetch."""
        from urllib.parse import urljoin
        locations = response.header_values("location")
        if len(locations) != 1 or not locations[0].strip():
            raise DriverRefused(PublicFetchOutcome.POLICY_BLOCKED,
                                "robots_redirect_location_ambiguous")
        absolute = urljoin(current.value, locations[0].strip())
        try:
            target = canonicalize_redirect_url(
                absolute, current, self._policy, ResourcePurpose.PAGE)
        except URLPolicyError as exc:
            raise DriverRefused(PublicFetchOutcome.POLICY_BLOCKED,
                                "robots_redirect_outside_authority") from exc
        hop = RedirectHop(
            operation_index=self._ops[-1].index, from_url=current.value,
            to_url=target.value, status=response.status, origin=current.origin,
            approved_addresses=self._peers[-1].approved_addresses)
        return target, hop

    # -- the flow ------------------------------------------------------------

    def execute(self, canonical_url: str) -> DriverObservation:
        current = canonicalize_observed_url(canonical_url, self._policy)
        self._final_url = current.value
        # §5.2: robots is fetched (or read from cache) before the body.
        if self._robots_gate(current) is RobotsDecision.DISALLOW:
            return self.observation(PublicFetchOutcome.ROBOTS_DENIED,
                                    "robots_disallow")
        seen = {current.value}
        followed = 0
        # the terminal operation KIND is the purpose's: an image is an ASSET
        # operation (the service validates exactly that), a page a BODY one.
        terminal_kind = (OperationKind.ASSET
                         if self._purpose is ResourcePurpose.IMAGE
                         else OperationKind.BODY)
        max_redirects = self._policy.ceiling.max_redirects
        while True:
            response = self._run_hop(
                current,
                lambda status: (OperationKind.REDIRECT
                                if status in _REDIRECT_STATUSES
                                else terminal_kind),
                resource_bound=self._resource_cap())
            status = response.status
            if status in _REDIRECT_STATUSES:
                # over-limit and looping redirects are OBSERVED but NOT followed:
                # the redirect operation _run_hop just recorded stays UNMATCHED
                # (no committed hop), and the service's failure-aware validation
                # accepts exactly one terminal unmatched redirect on an allowed
                # source — a truthful "saw it, refused to follow" record.
                if followed >= max_redirects:
                    raise DriverRefused(PublicFetchOutcome.REDIRECT_LIMIT,
                                        "redirect_limit")
                target = self._resolve_redirect_target(current, response)
                if target.value in seen:
                    raise DriverRefused(PublicFetchOutcome.REDIRECT_LIMIT,
                                        "redirect_loop")
                # commit the hop only now that we WILL follow this redirect
                self._commit_redirect_hop(current, target, response)
                current = target
                followed += 1
                seen.add(current.value)
                # a same-host HTTPS upgrade is a NEW origin needing fresh robots
                if current.origin != self._final_origin():
                    if self._robots_gate(current) is RobotsDecision.DISALLOW:
                        return self.observation(
                            PublicFetchOutcome.ROBOTS_DENIED, "robots_disallow")
                continue
            if 200 <= status <= 299:
                self._d._check_encoding(response)
                # R4a/R11: dispatch already bounded the read by the resource cap,
                # ceiling AND remaining aggregate without overreading; _read_body
                # only validates the size verdict + declared/actual truth.
                body = self._d._read_body(response)
                media = self._d._content_type(response)
                return self.observation(
                    PublicFetchOutcome.SUCCEEDED, "fetched", body=body,
                    http_status=status, declared_media_type=media,
                    observed_media_type=media)
            raise DriverRefused(PublicFetchOutcome.HTTP_ERROR,
                                f"http_status_{status}")

    def _final_origin(self) -> str:
        # the origin of the last BODY/REDIRECT peer we recorded
        return self._peers[-1].origin

    def _resolve_redirect_target(self, current: CanonicalURL,
                                 response: WireResponse) -> CanonicalURL:
        """Validate a 3xx Location under law-19 and return its canonical target
        WITHOUT committing a hop — an ambiguous or off-authority Location refuses
        POLICY_BLOCKED (the redirect operation stays unmatched)."""
        from urllib.parse import urljoin
        locations = response.header_values("location")
        if len(locations) != 1 or not locations[0].strip():
            raise DriverRefused(PublicFetchOutcome.POLICY_BLOCKED,
                                "redirect_location_ambiguous")
        redirect_purpose = (ResourcePurpose.IMAGE
                            if self._purpose is ResourcePurpose.IMAGE
                            else ResourcePurpose.PAGE)
        absolute = urljoin(current.value, locations[0].strip())
        try:
            return canonicalize_redirect_url(
                absolute, current, self._policy, redirect_purpose)
        except URLPolicyError as exc:
            raise DriverRefused(PublicFetchOutcome.POLICY_BLOCKED,
                                "redirect_outside_authority") from exc

    def _commit_redirect_hop(self, current: CanonicalURL, target: CanonicalURL,
                             response: WireResponse) -> None:
        """Record the hop for a redirect we ARE following (matches its op)."""
        self._redirects.append(RedirectHop(
            operation_index=self._ops[-1].index, from_url=current.value,
            to_url=target.value, status=response.status, origin=current.origin,
            approved_addresses=self._peers[-1].approved_addresses))

    # -- observation assembly ------------------------------------------------

    def observation(self, outcome: PublicFetchOutcome, safe_detail_code: str,
                    *, body: bytes | None = None, http_status: int | None = None,
                    declared_media_type: str = "",
                    observed_media_type: str = "") -> DriverObservation:
        # WO law 18 / A15: the stdlib driver is credential-free, so EVERY known
        # terminal outcome has a KNOWN provider actual of 0.0 — a network error
        # or refusal still spent nothing, and null must never masquerade as that
        # zero. Only a genuinely ambiguous post-dispatch UNKNOWN reserves null
        # (and unknown metering), mirroring the service's own UNKNOWN settlement.
        is_unknown = outcome is PublicFetchOutcome.UNKNOWN
        return DriverObservation(
            outcome=outcome,
            final_url=self._final_url or self._inv.request.requested_url,
            retrieved_at=self._retrieved_at,
            http_status=http_status,
            declared_media_type=declared_media_type,
            observed_media_type=observed_media_type,
            redirects=tuple(self._redirects),
            peers=tuple(self._peers),
            operation_evidence=tuple(self._ops),
            robots_observations=tuple(self._robots_obs),
            wire_bytes=self._wire_bytes,
            provider_actual_usd=None if is_unknown else 0.0,
            infrastructure_metering_state=(
                InfrastructureMeteringState.UNKNOWN if is_unknown
                else InfrastructureMeteringState.UNMETERED),
            infrastructure_actual_usd=None,
            safe_detail_code=safe_detail_code,
            body=body if outcome is PublicFetchOutcome.SUCCEEDED else None,
            robots_bodies=tuple(self._robots_bodies),
            robots_cache_uses=tuple(self._cache_uses))


def _plus_seconds(moment: datetime, seconds: int) -> datetime:
    from datetime import timedelta
    return moment + timedelta(seconds=seconds)
