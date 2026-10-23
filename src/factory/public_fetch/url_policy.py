"""Canonical URL, exact-origin, and public-address policy for CAP-3."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from factory.public_fetch.contracts import (
    PublicFetchContractError,
    PublicFetchPolicy,
    ResourcePurpose,
    canonical_digest,
)

_BAD_DOTS = {"\u3002", "\uff0e", "\uff61"}
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_INTEGERISH_HOST = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-7]+|[0-9]+)$")
_SECRET_QUERY_KEY = re.compile(
    r"(?i)^(?:authorization|cookie|password|passwd|secret|access[_-]?token|api[_-]?key|"
    r"client[_-]?secret|session[_-]?(?:id|token)|jwt)$"
)
_SECRET_QUERY_VALUE = re.compile(r"(?i)^(?:bearer\s+|sk-[A-Za-z0-9]|gh[pousr]_|eyJ)")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


class URLPolicyError(PublicFetchContractError):
    """A URL or address falls outside exact CAP-3 policy."""


@dataclass(frozen=True, slots=True)
class CanonicalURL:
    value: str = field(repr=False)
    scheme: str
    ascii_host: str
    effective_port: int
    origin: str
    query_pairs: int


def _split_query(query: str, maximum: int) -> int:
    if not query:
        return 0
    pieces = query.split("&")
    if len(pieces) > maximum:
        raise URLPolicyError("query pair limit exceeded")
    for piece in pieces:
        key, separator, value = piece.partition("=")
        if not key:
            raise URLPolicyError("query key is empty")
        if _BAD_PERCENT.search(piece):
            raise URLPolicyError("query contains malformed percent escape")
        # Scan both literal and percent-decoded ASCII without normalizing the
        # authority-bearing query that participates in the request digest.
        decoded_key = _decode_ascii_percent(key)
        decoded_value = _decode_ascii_percent(value) if separator else ""
        if _SECRET_QUERY_KEY.fullmatch(decoded_key) or _SECRET_QUERY_VALUE.match(decoded_value):
            raise URLPolicyError("query contains credential-bearing content")
    return len(pieces)


def _decode_ascii_percent(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        number = int(match.group(1), 16)
        return chr(number) if number < 128 else match.group(0).upper()
    return _PERCENT.sub(replace, value)


def _canonical_host(raw_host: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    if not raw_host or any(dot in raw_host for dot in _BAD_DOTS):
        raise URLPolicyError("host is empty or uses an ambiguous dot")
    if "%" in raw_host:
        raise URLPolicyError("zone identifiers and host escapes are forbidden")
    rootless = raw_host[:-1] if raw_host.endswith(".") else raw_host
    if not rootless or rootless.endswith(".") or ".." in rootless:
        raise URLPolicyError("host contains an empty label")
    literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        literal = ipaddress.ip_address(rootless)
    except ValueError:
        if _INTEGERISH_HOST.fullmatch(rootless) or re.fullmatch(r"[0-9.]+", rootless):
            # If an all-numeric/dotted spelling is not strict ipaddress syntax,
            # it is an ambiguous integer/octal/hex/noncanonical IPv4 spelling.
            raise URLPolicyError("non-canonical IPv4 spelling") from None
        try:
            ascii_host = rootless.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLPolicyError("host is not valid IDNA") from exc
        labels = ascii_host.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
               or not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
            raise URLPolicyError("host contains an invalid label")
        if len(ascii_host) > 253:
            raise URLPolicyError("host is too long")
        return ascii_host, None
    canonical = literal.compressed.lower()
    if rootless.lower() != canonical:
        raise URLPolicyError("IP literal is not canonical")
    return canonical, literal


def _canonical_path(path: str) -> str:
    if _BAD_PERCENT.search(path):
        raise URLPolicyError("path contains malformed percent escape")
    # Preserve existing escapes (upper-cased), encode non-ASCII exactly once,
    # and never decode reserved separators such as %2F.
    def normalize_escape(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else f"%{match.group(1).upper()}"

    protected = _PERCENT.sub(normalize_escape, path or "/")
    encoded = quote(protected, safe="/%:@!$&'()*+,;=-._~")
    return _remove_dot_segments(encoded)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4 normalization without decoding reserved '/' bytes."""
    source = path
    output = ""
    while source:
        if source.startswith("../"):
            source = source[3:]
        elif source.startswith("./"):
            source = source[2:]
        elif source.startswith("/./"):
            source = source[2:]
        elif source == "/.":
            source = "/"
        elif source.startswith("/../"):
            source = source[3:]
            output = output.rsplit("/", 1)[0]
        elif source == "/..":
            source = "/"
            output = output.rsplit("/", 1)[0]
        elif source in (".", ".."):
            source = ""
        else:
            boundary = source.find("/", 1 if source.startswith("/") else 0)
            if boundary < 0:
                output += source
                source = ""
            else:
                output += source[:boundary]
                source = source[boundary:]
    return output or "/"


def _canonical_query(query: str) -> str:
    return _PERCENT.sub(
        lambda match: (chr(int(match.group(1), 16))
                       if chr(int(match.group(1), 16)) in _UNRESERVED
                       else f"%{match.group(1).upper()}"),
        query)


def _parse_canonical_url(raw: str, policy: PublicFetchPolicy) -> CanonicalURL:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > policy.max_url_bytes:
        raise URLPolicyError("URL is empty or exceeds the policy byte limit")
    if raw != raw.strip() or "\\" in raw or any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        raise URLPolicyError("URL contains whitespace, controls, or backslash")
    if _BAD_PERCENT.search(raw):
        raise URLPolicyError("URL contains malformed percent escape")
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in policy.allowed_schemes or not parts.netloc:
        raise URLPolicyError("URL must be absolute HTTP(S)")
    if parts.fragment:
        raise URLPolicyError("fragments are forbidden")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise URLPolicyError("userinfo is forbidden")
    # Encoded delimiters in the raw authority must not be interpreted later.
    raw_authority = parts.netloc
    if re.search(r"(?i)%(?:2f|5c|40|3a|23|3f)", raw_authority):
        raise URLPolicyError("encoded authority delimiter is forbidden")
    try:
        raw_host = parts.hostname or ""
        explicit_port = parts.port
    except ValueError as exc:
        raise URLPolicyError("malformed port or authority") from exc
    host, literal = _canonical_host(raw_host)
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    if port not in policy.allowed_ports:
        raise URLPolicyError("port is outside server policy")
    if literal is not None:
        require_public_address(literal.compressed)
    host_for_url = f"[{host}]" if ":" in host else host
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host_for_url if default else f"{host_for_url}:{port}"
    query_pairs = _split_query(parts.query, policy.max_query_pairs)
    canonical_query = _canonical_query(parts.query)
    canonical = urlunsplit((scheme, netloc, _canonical_path(parts.path), canonical_query, ""))
    origin = f"{scheme}://{netloc}"
    if len(canonical.encode("utf-8")) > policy.max_url_bytes:
        raise URLPolicyError("canonical URL exceeds policy byte limit")
    return CanonicalURL(canonical, scheme, host, port, origin, query_pairs)


def canonicalize_url(raw: str, policy: PublicFetchPolicy, purpose: ResourcePurpose) -> CanonicalURL:
    result = _parse_canonical_url(raw, policy)
    if purpose is ResourcePurpose.IMAGE:
        allowed = policy.allowed_asset_origins
    elif purpose is ResourcePurpose.ROBOTS:
        allowed = (policy.page_origin,) + policy.allowed_asset_origins
    else:
        allowed = (policy.page_origin,)
    if result.origin not in allowed:
        raise URLPolicyError("origin is outside exact server authority")
    return result


def canonicalize_observed_url(raw: str, policy: PublicFetchPolicy) -> CanonicalURL:
    """Parse network evidence without granting an origin.

    Callers must compare the returned origin with authority already admitted by
    the invocation.  Keeping parsing separate is necessary for the one legal
    same-host HTTP-to-HTTPS transition.
    """
    return _parse_canonical_url(raw, policy)


def robots_target_digest(canonical_target_url: str,
                         policy: PublicFetchPolicy) -> tuple[CanonicalURL, str]:
    """Return exact canonical URL and digest of its RFC 9309 path+query target."""
    target = _parse_canonical_url(canonical_target_url, policy)
    parts = urlsplit(target.value)
    matcher_target = parts.path + (f"?{parts.query}" if parts.query else "")
    return target, canonical_digest({"robots_matcher_target": matcher_target})


def safe_projection_url(canonical_url: str) -> str:
    """Remove the complete authority-bearing query from every safe surface."""
    parts = urlsplit(canonical_url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def canonicalize_candidate_url(raw: str, source: CanonicalURL,
                               policy: PublicFetchPolicy,
                               purpose: ResourcePurpose) -> CanonicalURL:
    """Resolve one observed HTML reference and apply exact candidate authority."""
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > policy.max_url_bytes:
        raise URLPolicyError("candidate URL is empty or exceeds policy")
    target = _parse_canonical_url(urljoin(source.value, raw), policy)
    if purpose is ResourcePurpose.PAGE:
        if target.origin != source.origin:
            raise URLPolicyError("page candidate is outside the final page origin")
    elif purpose is ResourcePurpose.IMAGE:
        if target.origin not in policy.allowed_asset_origins:
            raise URLPolicyError("image candidate is outside exact asset authority")
    else:
        raise URLPolicyError("candidate purpose is outside v1")
    return target


def canonicalize_redirect_url(raw: str, source: CanonicalURL,
                              policy: PublicFetchPolicy,
                              purpose: ResourcePurpose) -> CanonicalURL:
    """Canonicalize a redirect target and apply the original origin grant.

    Parsing is deliberately separate from authority so the one v1 exception —
    same-host HTTP to HTTPS — can be evaluated without mutating policy.
    """
    target = _parse_canonical_url(raw, policy)
    if not redirect_allowed(source, target, policy, purpose):
        raise URLPolicyError("redirect target is outside exact server authority")
    return target


def redirect_allowed(source: CanonicalURL, target: CanonicalURL,
                     policy: PublicFetchPolicy, purpose: ResourcePurpose) -> bool:
    if source.scheme == "https" and target.scheme == "http":
        return False
    if purpose is ResourcePurpose.IMAGE:
        return source.origin in policy.allowed_asset_origins and target.origin == source.origin
    if target.origin == policy.page_origin:
        return True
    return bool(
        policy.allow_same_host_https_upgrade
        and source.scheme == "http"
        and target.scheme == "https"
        and source.ascii_host == target.ascii_host
        and source.effective_port == 80
        and target.effective_port == 443
        and source.origin == policy.page_origin
    )


def require_public_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise URLPolicyError("resolver returned an invalid address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_global or address.is_private or address.is_loopback or address.is_link_local:
        raise URLPolicyError("destination is not a public address")
    if address.is_multicast or address.is_reserved or address.is_unspecified:
        raise URLPolicyError("destination is a special-purpose address")
    return address.compressed.lower()


def freeze_public_addresses(values: tuple[str, ...], maximum: int) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > maximum:
        raise URLPolicyError("DNS answer count is empty or exceeds policy")
    normalized = tuple(require_public_address(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise URLPolicyError("DNS answer contains duplicates")
    return tuple(sorted(normalized))


def parse_public_transport_url(raw: str) -> CanonicalURL:
    """Validate an HTTP destination while preserving signed media query bytes.

    This boundary shares the public-address policy with CAP-3 without granting
    crawler authority or rewriting an application's signed path and query.
    DNS answers still require validation immediately before each connection.
    """
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 16384:
        raise URLPolicyError("URL is empty or too long")
    if "\\" in raw or any(ord(c) <= 32 or ord(c) == 127 for c in raw):
        raise URLPolicyError("URL contains whitespace or controls")
    if _BAD_PERCENT.search(raw):
        raise URLPolicyError("URL contains malformed percent escape")
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        port = parts.port or (443 if scheme == "https" else 80)
        host, literal = _canonical_host(parts.hostname or "")
    except ValueError as exc:
        raise URLPolicyError("invalid HTTP destination") from exc
    if scheme not in {"http", "https"} or not parts.netloc:
        raise URLPolicyError("URL must be absolute HTTP(S)")
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise URLPolicyError("URL credentials and fragments are forbidden")
    if parts.port == 0 or port not in {80, 443}:
        raise URLPolicyError("port is outside server policy")
    if literal is not None:
        require_public_address(str(literal))
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        authority += f":{port}"
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
    value = urlunsplit((scheme, authority, path, query, ""))
    return CanonicalURL(value, scheme, host, port, f"{scheme}://{authority}", 0)
