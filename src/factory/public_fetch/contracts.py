"""Closed, provider-neutral CAP-3 public-fetch contracts.

The records in this module are authority and evidence.  They are immutable,
canonically digestible, and deliberately contain neither credentials nor an
``accepted`` verdict.  Network implementations live in ``drivers/``.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol
from urllib.parse import urlsplit

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$")
_SECRET_VALUE = re.compile(
    r"(?i)(?:authorization|cookie|password|passwd|secret|access[_-]?token|api[_-]?key|"
    r"client[_-]?secret|session[_-]?(?:id|token))\s*[:=]\s*(?!\[REDACTED\])\S+|"
    r"bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_-]{8,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"
)


class PublicFetchContractError(ValueError):
    """A CAP-3 record is malformed or contains undeclared authority."""


def canonical_digest(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _text(value: str, name: str, maximum: int = 1024, *, safe_id: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or value != value.strip():
        raise PublicFetchContractError(f"{name} must be non-blank bounded text")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PublicFetchContractError(f"{name} contains a control character")
    if _SECRET_VALUE.search(value):
        raise PublicFetchContractError(f"{name} contains a credential value")
    if safe_id and not _SAFE_ID.fullmatch(value):
        raise PublicFetchContractError(f"{name} must be a safe identifier")
    return value


def _safe_surface_url(value: str, name: str) -> str:
    _text(value, name, 4096)
    if urlsplit(value).query:
        raise PublicFetchContractError(f"{name} exposes authority-bearing query data")
    return value


def _digest(value: str, name: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return value
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise PublicFetchContractError(f"{name} must be a lowercase sha256 digest")
    return value


def _time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PublicFetchContractError(f"{name} must be timezone-aware")
    if not math.isfinite(value.timestamp()):
        raise PublicFetchContractError(f"{name} must be finite")
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(timezone.utc).isoformat()


def _finite_nonnegative(value: float | None, name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PublicFetchContractError(f"{name} must be numeric or null")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise PublicFetchContractError(f"{name} must be finite and non-negative")
    return result


def _positive_int(value: int, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise PublicFetchContractError(f"{name} must be between 1 and {maximum}")
    return value


def _unique(values: tuple[str, ...], name: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > maximum:
        raise PublicFetchContractError(f"{name} must be an immutable bounded tuple")
    for value in values:
        _text(value, f"{name} entry", 4096)
    if len(values) != len(set(values)):
        raise PublicFetchContractError(f"{name} contains duplicates")
    return values


class ResourcePurpose(str, Enum):
    PAGE = "page"
    TEXT = "text"
    IMAGE = "image"
    ROBOTS = "robots"


class PublicFetchOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    ROBOTS_DENIED = "robots_denied"
    POLICY_BLOCKED = "policy_blocked"
    HTTP_ERROR = "http_error"
    NETWORK_ERROR = "network_error"
    TOO_LARGE = "too_large"
    UNSUPPORTED_TYPE = "unsupported_type"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    INVALID_CONTENT = "invalid_content"
    REDIRECT_LIMIT = "redirect_limit"
    UNKNOWN = "unknown"


class AttemptState(str, Enum):
    RESERVED = "reserved"
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class InfrastructureMeteringState(str, Enum):
    METERED = "metered"
    UNMETERED = "infrastructure_unmetered"
    UNKNOWN = "unknown"


class RobotsDecision(str, Enum):
    ALLOW = "allow"
    DISALLOW = "disallow"


class RobotsAbsenceReason(str, Enum):
    UNAVAILABLE_NO_BODY = "unavailable_no_body"
    ACCESS_REFUSED = "access_refused"
    RATE_LIMITED = "rate_limited"
    NETWORK_UNREACHABLE = "network_unreachable"
    SERVER_ERROR = "server_error_no_body"
    NO_BODY_STATUS = "no_body_status"
    OTHER_HTTP_STATUS = "other_http_status"
    REDIRECT_EXHAUSTED = "redirect_exhausted"
    POLICY_BLOCKED = "policy_blocked"


class RobotsOutcome(str, Enum):
    RULES_APPLIED = "rules_applied"
    RULES_DISALLOW = "rules_disallow"
    UNAVAILABLE_ALLOW = "unavailable_allow"
    ACCESS_REFUSED_DISALLOW = "access_refused_disallow"
    RATE_LIMITED_DISALLOW = "rate_limited_disallow"
    UNCERTAIN_DISALLOW = "uncertain_disallow"
    UNREACHABLE_DISALLOW = "unreachable_disallow"
    SERVER_ERROR_DISALLOW = "server_error_disallow"
    POLICY_BLOCKED = "policy_blocked"


_ROBOTS_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_OTHER_ROBOTS_STATUSES = frozenset(
    status for status in range(100, 500)
    if not 200 <= status <= 299
    and status not in _ROBOTS_REDIRECT_STATUSES
    and status not in {304, 401, 403, 404, 410, 429}
)


class RefreshReason(str, Enum):
    RECONCILED_NO_REMOTE_EFFECT = "reconciled_no_remote_effect"
    OWNER_AUTHORIZED_REOBSERVATION = "owner_authorized_reobservation"
    OPERATOR_CONFIRMED_TERMINAL = "operator_confirmed_terminal"


class ReservationDisposition(str, Enum):
    """Closed transport ownership returned by an atomic reservation."""

    OWNER = "owner"
    IN_PROGRESS = "in_progress"
    REPLAY = "replay"


class OperationKind(str, Enum):
    """The bounded external-operation vocabulary emitted by qualified drivers."""

    ROBOTS = "robots"
    BODY = "body"
    REDIRECT = "redirect"
    ASSET = "asset"


class CandidateAuthority(str, Enum):
    """Closed observation class; candidates never confer fetch authority."""

    SAME_ORIGIN_PAGE = "same_origin_page"
    EXACT_ASSET_ORIGIN = "exact_asset_origin"


class DeadlineBudget:
    """One transient monotonic budget shared by service and driver.

    Only duration values escape this object.  The host-absolute start value is
    deliberately private and has no serialization method.
    """

    __slots__ = ("_clock", "_started", "_total")

    def __init__(self, total_seconds: float, monotonic: Callable[[], float]) -> None:
        if (isinstance(total_seconds, bool) or not isinstance(total_seconds, (int, float))
                or not math.isfinite(float(total_seconds)) or float(total_seconds) <= 0):
            raise PublicFetchContractError("deadline total must be finite and positive")
        if not callable(monotonic):
            raise PublicFetchContractError("deadline clock must be callable")
        self._clock = monotonic
        self._total = float(total_seconds)
        self._started = float(monotonic())
        if not math.isfinite(self._started):
            raise PublicFetchContractError("deadline clock returned a non-finite value")

    @property
    def total_seconds(self) -> float:
        return self._total

    def elapsed_seconds(self) -> float:
        current = float(self._clock())
        if not math.isfinite(current) or current < self._started:
            raise PublicFetchContractError("monotonic deadline clock moved backwards")
        return current - self._started

    def remaining_seconds(self) -> float:
        return max(0.0, self._total - self.elapsed_seconds())

    @property
    def exhausted(self) -> bool:
        return self.remaining_seconds() <= 0.0


@dataclass(frozen=True, slots=True)
class ResourceCeiling:
    max_response_bytes: int
    max_total_bytes: int
    max_redirects: int = 5
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 10.0
    total_timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        _positive_int(self.max_response_bytes, "max_response_bytes", 8 * 1024 * 1024)
        _positive_int(self.max_total_bytes, "max_total_bytes", 64 * 1024 * 1024)
        if isinstance(self.max_redirects, bool) or not isinstance(self.max_redirects, int):
            raise PublicFetchContractError("max_redirects must be an integer")
        if not 0 <= self.max_redirects <= 8:
            raise PublicFetchContractError("max_redirects exceeds the v1 hard maximum")
        for value, name, maximum in (
            (self.connect_timeout_seconds, "connect_timeout_seconds", 10.0),
            (self.read_timeout_seconds, "read_timeout_seconds", 20.0),
            (self.total_timeout_seconds, "total_timeout_seconds", 120.0),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise PublicFetchContractError(f"{name} must be numeric")
            if not math.isfinite(float(value)) or not 0 < float(value) <= maximum:
                raise PublicFetchContractError(f"{name} exceeds the v1 hard maximum")
        if self.max_response_bytes > self.max_total_bytes:
            raise PublicFetchContractError("response ceiling exceeds aggregate ceiling")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "max_response_bytes": self.max_response_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_redirects": self.max_redirects,
            "connect_timeout_seconds": float(self.connect_timeout_seconds),
            "read_timeout_seconds": float(self.read_timeout_seconds),
            "total_timeout_seconds": float(self.total_timeout_seconds),
        }


@dataclass(frozen=True, slots=True)
class PublicFetchRequest:
    requested_url: str = field(repr=False)
    purpose: ResourcePurpose
    correlation_id: str

    def __post_init__(self) -> None:
        _text(self.requested_url, "requested_url", 4096)
        if not isinstance(self.purpose, ResourcePurpose):
            raise PublicFetchContractError("purpose must be ResourcePurpose")
        _text(self.correlation_id, "correlation_id", 256, safe_id=True)

    def canonical_payload(self) -> dict[str, object]:
        return {"requested_url": self.requested_url, "purpose": self.purpose.value,
                "correlation_id": self.correlation_id}

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class PublicFetchPolicy:
    revision: str
    page_origin: str
    allowed_asset_origins: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = (80, 443)
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allow_same_host_https_upgrade: bool = True
    user_agent_product_token: str = "AgentFactoryPublicFetch/1.0"
    min_origin_interval_ms: int = 500
    ceiling: ResourceCeiling = field(default_factory=lambda: ResourceCeiling(
        max_response_bytes=2 * 1024 * 1024, max_total_bytes=32 * 1024 * 1024))
    max_url_bytes: int = 2048
    max_dns_addresses: int = 8
    max_query_pairs: int = 64
    max_html_tokens: int = 50_000
    max_html_nesting: int = 128
    max_html_attributes: int = 64
    max_projection_chars: int = 120_000
    max_pages: int = 20
    max_crawl_depth: int = 2
    max_asset_hosts: int = 4
    max_images: int = 20
    max_header_fields: int = 50
    max_header_bytes: int = 32 * 1024
    max_robots_redirects: int = 3
    max_robots_body_bytes: int = 256 * 1024
    max_robots_lines: int = 5_000
    max_robots_bytes_per_line: int = 4 * 1024
    max_robots_rules: int = 2_048
    max_robots_groups: int = 128
    robots_success_ttl_seconds: int = 24 * 60 * 60
    robots_failure_cooldown_seconds: int = 5 * 60
    allowed_projection_kinds: tuple[str, ...] = ("text/plain", "text/html")
    allowed_image_kinds: tuple[str, ...] = (
        "image/png", "image/jpeg", "image/gif", "image/webp")

    def __post_init__(self) -> None:
        _text(self.revision, "revision", 128, safe_id=True)
        _text(self.page_origin, "page_origin", 512)
        _unique(self.allowed_asset_origins, "allowed_asset_origins", 8)
        if not isinstance(self.allowed_ports, tuple) or not self.allowed_ports:
            raise PublicFetchContractError("allowed_ports must be a non-empty tuple")
        if any(isinstance(x, bool) or not isinstance(x, int) or x not in (80, 443)
               for x in self.allowed_ports) or len(set(self.allowed_ports)) != len(self.allowed_ports):
            raise PublicFetchContractError("v1 ports are limited to unique 80 and 443")
        if self.allowed_schemes != ("http", "https"):
            raise PublicFetchContractError("v1 schemes must be exactly http and https")
        if not isinstance(self.allow_same_host_https_upgrade, bool):
            raise PublicFetchContractError("allow_same_host_https_upgrade must be boolean")
        _text(self.user_agent_product_token, "user_agent_product_token", 128)
        if not isinstance(self.ceiling, ResourceCeiling):
            raise PublicFetchContractError("ceiling must be ResourceCeiling")
        if (isinstance(self.min_origin_interval_ms, bool)
                or not isinstance(self.min_origin_interval_ms, int)
                or not 100 <= self.min_origin_interval_ms <= 86_400_000):
            raise PublicFetchContractError("origin interval may not be below 100ms")
        for value, name, maximum in (
            (self.max_url_bytes, "max_url_bytes", 4096),
            (self.max_dns_addresses, "max_dns_addresses", 16),
            (self.max_query_pairs, "max_query_pairs", 64),
            (self.max_html_tokens, "max_html_tokens", 100_000),
            (self.max_html_nesting, "max_html_nesting", 256),
            (self.max_html_attributes, "max_html_attributes", 128),
            (self.max_projection_chars, "max_projection_chars", 240_000),
            (self.max_pages, "max_pages", 40),
            (self.max_asset_hosts, "max_asset_hosts", 8),
            (self.max_images, "max_images", 40),
            (self.max_header_fields, "max_header_fields", 100),
            (self.max_header_bytes, "max_header_bytes", 64 * 1024),
            (self.max_robots_redirects, "max_robots_redirects", 5),
            (self.max_robots_body_bytes, "max_robots_body_bytes", 512 * 1024),
            (self.max_robots_lines, "max_robots_lines", 10_000),
            (self.max_robots_bytes_per_line, "max_robots_bytes_per_line", 8 * 1024),
            (self.max_robots_rules, "max_robots_rules", 4_096),
            (self.max_robots_groups, "max_robots_groups", 256),
            (self.robots_success_ttl_seconds, "robots_success_ttl_seconds", 24 * 60 * 60),
            (self.robots_failure_cooldown_seconds, "robots_failure_cooldown_seconds", 5 * 60),
        ):
            _positive_int(value, name, maximum)
        if (isinstance(self.max_crawl_depth, bool) or not isinstance(self.max_crawl_depth, int)
                or not 0 <= self.max_crawl_depth <= 3):
            raise PublicFetchContractError("max_crawl_depth must be between zero and three")
        projection_set = {"text/plain", "text/html"}
        image_set = {"image/png", "image/jpeg", "image/gif", "image/webp"}
        if (not isinstance(self.allowed_projection_kinds, tuple)
                or not self.allowed_projection_kinds
                or len(set(self.allowed_projection_kinds)) != len(self.allowed_projection_kinds)
                or not set(self.allowed_projection_kinds) <= projection_set):
            raise PublicFetchContractError("allowed_projection_kinds is outside v1")
        if (not isinstance(self.allowed_image_kinds, tuple) or not self.allowed_image_kinds
                or len(set(self.allowed_image_kinds)) != len(self.allowed_image_kinds)
                or not set(self.allowed_image_kinds) <= image_set):
            raise PublicFetchContractError("allowed_image_kinds is outside v1")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "revision": self.revision, "page_origin": self.page_origin,
            "allowed_asset_origins": list(self.allowed_asset_origins),
            "allowed_ports": list(self.allowed_ports), "allowed_schemes": list(self.allowed_schemes),
            "allow_same_host_https_upgrade": self.allow_same_host_https_upgrade,
            "user_agent_product_token": self.user_agent_product_token,
            "min_origin_interval_ms": self.min_origin_interval_ms,
            "ceiling": self.ceiling.canonical_payload(), "max_url_bytes": self.max_url_bytes,
            "max_dns_addresses": self.max_dns_addresses, "max_query_pairs": self.max_query_pairs,
            "max_html_tokens": self.max_html_tokens, "max_html_nesting": self.max_html_nesting,
            "max_html_attributes": self.max_html_attributes,
            "max_projection_chars": self.max_projection_chars,
            "max_pages": self.max_pages, "max_crawl_depth": self.max_crawl_depth,
            "max_asset_hosts": self.max_asset_hosts, "max_images": self.max_images,
            "max_header_fields": self.max_header_fields, "max_header_bytes": self.max_header_bytes,
            "max_robots_redirects": self.max_robots_redirects,
            "max_robots_body_bytes": self.max_robots_body_bytes,
            "max_robots_lines": self.max_robots_lines,
            "max_robots_bytes_per_line": self.max_robots_bytes_per_line,
            "max_robots_rules": self.max_robots_rules, "max_robots_groups": self.max_robots_groups,
            "robots_success_ttl_seconds": self.robots_success_ttl_seconds,
            "robots_failure_cooldown_seconds": self.robots_failure_cooldown_seconds,
            "allowed_projection_kinds": list(self.allowed_projection_kinds),
            "allowed_image_kinds": list(self.allowed_image_kinds),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class PublicFetchRefreshAuthority:
    tenant_id: str
    prior_attempt_digest: str
    operation_lineage_digest: str
    reason: RefreshReason
    issued_at: datetime
    expires_at: datetime
    authority_nonce_digest: str

    def __post_init__(self) -> None:
        _text(self.tenant_id, "tenant_id", 256, safe_id=True)
        _digest(self.prior_attempt_digest, "prior_attempt_digest")
        _digest(self.operation_lineage_digest, "operation_lineage_digest")
        if not isinstance(self.reason, RefreshReason):
            raise PublicFetchContractError("reason must be RefreshReason")
        object.__setattr__(self, "issued_at", _time(self.issued_at, "issued_at"))
        object.__setattr__(self, "expires_at", _time(self.expires_at, "expires_at"))
        if self.expires_at <= self.issued_at:
            raise PublicFetchContractError("refresh authority must expire after issue")
        _digest(self.authority_nonce_digest, "authority_nonce_digest")

    def canonical_payload(self) -> dict[str, object]:
        return {"tenant_id": self.tenant_id, "prior_attempt_digest": self.prior_attempt_digest,
                "operation_lineage_digest": self.operation_lineage_digest,
                "reason": self.reason.value, "issued_at": _iso(self.issued_at),
                "expires_at": _iso(self.expires_at),
                "authority_nonce_digest": self.authority_nonce_digest}

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class PublicFetchAuthorityBinding:
    """Server-registry authority; callers never construct or submit this value."""

    policy: PublicFetchPolicy
    idempotency_key_digest: str
    operation_lineage_digest: str
    driver_id: str
    driver_revision: str
    driver_qualification_digest: str
    refresh_authority: PublicFetchRefreshAuthority | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, PublicFetchPolicy):
            raise PublicFetchContractError("binding policy has wrong type")
        _digest(self.idempotency_key_digest, "idempotency_key_digest")
        _digest(self.operation_lineage_digest, "operation_lineage_digest")
        _text(self.driver_id, "driver_id", 128, safe_id=True)
        _text(self.driver_revision, "driver_revision", 128, safe_id=True)
        _digest(self.driver_qualification_digest, "driver_qualification_digest")
        if (self.refresh_authority is not None
                and not isinstance(self.refresh_authority, PublicFetchRefreshAuthority)):
            raise PublicFetchContractError("binding refresh authority has wrong type")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "policy": self.policy.canonical_payload(),
            "policy_digest": self.policy.digest,
            "idempotency_key_digest": self.idempotency_key_digest,
            "operation_lineage_digest": self.operation_lineage_digest,
            "driver_id": self.driver_id,
            "driver_revision": self.driver_revision,
            "driver_qualification_digest": self.driver_qualification_digest,
            "refresh_authority_digest": "" if self.refresh_authority is None
            else self.refresh_authority.digest,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class PublicFetchInvocation:
    tenant_id: str
    request: PublicFetchRequest
    policy: PublicFetchPolicy
    idempotency_key_digest: str
    operation_lineage_digest: str
    driver_id: str
    driver_revision: str
    driver_qualification_digest: str
    remaining_byte_authority: int
    remaining_time_authority_seconds: float
    invoked_at: datetime
    refresh_authority: PublicFetchRefreshAuthority | None = None

    def __post_init__(self) -> None:
        _text(self.tenant_id, "tenant_id", 256, safe_id=True)
        if not isinstance(self.request, PublicFetchRequest):
            raise PublicFetchContractError("request has wrong type")
        if not isinstance(self.policy, PublicFetchPolicy):
            raise PublicFetchContractError("policy has wrong type")
        _digest(self.idempotency_key_digest, "idempotency_key_digest")
        _digest(self.operation_lineage_digest, "operation_lineage_digest")
        _text(self.driver_id, "driver_id", 128, safe_id=True)
        _text(self.driver_revision, "driver_revision", 128, safe_id=True)
        _digest(self.driver_qualification_digest, "driver_qualification_digest")
        if (isinstance(self.remaining_byte_authority, bool)
                or not isinstance(self.remaining_byte_authority, int)
                or not 1 <= self.remaining_byte_authority
                <= self.policy.ceiling.max_total_bytes):
            raise PublicFetchContractError(
                "remaining byte authority is outside the policy ceiling")
        if (isinstance(self.remaining_time_authority_seconds, bool)
                or not isinstance(self.remaining_time_authority_seconds, (int, float))
                or not math.isfinite(float(self.remaining_time_authority_seconds))
                or not 0.0 < float(self.remaining_time_authority_seconds)
                <= self.policy.ceiling.total_timeout_seconds):
            raise PublicFetchContractError(
                "remaining time authority is outside the policy ceiling")
        object.__setattr__(self, "remaining_time_authority_seconds",
                           float(self.remaining_time_authority_seconds))
        object.__setattr__(self, "invoked_at", _time(self.invoked_at, "invoked_at"))
        if self.refresh_authority is not None:
            if self.refresh_authority.tenant_id != self.tenant_id:
                raise PublicFetchContractError("refresh authority tenant mismatch")
            if self.refresh_authority.operation_lineage_digest != self.operation_lineage_digest:
                raise PublicFetchContractError("refresh authority lineage mismatch")
            if not self.refresh_authority.issued_at <= self.invoked_at < self.refresh_authority.expires_at:
                raise PublicFetchContractError("refresh authority is not valid at invocation time")

    def canonical_payload(self) -> dict[str, object]:
        return {"tenant_id": self.tenant_id, "request": self.request.canonical_payload(),
                "request_digest": self.request.digest, "policy": self.policy.canonical_payload(),
                "policy_digest": self.policy.digest,
                "idempotency_key_digest": self.idempotency_key_digest,
                "operation_lineage_digest": self.operation_lineage_digest,
                "driver_id": self.driver_id, "driver_revision": self.driver_revision,
                "driver_qualification_digest": self.driver_qualification_digest,
                "remaining_byte_authority": self.remaining_byte_authority,
                "remaining_time_authority_seconds": self.remaining_time_authority_seconds,
                "invoked_at": _iso(self.invoked_at),
                "refresh_authority_digest": "" if self.refresh_authority is None
                else self.refresh_authority.digest}

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class RedirectHop:
    operation_index: int
    from_url: str = field(repr=False)
    to_url: str = field(repr=False)
    status: int
    origin: str
    approved_addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        if (isinstance(self.operation_index, bool) or not isinstance(self.operation_index, int)
                or not 0 <= self.operation_index < 256):
            raise PublicFetchContractError("redirect operation index is outside the v1 bound")
        _text(self.from_url, "from_url", 4096)
        _text(self.to_url, "to_url", 4096)
        _text(self.origin, "origin", 512)
        if self.status not in (301, 302, 303, 307, 308):
            raise PublicFetchContractError("redirect status is not admitted")
        _unique(self.approved_addresses, "approved_addresses", 16)

    def canonical_payload(self) -> dict[str, object]:
        return {"operation_index": self.operation_index,
                "from_url": self.from_url, "to_url": self.to_url, "status": self.status,
                "origin": self.origin, "approved_addresses": list(self.approved_addresses)}


@dataclass(frozen=True, slots=True)
class PeerEvidence:
    operation_index: int
    url: str = field(repr=False)
    origin: str
    lease_id_digest: str
    approved_addresses: tuple[str, ...]
    connected_address: str

    def __post_init__(self) -> None:
        if (isinstance(self.operation_index, bool) or not isinstance(self.operation_index, int)
                or not 0 <= self.operation_index < 256):
            raise PublicFetchContractError("peer operation index is outside the v1 bound")
        _text(self.url, "url", 4096)
        _text(self.origin, "origin", 512)
        _digest(self.lease_id_digest, "lease_id_digest")
        _unique(self.approved_addresses, "approved_addresses", 16)
        _text(self.connected_address, "connected_address", 128)
        if self.connected_address not in self.approved_addresses:
            raise PublicFetchContractError("connected peer is outside the approved address set")

    def canonical_payload(self) -> dict[str, object]:
        return {"operation_index": self.operation_index, "url": self.url,
                "origin": self.origin, "lease_id_digest": self.lease_id_digest,
                "approved_addresses": list(self.approved_addresses),
                "connected_address": self.connected_address}


@dataclass(frozen=True, slots=True)
class OriginPacingLease:
    tenant_id: str
    origin: str
    lease_id_digest: str
    acquired_at: datetime
    expires_at: datetime
    next_allowed_at: datetime

    def __post_init__(self) -> None:
        _text(self.tenant_id, "tenant_id", 256, safe_id=True)
        _text(self.origin, "origin", 512)
        _digest(self.lease_id_digest, "lease_id_digest")
        for name in ("acquired_at", "expires_at", "next_allowed_at"):
            object.__setattr__(self, name, _time(getattr(self, name), name))
        if self.expires_at <= self.acquired_at or self.next_allowed_at < self.acquired_at:
            raise PublicFetchContractError("invalid pacing lease chronology")

    def canonical_payload(self) -> dict[str, object]:
        return {"tenant_id": self.tenant_id, "origin": self.origin,
                "lease_id_digest": self.lease_id_digest, "acquired_at": _iso(self.acquired_at),
                "expires_at": _iso(self.expires_at), "next_allowed_at": _iso(self.next_allowed_at)}


class InitialPacingGrant:
    """Transient exact-origin grant; consuming it twice is a contract failure."""

    __slots__ = ("lease", "_consumed")

    def __init__(self, lease: OriginPacingLease) -> None:
        if not isinstance(lease, OriginPacingLease):
            raise PublicFetchContractError("initial pacing grant requires a lease")
        self.lease = lease
        self._consumed = False

    @property
    def consumed(self) -> bool:
        return self._consumed

    def consume(self, tenant_id: str, origin: str) -> OriginPacingLease:
        if self._consumed:
            raise PublicFetchContractError("initial pacing grant was already consumed")
        if self.lease.tenant_id != tenant_id or self.lease.origin != origin:
            raise PublicFetchContractError("initial pacing grant authority mismatch")
        self._consumed = True
        return self.lease


@dataclass(frozen=True, slots=True)
class OperationEvidence:
    index: int
    kind: OperationKind
    origin: str
    lease_id_digest: str
    elapsed_start_seconds: float
    elapsed_finish_seconds: float
    remaining_start_seconds: float
    exhausted_before_next: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or not 0 <= self.index < 256:
            raise PublicFetchContractError("operation index is outside the v1 bound")
        if not isinstance(self.kind, OperationKind):
            raise PublicFetchContractError("operation kind has wrong type")
        _text(self.origin, "origin", 512)
        _digest(self.lease_id_digest, "lease_id_digest")
        for name in ("elapsed_start_seconds", "elapsed_finish_seconds",
                     "remaining_start_seconds"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(float(value)) or float(value) < 0):
                raise PublicFetchContractError(f"{name} must be finite and non-negative")
        if self.elapsed_finish_seconds < self.elapsed_start_seconds:
            raise PublicFetchContractError("operation evidence finishes before it starts")
        if not isinstance(self.exhausted_before_next, bool):
            raise PublicFetchContractError("exhausted_before_next must be boolean")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "index": self.index,
            "kind": self.kind.value,
            "origin": self.origin,
            "lease_id_digest": self.lease_id_digest,
            "elapsed_start_seconds": float(self.elapsed_start_seconds),
            "elapsed_finish_seconds": float(self.elapsed_finish_seconds),
            "remaining_start_seconds": float(self.remaining_start_seconds),
            "exhausted_before_next": self.exhausted_before_next,
        }


@dataclass(frozen=True, slots=True)
class RobotsObservation:
    origin: str
    robots_target_digest: str
    operation_index: int
    lease_id_digest: str
    decision: RobotsDecision
    outcome_class: RobotsOutcome
    policy_revision: str
    product_token: str
    observed_at: datetime
    expires_at: datetime
    status: int | None
    artifact_digest: str = ""
    artifact_size: int = 0
    absence_reason: RobotsAbsenceReason | None = None
    redirects: tuple[RedirectHop, ...] = ()

    def __post_init__(self) -> None:
        _text(self.origin, "origin", 512)
        _digest(self.robots_target_digest, "robots_target_digest")
        if (isinstance(self.operation_index, bool) or not isinstance(self.operation_index, int)
                or not 0 <= self.operation_index < 256):
            raise PublicFetchContractError("robots operation index is outside the v1 bound")
        _digest(self.lease_id_digest, "lease_id_digest")
        if not isinstance(self.decision, RobotsDecision):
            raise PublicFetchContractError("decision must be RobotsDecision")
        if not isinstance(self.outcome_class, RobotsOutcome):
            raise PublicFetchContractError("outcome_class must be RobotsOutcome")
        allowed_decisions = {
            RobotsOutcome.RULES_APPLIED: RobotsDecision.ALLOW,
            RobotsOutcome.RULES_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.UNAVAILABLE_ALLOW: RobotsDecision.ALLOW,
            RobotsOutcome.ACCESS_REFUSED_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.RATE_LIMITED_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.UNCERTAIN_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.UNREACHABLE_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.SERVER_ERROR_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.POLICY_BLOCKED: RobotsDecision.DISALLOW,
        }
        if allowed_decisions[self.outcome_class] is not self.decision:
            raise PublicFetchContractError("robots outcome contradicts its decision")
        _text(self.policy_revision, "policy_revision", 128, safe_id=True)
        _text(self.product_token, "product_token", 128)
        object.__setattr__(self, "observed_at", _time(self.observed_at, "observed_at"))
        object.__setattr__(self, "expires_at", _time(self.expires_at, "expires_at"))
        if self.expires_at <= self.observed_at:
            raise PublicFetchContractError("robots evidence expiry must follow observation")
        if self.status is not None and (
                isinstance(self.status, bool) or not isinstance(self.status, int)
                or not 100 <= self.status <= 599):
            raise PublicFetchContractError("invalid robots status")
        if (isinstance(self.artifact_size, bool) or not isinstance(self.artifact_size, int)
                or self.artifact_size < 0):
            raise PublicFetchContractError("robots artifact_size must be a non-negative integer")
        if self.artifact_digest:
            _digest(self.artifact_digest, "artifact_digest")
            if self.absence_reason is not None or self.artifact_size <= 0:
                raise PublicFetchContractError("robots bytes require digest/size and no absence reason")
        elif not isinstance(self.absence_reason, RobotsAbsenceReason) or self.artifact_size != 0:
            raise PublicFetchContractError("missing robots bytes require a closed absence reason")
        absence_matrix: dict[
            RobotsAbsenceReason, tuple[frozenset[int | None], RobotsOutcome]
        ] = {
            RobotsAbsenceReason.UNAVAILABLE_NO_BODY: (frozenset({404, 410}),
                                                       RobotsOutcome.UNAVAILABLE_ALLOW),
            RobotsAbsenceReason.ACCESS_REFUSED: (frozenset({401, 403}),
                                                  RobotsOutcome.ACCESS_REFUSED_DISALLOW),
            RobotsAbsenceReason.RATE_LIMITED: (frozenset({429}),
                                                RobotsOutcome.RATE_LIMITED_DISALLOW),
            RobotsAbsenceReason.NETWORK_UNREACHABLE: (frozenset({None}),
                                                       RobotsOutcome.UNREACHABLE_DISALLOW),
            RobotsAbsenceReason.SERVER_ERROR: (frozenset(range(500, 600)),
                                                 RobotsOutcome.SERVER_ERROR_DISALLOW),
            RobotsAbsenceReason.NO_BODY_STATUS: (frozenset({204, 304}),
                                                  RobotsOutcome.UNCERTAIN_DISALLOW),
            RobotsAbsenceReason.OTHER_HTTP_STATUS: (
                _OTHER_ROBOTS_STATUSES, RobotsOutcome.UNCERTAIN_DISALLOW),
            RobotsAbsenceReason.REDIRECT_EXHAUSTED: (
                _ROBOTS_REDIRECT_STATUSES, RobotsOutcome.UNCERTAIN_DISALLOW),
            RobotsAbsenceReason.POLICY_BLOCKED: (frozenset({None}), RobotsOutcome.POLICY_BLOCKED),
        }
        if self.absence_reason is not None:
            statuses, outcome = absence_matrix[self.absence_reason]
            if self.status not in statuses or self.outcome_class is not outcome:
                raise PublicFetchContractError("robots absence reason contradicts status/outcome")
        elif (self.status is None or not 200 <= self.status <= 299 or self.status == 204
              or self.outcome_class not in {
                  RobotsOutcome.RULES_APPLIED,
                  RobotsOutcome.RULES_DISALLOW,
                  RobotsOutcome.UNCERTAIN_DISALLOW,
              }):
            raise PublicFetchContractError(
                "robots artifact requires a body-bearing 2xx rules outcome")
        if self.outcome_class is RobotsOutcome.RULES_APPLIED:
            if self.status is None or not 200 <= self.status <= 299 or not self.artifact_digest:
                raise PublicFetchContractError("rules-applied evidence requires a verified 2xx body")
        if self.outcome_class is RobotsOutcome.RULES_DISALLOW:
            if self.status is None or not 200 <= self.status <= 299 or not self.artifact_digest:
                raise PublicFetchContractError(
                    "rules-disallow evidence requires a verified 2xx body")
        if (not isinstance(self.redirects, tuple)
                or not all(isinstance(item, RedirectHop) for item in self.redirects)
                or len(self.redirects) > 5):
            raise PublicFetchContractError("robots redirects exceed their closed bound")
        indexes = tuple(item.operation_index for item in self.redirects)
        if (len(set(indexes)) != len(indexes)
                or any(index >= self.operation_index for index in indexes)):
            raise PublicFetchContractError(
                "robots redirect operations must be unique and precede the terminal hop")
        current = f"{self.origin}/robots.txt"
        for redirect in self.redirects:
            if redirect.from_url != current:
                raise PublicFetchContractError("robots redirect chain is not contiguous")
            current = redirect.to_url

    def canonical_payload(self) -> dict[str, object]:
        return {"origin": self.origin, "robots_target_digest": self.robots_target_digest,
                "operation_index": self.operation_index,
                "lease_id_digest": self.lease_id_digest,
                "decision": self.decision.value,
                "outcome_class": self.outcome_class.value,
                "policy_revision": self.policy_revision, "product_token": self.product_token,
                "observed_at": _iso(self.observed_at), "expires_at": _iso(self.expires_at),
                "status": self.status, "artifact_digest": self.artifact_digest,
                "artifact_size": self.artifact_size,
                "absence_reason": None if self.absence_reason is None else self.absence_reason.value,
                "redirects": [item.canonical_payload() for item in self.redirects]}

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class RobotsCacheUse:
    """Service-owned proof of a non-network use of one exact cached decision."""

    invocation_digest: str
    origin: str
    robots_target_digest: str
    policy_revision: str
    product_token: str
    decision: RobotsDecision
    outcome_class: RobotsOutcome
    source_observation_digest: str
    artifact_digest: str
    status: int | None
    absence_reason: RobotsAbsenceReason | None
    observed_at: datetime
    expires_at: datetime
    used_at: datetime

    def __post_init__(self) -> None:
        _digest(self.invocation_digest, "invocation_digest")
        _text(self.origin, "origin", 512)
        _digest(self.robots_target_digest, "robots_target_digest")
        _text(self.policy_revision, "policy_revision", 128, safe_id=True)
        _text(self.product_token, "product_token", 128)
        if not isinstance(self.decision, RobotsDecision):
            raise PublicFetchContractError("cache decision must be RobotsDecision")
        if not isinstance(self.outcome_class, RobotsOutcome):
            raise PublicFetchContractError("cache outcome_class must be RobotsOutcome")
        allowed_decisions = {
            RobotsOutcome.RULES_APPLIED: RobotsDecision.ALLOW,
            RobotsOutcome.RULES_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.UNAVAILABLE_ALLOW: RobotsDecision.ALLOW,
            RobotsOutcome.ACCESS_REFUSED_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.RATE_LIMITED_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.UNCERTAIN_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.UNREACHABLE_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.SERVER_ERROR_DISALLOW: RobotsDecision.DISALLOW,
            RobotsOutcome.POLICY_BLOCKED: RobotsDecision.DISALLOW,
        }
        if allowed_decisions[self.outcome_class] is not self.decision:
            raise PublicFetchContractError("cache outcome contradicts its decision")
        _digest(self.source_observation_digest, "source_observation_digest")
        if self.artifact_digest:
            _digest(self.artifact_digest, "artifact_digest")
            if self.absence_reason is not None:
                raise PublicFetchContractError("cached artifact cannot carry an absence reason")
        elif not isinstance(self.absence_reason, RobotsAbsenceReason):
            raise PublicFetchContractError("cached no-body source requires an absence reason")
        if self.status is not None and (
                isinstance(self.status, bool) or not isinstance(self.status, int)
                or not 100 <= self.status <= 599):
            raise PublicFetchContractError("invalid cached robots status")
        object.__setattr__(self, "observed_at", _time(self.observed_at, "observed_at"))
        object.__setattr__(self, "expires_at", _time(self.expires_at, "expires_at"))
        object.__setattr__(self, "used_at", _time(self.used_at, "used_at"))
        if not self.observed_at <= self.used_at < self.expires_at:
            raise PublicFetchContractError("cache use is outside its source lifetime")
        absence_matrix: dict[
            RobotsAbsenceReason, tuple[frozenset[int | None], RobotsOutcome]
        ] = {
            RobotsAbsenceReason.UNAVAILABLE_NO_BODY: (
                frozenset({404, 410}), RobotsOutcome.UNAVAILABLE_ALLOW),
            RobotsAbsenceReason.ACCESS_REFUSED: (
                frozenset({401, 403}), RobotsOutcome.ACCESS_REFUSED_DISALLOW),
            RobotsAbsenceReason.RATE_LIMITED: (
                frozenset({429}), RobotsOutcome.RATE_LIMITED_DISALLOW),
            RobotsAbsenceReason.NETWORK_UNREACHABLE: (
                frozenset({None}), RobotsOutcome.UNREACHABLE_DISALLOW),
            RobotsAbsenceReason.SERVER_ERROR: (
                frozenset(range(500, 600)), RobotsOutcome.SERVER_ERROR_DISALLOW),
            RobotsAbsenceReason.NO_BODY_STATUS: (
                frozenset({204, 304}), RobotsOutcome.UNCERTAIN_DISALLOW),
            RobotsAbsenceReason.OTHER_HTTP_STATUS: (
                _OTHER_ROBOTS_STATUSES, RobotsOutcome.UNCERTAIN_DISALLOW),
            RobotsAbsenceReason.REDIRECT_EXHAUSTED: (
                _ROBOTS_REDIRECT_STATUSES, RobotsOutcome.UNCERTAIN_DISALLOW),
            RobotsAbsenceReason.POLICY_BLOCKED: (
                frozenset({None}), RobotsOutcome.POLICY_BLOCKED),
        }
        if self.absence_reason is not None:
            statuses, outcome = absence_matrix[self.absence_reason]
            if self.status not in statuses or self.outcome_class is not outcome:
                raise PublicFetchContractError(
                    "cached absence reason contradicts source status/outcome")
        elif (self.status is None or not 200 <= self.status <= 299 or self.status == 204
              or self.outcome_class not in {
                  RobotsOutcome.RULES_APPLIED,
                  RobotsOutcome.RULES_DISALLOW,
                  RobotsOutcome.UNCERTAIN_DISALLOW,
              }):
            raise PublicFetchContractError(
                "cached artifact requires a body-bearing 2xx rules outcome")
        if self.outcome_class in (RobotsOutcome.RULES_APPLIED,
                                  RobotsOutcome.RULES_DISALLOW):
            if self.status is None or not 200 <= self.status <= 299 or not self.artifact_digest:
                raise PublicFetchContractError("cached rules require a verified 2xx artifact")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "invocation_digest": self.invocation_digest,
            "origin": self.origin,
            "robots_target_digest": self.robots_target_digest,
            "policy_revision": self.policy_revision,
            "product_token": self.product_token,
            "decision": self.decision.value,
            "outcome_class": self.outcome_class.value,
            "source_observation_digest": self.source_observation_digest,
            "artifact_digest": self.artifact_digest,
            "status": self.status,
            "absence_reason": (None if self.absence_reason is None
                               else self.absence_reason.value),
            "observed_at": _iso(self.observed_at),
            "expires_at": _iso(self.expires_at),
            "used_at": _iso(self.used_at),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


# Compatibility import name for the frozen pre-rev3 partial implementation.
# It resolves to the plural, operation-bound rev3 record rather than preserving
# a second legacy shape.
RobotsEvidence = RobotsObservation


@dataclass(frozen=True, slots=True)
class PublicFetchAttempt:
    tenant_id: str
    invocation_digest: str
    request_digest: str
    policy_digest: str
    idempotency_key_digest: str
    operation_lineage_digest: str
    canonical_url: str = field(repr=False)
    state: AttemptState
    reserved_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    previous_attempt_digest: str = ""
    revision_predecessor_digest: str = ""
    refresh_authority_digest: str = ""
    start_token_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.tenant_id, "tenant_id", 256, safe_id=True)
        for value, name in ((self.invocation_digest, "invocation_digest"),
                            (self.request_digest, "request_digest"),
                            (self.policy_digest, "policy_digest"),
                            (self.idempotency_key_digest, "idempotency_key_digest"),
                            (self.operation_lineage_digest, "operation_lineage_digest")):
            _digest(value, name)
        _text(self.canonical_url, "canonical_url", 4096)
        if not isinstance(self.state, AttemptState):
            raise PublicFetchContractError("state must be AttemptState")
        object.__setattr__(self, "reserved_at", _time(self.reserved_at, "reserved_at"))
        if self.started_at is not None:
            object.__setattr__(self, "started_at", _time(self.started_at, "started_at"))
        if self.finished_at is not None:
            object.__setattr__(self, "finished_at", _time(self.finished_at, "finished_at"))
        if self.state is AttemptState.RESERVED and (self.started_at or self.finished_at):
            raise PublicFetchContractError("reserved attempt cannot have later timestamps")
        if self.state is AttemptState.STARTED and (self.started_at is None or self.finished_at):
            raise PublicFetchContractError("started attempt requires only started_at")
        if self.state in (AttemptState.COMPLETED, AttemptState.FAILED, AttemptState.UNKNOWN):
            if self.started_at is None or self.finished_at is None:
                raise PublicFetchContractError("terminal attempt requires start and finish")
        if self.started_at and self.started_at < self.reserved_at:
            raise PublicFetchContractError("attempt starts before reservation")
        if self.finished_at and self.started_at and self.finished_at < self.started_at:
            raise PublicFetchContractError("attempt finishes before start")
        _digest(self.previous_attempt_digest, "previous_attempt_digest", optional=True)
        _digest(self.revision_predecessor_digest, "revision_predecessor_digest", optional=True)
        _digest(self.refresh_authority_digest, "refresh_authority_digest", optional=True)
        _digest(self.start_token_digest, "start_token_digest", optional=True)
        if not self.start_token_digest:
            raise PublicFetchContractError("attempt requires a start-token digest")

    def canonical_payload(self) -> dict[str, object]:
        return {"tenant_id": self.tenant_id, "invocation_digest": self.invocation_digest,
                "request_digest": self.request_digest, "policy_digest": self.policy_digest,
                "idempotency_key_digest": self.idempotency_key_digest,
                "operation_lineage_digest": self.operation_lineage_digest,
                "canonical_url": self.canonical_url, "state": self.state.value,
                "reserved_at": _iso(self.reserved_at), "started_at": _iso(self.started_at),
                "finished_at": _iso(self.finished_at),
                "previous_attempt_digest": self.previous_attempt_digest,
                "revision_predecessor_digest": self.revision_predecessor_digest,
                "refresh_authority_digest": self.refresh_authority_digest,
                "start_token_digest": self.start_token_digest}

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class DriverObservation:
    outcome: PublicFetchOutcome
    final_url: str = field(repr=False)
    retrieved_at: datetime
    http_status: int | None
    declared_media_type: str
    observed_media_type: str
    redirects: tuple[RedirectHop, ...]
    peers: tuple[PeerEvidence, ...]
    operation_evidence: tuple[OperationEvidence, ...]
    robots_observations: tuple[RobotsObservation, ...]
    wire_bytes: int
    provider_actual_usd: float | None
    infrastructure_metering_state: InfrastructureMeteringState
    infrastructure_actual_usd: float | None
    safe_detail_code: str
    body: bytes | None = field(default=None, repr=False)
    robots_bodies: tuple[bytes | None, ...] = field(default=(), repr=False)
    robots_cache_uses: tuple[RobotsCacheUse, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, PublicFetchOutcome):
            raise PublicFetchContractError("outcome must be PublicFetchOutcome")
        _text(self.final_url, "final_url", 4096)
        object.__setattr__(self, "retrieved_at", _time(self.retrieved_at, "retrieved_at"))
        if self.http_status is not None and not 100 <= self.http_status <= 599:
            raise PublicFetchContractError("invalid http status")
        for value, name in ((self.declared_media_type, "declared_media_type"),
                            (self.observed_media_type, "observed_media_type"),
                            (self.safe_detail_code, "safe_detail_code")):
            if value:
                _text(value, name, 256)
        if not isinstance(self.redirects, tuple) or not all(isinstance(x, RedirectHop) for x in self.redirects):
            raise PublicFetchContractError("redirects has wrong type")
        if not isinstance(self.peers, tuple) or not all(isinstance(x, PeerEvidence) for x in self.peers):
            raise PublicFetchContractError("peers has wrong type")
        if (not isinstance(self.operation_evidence, tuple)
                or not all(isinstance(item, OperationEvidence) for item in self.operation_evidence)
                or len(self.operation_evidence) > 256):
            raise PublicFetchContractError("operation evidence has wrong type or exceeds its bound")
        if tuple(item.index for item in self.operation_evidence) != tuple(range(len(self.operation_evidence))):
            raise PublicFetchContractError("operation evidence must be ordered and contiguous")
        lease_ids = tuple(item.lease_id_digest for item in self.operation_evidence)
        if len(set(lease_ids)) != len(lease_ids):
            raise PublicFetchContractError("each external operation requires a unique lease")
        operations = {item.index: item for item in self.operation_evidence}
        if len(self.peers) != len(self.operation_evidence):
            raise PublicFetchContractError("every external operation requires one peer observation")
        peer_by_index = {item.operation_index: item for item in self.peers}
        if len(peer_by_index) != len(self.peers):
            raise PublicFetchContractError("peer operation indexes must be unique")
        for operation in self.operation_evidence:
            peer = peer_by_index.get(operation.index)
            if (peer is None or peer.origin != operation.origin
                    or peer.lease_id_digest != operation.lease_id_digest):
                raise PublicFetchContractError("peer evidence is not bound to its operation")
        redirect_indexes = tuple(item.operation_index for item in self.redirects)
        if len(set(redirect_indexes)) != len(redirect_indexes):
            raise PublicFetchContractError("redirect operation indexes must be unique")
        for redirect in self.redirects:
            redirect_operation = operations.get(redirect.operation_index)
            peer = peer_by_index.get(redirect.operation_index)
            if (redirect_operation is None or redirect_operation.kind is not OperationKind.REDIRECT
                    or redirect_operation.origin != redirect.origin or peer is None
                    or peer.url != redirect.from_url
                    or peer.approved_addresses != redirect.approved_addresses):
                raise PublicFetchContractError("redirect evidence is not bound to its operation")
        if (not isinstance(self.robots_observations, tuple)
                or not all(isinstance(item, RobotsObservation) for item in self.robots_observations)
                or len(self.robots_observations) > 16):
            raise PublicFetchContractError("robots observations have wrong type or exceed their bound")
        robots_operation_indexes: set[int] = set()
        for item in self.robots_observations:
            item_indexes = {item.operation_index, *(hop.operation_index for hop in item.redirects)}
            if (robots_operation_indexes.intersection(item_indexes)
                    or set(redirect_indexes).intersection(item_indexes)):
                raise PublicFetchContractError(
                    "robots observations must use distinct non-page operation indexes")
            robots_operation_indexes.update(item_indexes)
            robots_operation = operations.get(item.operation_index)
            if (robots_operation is None or robots_operation.kind is not OperationKind.ROBOTS
                    or robots_operation.lease_id_digest != item.lease_id_digest):
                raise PublicFetchContractError("robots observation is not bound to its producing operation")
            terminal_url = f"{item.origin}/robots.txt"
            for redirect in item.redirects:
                redirect_operation = operations.get(redirect.operation_index)
                peer = peer_by_index.get(redirect.operation_index)
                if (redirect.operation_index in redirect_indexes
                        or redirect_operation is None
                        or redirect_operation.kind is not OperationKind.ROBOTS
                        or redirect_operation.origin != redirect.origin
                        or peer is None or peer.url != redirect.from_url
                        or peer.approved_addresses != redirect.approved_addresses):
                    raise PublicFetchContractError(
                        "robots redirect evidence is not bound to its operation")
                terminal_url = redirect.to_url
            terminal_peer = peer_by_index.get(item.operation_index)
            if terminal_peer is None or terminal_peer.url != terminal_url:
                raise PublicFetchContractError(
                    "robots terminal operation is not the redirect-chain terminus")
        if (not isinstance(self.robots_cache_uses, tuple)
                or not all(isinstance(item, RobotsCacheUse) for item in self.robots_cache_uses)
                or len(self.robots_cache_uses) > 16):
            raise PublicFetchContractError("robots cache uses have wrong type or exceed their bound")
        cache_keys = tuple((item.origin, item.robots_target_digest)
                           for item in self.robots_cache_uses)
        if len(set(cache_keys)) != len(cache_keys):
            raise PublicFetchContractError("robots cache uses contain duplicate target authority")
        fresh_keys = {(item.origin, item.robots_target_digest)
                      for item in self.robots_observations}
        if fresh_keys & set(cache_keys):
            raise PublicFetchContractError("fresh and cached robots evidence overlap")
        if isinstance(self.wire_bytes, bool) or not isinstance(self.wire_bytes, int) or self.wire_bytes < 0:
            raise PublicFetchContractError("wire_bytes must be non-negative")
        object.__setattr__(self, "provider_actual_usd",
                           _finite_nonnegative(self.provider_actual_usd, "provider_actual_usd"))
        if not isinstance(self.infrastructure_metering_state, InfrastructureMeteringState):
            raise PublicFetchContractError("invalid infrastructure metering state")
        object.__setattr__(self, "infrastructure_actual_usd", _finite_nonnegative(
            self.infrastructure_actual_usd, "infrastructure_actual_usd"))
        if ((self.infrastructure_metering_state is InfrastructureMeteringState.METERED)
                != (self.infrastructure_actual_usd is not None)):
            raise PublicFetchContractError("infrastructure actual must match metering state")
        if self.outcome is PublicFetchOutcome.SUCCEEDED and self.body is None:
            raise PublicFetchContractError("success requires body bytes")
        if self.outcome is not PublicFetchOutcome.SUCCEEDED and self.body is not None:
            raise PublicFetchContractError("failed observation cannot expose adoptable body")
        if self.body is not None and not isinstance(self.body, bytes):
            raise PublicFetchContractError("body must be immutable bytes")
        if (not isinstance(self.robots_bodies, tuple)
                or len(self.robots_bodies) != len(self.robots_observations)):
            raise PublicFetchContractError("robots bodies must align with observations")
        for evidence, content in zip(self.robots_observations, self.robots_bodies, strict=True):
            if evidence.artifact_digest:
                if (not isinstance(content, bytes) or not content
                        or hashlib.sha256(content).hexdigest() != evidence.artifact_digest
                        or len(content) != evidence.artifact_size):
                    raise PublicFetchContractError("robots bytes do not match their observation")
            elif content is not None:
                raise PublicFetchContractError("no-body robots observation carried bytes")


@dataclass(frozen=True, slots=True)
class PublicFetchReceipt:
    tenant_id: str
    attempt_digest: str
    invocation_digest: str
    request_digest: str
    policy_digest: str
    requested_url: str = field(repr=False)
    canonical_url: str = field(repr=False)
    final_url: str = field(repr=False)
    outcome: PublicFetchOutcome
    retrieved_at: datetime
    settled_at: datetime
    driver_id: str
    driver_revision: str
    driver_qualification_digest: str
    redirects: tuple[RedirectHop, ...]
    peers: tuple[PeerEvidence, ...]
    operation_evidence: tuple[OperationEvidence, ...]
    robots_observations: tuple[RobotsObservation, ...]
    http_status: int | None
    response_artifact_digest: str
    response_size: int
    declared_media_type: str
    observed_media_type: str
    provider_actual_usd: float | None
    infrastructure_metering_state: InfrastructureMeteringState
    infrastructure_actual_usd: float | None
    observed_wire_bytes: int
    resource_ceiling: ResourceCeiling
    remaining_byte_authority: int
    remaining_time_authority_seconds: float
    safe_detail_code: str
    robots_cache_uses: tuple[RobotsCacheUse, ...] = ()

    def __post_init__(self) -> None:
        _text(self.tenant_id, "tenant_id", 256, safe_id=True)
        for value, name in ((self.attempt_digest, "attempt_digest"),
                            (self.invocation_digest, "invocation_digest"),
                            (self.request_digest, "request_digest"),
                            (self.policy_digest, "policy_digest"),
                            (self.driver_qualification_digest, "driver_qualification_digest")):
            _digest(value, name)
        for value, name in ((self.requested_url, "requested_url"),
                            (self.canonical_url, "canonical_url"), (self.final_url, "final_url")):
            _text(value, name, 4096)
        if not isinstance(self.outcome, PublicFetchOutcome):
            raise PublicFetchContractError("invalid outcome")
        object.__setattr__(self, "retrieved_at", _time(self.retrieved_at, "retrieved_at"))
        object.__setattr__(self, "settled_at", _time(self.settled_at, "settled_at"))
        if self.settled_at < self.retrieved_at:
            raise PublicFetchContractError("settlement predates retrieval")
        _text(self.driver_id, "driver_id", 128, safe_id=True)
        _text(self.driver_revision, "driver_revision", 128, safe_id=True)
        if not isinstance(self.redirects, tuple) or not all(isinstance(x, RedirectHop) for x in self.redirects):
            raise PublicFetchContractError("invalid redirect evidence")
        if not isinstance(self.peers, tuple) or not all(isinstance(x, PeerEvidence) for x in self.peers):
            raise PublicFetchContractError("invalid peer evidence")
        if (not isinstance(self.operation_evidence, tuple)
                or not all(isinstance(item, OperationEvidence) for item in self.operation_evidence)
                or tuple(item.index for item in self.operation_evidence)
                != tuple(range(len(self.operation_evidence)))):
            raise PublicFetchContractError("invalid ordered operation evidence")
        lease_ids = tuple(item.lease_id_digest for item in self.operation_evidence)
        if len(set(lease_ids)) != len(lease_ids):
            raise PublicFetchContractError("receipt operations require unique leases")
        operations = {item.index: item for item in self.operation_evidence}
        if len(self.peers) != len(self.operation_evidence):
            raise PublicFetchContractError("receipt requires one peer per external operation")
        peer_by_index = {item.operation_index: item for item in self.peers}
        if len(peer_by_index) != len(self.peers):
            raise PublicFetchContractError("receipt peer operation indexes must be unique")
        for operation in self.operation_evidence:
            peer = peer_by_index.get(operation.index)
            if (peer is None or peer.origin != operation.origin
                    or peer.lease_id_digest != operation.lease_id_digest):
                raise PublicFetchContractError("receipt peer evidence is incoherent")
        redirect_indexes = tuple(item.operation_index for item in self.redirects)
        if len(set(redirect_indexes)) != len(redirect_indexes):
            raise PublicFetchContractError("receipt redirect operation indexes must be unique")
        for redirect in self.redirects:
            redirect_operation = operations.get(redirect.operation_index)
            peer = peer_by_index.get(redirect.operation_index)
            if (redirect_operation is None or redirect_operation.kind is not OperationKind.REDIRECT
                    or redirect_operation.origin != redirect.origin or peer is None
                    or peer.url != redirect.from_url
                    or peer.approved_addresses != redirect.approved_addresses):
                raise PublicFetchContractError("receipt redirect evidence is incoherent")
        if (not isinstance(self.robots_observations, tuple)
                or not all(isinstance(item, RobotsObservation) for item in self.robots_observations)
                or len(self.robots_observations) > 16):
            raise PublicFetchContractError("invalid robots observations")
        robots_operation_indexes: set[int] = set()
        for item in self.robots_observations:
            item_indexes = {item.operation_index, *(hop.operation_index for hop in item.redirects)}
            if (robots_operation_indexes.intersection(item_indexes)
                    or set(redirect_indexes).intersection(item_indexes)):
                raise PublicFetchContractError(
                    "receipt robots observations reuse an operation index")
            robots_operation_indexes.update(item_indexes)
            robots_operation = operations.get(item.operation_index)
            if (robots_operation is None or robots_operation.kind is not OperationKind.ROBOTS
                    or robots_operation.lease_id_digest != item.lease_id_digest):
                raise PublicFetchContractError("receipt robots evidence is incoherent")
            terminal_url = f"{item.origin}/robots.txt"
            for redirect in item.redirects:
                redirect_operation = operations.get(redirect.operation_index)
                peer = peer_by_index.get(redirect.operation_index)
                if (redirect.operation_index in redirect_indexes
                        or redirect_operation is None
                        or redirect_operation.kind is not OperationKind.ROBOTS
                        or redirect_operation.origin != redirect.origin
                        or peer is None or peer.url != redirect.from_url
                        or peer.approved_addresses != redirect.approved_addresses):
                    raise PublicFetchContractError(
                        "receipt robots redirect evidence is incoherent")
                terminal_url = redirect.to_url
            terminal_peer = peer_by_index.get(item.operation_index)
            if terminal_peer is None or terminal_peer.url != terminal_url:
                raise PublicFetchContractError(
                    "receipt robots terminal evidence is incoherent")
        if (not isinstance(self.robots_cache_uses, tuple)
                or not all(isinstance(item, RobotsCacheUse) for item in self.robots_cache_uses)
                or len(self.robots_cache_uses) > 16):
            raise PublicFetchContractError("invalid robots cache uses")
        cache_keys = tuple((item.origin, item.robots_target_digest)
                           for item in self.robots_cache_uses)
        if len(set(cache_keys)) != len(cache_keys):
            raise PublicFetchContractError("receipt cache uses contain duplicate target authority")
        if any(item.invocation_digest != self.invocation_digest
               for item in self.robots_cache_uses):
            raise PublicFetchContractError("receipt cache use invocation binding drift")
        fresh_keys = {(item.origin, item.robots_target_digest)
                      for item in self.robots_observations}
        if fresh_keys & set(cache_keys):
            raise PublicFetchContractError("receipt fresh and cached robots evidence overlap")
        if self.response_artifact_digest:
            _digest(self.response_artifact_digest, "response_artifact_digest")
        if (isinstance(self.response_size, bool) or not isinstance(self.response_size, int)
                or isinstance(self.observed_wire_bytes, bool)
                or not isinstance(self.observed_wire_bytes, int)
                or self.response_size < 0 or self.observed_wire_bytes < 0):
            raise PublicFetchContractError("sizes must be non-negative")
        if not isinstance(self.resource_ceiling, ResourceCeiling):
            raise PublicFetchContractError("resource_ceiling must be ResourceCeiling")
        if (isinstance(self.remaining_byte_authority, bool)
                or not isinstance(self.remaining_byte_authority, int)
                or not 1 <= self.remaining_byte_authority
                <= self.resource_ceiling.max_total_bytes):
            raise PublicFetchContractError(
                "receipt remaining byte authority is outside its resource ceiling")
        if (isinstance(self.remaining_time_authority_seconds, bool)
                or not isinstance(self.remaining_time_authority_seconds, (int, float))
                or not math.isfinite(float(self.remaining_time_authority_seconds))
                or not 0.0 < float(self.remaining_time_authority_seconds)
                <= self.resource_ceiling.total_timeout_seconds):
            raise PublicFetchContractError(
                "receipt remaining time authority is outside its resource ceiling")
        object.__setattr__(self, "remaining_time_authority_seconds",
                           float(self.remaining_time_authority_seconds))
        if any(item.elapsed_finish_seconds > self.remaining_time_authority_seconds
               or item.remaining_start_seconds > self.remaining_time_authority_seconds
               for item in self.operation_evidence):
            raise PublicFetchContractError(
                "operation evidence exceeds its remaining time authority")
        if self.response_size > self.resource_ceiling.max_response_bytes:
            raise PublicFetchContractError("response exceeds its authorized ceiling")
        if self.response_size > self.remaining_byte_authority:
            raise PublicFetchContractError("response exceeds its remaining byte authority")
        if self.observed_wire_bytes > self.remaining_byte_authority:
            raise PublicFetchContractError("wire bytes exceed their authorized ceiling")
        if len(self.redirects) > self.resource_ceiling.max_redirects:
            raise PublicFetchContractError("redirect evidence exceeds its authorized ceiling")
        if self.outcome is PublicFetchOutcome.SUCCEEDED:
            if not self.response_artifact_digest or self.response_size <= 0:
                raise PublicFetchContractError("success requires a verified artifact")
        elif self.response_artifact_digest or self.response_size:
            raise PublicFetchContractError("non-success cannot expose an adoptable artifact")
        object.__setattr__(self, "provider_actual_usd",
                           _finite_nonnegative(self.provider_actual_usd, "provider_actual_usd"))
        if not isinstance(self.infrastructure_metering_state, InfrastructureMeteringState):
            raise PublicFetchContractError("invalid infrastructure metering state")
        object.__setattr__(self, "infrastructure_actual_usd", _finite_nonnegative(
            self.infrastructure_actual_usd, "infrastructure_actual_usd"))
        if ((self.infrastructure_metering_state is InfrastructureMeteringState.METERED)
                != (self.infrastructure_actual_usd is not None)):
            raise PublicFetchContractError("infrastructure actual must match metering state")
        if self.outcome is PublicFetchOutcome.UNKNOWN and self.provider_actual_usd == 0.0:
            raise PublicFetchContractError("UNKNOWN may not manufacture zero provider cost")
        _text(self.safe_detail_code, "safe_detail_code", 256, safe_id=True)

    def canonical_payload(self) -> dict[str, object]:
        return {"tenant_id": self.tenant_id, "attempt_digest": self.attempt_digest,
                "invocation_digest": self.invocation_digest, "request_digest": self.request_digest,
                "policy_digest": self.policy_digest, "requested_url": self.requested_url,
                "canonical_url": self.canonical_url, "final_url": self.final_url,
                "outcome": self.outcome.value, "retrieved_at": _iso(self.retrieved_at),
                "settled_at": _iso(self.settled_at), "driver_id": self.driver_id,
                "driver_revision": self.driver_revision,
                "driver_qualification_digest": self.driver_qualification_digest,
                "redirects": [x.canonical_payload() for x in self.redirects],
                "peers": [x.canonical_payload() for x in self.peers],
                "operation_evidence": [x.canonical_payload() for x in self.operation_evidence],
                "robots_observations": [x.canonical_payload() for x in self.robots_observations],
                "robots_cache_uses": [x.canonical_payload() for x in self.robots_cache_uses],
                "http_status": self.http_status,
                "response_artifact_digest": self.response_artifact_digest,
                "response_size": self.response_size,
                "declared_media_type": self.declared_media_type,
                "observed_media_type": self.observed_media_type,
                "provider_actual_usd": self.provider_actual_usd,
                "infrastructure_metering_state": self.infrastructure_metering_state.value,
                "infrastructure_actual_usd": self.infrastructure_actual_usd,
                "observed_wire_bytes": self.observed_wire_bytes,
                "resource_ceiling": self.resource_ceiling.canonical_payload(),
                "remaining_byte_authority": self.remaining_byte_authority,
                "remaining_time_authority_seconds": self.remaining_time_authority_seconds,
                "safe_detail_code": self.safe_detail_code}

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class PublicFetchCandidate:
    from_url: str
    final_url: str
    candidate_url: str
    purpose: ResourcePurpose
    authority: CandidateAuthority

    def __post_init__(self) -> None:
        _safe_surface_url(self.from_url, "candidate from_url")
        _safe_surface_url(self.final_url, "candidate final_url")
        _safe_surface_url(self.candidate_url, "candidate URL")
        if self.purpose not in (ResourcePurpose.PAGE, ResourcePurpose.IMAGE):
            raise PublicFetchContractError("candidate purpose is outside the crawl vocabulary")
        if not isinstance(self.authority, CandidateAuthority):
            raise PublicFetchContractError("candidate authority has wrong type")
        if ((self.purpose is ResourcePurpose.PAGE)
                != (self.authority is CandidateAuthority.SAME_ORIGIN_PAGE)):
            raise PublicFetchContractError("candidate purpose contradicts authority class")


@dataclass(frozen=True, slots=True)
class PublicFetchProjection:
    receipt_digest: str
    outcome: PublicFetchOutcome
    final_url: str
    retrieved_at: datetime
    safe_detail_code: str
    text: str = ""
    artifact_digest: str = ""
    media_type: str = ""
    byte_count: int = 0
    candidates: tuple[PublicFetchCandidate, ...] = ()

    def __post_init__(self) -> None:
        _digest(self.receipt_digest, "receipt_digest")
        if not isinstance(self.outcome, PublicFetchOutcome):
            raise PublicFetchContractError("invalid projection outcome")
        _safe_surface_url(self.final_url, "final_url")
        object.__setattr__(self, "retrieved_at", _time(self.retrieved_at, "retrieved_at"))
        _text(self.safe_detail_code, "safe_detail_code", 256, safe_id=True)
        if self.artifact_digest:
            _digest(self.artifact_digest, "artifact_digest")
        if (isinstance(self.byte_count, bool) or not isinstance(self.byte_count, int)
                or self.byte_count < 0):
            raise PublicFetchContractError("byte_count must be non-negative")
        if not isinstance(self.text, str) or any(ord(char) < 0x20 and char not in "\n\t"
                                                 for char in self.text):
            raise PublicFetchContractError("projection text has wrong type or controls")
        if _SECRET_VALUE.search(self.text):
            raise PublicFetchContractError("projection text contains an unredacted credential value")
        if len(self.text) > 240_000:
            raise PublicFetchContractError("projection text exceeds the hard maximum")
        if self.media_type:
            _text(self.media_type, "media_type", 128)
        if self.artifact_digest and (self.text or not self.media_type or self.byte_count <= 0):
            raise PublicFetchContractError("opaque projection shape is inconsistent")
        if self.text and (self.artifact_digest or self.byte_count <= 0):
            raise PublicFetchContractError("text projection shape is inconsistent")
        if (not isinstance(self.candidates, tuple)
                or not all(isinstance(item, PublicFetchCandidate) for item in self.candidates)
                or len(self.candidates) > 80):
            raise PublicFetchContractError("projection candidates exceed their closed hard bound")
        candidate_keys = tuple((item.purpose, item.candidate_url) for item in self.candidates)
        if len(set(candidate_keys)) != len(candidate_keys):
            raise PublicFetchContractError("projection candidates contain duplicates")
        if self.candidates and not self.text:
            raise PublicFetchContractError("only HTML text projections may carry candidates")


class OriginPacer(Protocol):
    """Invocation-bound driver port; tenant and pacing policy are not parameters."""

    def acquire_origin(self, origin: str) -> OriginPacingLease: ...
    def release_origin(self, lease_id_digest: str) -> None: ...


class RobotsCacheReader(Protocol):
    """Invocation-bound cache port; policy revision and tenant are fixed."""

    def get_robots(self, canonical_target_url: str) -> RobotsCacheUse | None: ...


class PublicFetchAuthorityRegistry(Protocol):
    def resolve(self, tenant_id: str,
                request: PublicFetchRequest) -> PublicFetchAuthorityBinding: ...


class PublicFetchDriverRegistry(Protocol):
    def resolve(self, binding: PublicFetchAuthorityBinding) -> PublicFetchDriver: ...


class DeadlineWaiter(Protocol):
    def wait(self, seconds: float, deadline: DeadlineBudget) -> None: ...


class PublicFetchDriver(Protocol):
    def fetch(self, invocation: PublicFetchInvocation, canonical_url: str,
              initial_grant: InitialPacingGrant, deadline: DeadlineBudget,
              pacer: OriginPacer, robots_cache: RobotsCacheReader) -> DriverObservation: ...
