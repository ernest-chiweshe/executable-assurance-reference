"""Load externally protected evidence-history pins for the reference host.

The deployment supplies one bounded catalog whose head and checkpoint history
live outside the mutable evidence database.  This module never discovers pins
from database rows and never substitutes an unconfigured tenant.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from regulated_core.evidence_checkpoints_pg import Checkpoint, PinnedHistory, PinnedVerifier
from regulated_core.persistence_pg import PersistenceError
from regulated_core.signing import Signature, TrustDirectory

PINNED_HISTORY_SCHEMA = "reference/pinned-evidence-histories/v1"
_MAX_HISTORY_BYTES = 1_048_576
_MAX_TENANTS = 10_000
_MAX_CHECKPOINTS_PER_TENANT = 4_096
_MAX_VERIFICATION_ENTRIES = 4_096
_TOP_LEVEL_FIELDS = {
    "schema",
    "profile",
    "current_evidence_key_id",
    "evidence_key_ids",
    "max_entries",
    "tenants",
}
_TENANT_FIELDS = {"tenant_id", "checkpoints", "head_digest"}
_CHECKPOINT_FIELDS = {
    "schema",
    "tenant",
    "from_seq",
    "to_seq",
    "previous_digest",
    "last_entry_hash",
    "profile",
    "signature",
}
_SIGNATURE_FIELDS = {"key_id", "value", "alg"}
_HEX = frozenset("0123456789abcdef")


class PinnedHistoryConfigError(ValueError):
    """The deployment's protected Pinned evidence history is invalid."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PinnedHistoryConfigError(
                "Pinned evidence history contains a duplicate field"
            )
        result[key] = value
    return result


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise PinnedHistoryConfigError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    digest = _text(value, label, maximum=64)
    if len(digest) != 64 or not set(digest) <= _HEX:
        raise PinnedHistoryConfigError(f"{label} is invalid")
    return digest


def _integer(value: Any, label: str, *, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise PinnedHistoryConfigError(f"{label} is invalid")
    return value


def _checkpoint(raw: Any) -> Checkpoint:
    if not isinstance(raw, dict) or set(raw) != _CHECKPOINT_FIELDS:
        raise PinnedHistoryConfigError(
            "Pinned evidence checkpoint has an unsupported shape"
        )
    if raw["schema"] != "regulated/evidence-checkpoint/v1":
        raise PinnedHistoryConfigError(
            "Pinned evidence checkpoint has an unsupported schema"
        )
    signature = raw["signature"]
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_FIELDS:
        raise PinnedHistoryConfigError(
            "Pinned evidence checkpoint has an invalid signature shape"
        )
    return Checkpoint(
        tenant=_text(raw["tenant"], "checkpoint tenant", maximum=256),
        from_seq=_integer(raw["from_seq"], "checkpoint start", low=0, high=2**63 - 1),
        to_seq=_integer(raw["to_seq"], "checkpoint end", low=0, high=2**63 - 1),
        previous_digest=_digest(raw["previous_digest"], "checkpoint previous digest"),
        last_entry_hash=_digest(raw["last_entry_hash"], "checkpoint entry hash"),
        profile=_text(raw["profile"], "checkpoint profile", maximum=128),
        signature=Signature(
            key_id=_text(signature["key_id"], "checkpoint key identity"),
            value=_text(signature["value"], "checkpoint signature", maximum=4_096),
            alg=_text(signature["alg"], "checkpoint signature algorithm", maximum=32),
        ),
    )


class PinnedHistories:
    """Immutable tenant lookup for already validated pinned verifiers."""

    def __init__(self, verifiers: Mapping[str, PinnedVerifier]) -> None:
        self._verifiers = MappingProxyType(dict(verifiers))

    def for_tenant(self, tenant_id: str) -> PinnedVerifier:
        """Return exactly one tenant's configured verifier or refuse."""

        tenant = _text(tenant_id, "Pinned evidence tenant", maximum=256)
        try:
            return self._verifiers[tenant]
        except KeyError as exc:
            raise PinnedHistoryConfigError(
                "Pinned evidence history is not configured for this tenant"
            ) from exc


def _read_catalog(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise PinnedHistoryConfigError(
            "Pinned history catalog must be an absolute path"
        )
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > _MAX_HISTORY_BYTES:
            raise PinnedHistoryConfigError(
                "Pinned evidence history must be one bounded file"
            )
        with resolved.open("rb") as stream:
            encoded = stream.read(_MAX_HISTORY_BYTES + 1)
        if len(encoded) > _MAX_HISTORY_BYTES:
            raise PinnedHistoryConfigError("Pinned evidence history must be one bounded file")
        raw = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                PinnedHistoryConfigError(
                    "Pinned evidence history contains a non-finite number"
                )
            ),
        )
    except PinnedHistoryConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PinnedHistoryConfigError(
            "Pinned evidence history cannot be read"
        ) from exc
    if not isinstance(raw, dict) or set(raw) != _TOP_LEVEL_FIELDS:
        raise PinnedHistoryConfigError(
            "Pinned evidence history has an unsupported document shape"
        )
    return raw


def load_pinned_histories(
    path: Path,
    *,
    profile: str,
    trust: TrustDirectory,
    expected_current_key_id: str,
    expected_evidence_key_ids: frozenset[str],
) -> PinnedHistories:
    """Load an explicit host-owned catalog; never infer a tenant or database head."""
    profile = _text(profile, "managed evidence profile", maximum=128)
    current = _text(expected_current_key_id, "managed current evidence key")
    if (
        not isinstance(expected_evidence_key_ids, frozenset)
        or not expected_evidence_key_ids
        or current not in expected_evidence_key_ids
        or any(
            not isinstance(key, str) or not key or not trust.is_known(key)
            for key in expected_evidence_key_ids
        )
    ):
        raise PinnedHistoryConfigError(
            "managed evidence key configuration is invalid"
        )
    raw = _read_catalog(Path(path))
    if (
        raw["schema"] != PINNED_HISTORY_SCHEMA
        or raw["profile"] != profile
        or raw["current_evidence_key_id"] != current
    ):
        raise PinnedHistoryConfigError(
            "Pinned evidence history does not match the managed host"
        )
    key_values = raw["evidence_key_ids"]
    if (
        not isinstance(key_values, list)
        or not key_values
        or any(not isinstance(key, str) for key in key_values)
        or len(set(key_values)) != len(key_values)
        or frozenset(key_values) != expected_evidence_key_ids
    ):
        raise PinnedHistoryConfigError(
            "Pinned evidence history key domain does not match the managed host"
        )
    bound = _integer(
        raw["max_entries"],
        "Pinned evidence verification bound",
        low=1,
        high=_MAX_VERIFICATION_ENTRIES,
    )
    tenants = raw["tenants"]
    if not isinstance(tenants, list) or not 1 <= len(tenants) <= _MAX_TENANTS:
        raise PinnedHistoryConfigError(
            "Pinned evidence history requires a bounded tenant list"
        )
    verifiers: dict[str, PinnedVerifier] = {}
    for entry in tenants:
        if not isinstance(entry, dict) or set(entry) != _TENANT_FIELDS:
            raise PinnedHistoryConfigError(
                "Pinned tenant evidence history has an unsupported shape"
            )
        tenant = _text(entry["tenant_id"], "Pinned evidence tenant", maximum=256)
        if tenant in verifiers:
            raise PinnedHistoryConfigError(
                "Pinned evidence history contains a duplicate tenant"
            )
        checkpoint_values = entry["checkpoints"]
        if (
            not isinstance(checkpoint_values, list)
            or len(checkpoint_values) > _MAX_CHECKPOINTS_PER_TENANT
        ):
            raise PinnedHistoryConfigError(
                "Pinned tenant checkpoint history is not bounded"
            )
        checkpoints = tuple(_checkpoint(item) for item in checkpoint_values)
        try:
            verifiers[tenant] = PinnedVerifier(
                PinnedHistory(
                    tenant=tenant,
                    profile=profile,
                    checkpoints=checkpoints,
                    head_digest=_digest(entry["head_digest"], "Pinned evidence head"),
                ),
                trust=trust,
                current_key=current,
                max_entries=bound,
                evidence_key_ids=expected_evidence_key_ids,
            )
        except (PersistenceError, TypeError, ValueError) as exc:
            raise PinnedHistoryConfigError(
                "Pinned tenant evidence history failed validation"
            ) from exc
    return PinnedHistories(verifiers)


__all__ = ["PINNED_HISTORY_SCHEMA", "PinnedHistoryConfigError", "PinnedHistories", "load_pinned_histories"]
