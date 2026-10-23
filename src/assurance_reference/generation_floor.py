"""Bind a host-selected generation floor to a managed local trust anchor.

Derived from the pinned Studio configuration loader. The original PostgreSQL
verifier remains unchanged; configuration performs no database or provider I/O.
"""

from collections.abc import Mapping
import logging
import re

from factory.customer.generation_floor_pg import GenerationFloorVerifier as OriginalVerifier
from regulated_core.signing import TrustDirectory


class GenerationFloorConfigError(ValueError):
    """The host's floor configuration is incomplete or invalid."""


def log_floor_non_use(*, prefix: str, reason: str):
    """Record an explicit host decision without implying signed audit retention."""
    if not isinstance(prefix, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", prefix) is None:
        raise GenerationFloorConfigError("generation floor prefix is invalid")
    if (not isinstance(reason, str) or not 1 <= len(reason) <= 256
            or reason != reason.strip() or not reason.isprintable()):
        raise GenerationFloorConfigError("generation floor non-use reason is invalid")
    logging.getLogger(__name__).warning(
        "generation_floor_not_used prefix=%s reason=%s", prefix, reason,
        extra={"generation_floor_mode": "not_used", "generation_floor_prefix": prefix,
               "generation_floor_reason": reason})


class GenerationFloorVerifier(OriginalVerifier):
    """Original floor enforcement with a domain-neutral configuration constructor."""

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, prefix: str,
                 trust: TrustDirectory, schema: str,
                 floor_not_used_reason: str | None = None) -> "GenerationFloorVerifier | None":
        """Read AUTHORITY, INSTALLATION and MINIMUM under an explicit host prefix.

        Missing configuration refuses unless the host explicitly declares non-use
        with a bounded reason, which is logged before returning None. Non-use
        cannot override partial or complete floor configuration. These arguments
        are host configuration and must not come from request data.
        """
        if not isinstance(prefix, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", prefix) is None:
            raise GenerationFloorConfigError("generation floor prefix is invalid")
        values = [env.get(prefix + "_" + field, "")
                  for field in ("AUTHORITY", "INSTALLATION", "MINIMUM")]
        if any(not isinstance(value, str) for value in values):
            raise GenerationFloorConfigError("generation floor configuration must contain text")
        authority, installation, minimum = (value.strip() for value in values)
        if floor_not_used_reason is not None:
            if (not isinstance(floor_not_used_reason, str)
                    or not 1 <= len(floor_not_used_reason) <= 256
                    or floor_not_used_reason != floor_not_used_reason.strip()
                    or not floor_not_used_reason.isprintable()):
                raise GenerationFloorConfigError("generation floor non-use reason is invalid")
            if any((authority, installation, minimum)):
                raise GenerationFloorConfigError(
                    "generation floor non-use conflicts with configured floor values")
            log_floor_non_use(prefix=prefix, reason=floor_not_used_reason)
            return None
        if not any((authority, installation, minimum)):
            raise GenerationFloorConfigError(
                "generation floor configuration is required unless non-use is explicitly declared")
        if not all((authority, installation, minimum)):
            raise GenerationFloorConfigError(
                "generation floor authority, installation, and minimum must be configured together")
        if not trust.is_known(authority):
            raise GenerationFloorConfigError("generation floor authority is not a managed trust anchor")
        if (re.fullmatch(r"[0-9]{1,10}", minimum) is None
                or not 1 <= int(minimum) <= 2**31 - 1
                or len(installation) > 256
                or not isinstance(schema, str) or not schema or schema != schema.strip()):
            raise GenerationFloorConfigError("generation floor deployment binding is invalid")
        try:
            return cls(trust=trust, issuer_key_id=authority, installation_id=installation,
                       schema=schema, minimum_generation=int(minimum))
        except ValueError as exc:
            raise GenerationFloorConfigError("generation floor deployment binding is invalid") from exc
