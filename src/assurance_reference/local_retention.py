"""Persistent local retention contract for offline reference demonstrations.

Exclusive files and read-back checks preserve exact receipt bindings across
process restarts. This is not deployed HSM custody, compliance WORM storage,
administrator-resistant storage or proof of survival of physical media failure.
"""

from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re

from regulated_core.canonical import canonical_bytes
from regulated_core.worm import WormError, WormReceipt, WormUnavailable

_PROVIDER = "reference-local-retention"
_REF = re.compile(r"reference-local://([0-9a-f]{64})/([0-9a-f]{64})\Z")


class LocalRetentionStore:
    def __init__(self, root: Path):
        self.root = root.absolute()
        if self.root.is_symlink() or getattr(self.root, "is_junction", lambda: False)():
            raise ValueError("retention root must not be a link")
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve(strict=True)

    def _path(self, reference: str) -> Path:
        match = _REF.fullmatch(reference)
        if match is None:
            raise WormError("invalid local retention reference")
        target = self.root / (match[1] + "-" + match[2] + ".json")
        if target.is_symlink() or getattr(target, "is_junction", lambda: False)():
            raise WormError("linked retention object refused")
        return target

    def _read(self, reference: str) -> tuple[dict, bytes, WormReceipt]:
        try:
            raw = json.loads(self._path(reference).read_bytes())
            if set(raw) != {"schema", "tenant", "data_base64", "receipt"}:
                raise ValueError("unexpected object fields")
            receipt = WormReceipt(**raw["receipt"])
            data = base64.b64decode(raw["data_base64"], validate=True)
            if (raw["schema"] != "executable-assurance/local-retention/v1"
                    or receipt.provider != _PROVIDER or receipt.object_ref != reference
                    or receipt.content_digest != sha256(data).hexdigest()
                    or receipt.receipt_id != self._identity(raw["tenant"], data,
                                                          receipt.stored_at_us,
                                                          receipt.retained_until_us)
                    or reference != self._reference(raw["tenant"], receipt.receipt_id)):
                raise ValueError("retention binding differs")
            return raw, data, receipt
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise WormUnavailable("local retention object unavailable or inconsistent") from exc

    @staticmethod
    def _identity(tenant: str, data: bytes, now: int, until: int) -> str:
        if (not isinstance(tenant, str) or not tenant or type(now) is not int
                or type(until) is not int or now < 0 or until <= now):
            raise ValueError("explicit tenant and positive retention window required")
        return sha256(canonical_bytes({"tenant": tenant, "digest": sha256(data).hexdigest(),
                                       "stored_at_us": now, "retained_until_us": until})).hexdigest()

    @staticmethod
    def _reference(tenant: str, identity: str) -> str:
        return "reference-local://" + sha256(tenant.encode()).hexdigest() + "/" + identity

    def anchor(self, tenant: str, data: bytes, *, retain_us: int, now_us: int) -> WormReceipt:
        if not isinstance(data, bytes) or type(retain_us) is not int or retain_us <= 0:
            raise WormError("exact bytes and a positive retention interval required")
        try:
            until = now_us + retain_us
            identity = self._identity(tenant, data, now_us, until)
            reference = self._reference(tenant, identity)
            receipt = WormReceipt(_PROVIDER, reference, sha256(data).hexdigest(), until,
                                  identity, now_us)
            encoded = canonical_bytes({"schema": "executable-assurance/local-retention/v1",
                                       "tenant": tenant, "data_base64": base64.b64encode(data).decode(),
                                       "receipt": receipt.as_dict()})
            try:
                with self._path(reference).open("xb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
            _, found, retained = self._read(reference)
            if found != data or retained != receipt:
                raise WormError("existing retention object differs")
            return retained
        except (OSError, ValueError, TypeError) as exc:
            raise WormUnavailable("local retention append failed") from exc

    def fetch(self, tenant: str, object_ref: str) -> bytes:
        raw, data, _ = self._read(object_ref)
        if raw["tenant"] != tenant:
            raise WormError("retention object belongs to another tenant")
        return data

    def verify(self, receipt: WormReceipt) -> bool:
        try:
            return self._read(receipt.object_ref)[2] == receipt
        except WormError:
            return False
