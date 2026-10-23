"""WORM / retention adapter seam — immutable retention for the tamper-evident evidence chain.

A hash-chained evidence log proves integrity, but integrity without RETENTION is not enough for a
regulator: the records must also be provably un-deletable for a mandated window (e.g. SEC 17a-4 WORM,
or a GDPR/health retention schedule). This anchors the per-tenant evidence chain to a write-once store
and binds the returned RECEIPT into the evidence pack.

Pure core (no factory dependency). `LocalWormStore` is a deterministic, credential-free mock for
tests/dev — write-once, refuses deletion within retention. A real provider (S3 Object-Lock, Azure
immutable blob, a WORM appliance) drops in behind the `WormStore` protocol with no core change.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from .canonical import canonical_bytes


class WormError(Exception):
    """A WORM invariant was violated (attempted mutation/deletion within retention, or a bad receipt)."""


class WormUnavailable(WormError):
    """The WORM store could not be reached — fail closed: no retention receipt, no release."""


@dataclass(frozen=True, slots=True)
class WormReceipt:
    """Proof the provider stored these exact bytes immutably until `retained_until_us`."""

    provider: str            # 'local-mock' | 's3-object-lock' | 'azure-immutable-blob' | ...
    object_ref: str          # where it lives (bucket/key, blob uri, ...)
    content_digest: str      # sha256 of the retained bytes
    retained_until_us: int   # end of the immutability window
    receipt_id: str          # provider version/receipt id
    stored_at_us: int

    def as_dict(self) -> dict[str, Any]:
        return {"provider": self.provider, "object_ref": self.object_ref, "content_digest": self.content_digest,
                "retained_until_us": self.retained_until_us, "receipt_id": self.receipt_id,
                "stored_at_us": self.stored_at_us}


class WormStore(Protocol):
    def anchor(self, tenant: str, data: bytes, *, retain_us: int, now_us: int) -> WormReceipt: ...
    def fetch(self, tenant: str, object_ref: str) -> bytes: ...
    def verify(self, receipt: WormReceipt) -> bool: ...


class LocalWormStore:
    """Deterministic write-once mock. The object ref is content-addressed, so a re-anchor of identical
    bytes is idempotent (returns the same receipt); mutation/deletion within retention is refused."""

    def __init__(self) -> None:
        self._objects: dict[str, tuple[bytes, WormReceipt]] = {}
        self._available = True

    def set_available(self, available: bool) -> None:
        """Simulate a provider outage (resilience drills): anchoring fails closed while down."""
        self._available = available

    def anchor(self, tenant: str, data: bytes, *, retain_us: int, now_us: int) -> WormReceipt:
        if not self._available:
            raise WormUnavailable("WORM store unreachable")
        digest = sha256(data).hexdigest()
        object_ref = f"worm://{tenant}/{digest}"
        if object_ref in self._objects:                        # write-once: idempotent re-anchor
            return self._objects[object_ref][1]
        receipt = WormReceipt("local-mock", object_ref, digest, now_us + retain_us, digest[:16], now_us)
        self._objects[object_ref] = (data, receipt)
        return receipt

    def fetch(self, tenant: str, object_ref: str) -> bytes:
        try:
            return self._objects[object_ref][0]
        except KeyError:
            raise WormError(f"no WORM object {object_ref!r}")

    def verify(self, receipt: WormReceipt) -> bool:
        rec = self._objects.get(receipt.object_ref)
        return rec is not None and sha256(rec[0]).hexdigest() == receipt.content_digest

    def delete(self, tenant: str, object_ref: str, *, now_us: int) -> None:
        rec = self._objects.get(object_ref)
        if rec is not None and now_us < rec[1].retained_until_us:
            raise WormError("WORM object is immutable within its retention window")
        self._objects.pop(object_ref, None)                    # deletion allowed only AFTER retention


def anchor_evidence_chain(store: WormStore, recorder: object, tenant: str, *, retain_us: int, now_us: int) -> WormReceipt:
    """Serialize the tenant's signed evidence chain canonically and anchor it to WORM. The returned
    receipt is what `bind_worm_receipt` folds into the evidence pack."""
    entries = [
        {"seq": e.seq, "prev_hash": e.prev_hash, "record_hash": e.record_hash,
         "signature": {"key_id": e.signature.key_id, "value": e.signature.value},
         **({"schema": "regulated/evidence/v2", "clock_domain": e.clock_domain}
            if e.clock_domain else {})}
        for e in recorder.entries(tenant) if e.record.tenant_id == tenant  # type: ignore[attr-defined]
    ]
    data = canonical_bytes({"schema": "regulated/worm-anchor/v1", "tenant": tenant, "entries": entries})
    return store.anchor(tenant, data, retain_us=retain_us, now_us=now_us)


def bind_worm_receipt(evidence_pack: dict[str, Any], receipt: WormReceipt) -> dict[str, Any]:
    """Bind a WORM retention receipt into an evidence pack (returns a new dict)."""
    return {**evidence_pack, "worm_retention": receipt.as_dict()}
