"""Verify the two pinned Education bundles without installing or activating them."""

from __future__ import annotations

import json
from pathlib import Path

from factory.packs.manifest import load_manifest
from factory.packs.signing import verify_pack_signature, verify_provenance
from regulated_core.signing import TrustDirectory

FIXTURES = Path(__file__).parent / "fixtures" / "packs"
PUBLISHER = "education-pilot-authority-2026-09-10"
VERSIONS = ("0.1.1", "0.1.2")


def verify_bundles() -> dict:
    """Check historical content and attestations under a separately pinned public anchor."""
    trust = TrustDirectory()
    anchors = json.loads((FIXTURES / "trust-anchors.json").read_bytes())
    if anchors["schema"] != "lumiwright.pack-trust/v1":
        raise ValueError("unexpected trust anchor schema")
    for key in anchors["keys"]:
        trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    verified = []
    for version in VERSIONS:
        directory = FIXTURES / "bundles" / f"education-{version}"
        manifest = load_manifest(directory)
        signature = verify_pack_signature(directory, manifest, trust, publisher_key_id=PUBLISHER)
        provenance = verify_provenance(directory, manifest, trust)
        if provenance.signer_key_id != PUBLISHER:
            raise ValueError("unexpected provenance signer")
        verified.append(
            {
                "reference": manifest.reference,
                "manifest_digest": manifest.digest,
                "signed_file_count": signature.file_count,
                "publisher": signature.key_id,
                "builder": provenance.builder_id,
            }
        )
    return {
        "status": "PASS",
        "scope": "Pinned historical bundle integrity and signed provenance only",
        "activated": False,
        "bundles": verified,
    }


def main() -> None:
    print(json.dumps(verify_bundles(), indent=2))


if __name__ == "__main__":
    main()
