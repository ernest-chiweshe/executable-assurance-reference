"""Verify historical bundle attestations directly with cryptography and raw JSON."""

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from assurance_reference.packs import FIXTURES, PUBLISHER, VERSIONS, verify_bundles


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def test_bundles_have_independently_verified_contents_and_provenance():
    anchor = json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"][0]
    assert anchor["key_id"] == PUBLISHER
    assert anchor["alg"] == "ecdsa-p384"
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(), bytes.fromhex(anchor["public_key_hex"])
    )
    expected_digests = {
        "0.1.1": "1f43103defda5f195b5288e2bb8ff2c863ad678fe7061a68b73561912a60fc66",
        "0.1.2": "597a23ad9211fe393107372d846121d10f8f9f9e3808e9fa5ba517860c939987",
    }
    results = verify_bundles()
    assert results["status"] == "PASS" and results["activated"] is False
    assert len(results["bundles"]) == 2
    for version, observed in zip(VERSIONS, results["bundles"], strict=True):
        directory = FIXTURES / "bundles" / f"education-{version}"
        manifest = json.loads((directory / "pack.json").read_bytes())
        digest = hashlib.sha256(canonical(manifest)).hexdigest()
        assert digest == expected_digests[version] == observed["manifest_digest"]
        reference = f"{manifest['id']}#{manifest['version']}"
        assert reference == observed["reference"]
        shipped = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
        assert shipped == set(manifest["files"]) | {
            "pack.json",
            ".signatures.json",
            "provenance.json",
        }
        for name, expected in manifest["files"].items():
            assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected

        attestation = json.loads((directory / ".signatures.json").read_bytes())
        signature = attestation.pop("signature")
        assert signature["key_id"] == PUBLISHER and signature["alg"] == "ecdsa-p384"
        public_key.verify(
            bytes.fromhex(signature["value"]), canonical(attestation), ec.ECDSA(hashes.SHA384())
        )
        assert attestation["pack"] == reference and attestation["scope"] == "install"
        assert attestation["schema"] == "lumiwright.pack-signature/v1"
        expected_files = [{"name": "pack.json", "hash": digest, "algorithm": "SHA256"}]
        expected_files += [
            {"name": name, "hash": value, "algorithm": "SHA256"}
            for name, value in sorted(manifest["files"].items())
        ]
        assert attestation["files"] == expected_files
        assert observed["signed_file_count"] == len(expected_files)

        provenance = json.loads((directory / "provenance.json").read_bytes())
        signature = provenance["signature"]
        assert signature["key_id"] == PUBLISHER and signature["alg"] == "ecdsa-p384"
        statement = provenance["statement"]
        public_key.verify(
            bytes.fromhex(signature["value"]), canonical(statement), ec.ECDSA(hashes.SHA384())
        )
        assert statement["subject"] == [{"name": reference, "digest": {"sha256": digest}}]
        assert statement["_type"] == "https://in-toto.io/Statement/v1"
        assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
        assert statement["predicate"]["runDetails"]["builder"]["id"] == observed["builder"]


def test_extracted_pack_sources_match_recorded_historical_bytes():
    root = Path(__file__).resolve().parents[1]
    records = json.loads((root / "source-provenance-packs.json").read_bytes())
    assert records["source_commit"] == "6bba989aeca27575b971c78a103cbf3745cfda6a"
    assert len(records["files"]) == 38
    for record in records["files"]:
        assert hashlib.sha256((root / record["path"]).read_bytes()).hexdigest() == record["sha256"]
