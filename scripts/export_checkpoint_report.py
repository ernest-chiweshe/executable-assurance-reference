"""Export a bounded local A13 report using explicit host trust and scope pins."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from assurance_reference.checkpoint_report import MAX_EXPORT_BYTES, checkpoint_report
from regulated_core.signing import TrustDirectory


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("finite JSON required")


def _read(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input exceeds byte limit")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant), hashlib.sha256(raw).hexdigest()


def _trust(document):
    if type(document) is not dict or set(document) != {"keys"}:
        raise ValueError("host trust file requires only a keys list")
    keys = document["keys"]
    if type(keys) is not list or not 1 <= len(keys) <= 128:
        raise ValueError("host trust file requires 1 to 128 public keys")
    trust, seen = TrustDirectory(), set()
    for key in keys:
        if (type(key) is not dict or set(key) != {"key_id", "public_key_hex", "alg"}
                or type(key["key_id"]) is not str or not key["key_id"].strip()
                or len(key["key_id"]) > 512 or key["key_id"] in seen
                or key["alg"] != "ed25519" or type(key["public_key_hex"]) is not str
                or len(key["public_key_hex"]) != 64):
            raise ValueError("distinct bounded Ed25519 public keys required")
        public = bytes.fromhex(key["public_key_hex"])
        if len(public) != 32:
            raise ValueError("Ed25519 public key must contain 32 bytes")
        trust.register(key["key_id"], public, key["alg"])
        seen.add(key["key_id"])
    return trust


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, help="local JSON list of checkpoint/report/receipts")
    parser.add_argument("--trust", required=True, help="host-selected public-key JSON, separate from evidence")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--witness", action="append", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--previous-digest", required=True, help="exact prior digest, or empty for initial position")
    parser.add_argument("--start-seq", type=int, required=True)
    parser.add_argument("--end-seq", type=int, required=True)
    parser.add_argument("--now-us", type=int, required=True, help="explicit host verification time")
    parser.add_argument("--output", required=True, help="new local directory; existing paths refuse")
    args = parser.parse_args(argv)
    try:
        items, evidence_hash = _read(args.evidence, MAX_EXPORT_BYTES)
        keys, trust_hash = _read(args.trust, 128 * 1024)
        if len(set(args.witness)) != len(args.witness):
            raise ValueError("required witness identities must be distinct")
        result = checkpoint_report(items, trust=_trust(keys), issuer_key_id=args.issuer,
            required_witness_ids=tuple(args.witness), tenant=args.tenant,
            previous_digest=args.previous_digest, start_seq=args.start_seq, end_seq=args.end_seq,
            now_us=args.now_us)
        output = Path(args.output)
        output.mkdir(exist_ok=False)
        payloads = {"report.json": result["json_bytes"], "report.html": result["html"].encode("utf-8")}
        for name, body in payloads.items():
            with (output / name).open("xb") as stream:
                stream.write(body)
        receipt = {"schema": "reference/local-checkpoint-export-receipt/v1",
            "status": result["status"], "input_sha256": evidence_hash, "host_trust_sha256": trust_hash,
            "files": {name: hashlib.sha256(body).hexdigest() for name, body in payloads.items()},
            "limits": ["Unsigned local export; hashes are integrity references, not authority signatures.",
                       "Verification applies only at the explicit host time and supplied scope.",
                       "No publication, complete-history proof, external-custody proof or target mutation."]}
        # Written last: a partial filesystem write does not produce this receipt.
        with (output / "EXPORT.json").open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"status": result["status"], "output": str(output.resolve()),
                          "report_sha256": result["sha256"], "scope": "supplied local observations only"}))
        return 0 if result["status"] == "ONE_VERIFIED_CHECKPOINT_OBSERVED" else 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print("Checkpoint export refused: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
