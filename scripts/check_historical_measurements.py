"""Read retained local records; compare their bounded summary with the handoff.

No providers, database, subprocesses, extraction or writes. This checks saved
records, not their historical authenticity or the deployment that produced them.
"""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re


def inspect_sources(source: Path) -> dict:
    hashes = {}

    def read(relative):
        data = (source / relative).read_bytes()
        hashes[relative] = hashlib.sha256(data).hexdigest()
        return data.decode("utf-8")

    prefix = "research/artifacts/operational/s3-mirror/"
    baselines = {}
    for profile in ("managed", "strict"):
        text = read(prefix + f"baseline_aws_{profile}_n300.txt")
        if re.findall(r"decisions:\s*(\d+)", text) != ["300"]:
            raise ValueError("baseline does not declare exactly 300 decisions")
        if not re.search(r"stage\s+p50 ms\s+p95 ms\s+p99 ms\s+mean ms", text):
            raise ValueError("unrecognized baseline columns")
        stages = {}
        for stage in ("approval", "release", "total", "signing", "worm"):
            rows = re.findall(rf"^{stage}\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s*$",
                              text, re.MULTILINE)
            if len(rows) != 1:
                raise ValueError("missing or repeated baseline stage")
            stages[stage] = dict(zip(("p50_ms", "p95_ms", "p99_ms", "mean_ms"), map(float, rows[0])))
        baselines[profile] = {"declared_decisions": 300, "stages": stages}

    restore = json.loads(read(prefix + "restore_rto.json"))
    restore_values = {k: restore[k] for k in ("utc", "restore_rto_seconds", "active_confirm_seconds")}
    if any(type(restore_values[k]) is not int or restore_values[k] < 0
           for k in ("restore_rto_seconds", "active_confirm_seconds")):
        raise ValueError("restore durations must be nonnegative integers")

    stamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
    summary = read(prefix + "soak/soak.log").splitlines()
    if len(summary) != 2:
        raise ValueError("unexpected soak summary length")
    start = re.fullmatch(rf"({stamp}) soak start: 24h, batch=300, profile=strict", summary[0])
    end = re.fullmatch(rf"({stamp}) soak end: (\d+) batches, (\d+) decisions", summary[1])
    if not start or not end:
        raise ValueError("unexpected soak summary format")

    def instant(value):
        if not isinstance(value, str) or not re.fullmatch(stamp, value):
            raise ValueError("expected an explicit UTC timestamp")
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")

    paths = sorted((source / prefix / "soak").glob("heartbeat_*.json"))
    if len(paths) != 24:
        raise ValueError("expected exactly 24 retained heartbeats")
    heartbeats = []
    for path in paths:
        relative = path.relative_to(source).as_posix()
        value = json.loads(read(relative))
        if (value["profile"] != "strict" or type(value["batches"]) is not int
                or type(value["decisions_total"]) is not int
                or value["decisions_total"] != value["batches"] * 300):
            raise ValueError("heartbeat count or profile differs")
        heartbeats.append((instant(value["utc"]), relative, value))
    previous, previous_count = instant(start[1]), 0
    intervals = []
    for time, relative, value in sorted(heartbeats):
        seconds = int((time - previous).total_seconds())
        count = value["decisions_total"] - previous_count
        if seconds <= 0 or count < 0 or time > instant(end[1]):
            raise ValueError("heartbeat chronology or cumulative count differs")
        intervals.append({"source": relative, "end_utc": value["utc"],
                          "seconds": seconds, "recorded_decisions": count,
                          "cumulative_decisions": value["decisions_total"]})
        previous, previous_count = time, value["decisions_total"]
    if previous_count != int(end[3]) or int(end[2]) * 300 != previous_count:
        raise ValueError("heartbeats disagree with the soak summary")

    reproduction = read(".publication-review/2026-09-24/reproduce.log")
    counts = re.findall(r"^\s*(\d+) passed, (\d+) skipped in [\d.]+s\s*$", reproduction, re.MULTILINE)
    if len(counts) != 1:
        raise ValueError("unexpected historical reproduction summary")
    if "== 4/4 skipped (pass --full for the platform-wide non-regression number) ==" not in reproduction:
        raise ValueError("historical full-suite disposition differs")
    return {
        "schema": "executable-assurance/historical-record-summary/v1",
        "basis": "Saved local records; no provider rerun or historical-origin attestation",
        "inputs_sha256": dict(sorted(hashes.items())), "baselines": baselines,
        "restore_record": restore_values,
        "soak": {"start_utc": start[1], "end_utc": end[1], "profile": "strict",
                 "recorded_decisions": previous_count, "intervals": intervals,
                 "interval_count_min": min(r["recorded_decisions"] for r in intervals),
                 "interval_count_max": max(r["recorded_decisions"] for r in intervals),
                 "interval_count_mean": previous_count / len(intervals)},
        "historical_reproduction_log": {"passed": int(counts[0][0]), "skipped": int(counts[0][1]),
                                        "platform_wide_run": "skipped in this log"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Original Agent Factory repository")
    parser.add_argument("--expected", type=Path, required=True, help="Reviewed summary JSON")
    args = parser.parse_args()
    if inspect_sources(args.source) != json.loads(args.expected.read_text(encoding="utf-8")):
        raise SystemExit("Historical summary differs; inspect source hashes and values")
    print("PASS: saved baseline, restore, heartbeat and reproduction records match the summary")


if __name__ == "__main__":
    main()
