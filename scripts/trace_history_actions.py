"""Trace intact ordinary tests without replacing their functions or guards.

Includes fixture setup/call/teardown and reports them separately. This establishes
dynamic reach on the named cases, not scaling or latency acceptance. Database
internal work and unobserved action variants still require their own evidence.
"""
from collections import Counter
import json
from pathlib import Path
import sys
from threading import Lock
import threading

import pytest
from history_work import TABLE


class Trace:
    def __init__(self, root):
        self.root = str(root.resolve()).replace("\\", "/") + "/"
        self.active = None
        self.counts = {}
        self.errors = []
        self.lock = Lock()
        self.outcomes = []

    def profile(self, frame, event, value):
        if self.active is None or event not in {"call", "return"}:
            return
        try:
            filename = frame.f_code.co_filename.replace("\\", "/")
            name = frame.f_code.co_name
            labels = []
            if filename.startswith(self.root + "src/"):
                key = filename[len(self.root):] + ":" + str(frame.f_code.co_firstlineno) + ":" + name
                if event == "call":
                    labels.append(("calls:" + key, 1))
                elif name in {"entries", "events", "_read", "_load", "_rows", "_verified_history"}:
                    if isinstance(value, (tuple, list, dict)):
                        labels.append(("returned_items:" + key, len(value)))
            if "/psycopg/cursor.py" in filename:
                if name == "execute" and event == "call":
                    labels.append(("sql_execute_calls", 1))
                    query = frame.f_locals.get("query")
                    if isinstance(query, bytes):
                        query = query.decode("utf-8", errors="replace")
                    if isinstance(query, str):
                        for table in set(TABLE.findall(query)):
                            labels.append(("sql_referencing:" + table.lower(), 1))
                    else:
                        labels.append(("sql_composed_or_dynamic", 1))
                if event == "return" and name in {"fetchall", "fetchmany"} and isinstance(value, list):
                    labels.append(("rows_fetched", len(value)))
                elif event == "return" and name == "fetchone" and value is not None:
                    labels.append(("rows_fetched", 1))
            if labels:
                with self.lock:
                    if self.active is not None:
                        self.counts.setdefault(self.active, Counter()).update(dict(labels))
        except Exception as error:
            # Measurement must not change the observed operation. An observer
            # error invalidates the qualification report instead.
            self.errors.append(type(error).__name__)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_setup(self, item):
        self.active = item.nodeid + "::setup"
        yield
        self.active = None

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        self.active = item.nodeid + "::call"
        yield
        self.active = None

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_teardown(self, item):
        self.active = item.nodeid + "::teardown"
        yield
        self.active = None

    def pytest_runtest_logreport(self, report):
        self.outcomes.append({"nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome})


def main():
    output = Path(sys.argv[1])
    root = Path(__file__).resolve().parents[1]
    tracer = Trace(root)
    old, old_thread = sys.getprofile(), threading.getprofile()
    try:
        sys.setprofile(tracer.profile)
        threading.setprofile(tracer.profile)
        code = int(pytest.main(sys.argv[2:], plugins=[tracer]))
    finally:
        sys.setprofile(old)
        threading.setprofile(old_thread)
    output.write_text(json.dumps({
        "scope": "Intact ordinary-case dynamic reach; no timing or scaling conclusion.",
        "limits": ["Existing worker threads are not retroactively profiled.",
                   "Returned rows are not rows examined inside PostgreSQL.",
                   "Fixture work is separated from test calls; synthetic cases do not prove universal reach."],
        "pytest_exit_code": code, "observer_errors": tracer.errors,
        "outcomes": tracer.outcomes,
        "counts": {key: dict(sorted(value.items())) for key, value in tracer.counts.items()},
    }, indent=2) + "\n", encoding="utf-8")
    return code or (1 if tracer.errors else 0)


if __name__ == "__main__":
    raise SystemExit(main())
