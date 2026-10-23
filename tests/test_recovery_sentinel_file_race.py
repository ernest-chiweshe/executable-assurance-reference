"""R-2b: writers sharing one sentinel file never lose another domain's high-water (review finding 4e180f93).

No database: the sentinel file is written from the process high-water registry. The window between a writer's
read and its replace is widened, so an unserialised writer would overwrite the other domain's row.
"""
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import assurance_reference.clock_floor as clock_floor
from assurance_reference.clock_floor import DurableClock
from regulated_core.clock import ClockError

DOMAINS = [f"test:{name}" for name in "abcdef"]


def _writer(domain: str, path: Path) -> DurableClock:
    clock = object.__new__(DurableClock)  # only the sentinel path of the clock is exercised here
    clock._domain, clock._sentinel_file, clock._sentinel_lock = domain, path, threading.Lock()
    return clock


def test_threads_with_their_own_clocks_never_lose_a_domain(tmp_path, monkeypatch):
    path = tmp_path / "sentinel.json"
    with clock_floor._SENTINEL_LOCK:
        saved = dict(clock_floor._HIGHWATER)
        clock_floor._HIGHWATER.clear()
        clock_floor._HIGHWATER.update({(d, "db", "s"): 100 + i for i, d in enumerate(DOMAINS)})
    original = Path.read_text

    def slow_read(self, *args, **kwargs):
        text = original(self, *args, **kwargs)
        if self == path:
            time.sleep(0.05)  # a writer that read the old contents is still merging when the next one reads
        return text

    monkeypatch.setattr(Path, "read_text", slow_read)
    errors = []

    def persist(writer):
        try:
            writer._persist()
        except BaseException as failed:  # every worker's outcome is asserted, not only the final file
            errors.append(repr(failed))

    try:
        writers = [_writer(d, path) for d in DOMAINS]
        threads = [threading.Thread(target=persist, args=(w,)) for w in writers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not any(thread.is_alive() for thread in threads), "a writer did not terminate"
        assert errors == []
        rows = {tuple(row[:3]): row[3] for row in json.loads(original(path, encoding="utf-8"))}
    finally:
        with clock_floor._SENTINEL_LOCK:  # restored only after every writer has terminated (asserted above)
            clock_floor._HIGHWATER.clear()
            clock_floor._HIGHWATER.update(saved)
    assert rows == {(d, "db", "s"): 100 + i for i, d in enumerate(DOMAINS)}


def test_a_permanent_lock_error_fails_closed_at_once(tmp_path, monkeypatch):
    def broken(handle):
        raise OSError(5, "injected permanent I/O error")  # EIO: not contention

    monkeypatch.setattr(clock_floor, "_os_try_lock", lambda handle: broken(handle))
    started = time.monotonic()
    with pytest.raises(ClockError, match="lock unavailable"):
        with clock_floor._sentinel_path_lock(tmp_path / "sentinel.json", timeout_s=30):
            pass
    assert time.monotonic() - started < 2  # no retry loop on a permanent error


def test_contention_beyond_the_timeout_fails_closed_and_releases(tmp_path):
    path = tmp_path / "sentinel.json"
    holder = subprocess.Popen([sys.executable, "-c", HOLD, str(path)], stdout=subprocess.PIPE)
    try:
        assert holder.stdout.readline().strip() == b"held"
        started = time.monotonic()
        with pytest.raises(ClockError, match="another process holds it"):
            with clock_floor._sentinel_path_lock(path, timeout_s=0.5):
                pass
        assert 0.4 < time.monotonic() - started < 5
    finally:
        holder.kill()
        holder.wait(timeout=30)
    with clock_floor._sentinel_path_lock(path, timeout_s=5):  # the in-process lock was released on failure
        pass


HOLD = r'''
import sys, time
from pathlib import Path
import assurance_reference.clock_floor as cf
with cf._sentinel_path_lock(Path(sys.argv[1]), timeout_s=5):
    print("held", flush=True)
    time.sleep(60)
'''


def test_a_failing_sentinel_write_is_counted_and_the_heartbeat_keeps_running(tmp_path, monkeypatch):
    clock = _writer("test:hb", tmp_path / "sentinel.json")
    clock._stop, clock._heartbeat = threading.Event(), None
    monkeypatch.setattr(DurableClock, "read", lambda self: None)
    monkeypatch.setattr(DurableClock, "_persist", lambda self: (_ for _ in ()).throw(ClockError("injected")))
    clock.start_heartbeat(0.05)
    try:
        deadline = time.monotonic() + 5
        while clock.sentinel_failures < 3 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert clock.sentinel_failures >= 3 and clock._heartbeat.is_alive()
    finally:
        clock.stop_heartbeat()
    assert clock._heartbeat is None


CHILD = r'''
import sys, threading, time
from pathlib import Path
import assurance_reference.clock_floor as cf
path, domain, rounds = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
clock = object.__new__(cf.DurableClock)
clock._domain, clock._sentinel_file, clock._sentinel_lock = domain, path, threading.Lock()
original = Path.read_text
def slow(self, *a, **k):
    text = original(self, *a, **k)
    if self == path:
        time.sleep(0.01)
    return text
Path.read_text = slow
for value in range(1, rounds + 1):
    cf._HIGHWATER[(domain, "db", "s")] = value
    clock._persist()
'''


def test_separate_processes_sharing_a_sentinel_file_never_lose_a_domain(tmp_path):
    path = tmp_path / "sentinel.json"
    rounds = 25
    children = [subprocess.Popen([sys.executable, "-c", CHILD, str(path), d, str(rounds)],
                                 stderr=subprocess.PIPE) for d in DOMAINS[:4]]
    for child in children:
        _, err = child.communicate(timeout=120)
        assert child.returncode == 0, err.decode(errors="replace")[-2000:]
    rows = {tuple(row[:3]): row[3] for row in json.loads(path.read_text(encoding="utf-8"))}
    assert rows == {(d, "db", "s"): rounds for d in DOMAINS[:4]}
