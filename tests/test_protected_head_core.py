"""Local crash/publication/locking tests; no administrator-custody claim."""
import json
import multiprocessing
from dataclasses import replace
from pathlib import Path

import pytest

from assurance_reference.protected_head import FileProtectedHeadStore
from regulated_core.canonical import canonical_bytes
from regulated_core.evidence_service import EvidenceError, TreeHead
from regulated_core.signing import TrustDirectory
from test_evidence_service_formats import case  # shared deterministic-input fixture


def store_for(path, case, **kwargs):
    return FileProtectedHeadStore(path, tenant="tenant", clock_domain=case[0].domain,
                                  trust=case[3], existing_heads={}, advancing_heads=case[4], **kwargs)


def test_publish_read_idempotence_and_compare_and_set(tmp_path, case):
    store = store_for(tmp_path, case)
    heads, tree = case[6], case[5]
    assert store.read() is None
    assert store.advance(None, heads[0], ()) == heads[0]
    assert store.read() == heads[0]
    assert store.advance(None, heads[0], ()) == heads[0]
    store.advance(heads[0], heads[1], tree.consistency(1, 2))
    with pytest.raises(EvidenceError, match="compare-and-set"):
        store.advance(heads[0], heads[2], tree.consistency(1, 3))
    assert store.read() == heads[1]
    store.advance(heads[1], heads[2], tree.consistency(2, 3))
    assert store.read() == heads[2]
    assert store.directory.name == "evidence"


def test_crash_after_head_fsync_before_current_is_recovered(tmp_path, case, monkeypatch):
    store = store_for(tmp_path, case)
    real = store._replace_current
    def outage(publication):
        raise OSError("simulated pointer write outage")
    monkeypatch.setattr(store, "_replace_current", outage)
    with pytest.raises(OSError, match="outage"):
        store.advance(None, case[6][0], ())
    assert not (store.directory / "CURRENT").exists()
    assert (store.directory / "00000000000000000001.json").exists()
    monkeypatch.setattr(store, "_replace_current", real)
    assert store.read() == case[6][0]
    assert store.advance(None, case[6][0], ()) == case[6][0]


def test_torn_temporary_pointer_does_not_replace_current(tmp_path, case):
    store = store_for(tmp_path, case)
    store.advance(None, case[6][0], ())
    (store.directory / "CURRENT.tmp").write_bytes(b'{"counter":')
    assert store.read() == case[6][0]
    store.advance(case[6][0], case[6][1], case[5].consistency(1, 2))
    assert store.read() == case[6][1]


def test_current_rewind_rolls_forward_without_directory_scan(tmp_path, case, monkeypatch):
    store = store_for(tmp_path, case)
    heads, tree = case[6], case[5]
    store.advance(None, heads[0], ())
    old = (store.directory / "CURRENT").read_bytes()
    store.advance(heads[0], heads[1], tree.consistency(1, 2))
    store.advance(heads[1], heads[2], tree.consistency(2, 3))
    (store.directory / "CURRENT").write_bytes(old)
    calls = []
    read = store._read_file
    def counted(path, limit):
        calls.append(path.name)
        return read(path, limit)
    monkeypatch.setattr(store, "_read_file", counted)
    assert store.read() == heads[2]
    assert calls == ["CURRENT", "00000000000000000001.json", "00000000000000000002.json",
                     "00000000000000000003.json", "00000000000000000004.json"]
    calls.clear()
    assert store.read() == heads[2]
    assert calls == ["CURRENT", "00000000000000000003.json", "00000000000000000004.json"]


def test_recovery_bound_refuses_and_persists_latch(tmp_path, case):
    store = store_for(tmp_path, case, max_roll_forward=1)
    heads, tree = case[6], case[5]
    store.advance(None, heads[0], ())
    old = (store.directory / "CURRENT").read_bytes()
    store.advance(heads[0], heads[1], tree.consistency(1, 2))
    store.advance(heads[1], heads[2], tree.consistency(2, 3))
    (store.directory / "CURRENT").write_bytes(old)
    with pytest.raises(EvidenceError, match="refused"):
        store.read()
    assert (store.directory / "LATCH").exists()
    with pytest.raises(EvidenceError, match="latched"):
        store_for(tmp_path, case).read()


@pytest.mark.parametrize("damage", ["pointer", "head", "missing_head", "extra_head", "oversize"])
def test_corrupt_publication_refuses_and_latches(tmp_path, case, damage):
    store = store_for(tmp_path, case)
    store.advance(None, case[6][0], ())
    head_path = store.directory / "00000000000000000001.json"
    if damage == "pointer":
        (store.directory / "CURRENT").write_bytes(b'{"counter":')
    elif damage == "head":
        value = json.loads(head_path.read_bytes())
        value["head"]["body"]["tenant"] = "other"
        head_path.write_bytes(canonical_bytes(value))
    elif damage == "missing_head":
        head_path.rename(store.directory / "fixture-hidden-head.json")
    elif damage == "extra_head":
        (store.directory / "00000000000000000002.json").write_bytes(b"corrupt newer head")
    else:
        head_path.write_bytes(b"x" * (store.max_head_bytes + 1))
    with pytest.raises(EvidenceError):
        store.read()
    assert (store.directory / "LATCH").exists()


def test_joint_file_rollback_is_explicitly_not_detected(tmp_path, case):
    store = store_for(tmp_path, case)
    heads, tree = case[6], case[5]
    store.advance(None, heads[0], ())
    old = (store.directory / "CURRENT").read_bytes()
    store.advance(heads[0], heads[1], tree.consistency(1, 2))
    # A local administrator can remove the newer publication and rewind the
    # pointer. Move only this test fixture to preserve the evidence of the test.
    (store.directory / "00000000000000000002.json").rename(store.directory / "fixture-removed-newer-head.json")
    (store.directory / "CURRENT").write_bytes(old)
    assert store.read() == heads[0]  # documented limitation, not rollback protection


def _race(base, key_id, public_key, domain, document, ready, start, result):
    trust = TrustDirectory()
    trust.register(key_id, public_key)
    store = FileProtectedHeadStore(Path(base), tenant="tenant", clock_domain=domain,
                                   trust=trust, existing_heads={}, advancing_heads=frozenset({key_id}))
    ready.put(True)
    start.wait(15)
    try:
        store.advance(None, TreeHead.from_document(document), ())
        result.put("accepted")
    except EvidenceError:
        result.put("refused")


def test_two_processes_cannot_publish_conflicting_initial_heads(tmp_path, case):
    signer, heads = case[1], case[6]
    first = heads[0]
    second = replace(first, map_root="f" * 64)
    second = replace(second, signature=signer.sign(second.body()))
    context = multiprocessing.get_context("spawn")
    ready, results, start = context.Queue(), context.Queue(), context.Event()
    processes = [context.Process(target=_race, args=(str(tmp_path), signer.key_id,
                 signer.public_key_bytes, case[0].domain, json.loads(canonical_bytes(head.document())),
                 ready, start, results)) for head in (first, second)]
    for process in processes:
        process.start()
    assert ready.get(timeout=15) and ready.get(timeout=15)
    start.set()
    answers = [results.get(timeout=20), results.get(timeout=20)]
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert sorted(answers) == ["accepted", "refused"]
    assert store_for(tmp_path, case).read() in (first, second)
