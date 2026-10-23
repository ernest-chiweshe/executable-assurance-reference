"""Typed input contracts at the two core receiving entrances, before host I/O.

Synthetic non-permit values exercise the public contract with guards intact.
These checks cover the outer type, not malformed internals or derived adapters.
"""

import pytest

from regulated_core.target import Outcome
from test_receiving_signature_contracts import (
    database_fixture, filesystem_fixture, keys,  # noqa: F401
)


NON_PERMITS = (None, False, "synthetic:not-a-permit", {}, object())
CASE_IDS = ("absent", "boolean", "text", "mapping", "object")


@pytest.mark.parametrize("value", NON_PERMITS, ids=CASE_IDS)
def test_filesystem_requires_outer_permit_before_host_io(tmp_path, keys, value):  # noqa: F811
    adapter, ports, preparation_calls = filesystem_fixture(tmp_path, keys)
    assert not adapter.path.parent.exists()
    result = adapter.commit(value, b"synthetic output")
    assert result.outcome is Outcome.FAILED
    assert result.detail == "a signed target permit is required"
    assert ports.calls == preparation_calls == []
    assert not adapter.path.parent.exists()


@pytest.mark.parametrize("value", NON_PERMITS, ids=CASE_IDS)
def test_database_requires_outer_permit_before_host_io(keys, value):  # noqa: F811
    receiver, ports = database_fixture(keys)
    result = receiver.commit(value, b"synthetic output")
    assert result.outcome is Outcome.FAILED
    assert result.detail == "a signed target permit is required"
    assert ports.calls == []
