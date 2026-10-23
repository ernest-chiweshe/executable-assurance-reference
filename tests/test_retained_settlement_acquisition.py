"""C050-R1: a failure while entering the settlement lock unwinds every context already entered, keeping the original
exception. An ordinary synthetic connection whose first statement fails; no database, no guard change."""
import pytest

from assurance_reference.retained_settlement import RetainedSettlements


class _Context:
    def __init__(self, log, name, value=None):
        self.log, self.name, self.value = log, name, value

    def __enter__(self):
        self.log.append(("enter", self.name))
        return self.value

    def __exit__(self, kind, exc, tb):
        self.log.append(("exit", self.name, kind))
        return False


class _Connection:
    def __init__(self, log):
        self.log = log

    def transaction(self):
        return _Context(self.log, "transaction")

    def execute(self, statement, params=()):
        raise RuntimeError("synthetic statement failure")


class _Pool:
    def __init__(self):
        self.log = []

    def connection(self):
        return _Context(self.log, "connection", _Connection(self.log))


def test_failed_lock_entry_unwinds_transaction_and_connection_with_the_original_error():
    pool = _Pool()
    with pytest.raises(RuntimeError, match="synthetic statement failure"):
        with RetainedSettlements(pool=pool).transaction("tenant-a", "review-1"):
            pytest.fail("the body must not run")
    assert pool.log == [("enter", "connection"), ("enter", "transaction"),
                        ("exit", "transaction", RuntimeError), ("exit", "connection", RuntimeError)]
