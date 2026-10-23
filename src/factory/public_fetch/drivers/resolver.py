"""CAP-3 §5.1: the cancellable, deadline-bound DNS resolution boundary.

The blocking OS lookup runs ONLY inside a fixed, short-lived worker whose
target is server code (never caller data). The parent enforces the remaining
monotonic deadline; on expiry it terminates AND joins the worker and records
whether any child survived before returning a typed DNS timeout. Success
admits only a closed, bounded, unique address tuple. Free tests inject a fake
worker factory: no process is spawned and no DNS query leaves the host.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol, cast

from ..contracts import DeadlineBudget, PublicFetchContractError

# The parent grants a terminated worker this long to die; a worker still
# alive afterwards is a qualification failure fact, never silent.
_TERMINATE_GRACE_SECONDS = 1.0

_MAX_ADDRESS_TEXT = 128

# The closed failure vocabulary — every non-success is one of these.
_FAILURES = frozenset({
    "dns_timeout", "dns_failure", "dns_answer_bound", "dns_worker_unclean",
})


@dataclass(frozen=True, slots=True)
class ResolutionOutcome:
    """The closed resolver result: addresses XOR one typed failure.

    `worker_started`/`worker_joined`/`worker_alive_after` are qualification
    facts (§5.1: worker startup, termination and join are evidence), so a
    reviewer can prove no lookup escaped the deadline boundary.
    """

    addresses: tuple[str, ...]
    failure: str
    worker_started: bool
    worker_joined: bool
    worker_alive_after: bool

    def __post_init__(self) -> None:
        if not isinstance(self.addresses, tuple) or not all(
                isinstance(item, str) and item.strip()
                and len(item) <= _MAX_ADDRESS_TEXT
                for item in self.addresses):
            raise PublicFetchContractError("resolver addresses are malformed")
        if len(set(self.addresses)) != len(self.addresses):
            raise PublicFetchContractError("resolver addresses must be unique")
        if self.failure and self.failure not in _FAILURES:
            raise PublicFetchContractError("resolver failure code is not closed")
        if bool(self.addresses) == bool(self.failure):
            raise PublicFetchContractError(
                "resolution is addresses XOR one typed failure")
        if self.worker_alive_after and not self.failure:
            raise PublicFetchContractError(
                "a surviving worker can never accompany success")


class ResolverWorker(Protocol):
    """The injected short-lived lookup worker seam (fake in every free test).

    The production implementation wraps one `multiprocessing` process whose
    target is the module-level server function below; a caller can neither
    choose the executable nor the target.
    """

    def start(self) -> None: ...

    def join(self, timeout_seconds: float) -> None: ...

    def terminate(self) -> None: ...

    def is_alive(self) -> bool: ...

    def result(self) -> tuple[str, ...] | None: ...

    def error(self) -> str: ...


ResolverWorkerFactory = Callable[[str], ResolverWorker]


class DeadlineBoundResolver:
    """Run one lookup under the REMAINING monotonic deadline, cancellably."""

    def __init__(self, worker_factory: ResolverWorkerFactory, *,
                 max_addresses: int) -> None:
        if not callable(worker_factory):
            raise PublicFetchContractError("resolver requires a worker factory")
        if (isinstance(max_addresses, bool) or not isinstance(max_addresses, int)
                or not 1 <= max_addresses <= 16):
            raise PublicFetchContractError("resolver address bound is not closed")
        self._factory = worker_factory
        self._max_addresses = max_addresses

    def resolve(self, host: str, deadline: DeadlineBudget) -> ResolutionOutcome:
        if not isinstance(host, str) or not host.strip():
            raise PublicFetchContractError("resolver requires a host")
        remaining = deadline.remaining_seconds()
        if remaining <= 0.0:
            # No worker starts once the budget is spent — the refusal happens
            # BEFORE the external operation, per the ceiling law.
            return ResolutionOutcome((), "dns_timeout", False, False, False)
        worker = self._factory(host)
        worker.start()
        worker.join(remaining)
        if worker.is_alive():
            # Deadline expiry: terminate, join, and PROVE whether a child
            # survived. Survival is recorded, never hidden by the timeout.
            worker.terminate()
            worker.join(_TERMINATE_GRACE_SECONDS)
            alive_after = worker.is_alive()
            return ResolutionOutcome(
                (), "dns_worker_unclean" if alive_after else "dns_timeout",
                True, not alive_after, alive_after)
        if worker.error():
            return ResolutionOutcome((), "dns_failure", True, True, False)
        answers = worker.result()
        if (not isinstance(answers, tuple) or not answers
                or not all(isinstance(item, str) and item.strip()
                           and len(item) <= _MAX_ADDRESS_TEXT
                           for item in answers)):
            return ResolutionOutcome((), "dns_failure", True, True, False)
        # DNS answer count is checked BEFORE the next external operation —
        # an over-limit answer set refuses outright, never truncates.
        unique = tuple(dict.fromkeys(answers))
        if len(unique) != len(answers) or len(answers) > self._max_addresses:
            return ResolutionOutcome((), "dns_answer_bound", True, True, False)
        return ResolutionOutcome(answers, "", True, True, False)


# A defensive worker-side cap, ABOVE any lawful policy address bound (<=16), so a
# pathological answer set is refused as overflow rather than piped wholesale. The
# worker NEVER truncates to the policy bound — that authority check is the
# parent's, and truncating here would let an over-count host masquerade as valid.
_WORKER_ADDRESS_HARD_CAP = 64


def _addresses_from_lookup(
        host: str,
        lookup: Callable[..., object],
) -> tuple[str, object]:
    """The pure worker core: run the injected OS lookup and return ONE closed
    reply — ('ok', complete-unique-addresses) or ('error', safe_code). It returns
    the COMPLETE unique set (never a slice); an over-hard-cap set is an explicit
    `dns_answer_bound` overflow, so the parent's policy bound still sees a truthful
    count. Tested directly with a fake lookup — no DNS query, no process."""
    import socket

    try:
        raw = lookup(host, None, proto=socket.IPPROTO_TCP)
    except Exception:  # noqa: BLE001 - any lookup failure is one safe code
        return ("error", "dns_failure")
    # getaddrinfo entries are (family, type, proto, canonname, sockaddr); the
    # address is sockaddr[0]. Cast the injected reply to that shape once.
    infos = cast("list[tuple[Any, ...]]", raw)
    unique = tuple(dict.fromkeys(str(item[4][0]) for item in infos))
    if len(unique) > _WORKER_ADDRESS_HARD_CAP:
        # Overflow is a refusal fact, never a silent truncation to the cap.
        return ("error", "dns_answer_bound")
    return ("ok", unique)


def _resolve_host_worker(host: str, connection: object) -> None:
    """The FIXED worker target (server code): one OS lookup, closed reply.

    Runs only inside the production worker process. The parent supplies the
    pipe; the child sends either ("ok", addresses) or ("error", safe_code)
    and exits. It never receives caller-controlled code or paths.
    """
    import socket

    send = getattr(connection, "send", None)
    close = getattr(connection, "close", None)
    try:
        reply = _addresses_from_lookup(host, socket.getaddrinfo)
        if callable(send):
            send(reply)
    except Exception:  # noqa: BLE001 - the child reports one safe code only
        if callable(send):
            send(("error", "dns_failure"))
    finally:
        if callable(close):
            close()


class OSResolverWorker:
    """Production `ResolverWorker` over one spawn-context process.

    Constructed only by the production factory below; the target function is
    pinned to `_resolve_host_worker`. Free tests never instantiate this.
    """

    def __init__(self, host: str) -> None:
        import multiprocessing

        context = multiprocessing.get_context("spawn")
        self._parent, child = context.Pipe(duplex=False)
        self._process = context.Process(
            target=_resolve_host_worker, args=(host, child), daemon=True)
        self._reply: tuple[str, object] | None = None

    def start(self) -> None:
        self._process.start()

    def join(self, timeout_seconds: float) -> None:
        self._process.join(timeout_seconds)

    def terminate(self) -> None:
        self._process.terminate()

    def is_alive(self) -> bool:
        return self._process.is_alive()

    def _receive(self) -> tuple[str, object] | None:
        if self._reply is None and self._parent.poll(0):
            try:
                received = self._parent.recv()
            except Exception:  # noqa: BLE001 - a broken pipe is a dns failure
                received = ("error", "dns_failure")
            if (isinstance(received, tuple) and len(received) == 2
                    and isinstance(received[0], str)):
                self._reply = (received[0], received[1])
            else:
                self._reply = ("error", "dns_failure")
        return self._reply

    def result(self) -> tuple[str, ...] | None:
        reply = self._receive()
        if reply is None or reply[0] != "ok":
            return None
        value = reply[1]
        if isinstance(value, tuple) and all(isinstance(x, str) for x in value):
            return value
        return None

    def error(self) -> str:
        reply = self._receive()
        if reply is None:
            return "dns_failure"
        if reply[0] == "error":
            code = reply[1]
            return code if isinstance(code, str) and code else "dns_failure"
        return ""


def os_resolver_worker_factory(host: str) -> ResolverWorker:
    """The production factory: fixed target, spawn context, daemon child."""
    return OSResolverWorker(host)
