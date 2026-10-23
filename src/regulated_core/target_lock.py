"""Process-owned filesystem target locks with conservative legacy handling.

The versioned marker stays at one inode. OS locks release when a holder exits;
unlinking the marker would allow two independent locks for the same target.
An old or unrecognized marker is preserved for explicit reconciliation.
"""

from __future__ import annotations

import errno
import math
import os
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_LOCKING_API = "windows-byte-range" if sys.platform == "win32" else "posix-flock"
_MAGIC = ("factory-target-lock/v1:" + _LOCKING_API + "\n").encode("ascii")


class TargetBusy(Exception):
    """Exclusive ownership is unavailable or the prior lock is unresolved."""


def _initialize(path: Path) -> None:
    """Install a complete marker atomically without replacing an existing one."""
    try:
        path.lstat()
        return
    except FileNotFoundError:
        pass
    fd, temporary = tempfile.mkstemp(prefix=".target-lock-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(_MAGIC)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary)


def _acquire(fd: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(fd: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def target_file_lock(path: Path, *, wait_s: float) -> Iterator[None]:
    """Serialize cooperating processes and retain ambiguous legacy markers.

    The marker is never deleted, including on normal release. Older adapters
    using exclusive marker creation consequently cannot run alongside this
    protocol. The marker also pins the OS locking API, so mixed Windows/POSIX
    access is refused rather than assuming interoperable locks. Deployments
    must qualify their filesystem locking support and coordinate versions;
    existing legacy markers
    require separate reconciliation, never automatic stale-file deletion.
    """
    if not math.isfinite(wait_s) or wait_s < 0:
        raise ValueError("target lock wait must be finite and nonnegative")
    try:
        _initialize(path)
    except OSError as exc:
        raise TargetBusy("target lock initialization unavailable") from exc
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise TargetBusy("target lock must be a regular protocol marker")
        fd = os.open(path, flags)
    except OSError as exc:
        raise TargetBusy("target lock cannot be opened safely") from exc
    locked = False
    deadline = time.monotonic() + wait_s
    try:
        while True:
            try:
                _acquire(fd)
                locked = True
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise TargetBusy("target lock ownership unavailable") from exc
                if time.monotonic() >= deadline:
                    raise TargetBusy(f"another commit holds {path.name}") from None
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        held, named = os.fstat(fd), path.lstat()
        if not stat.S_ISREG(named.st_mode) or (held.st_dev, held.st_ino) != (
            named.st_dev,
            named.st_ino,
        ):
            raise TargetBusy("target lock identity changed")
        if os.read(fd, len(_MAGIC) + 1) != _MAGIC:
            raise TargetBusy(
                f"another commit holds {path.name} or its lock protocol is legacy/unknown; "
                "preserve it for explicit reconciliation"
            )
        yield
    finally:
        try:
            if locked:
                _release(fd)
        finally:
            os.close(fd)
