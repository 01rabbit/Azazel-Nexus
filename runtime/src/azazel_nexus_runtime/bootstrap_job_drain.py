"""Bounded exact-pair job cancellation under an independently closed gate.

CancelJob does not undo an operation that has begun. Queue absence is NOT
inactive/cgroup/loaded-mask evidence. The enclosing deployment must keep its
start fence closed, then stop and observe both helpers before grant withdrawal.
The bootstrap manager composes this component; callers still must keep the
start fence closed as above.
"""

from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .systemd_bus import _unit_object_path
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed

_PAIR = frozenset(UNIT_NAMES[key] for key in (UnitKey.AUDITD, UnitKey.COMMISSIOND))


def _rows(body):
    if type(body) is not list or len(body) != 1 or type(body[0]) is not list:
        raise UnitOperationFailed("bootstrap job list malformed")
    if len(body[0]) > 4096:
        raise UnitOperationFailed("bootstrap job list exceeds budget")
    selected = []
    seen = set()
    for row in body[0]:
        if type(row) is not list or len(row) != 6:
            raise UnitOperationFailed("bootstrap job row malformed")
        job, unit, kind, state, path, unit_path = row
        if (type(job) is not int or not 0 < job <= 0xFFFFFFFF or job in seen
                or type(unit) is not str or not 0 < len(unit) <= 256
                or not unit.isascii() or "/" in unit or "\x00" in unit
                or any(char.isspace() for char in unit)
                or type(kind) is not str or not 0 < len(kind) <= 64
                or not kind.isascii() or not all(char.isalnum() or char == "-" for char in kind)
                or type(state) is not str or state not in {"waiting", "running"}
                or type(path) is not str or path != f"/org/freedesktop/systemd1/job/{job}"
                or type(unit_path) is not str or unit_path != _unit_object_path(unit)):
            raise UnitOperationFailed("bootstrap job identity malformed")
        seen.add(job)
        if unit in _PAIR:
            selected.append(job)
    return tuple(selected)


class BootstrapJobDrain:
    """Trusted composition only, on one owned dedicated bus connection.

    check_closed is an async, bounded-by-this-operation revalidator of the
    deployment's already effective loaded mask/reload and new-start fence.
    It must not learn authorization from ListJobs or a process-local flag.
    The caller owns disconnect/drain of this session on every outcome.
    expected_owner carries an enclosing transaction's manager identity. It
    binds observations across adapters, but does not itself establish a fence.
    """

    def __init__(self, *, bus, message_factory, message_type,
                 timeout_seconds, check_closed, expected_owner=None):
        self._expected_owner = _validate_expected_owner(expected_owner)
        if not callable(check_closed):
            raise ValueError("independent closed-start fence revalidator required")
        self._check = check_closed
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds,
        )
        self._used = False

    async def drain(self) -> None:
        if self._used:
            raise UnitOperationFailed("bootstrap job drain requires fresh session")
        self._used = True
        reader = self._reader

        async def guard():
            if await self._check() is not None:
                raise UnitOperationFailed("bootstrap start fence unconfirmed")

        async def operation():
            await guard()
            owner = await reader._owner()
            if self._expected_owner is not None and owner != self._expected_owner:
                raise UnitOperationFailed("enclosing systemd owner changed")
            reader._manager_owner = owner

            async def stable():
                await guard()
                if await reader._owner() != owner:
                    raise UnitOperationFailed("bootstrap systemd owner changed")

            empty = 0
            for _ in range(8):
                await stable()
                jobs = _rows(await reader._call("ListJobs", "", [], "a(usssoo)"))
                await stable()
                if not jobs:
                    empty += 1
                    if empty == 2:
                        return
                    continue
                empty = 0
                for job in jobs:
                    await stable()
                    # IDs are unique within one pinned systemd instance. An
                    # already-gone job/error is uncertainty, never success.
                    if await reader._call("CancelJob", "u", [job], "") != []:
                        raise UnitOperationFailed("bootstrap cancellation unconfirmed")
                    await stable()
            raise UnitOperationFailed("bootstrap pair jobs did not quiesce")

        try:
            await reader._bounded(operation())
        except Exception:
            raise UnitOperationFailed("bootstrap job drain unconfirmed") from None
