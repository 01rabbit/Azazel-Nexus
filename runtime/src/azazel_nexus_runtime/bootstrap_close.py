"""Connected close/reload/loaded-mask/job-drain transaction.

Trusted composition supplies a held-lock owned-file backend and a dedicated
bus. No path opener, CLI, grant, stop or cgroup assertion is provided here.
Reload affects the manager globally; deployment authorization remains required.
The caller owns disconnect and pending-task draining on every outcome.
The deadline rejects overdue results but cannot preempt synchronous filesystem
IO. Deployment must supply an independently supervised controller lifetime;
moving writes to an abandoned worker thread would permit late mutation.
"""

from .bootstrap_job_drain import BootstrapJobDrain
from .bootstrap_masked import BootstrapMaskedPairInspector, _observe_profile
from .bootstrap_stop import BootstrapStopJobs
from .units import UnitOperationFailed


class BootstrapCloseSequence:
    """Single-use bus-budgeted sequence; filesystem latency is not bounded."""

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds, files):
        self._arguments = dict(bus=bus, message_factory=message_factory,
                               message_type=message_type, timeout_seconds=timeout_seconds)
        self._reader = BootstrapStopJobs(**self._arguments)
        if not callable(getattr(files, "close", None)) or not callable(getattr(files, "check", None)):
            raise ValueError("trusted owned-file closure required")
        self._files = files
        self._used = False

    async def close(self):
        if self._used:
            raise UnitOperationFailed("bootstrap close requires a fresh transaction")
        self._used = True
        reader = self._reader

        async def operation():
            owner = await reader._owner()
            reader._manager_owner = owner
            profile = await _observe_profile(reader)
            if await reader._owner() != owner:
                raise UnitOperationFailed("bootstrap close owner changed")
            if self._files.close() is not None:
                raise UnitOperationFailed("owned-file close unconfirmed")
            fragments = self._files.check()
            if await reader._owner() != owner:
                raise UnitOperationFailed("bootstrap close owner changed")
            if await reader._call("Reload", "", [], "") != []:
                raise UnitOperationFailed("bootstrap reload unconfirmed")

            async def check_closed():
                if self._files.check() != fragments:
                    raise UnitOperationFailed("bootstrap closed file identity changed")
                if (await reader._owner() != owner
                        or await _observe_profile(reader) != profile):
                    raise UnitOperationFailed("bootstrap close manager changed")
                observed = await BootstrapMaskedPairInspector(
                    **self._arguments, expected_owner=owner,
                    expected_fragments=fragments,
                ).inspect()
                if observed.fragments != fragments:
                    raise UnitOperationFailed("loaded masks do not match owned closure")
                if self._files.check() != fragments:
                    raise UnitOperationFailed("bootstrap closed files changed during observation")
                if (await _observe_profile(reader) != profile
                        or await reader._owner() != owner):
                    raise UnitOperationFailed("bootstrap manager changed during mask observation")
                return None

            await check_closed()
            await BootstrapJobDrain(
                **self._arguments, expected_owner=owner, check_closed=check_closed,
            ).drain()
            await check_closed()
            # This final observation is not stopped/cgroup-empty evidence.
            result = await BootstrapMaskedPairInspector(
                **self._arguments, expected_owner=owner,
                expected_fragments=fragments,
            ).inspect()
            if (result.fragments != fragments or self._files.check() != fragments
                    or await _observe_profile(reader) != profile
                    or await reader._owner() != owner):
                raise UnitOperationFailed("final bootstrap close observation changed")
            return result

        try:
            return await reader._bounded(operation())
        except Exception:
            raise UnitOperationFailed("bootstrap close/reload/drain unconfirmed") from None
