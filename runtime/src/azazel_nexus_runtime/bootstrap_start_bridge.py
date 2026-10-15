"""Private fixed-phase bridge for synchronous admission around one async job.

Not start authorization. A synchronous guard cannot be preempted: it must obey
its existing bounded contract. Expired or failed checks never release a pause.
The owning manager must disconnect and drain the retained session on all exits.
"""

import asyncio
import math

from .units import UnitOperationFailed

_PHASES = ("before_observation", "before_submission", "after_completion")


class _StartCheckpointBridge:
    def __init__(self, loop, observer):
        if loop.is_closed() or loop.is_running():
            raise UnitOperationFailed("bootstrap bridge requires an idle owned loop")
        self._loop = loop
        self._observer = observer
        self._notice = loop.create_future()
        self._pending = None
        self._index = 0
        self._deadline = None
        self._failed = False
        self._used = False

    async def checkpoint(self, phase, deadline):
        if (self._failed or asyncio.get_running_loop() is not self._loop
                or self._pending is not None or self._index >= len(_PHASES)
                or type(phase) is not str or phase != _PHASES[self._index]
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or (self._deadline is not None and deadline != self._deadline)
                or self._loop.time() >= deadline):
            raise UnitOperationFailed("bootstrap checkpoint phase refused")
        self._deadline = deadline
        release = self._loop.create_future()
        pending = (phase, deadline, release)
        self._pending = pending
        self._notice.set_result(None)
        await release
        if self._failed or self._pending is not pending:
            raise UnitOperationFailed("bootstrap checkpoint release refused")
        self._pending = None
        self._index += 1

    def _check_pending(self, task):
        if (self._failed or not self._observer._usable or task.done() or self._pending is None
                or self._pending[2].done()
                or self._loop.time() >= self._pending[1]):
            raise UnitOperationFailed("bootstrap checkpoint expired or no longer pending")

    def run(self, awaitable, check_start):
        if self._used or not callable(check_start):
            raise UnitOperationFailed("single-use bootstrap bridge requires a checkpoint")
        self._used = True
        task = self._loop.create_task(awaitable)
        try:
            while not task.done():
                self._loop.run_until_complete(asyncio.wait(
                    {task, self._notice}, return_when=asyncio.FIRST_COMPLETED,
                ))
                if task.done():
                    break
                self._check_pending(task)
                # The owned loop is stopped here. Admission may use a separate
                # synchronous D-Bus session without re-entering a running loop.
                if check_start() is not None:
                    raise UnitOperationFailed("bootstrap synchronous checkpoint refused")
                self._check_pending(task)
                self._notice = self._loop.create_future()
                self._pending[2].set_result(None)
            result = task.result()
            if self._pending is not None or self._index != len(_PHASES) or result is not None:
                raise UnitOperationFailed("bootstrap checkpoint sequence incomplete")
            return None
        except BaseException:
            self._failed = True
            self._observer._usable = False
            if self._pending is not None:
                self._pending[2].cancel()
            task.cancel()
            def discard(finished):
                try:
                    finished.result()
                except BaseException:
                    pass
            task.add_done_callback(discard)
            raise
        finally:
            self._notice.cancel()
