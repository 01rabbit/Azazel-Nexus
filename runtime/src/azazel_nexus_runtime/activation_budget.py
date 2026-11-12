"""A wall-clock budget for a whole evaluation, enforced where it is running.

`azazel-activated.service` has `TimeoutStartSec=60s` and the recheck
`TimeoutStartSec=40s`; past that systemd kills the process with no controlled
narrowing and no record. A budget that is only passed to the broker's stop
wait does not hold when input collection, a D-Bus call or the READY barrier
is slow. So the budget is also armed as a real-time alarm for the whole
evaluation: when it fires the evaluation is abandoned by `PassBudgetExpired`
(a `BaseException`, so no broad `except Exception` in the pass swallows it),
and the caller narrows with the time that is left before systemd's timeout.

The phase checks (`check_budget`) are the cooperative half, used between
phases with the caller's own clock. The alarm needs the main thread; where it
cannot be armed (another thread), only the phase checks apply.
"""

from __future__ import annotations

import contextlib
import signal
import threading
from typing import Callable

__all__ = ["PassBudgetExpired", "alarm_budget", "check_budget"]


class PassBudgetExpired(BaseException):
    """The evaluation used its whole budget. Narrow, then fail."""


def check_budget(deadline: float, clock: Callable[[], float]) -> None:
    """Raise `PassBudgetExpired` if `clock()` is at or past `deadline`."""
    if clock() >= deadline:
        raise PassBudgetExpired("the evaluation budget is used")


@contextlib.contextmanager
def alarm_budget(seconds: float):
    """Raise `PassBudgetExpired` in this thread after `seconds` of real time."""
    if (threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "setitimer")):
        yield
        return

    def expired(_signum, _frame):
        raise PassBudgetExpired("the evaluation budget is used")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
