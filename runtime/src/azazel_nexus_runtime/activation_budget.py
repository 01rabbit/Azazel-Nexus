"""Cooperative time budgets for the main pass and the recheck.

`azazel-activated.service` has `TimeoutStartSec=60s` and the recheck
`TimeoutStartSec=40s`; past that systemd kills the process with no controlled
narrowing and no record. The budget is therefore kept by the code itself, and
never by interrupting it asynchronously (a signal raised into a ledger append,
a high-water rename or a pending D-Bus future would leave a torn file or an
unanswered call):

* a monotonic deadline is fixed before the bus is even connected;
* it is checked between the phases (`check_budget`);
* every D-Bus call is refused once it has passed and otherwise limited to the
  time that remains (`SystemdBusSession.set_remaining`, `bind_remaining`);
* a call that times out poisons its session: the future is cancelled and
  drained, nothing more is sent on that session, and any narrowing that is
  still needed runs on a fresh one inside a small fixed reserve that is held
  back from the budget.

What this cannot bound is work that is neither a bus call nor between two
checks (for instance a file read that blocks in the kernel); that is stated in
the documentation, not hidden.
"""

from __future__ import annotations

from typing import Callable

__all__ = ["PassBudgetExpired", "bind_remaining", "check_budget"]


class PassBudgetExpired(BaseException):
    """The evaluation used its budget. Narrow, then fail.

    A `BaseException` so that no broad ``except Exception`` in the pass turns
    it into "a producer failed" and carries on; it is only raised by
    `check_budget`, between phases, never inside a write.
    """


def check_budget(deadline: float, clock: Callable[[], float]) -> None:
    """Raise `PassBudgetExpired` if `clock()` is at or past `deadline`."""
    if clock() >= deadline:
        raise PassBudgetExpired("the evaluation budget is used")


def bind_remaining(manager, deadline: float, clock: Callable[[], float]) -> None:
    """Tell the manager's bus session how long it has until `deadline`.

    A manager without a session that takes a deadline (the in-memory
    recording manager) is left alone.
    """
    setter = getattr(getattr(manager, "call", None), "set_remaining", None)
    if callable(setter):
        setter(lambda: deadline - clock())
