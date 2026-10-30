"""`az-units-observe`: write the packaged units' states for operators (U2).

Runs once per `azazel-units-observe.timer` period as `azprobe`, the account
that already reads one unit's state for the Edge probe, with `AF_UNIX` only
and `IPAddressDeny=any`. It reads `LoadState`/`ActiveState`/`SubState` of
the fixed `operator_snapshots.OBSERVED_UNITS` through
`systemd_bus.UnitStatesReader` (read-only; no unit name is taken from
anyone) and writes `units-status/v1` into its own leaf
(`/var/lib/azazel/run/units-status`, `2750 azprobe:azazel-operator`).

It takes no argument, it decides nothing, and no unit requires or binds to
it: stopping it, or its timer, leaves every other unit as it was; the
snapshot then goes stale and status says so.
"""

from __future__ import annotations

import sys
import time
from typing import Callable, Optional, Sequence

from azazel_nexus.operator_snapshots import UNITS_BYTES, units_snapshot

__all__ = ["main", "observe"]


def observe(reader, *, clock: Callable[[], float] = time.time) -> dict:
    """One `units-status/v1` snapshot from one pass of `reader.read_all()`."""

    return units_snapshot(reader.read_all(), clock())


def main(argv: Optional[Sequence[str]] = None, *, reader=None,
         clock: Callable[[], float] = time.time) -> int:
    from .runtime_paths import ui_copy_path, units_status_path
    from .status_snapshot import SnapshotWriter
    from .systemd_bus import UnitStatesReader

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-units-observe takes no arguments")
    reader = reader if reader is not None else UnitStatesReader()
    writer = SnapshotWriter(units_status_path(), lambda: observe(reader, clock=clock),
                            limit=UNITS_BYTES, interval_s=0, name="az-units-observe",
                            ui_path=ui_copy_path("units_status"))
    return 0 if writer.write() else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
