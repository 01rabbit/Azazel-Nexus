"""`az-noc-observe`: write the passive NOC observation for operators (U3).

Runs once per `azazel-noc-observe.timer` period as `aznoc`, with
`RestrictAddressFamilies=AF_NETLINK AF_UNIX` and `IPAddressDeny=any`. It
calls `noc_observe.collect` -- the same passive collection `az-nexus-noc`
prints: one `AF_NETLINK`/`NETLINK_ROUTE` dump of links, addresses and routes,
sysfs counters read twice one second apart, the resolver files and DHCP lease
files; no packet, no probe, no name resolution -- and writes
`noc_status.project` of it (`noc-status/v1`) into its own leaf
(`/var/lib/azazel/run/noc-status`, `2750 aznoc:azazel-operator`).

The projection carries no interface name, MAC, address, gateway, nameserver
or search domain. A collection that fails is written as `failed` with a fixed
code, never with the exception's text. Roles are not resolved here (no
commissioning evidence is supplied), as for the operator command.

It takes no argument and decides nothing. No unit requires or binds to it;
stopping it, or its timer, leaves every other unit running, and the snapshot
goes stale.
"""

from __future__ import annotations

import sys
import time
from typing import Callable, Optional, Sequence

from azazel_nexus.noc_status import NOC_BYTES, failed, project

__all__ = ["main", "observe"]

#: Seconds between the two counter reads, the operator command's default.
INTERVAL_S = 1.0


def observe(collect: Callable[..., dict], *, clock: Callable[[], float] = time.time) -> dict:
    """One `noc-status/v1` snapshot. Never raises."""

    try:
        observation = collect(interval=INTERVAL_S)
    except Exception:  # noqa: BLE001 - a fixed code, never the exception's text
        return failed(clock())
    return project(observation, clock())


def main(argv: Optional[Sequence[str]] = None, *, collect: Optional[Callable[..., dict]] = None,
         clock: Callable[[], float] = time.time) -> int:
    from .noc_observe import collect as passive_collect
    from .runtime_paths import noc_status_path, ui_copy_path
    from .status_snapshot import SnapshotWriter

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-noc-observe takes no arguments")
    collect = collect if collect is not None else passive_collect
    writer = SnapshotWriter(noc_status_path(), lambda: observe(collect, clock=clock),
                            limit=NOC_BYTES, interval_s=0, name="az-noc-observe",
                            ui_path=ui_copy_path("noc_status"))
    return 0 if writer.write() else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
