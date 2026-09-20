"""`az-commissiond`: it reads permanent MACs, and that is the whole daemon (#38).

Not "primarily". The verb table has two entries and neither of them changes
anything on the host.

## The ordinal problem

An operator picks an interface from a list. The obvious request carries the
row number — and the row number means nothing on its own, because the kernel
may enumerate differently on the next boot, a USB adapter may be unplugged
between the listing and the confirmation, and a second read may simply return
a different order.

So a request carries an ordinal **and the digest of the enumeration it was
chosen from**. The daemon re-enumerates, digests what it now sees, and
compares. If the digests differ the request is refused and the operator is
asked to look again — not silently re-resolved against the new list, which is
how a confirmation for one adapter gets applied to another.

The digest covers each interface's composite identity in order, so two
enumerations agreeing on it agree on which adapter is at every position.
That is what turns an ordinal into an identification.

## What it refuses

*No `IFLA_PERM_ADDRESS`* — refused. There is no fallback to the current MAC,
which is the address the device is presently using and which a bond, a
randomisation or an attacker changes. `docs/commissioning.md` §3 forbids
resolving an assignment from it, and a fallback here would be that, one layer
down and harder to see.

*A stale snapshot* — refused, with the instruction to re-read the inventory.

*Anything else* — there is nothing else. No verb here assigns a role, changes
a link, or writes to the host.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from azazel_nexus.commissioning import describe_for_operator
from azazel_nexus.inventory import InterfaceReadout, read_interfaces

from .netlink import LinkRecord, NetlinkUnavailable, read_links
from .principal import PrincipalClass
from .protocol import Argument, ArgumentKind, Refusal, RequestRefused, Verb, VerbRegistry

__all__ = [
    "MAX_INTERFACES",
    "CommissionService",
    "Snapshot",
    "VERBS",
    "build_snapshot",
]

#: The largest enumeration this daemon will describe.
#:
#: An ordinal has to declare a ceiling (`ArgumentKind.ORDINAL`), and the
#: ceiling has to be a number rather than "however many there are" -- a bound
#: the caller chooses the size of is not a bound.
MAX_INTERFACES = 255


@dataclass(frozen=True)
class Snapshot:
    """One enumeration of the host's interfaces, and its digest.

    The digest covers each interface's composite identity **in order**. Two
    snapshots that agree on it agree on which adapter is at every position,
    which is the only thing that makes an ordinal mean something.
    """

    readouts: tuple[InterfaceReadout, ...]
    permanent_macs: tuple[Optional[str], ...]
    digest: str

    def __post_init__(self) -> None:
        if len(self.readouts) != len(self.permanent_macs):
            raise ValueError(
                "the snapshot holds a different number of interfaces and "
                "addresses; one of them describes something the other does not"
            )

    def describe(self) -> list[dict]:
        """The rows an operator sees. No kernel name, ever.

        `describe_for_operator` is the library's, and it excludes the kernel
        name by construction. Reusing it rather than assembling rows here
        keeps one definition of what an operator may be shown.
        """

        rows = []
        for ordinal, readout in enumerate(self.readouts):
            rows.append(
                {
                    "ordinal": ordinal,
                    "description": describe_for_operator(readout),
                    "permanent_mac_readable": self.permanent_macs[ordinal] is not None,
                }
            )
        return rows


def _composite(readout: InterfaceReadout, permanent_mac: Optional[str]) -> list:
    """What the digest covers for one interface.

    The permanent address is included: an adapter swapped for another in the
    same slot would otherwise produce the same digest, and the ordinal would
    then point at a different device while claiming to point at the same one.
    """

    return [
        sorted((name, value) for name, value in readout.fields.items()),
        permanent_mac,
    ]


def build_snapshot(
    *,
    sysfs: Optional[Path] = None,
    links: Optional[Sequence[LinkRecord]] = None,
    read_links_fn: Callable[[], Sequence[LinkRecord]] = read_links,
) -> Snapshot:
    """Enumerate, read permanent addresses, and digest the pair.

    `links` is accepted so a caller that already has a dump does not take a
    second one: two reads of a moving table are two different tables, and the
    whole point here is to describe one.
    """

    readouts = read_interfaces(sysfs)
    if len(readouts) > MAX_INTERFACES:
        raise RequestRefused(
            Refusal.ARGUMENT_RANGE,
            "interfaces",
        )
    records = list(links) if links is not None else list(read_links_fn())
    by_name = {record.name: record for record in records if record.name}

    macs: list[Optional[str]] = []
    for readout in readouts:
        record = by_name.get(readout.kernel_name)
        macs.append(record.permanent_mac if record is not None else None)

    payload = [
        _composite(readout, mac) for readout, mac in zip(readouts, macs)
    ]
    digest = "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return Snapshot(
        readouts=tuple(readouts), permanent_macs=tuple(macs), digest=digest
    )


#: The whole verb table. Two entries, neither of which changes anything.
VERBS = (
    Verb(
        "commission.inventory",
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR}),
    ),
    Verb(
        "commission.permanent_mac",
        arguments=(
            Argument("snapshot", ArgumentKind.DIGEST),
            Argument("ordinal", ArgumentKind.ORDINAL, maximum=MAX_INTERFACES - 1),
        ),
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR}),
    ),
)

REGISTRY = VerbRegistry(VERBS)


class CommissionService:
    """The handler behind the socket. Re-enumerates on every request.

    Not cached. A cached enumeration is a description of the host at the
    moment it was cached, and the request it would answer is precisely the one
    asking whether the host still looks that way.
    """

    def __init__(
        self,
        *,
        sysfs: Optional[Path] = None,
        read_links_fn: Callable[[], Sequence[LinkRecord]] = read_links,
    ) -> None:
        self.sysfs = sysfs
        self.read_links_fn = read_links_fn

    def snapshot(self) -> Snapshot:
        try:
            return build_snapshot(sysfs=self.sysfs, read_links_fn=self.read_links_fn)
        except NetlinkUnavailable as exc:
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "netlink") from exc

    def handle(self, request) -> dict:
        if request.verb.name == "commission.inventory":
            snapshot = self.snapshot()
            return {"snapshot": snapshot.digest, "interfaces": snapshot.describe()}
        return self._permanent_mac(request.arguments)

    def _permanent_mac(self, arguments: dict) -> dict:
        snapshot = self.snapshot()
        if arguments["snapshot"] != snapshot.digest:
            # Not re-resolved against the new enumeration. An operator
            # confirmed a row in a list that no longer describes this host,
            # and applying it anyway is how a confirmation for one adapter
            # reaches another.
            return {
                "readable": False,
                "reason": "inventory_changed",
                "detail": (
                    "the interfaces enumerated differently since this list was "
                    "read. Read the inventory again and confirm against what "
                    "is there now"
                ),
                "snapshot": snapshot.digest,
            }
        ordinal = arguments["ordinal"]
        if ordinal >= len(snapshot.readouts):
            # Unreachable while the digests match, and kept because the two
            # checks guard different things: the digest guards which adapter
            # is at a position, this guards that the position exists.
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "ordinal")

        mac = snapshot.permanent_macs[ordinal]
        if mac is None:
            return {
                "readable": False,
                "reason": "no_permanent_address",
                "detail": (
                    "the driver reports no permanent address for this "
                    "interface. There is no fallback to the address it is "
                    "currently using: a role bound to that would be resolved "
                    "by whatever set it last"
                ),
                "snapshot": snapshot.digest,
            }
        return {"readable": True, "permanent_mac": mac, "snapshot": snapshot.digest}


def main(argv: Optional[Sequence[str]] = None) -> int:  # pragma: no cover - needs a host
    """Serve until stopped. Exercised by the E2E harness (#43), not by CI."""

    raise SystemExit(
        "az-commissiond's service loop is wired in #42; the request handling "
        "it will serve is implemented and tested here"
    )
