"""Local commissioning inventory and ROOT-only trust changes (#38, #86, P4).

Inventory remains read-only. Trust replacement has its own explicit verb
allowlist and short-lived, peer-bound interactive confirmation. Accepting a
signed Knowledge Lite revocation list is a third ROOT-only verb on the same
trust root (`lite_revocation_accept`); the signed statement is its authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from azazel_nexus.commissioning import describe_for_operator
from azazel_nexus.inventory import InterfaceReadout, read_interfaces

from .lite_revocation_accept import REVOCATION_INPUT, RevocationAcceptance
from .netlink import LinkRecord, NetlinkMalformed, NetlinkUnavailable, read_links
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
)
from .repin_confirmation import (
    ANCHOR_FILENAME,
    REASONS,
    ConfirmationLike,
    OutcomeLike,
    RepinConfirmation,
    RepinRequestLike,
    production_repin,
)
from .serve import serve_forever

__all__ = [
    "MAX_INTERFACES",
    "VERBS",
    "CommissionService",
    "Snapshot",
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
    permanent_macs: tuple[str | None, ...]
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


def _composite(readout: InterfaceReadout, permanent_mac: str | None) -> list:
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
    sysfs: Path | None = None,
    links: Sequence[LinkRecord] | None = None,
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

    macs: list[str | None] = []
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


#: Read-only inventory verbs. Trust mutation is separately declared below.
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

REPIN_VERBS = (
    Verb(
        "trust.repin.challenge",
        arguments=(
            Argument("reason", ArgumentKind.ENUM, choices=REASONS),
            Argument("new_anchor_file", ArgumentKind.ENUM, choices=(ANCHOR_FILENAME,)),
        ),
        admits=frozenset({PrincipalClass.ROOT}),
    ),
    Verb(
        "trust.repin.confirm",
        arguments=(
            Argument("nonce", ArgumentKind.DIGEST),
            Argument("echo", ArgumentKind.IDENTIFIER),
        ),
        admits=frozenset({PrincipalClass.ROOT}),
    ),
)

#: Signed cumulative Knowledge Lite revocations, from one fixed leaf. ROOT only.
REVOCATION_VERBS = (
    Verb(
        "trust.revocation.accept",
        arguments=(
            Argument("revocation_file", ArgumentKind.ENUM, choices=(REVOCATION_INPUT,)),
        ),
        admits=frozenset({PrincipalClass.ROOT}),
    ),
)

REGISTRY = VerbRegistry(VERBS + REPIN_VERBS + REVOCATION_VERBS)


class CommissionService:
    """Local commissioning handler with separate inventory and repin state.

    Inventory re-enumerates on each inventory request. Only repin challenges
    are retained, and they expire or are consumed by one confirmation attempt.
    """

    def __init__(
        self,
        *,
        sysfs: Path | None = None,
        read_links_fn: Callable[[], Sequence[LinkRecord]] = read_links,
        repin: Callable[[RepinRequestLike, ConfirmationLike], OutcomeLike] = production_repin,
        commissioning_dir: Path | None = None,
        snapshot_dir: Path | None = None,
        clock: Callable[[], float] | None = None,
        now: Callable[[], str] | None = None,
        revocation: RevocationAcceptance | None = None,
    ) -> None:
        self.sysfs = sysfs
        self.read_links_fn = read_links_fn
        from .runtime_paths import ROOT, state_dir

        options = {}
        if clock is not None:
            options["clock"] = clock
        if now is not None:
            options["now"] = now
        self.repin_confirmation = RepinConfirmation(
            commissioning_dir=(commissioning_dir if commissioning_dir is not None
                               else ROOT / "etc/azazel/commissioning"),
            snapshot_dir=(snapshot_dir if snapshot_dir is not None
                          else state_dir() / "commission"),
            repin=repin, **options,
        )
        self.revocation = revocation if revocation is not None else RevocationAcceptance(
            commissioning_dir=self.repin_confirmation.commissioning_dir)

    def snapshot(self) -> Snapshot:
        try:
            return build_snapshot(sysfs=self.sysfs, read_links_fn=self.read_links_fn)
        except (NetlinkUnavailable, NetlinkMalformed) as exc:
            # A dump that cannot be read whole (a forged, interrupted or cut
            # reply, #310) is refused as a missing one is: never an inventory,
            # and not retried here.
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "netlink") from exc

    def handle(self, request) -> dict:
        if request.verb.name == "trust.repin.challenge":
            return self.repin_confirmation.challenge(request.principal, **request.arguments)
        if request.verb.name == "trust.repin.confirm":
            return self.repin_confirmation.confirm(request.principal, **request.arguments)
        if request.verb.name == "trust.revocation.accept":
            return self.revocation.accept(request.principal, **request.arguments)
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


def main(
    argv: Sequence[str] | None = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    """Serve until stopped.

    `stop` and `ready` are injected so the E2E harness can start this daemon
    and end it on a condition it controls, in bounded time. A daemon that
    could only be stopped by a signal is one whose shutdown path is never
    exercised.
    """

    from .runtime_paths import audit_sink, socket_path
    from .systemd_notify import runtime_ready_callback

    return serve_forever(
        path=socket_path("commission"),
        registry=REGISTRY,
        policy=PrincipalPolicy.resolve(),
        audit=audit_sink("commission"),
        handler=CommissionService().handle,
        stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
