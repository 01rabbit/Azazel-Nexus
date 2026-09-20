"""What an inventory permits, and what it leaves for an operator to settle.

Phase 0b's second row. A logical role is assigned **only** by explicit operator
confirmation against the inventory (`docs/commissioning.md` §4). Nothing here
assigns one, proposes one, ranks one, or hints at one, and that is structural
rather than careful: there is no role-to-interface mapping in this module to
get wrong.

What it does produce is a proposal in the narrow sense the document means --
*these* interfaces carry an unambiguous composite identity, *these* are the
roles that exist, and here is what an operator can physically check about each
interface. Which role goes where is the operator's answer, not this module's
suggestion.

Why no role is ever suggested
-----------------------------
Every fact that would make a suggestion possible is a fact
`docs/commissioning.md` §4 forbids reading: the interface name, the carrier or
link state, the default route, an autoconfigured address, a resource
measurement. Fabric refuses the same set by name
(`BANNED_ROLE_INFERENCE_FIELDS`), and none of them is even read by
`azazel_nexus.inventory`, so there is nothing here to infer from. A module that
held them and promised not to use them would be one edit away from using them.

The kernel name is the interesting case. It *is* read -- an operator sees it on
a screen -- and it is excluded from everything else:
`describe_for_operator` never returns it. An operator confirms "the port with
the blue tag", not `enp3s0`. A name they cannot check against the machine in
front of them invites a confirmation that means nothing, and the name is not
stable enough to mean anything anyway.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from azazel_nexus.inventory import InterfaceReadout

__all__ = [
    "INTERFACE_ROLES",
    "OFFERABLE_ROLES",
    "Proposal",
    "describe_for_operator",
    "propose",
]

#: Azazel-Fabric's registered interface roles, mirrored locally.
#:
#: Named here rather than imported because commissioning is a CORE path and
#: `azazel_fabric` reaches this package through one boundary module only
#: (ADR-0001). `tests/unit/test_commissioning.py` pins this tuple against
#: `azazel_fabric.provisioning_contracts.INTERFACE_ROLES`, so a mirror that
#: drifts from what it mirrors goes red.
#:
#: **This replaced the list in `docs/commissioning.md` §4**, and the change is
#: recorded rather than quietly applied. That document named `protected`,
#: `observation`, `management`, `decoy`, `egress/module`; Azazel-Boot's code
#: held a third set and its own architecture document a fourth. `management`
#: was the only value all four shared, and two pairs were near-misses that read
#: as agreement -- `observation`/`observe`, `decoy`/`deception_bridge`.
#:
#: The old lists mixed two questions. *What does the node do on this
#: interface?* is the **role**: it is what another product needs to know, and
#: it is what Fabric registers. *Which side of the boundary does this interface
#: face?* -- `protected`, `egress` -- is **topology**: it is Nexus's own and it
#: never crosses a product boundary as a role. Nexus assigns no zone today and
#: names none here; a second local vocabulary to hold one would repeat the
#: mistake this is correcting.
INTERFACE_ROLES = (
    "asset_acquisition",
    "deception_bridge",
    "management",
    "observation",
    "unassigned",
)

#: Of those, the ones an operator may confirm against an interface.
#:
#: `unassigned` is not offered because it is not a confirmation: it is what an
#: interface is when nobody has confirmed anything. `docs/commissioning.md` §4
#: says unassigned interfaces stay unassigned, which is a description of the
#: default, not of a choice someone makes.
OFFERABLE_ROLES = tuple(role for role in INTERFACE_ROLES if role != "unassigned")

#: Facts about an interface an operator can check by looking at the machine.
#:
#: The kernel name is deliberately absent. So is anything §4 forbids reading --
#: not filtered out here, but never read in the first place.
OPERATOR_VISIBLE_FIELDS = ("physical_label", "bus_path", "pci_id", "usb_vid_pid", "serial")


@dataclass(frozen=True)
class Proposal:
    """What an operator may be asked. Not what they should answer."""

    #: Interfaces whose composite identity is unambiguous enough to confirm a
    #: role against. Empty is a valid answer and means `COMMISSIONING_REQUIRED`.
    commissionable: tuple[InterfaceReadout, ...] = ()
    #: `(kernel_name, reasons)` for each interface that is not. Carried rather
    #: than dropped: an operator looking for an adapter that was seen and
    #: discarded has no other way to find out what happened to it.
    refused: tuple[tuple[str, tuple[str, ...]], ...] = ()
    #: The roles that exist. The same tuple for every proposal, because the
    #: list of roles does not depend on what this host happens to have.
    offerable_roles: tuple[str, ...] = OFFERABLE_ROLES
    #: Why this host is or is not ready to be asked.
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def commissioning_required(self) -> bool:
        """True when no role can be confirmed yet.

        `docs/IMPLEMENTATION_SPEC.md` names `COMMISSIONING_REQUIRED` as the
        state; this is the condition for it, not a second state machine.
        """

        return not self.commissionable


def describe_for_operator(readout: InterfaceReadout) -> dict[str, str]:
    """What an operator may be shown about one interface.

    Only physically checkable facts, and only the ones present. The kernel name
    is never included -- see this module's docstring for why that is the point
    rather than an omission.
    """

    return {
        name: value
        for name in OPERATOR_VISIBLE_FIELDS
        if (value := readout.fields.get(name))
    }


def propose(readouts: tuple[InterfaceReadout, ...]) -> Proposal:
    """Report what an operator would have to settle. Settle nothing.

    Ambiguity fails closed in both directions §3 names: an interface whose
    identity could not be established is not commissionable, and two interfaces
    that share a composite identity make *both* uncommissionable rather than
    one of them the winner. The node refuses to choose; Fabric's resolver
    refuses the same way at the contract level.
    """

    refused = [
        (readout.kernel_name, readout.incomplete_reasons)
        for readout in readouts
        if not readout.is_commissionable
    ]
    candidates = [readout for readout in readouts if readout.is_commissionable]

    # A composite identity that is not unique identifies nothing. Counting
    # before selecting is what makes zero and several the same answer.
    seen: dict[tuple, int] = {}
    for readout in candidates:
        key = tuple(readout.fields.get(name) for name in sorted(readout.fields))
        seen[key] = seen.get(key, 0) + 1

    commissionable = []
    for readout in candidates:
        key = tuple(readout.fields.get(name) for name in sorted(readout.fields))
        if seen[key] > 1:
            refused.append(
                (
                    readout.kernel_name,
                    (
                        f"{seen[key]} interfaces share this composite identity; "
                        "an ambiguous identity fails closed rather than picking one",
                    ),
                )
            )
        else:
            commissionable.append(readout)

    reasons = []
    if not commissionable:
        reasons.append(
            "no interface carries an unambiguous composite identity, so no role "
            "can be confirmed against anything"
        )
    else:
        reasons.append(
            f"{len(commissionable)} interfaces carry distinct composite identities; "
            "every role stays unassigned until an operator confirms it"
        )
    if refused:
        reasons.append(f"{len(refused)} interfaces cannot carry a confirmed role")

    return Proposal(
        commissionable=tuple(commissionable),
        refused=tuple(refused),
        reasons=tuple(reasons),
    )


# ---------------------------------------------------------------------------
# The record an operator's confirmation produces (#27)
# ---------------------------------------------------------------------------

#: The three profiles §2.3 requires before anything may be enforced.
#:
#: Named rather than counted. "Three profiles" is a number; these are the
#: three, and a reader deciding whether a node is ready needs to know which
#: one is missing rather than that one is.
REQUIRED_PROFILES = ("hardware", "resource", "topology")


class CommissioningRefused(Exception):
    """The record was not built, and nothing was assumed in its place."""


@dataclass(frozen=True)
class ConfirmedRole:
    """One interface, one role, confirmed by one operator.

    `composite` is the identity the role is bound to. The kernel name is
    deliberately absent: it is how the operator's machine happened to enumerate
    the adapter on one boot, and `docs/commissioning.md` §4 forbids binding a
    role to it.
    """

    composite: tuple[tuple[str, str], ...]
    role: str
    confirmed_by: str
    confirmed_at: str

    def __post_init__(self) -> None:
        if self.role not in OFFERABLE_ROLES:
            raise CommissioningRefused(
                f"{self.role!r} is not a role an operator may confirm; "
                f"offerable roles are {OFFERABLE_ROLES}"
            )
        if not self.composite:
            raise CommissioningRefused(
                "a confirmed role must name the composite identity it binds to"
            )
        if not self.confirmed_by.strip():
            raise CommissioningRefused(
                "a confirmed role must record who confirmed it; a role with no "
                "operator behind it is an inferred role wearing a record"
            )


@dataclass(frozen=True)
class CommissioningRecord:
    """What an operator settled. Read-only to every daemon (§3).

    An empty `roles` tuple is a valid record and means the node is
    commissioned as observe-only: every interface was seen, none was given a
    role. That is different from having no record at all, which means nobody
    has looked.
    """

    roles: tuple[ConfirmedRole, ...]
    profiles_present: tuple[str, ...]
    created_at: str

    @property
    def observe_only(self) -> bool:
        """True while no interface carries a role.

        `IMPLEMENTATION_SPEC.md` §2.3: until commissioning completes the node
        transmits nothing outside the bounded asset-acquisition state. An
        empty record is that state expressed as data.
        """

        return not self.roles

    @property
    def missing_profiles(self) -> tuple[str, ...]:
        return tuple(p for p in REQUIRED_PROFILES if p not in self.profiles_present)

    @property
    def enforcement_ready(self) -> bool:
        """All three profiles present **and** a role confirmed.

        Two conditions, and neither is sufficient. A node with every profile
        and no confirmed interface has nothing to enforce on; a node with a
        confirmed interface and a missing profile has not established what it
        is running on. §2.3 requires both before enforcement is claimed.
        """

        return not self.missing_profiles and bool(self.roles)

    def digest(self) -> str:
        """A digest over what was confirmed, for a generation to name.

        Deterministic: sorted, canonical, no clock. Two nodes that confirmed
        the same bindings produce the same digest, which is what lets a
        generation say *which* commissioning it was rendered from.
        """

        import hashlib
        import json

        payload = {
            "created_at": self.created_at,
            "profiles_present": sorted(self.profiles_present),
            "roles": sorted(
                (
                    {
                        "composite": [list(pair) for pair in role.composite],
                        "role": role.role,
                        "confirmed_by": role.confirmed_by,
                        "confirmed_at": role.confirmed_at,
                    }
                    for role in self.roles
                ),
                key=lambda item: (
                    item["role"],
                    json.dumps(item["composite"], sort_keys=True),
                ),
            ),
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


def confirm_roles(
    proposal: Proposal,
    confirmations: tuple[tuple[InterfaceReadout, str], ...],
    *,
    operator: str,
    at: str,
    profiles_present: tuple[str, ...],
) -> CommissioningRecord:
    """Turn explicit operator confirmations into a record. Infer nothing.

    Every binding must name an interface the proposal offered. An interface
    the proposal refused cannot acquire a role by being passed in here --
    that would route around the ambiguity check rather than resolving it, and
    `docs/commissioning.md` §3 makes zero matches and several matches the same
    answer for exactly that reason.
    """

    offered = {id(readout): readout for readout in proposal.commissionable}
    roles = []
    for readout, role in confirmations:
        if id(readout) not in offered:
            raise CommissioningRefused(
                f"{readout.kernel_name} was not offered for commissioning; "
                f"reasons: {readout.incomplete_reasons or ('not in proposal',)}"
            )
        roles.append(
            ConfirmedRole(
                composite=tuple(sorted(readout.fields.items())),
                role=role,
                confirmed_by=operator,
                confirmed_at=at,
            )
        )

    seen = [role.composite for role in roles]
    if len(set(seen)) != len(seen):
        raise CommissioningRefused(
            "the same interface was confirmed twice; one interface carries one "
            "role, and two confirmations for one adapter is an operator error "
            "rather than a pair of bindings"
        )
    return CommissioningRecord(
        roles=tuple(roles),
        profiles_present=tuple(profiles_present),
        created_at=at,
    )
