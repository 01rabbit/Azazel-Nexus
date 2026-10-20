"""What an operator is shown, and the four things it may never say (#29).

The display is where an honest system most easily becomes a dishonest one,
because every wrong answer here is reassuring. So the report is a structure
with refusals in it rather than a function that formats strings, and the four
prohibitions in issue #29 are each answered by making the wrong statement
unrepresentable rather than by remembering not to write it:

*Enforcement-ready.* There is no field. It is derived from the commissioning
record every time it is read, so a report cannot carry a stale or optimistic
one.

*A module that was not reached.* `ModuleReport` takes a state from an enum,
not a sentence. There is no free text in which "unreachable" could be phrased
as "fine", and every state but `ATTESTED` requires a reason.

*An uncommissioned interface.* `InterfacePresentation` derives its own
readiness from the readout and the record. Its own constructor refuses if the
kernel name appears anywhere in what it would show, because an operator asked
to confirm `enp3s0` is being asked about something they cannot check against
the machine in front of them (`docs/commissioning.md` §4, Nexus#9).

*Degradation.* A report that lists what was lost and nothing that continues is
refused. Losing the remote cognition path and rendering a screen of red is a
node telling its operator it is broken when it is doing its job.

Nothing here reads a clock, a network, or a default route. A status command
that needs connectivity is a status command that is unavailable exactly when
an operator needs to know why they have none.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Mapping, Optional, Sequence

from .capability import CORE_CAPABILITIES, CapabilityState, state_for
from .commissioning import CommissioningRecord, describe_for_operator
from .inventory import InterfaceReadout
from .resource_profile import ResourceProfile, ResourceReading
from .status import StatusClaim, VerificationState

__all__ = [
    "CapabilityReport",
    "HealthReport",
    "InterfacePresentation",
    "ModuleReport",
    "ModuleState",
    "NextAction",
    "OperatorReport",
    "ProfileReport",
    "ReportRefused",
    "build_report",
]


class ReportRefused(Exception):
    """The report was not built. Nothing partial was rendered in its place."""


class ModuleState(str, Enum):
    """What is known about an external module. Four states, no sentences.

    `ABSENT` and `UNREACHABLE` are deliberately distinct. "We looked and it is
    not configured" and "it is configured and we could not reach it" call for
    different operator actions, and collapsing them into one word is how a
    disconnected node comes to read as a quiet one.
    """

    #: Reached and its response verified against a contract. Needs evidence.
    ATTESTED = "attested"
    #: Configured, reached, and nothing was verified about what it said.
    UNVERIFIED = "unverified"
    #: Configured and not reached.
    UNREACHABLE = "unreachable"
    #: Not configured on this node.
    ABSENT = "absent"


#: States that may never be rendered as a working module.
#:
#: Named as a set rather than checked inline so that a fifth state added later
#: has to be classified by whoever adds it.
NOT_WORKING = frozenset(
    {ModuleState.UNVERIFIED, ModuleState.UNREACHABLE, ModuleState.ABSENT}
)


@dataclass(frozen=True)
class ModuleReport:
    """One external module, as this node may describe it."""

    name: str
    state: ModuleState
    reason: Optional[str] = None
    claim: Optional[StatusClaim] = None

    def __post_init__(self) -> None:
        if self.state is not ModuleState.ATTESTED and not (self.reason or "").strip():
            raise ReportRefused(
                f"{self.name} is {self.state.value} and the report says nothing "
                "about why. An unexplained absence reads as agreement"
            )
        if self.state is ModuleState.ATTESTED:
            if self.claim is None:
                raise ReportRefused(
                    f"{self.name} is reported attested with no claim behind it; "
                    "attestation is evidence, not a adjective"
                )
            if self.claim.verification_state is VerificationState.VERIFIED:
                raise ReportRefused(
                    f"{self.name} is another product and cannot be verified "
                    "from here; the strongest available state is observed "
                    "(Nexus#23)"
                )

    @property
    def working(self) -> bool:
        return self.state not in NOT_WORKING


@dataclass(frozen=True)
class InterfacePresentation:
    """One interface as an operator may see it. Never by kernel name.

    `handle` is a selection token for this run, not an identity: an operator
    types it to pick a row, and nothing downstream matches on it. The identity
    a role binds to is the composite one, which is the thing that survives a
    reboot renaming the adapter.
    """

    handle: str
    description: Mapping[str, str]
    commissionable: bool
    role: Optional[str] = None
    blocked_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.description:
            raise ReportRefused(
                f"{self.handle} would be shown with nothing an operator can "
                "check against the machine in front of them; a row they cannot "
                "identify invites a confirmation that means nothing"
            )
        if not self.commissionable and not self.blocked_by:
            raise ReportRefused(
                f"{self.handle} cannot be commissioned and the report does not "
                "say what is missing"
            )

    @property
    def configured(self) -> bool:
        """A role was confirmed against this interface. Nothing weaker."""

        return self.role is not None


@dataclass(frozen=True)
class ProfileReport:
    """The measured RAM and the class it amounts to, or why neither is known."""

    reading: Optional[ResourceReading] = None
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.reading is None and not (self.reason or "").strip():
            raise ReportRefused(
                "no profile was measured and the report says nothing about "
                "why. A default here would be a hardware class asserted on no "
                "measurement"
            )

    @property
    def profile(self) -> Optional[ResourceProfile]:
        return self.reading.profile if self.reading is not None else None


@dataclass(frozen=True)
class CapabilityReport:
    """What is available, what is not, and what continues regardless.

    `retained` is not decoration. Issue #29: a degraded node must show what is
    still working, not only what it lost. A node that lost its remote
    cognition path and renders a screen of red is telling its operator it is
    broken while it is doing its job.

    The invariant that makes that possible is that `retained` is never empty
    for a report that can be built at all -- see `__post_init__` for why that
    follows from the core-capability refusal rather than from a check of its
    own.
    """

    available: frozenset[str]
    lost: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # There is deliberately no separate "lists losses and nothing that
        # continues" branch. `retained` is empty only when `available` is, and
        # an available set missing the core capabilities is refused below --
        # so such a branch would read like the guard for issue #29's
        # degradation rule and never once execute. A guard that cannot run is
        # not a guard, and it would have absorbed the attention owed to the
        # check that does the work: the renderer must print what continues,
        # and `tests/unit/test_wizard_and_cli.py` is where that is enforced.
        missing_core = sorted(CORE_CAPABILITIES - self.available)
        if missing_core:
            raise ReportRefused(
                f"core capabilities are absent: {missing_core}. A core "
                "capability is never sourced from an optional component, so "
                "this is not degradation to display -- it is a broken node"
            )

    @property
    def retained(self) -> tuple[str, ...]:
        return tuple(sorted(self.available))

    @property
    def state(self) -> CapabilityState:
        return state_for(self.available)


@dataclass(frozen=True)
class HealthReport:
    """One checked thing. `healthy=None` means it was not established."""

    subject: str
    healthy: Optional[bool]
    detail: str
    #: A condition that is not a failure but that the operator should act on
    #: (for example an audit capacity warning). Listed under next actions;
    #: it never turns `healthy` false.
    advisory: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.detail.strip():
            raise ReportRefused(
                f"the health of {self.subject!r} is reported with no detail; "
                "a bare green is a claim with nothing behind it"
            )

    @property
    def unknown(self) -> bool:
        return self.healthy is None


@dataclass(frozen=True)
class NextAction:
    """What the operator should do next, concretely."""

    summary: str
    command: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise ReportRefused("a next action must say what to do")


@dataclass(frozen=True)
class OperatorReport:
    """Everything `azazel-nexus status` has to say, and nothing it may invent."""

    profile: ProfileReport
    interfaces: tuple[InterfacePresentation, ...]
    capabilities: CapabilityReport
    modules: tuple[ModuleReport, ...]
    health: tuple[HealthReport, ...]
    record: Optional[CommissioningRecord] = None
    next_actions: tuple[NextAction, ...] = field(default_factory=tuple)

    @property
    def enforcement_ready(self) -> bool:
        """Derived on every read. There is no field to set wrongly.

        Both halves of `IMPLEMENTATION_SPEC.md` §2.3: all three profiles
        confirmed **and** a role confirmed against an interface. A node with
        every profile and no confirmed interface has nothing to enforce on.
        """

        return self.record is not None and self.record.enforcement_ready

    @property
    def unconfigured(self) -> tuple[InterfacePresentation, ...]:
        return tuple(i for i in self.interfaces if not i.configured)


def build_report(
    *,
    readouts: Sequence[InterfaceReadout],
    profile: ProfileReport,
    record: Optional[CommissioningRecord] = None,
    capabilities: CapabilityReport,
    modules: Sequence[ModuleReport] = (),
    health: Sequence[HealthReport] = (),
) -> OperatorReport:
    """Assemble the report and derive the next actions from its own contents.

    The actions are derived rather than passed in, so that a report cannot
    describe a node as needing nothing while carrying an uncommissioned
    interface, a missing profile, or an unverifiable module.
    """

    confirmed = _roles_by_identity(record)
    interfaces = tuple(
        _present(readout, index, confirmed)
        for index, readout in enumerate(readouts, start=1)
    )

    report = OperatorReport(
        profile=profile,
        interfaces=interfaces,
        capabilities=capabilities,
        modules=tuple(modules),
        health=tuple(health),
        record=record,
    )
    # Derived from the finished report rather than from the arguments, so the
    # actions describe what a reader will actually see.
    return replace(report, next_actions=_next_actions(report))


def _roles_by_identity(
    record: Optional[CommissioningRecord],
) -> dict[tuple[tuple[str, str], ...], str]:
    if record is None:
        return {}
    return {role.composite: role.role for role in record.roles}


def _present(
    readout: InterfaceReadout,
    index: int,
    confirmed: Mapping[tuple[tuple[str, str], ...], str],
) -> InterfacePresentation:
    description = describe_for_operator(readout)
    if not description:
        description = {
            "note": "no physically checkable identifier was readable for this "
            "adapter"
        }
    # Built exactly as `confirm_roles` builds it, unfiltered. A presentation
    # that dropped the empty fields would compute a composite that no record
    # contains, and every commissioned interface would render as unconfigured.
    composite = tuple(sorted(readout.fields.items()))
    presentation = InterfacePresentation(
        handle=f"if-{index}",
        description=description,
        commissionable=readout.is_commissionable,
        role=confirmed.get(composite),
        blocked_by=readout.incomplete_reasons,
    )
    _refuse_kernel_name(presentation, readout.kernel_name)
    return presentation


def _refuse_kernel_name(presentation: InterfacePresentation, kernel_name: str) -> None:
    """The kernel name must not reach the screen, by any route.

    Checked against what would be displayed rather than trusted to the
    filtering upstream: `describe_for_operator` excludes it today, and this is
    what notices if a field is ever added that carries it along.
    """

    shown = [presentation.handle, *presentation.description.values()]
    if any(kernel_name == str(value).strip() for value in shown):
        raise ReportRefused(
            f"the kernel name {kernel_name!r} would be shown to an operator. "
            "It is how this boot happened to enumerate the adapter, it is not "
            "checkable against the machine, and a role never binds to it"
        )


def _next_actions(report: OperatorReport) -> tuple[NextAction, ...]:
    actions: list[NextAction] = []

    if report.profile.reading is None:
        actions.append(
            NextAction(
                "No resource profile was measured: " + (report.profile.reason or ""),
                "azazel-nexus profile",
            )
        )

    if report.record is None:
        actions.append(
            NextAction(
                "No operator has confirmed what this node is attached to. "
                "Commission it before anything is activated.",
                "azazel-nexus commission",
            )
        )
    else:
        missing = report.record.missing_profiles
        if missing:
            actions.append(
                NextAction(
                    "Commissioning is incomplete; these profiles are missing: "
                    + ", ".join(missing),
                    "azazel-nexus commission",
                )
            )
        if report.record.observe_only:
            actions.append(
                NextAction(
                    "Every interface was seen and none carries a confirmed "
                    "role. The node observes and enforces nothing.",
                    "azazel-nexus commission",
                )
            )

    unconfigured = [i for i in report.unconfigured if i.commissionable]
    if unconfigured:
        actions.append(
            NextAction(
                "These interfaces can be commissioned and carry no role: "
                + ", ".join(i.handle for i in unconfigured),
                "azazel-nexus commission",
            )
        )

    for interface in report.interfaces:
        if not interface.commissionable:
            actions.append(
                NextAction(
                    f"{interface.handle} cannot be commissioned as read: "
                    + "; ".join(interface.blocked_by)
                )
            )

    # Named separately because it is one cause with one answer, and repeating
    # "permanent_mac could not be read" once per adapter tells an operator
    # what is wrong without telling them anything they can act on.
    if report.interfaces and all(
        any("permanent_mac" in reason for reason in i.blocked_by)
        for i in report.interfaces
    ):
        actions.append(
            NextAction(
                "No interface on this host has a readable permanent MAC, so "
                "none can be commissioned. Reading it requires a privileged "
                "driver query that this build does not perform: see "
                "docs/hardware-gates.md HG-04."
            )
        )

    for check in report.health:
        if check.healthy is False:
            actions.append(NextAction(f"{check.subject}: {check.detail}"))
        elif check.advisory:
            actions.append(NextAction(f"{check.subject}: {check.advisory}"))

    return tuple(actions)
