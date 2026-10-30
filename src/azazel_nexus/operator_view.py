"""What the operator sees after installation, and what they may do next (#99).

This is the one screen. Installer and commissioning UX -- what to ask, what
not to ask, how to keep confirmations apart -- and the state of the catalog
and its artifacts are separate concerns, but they land on the same page, and
building them apart would build two pages.

## Answers that are mechanical are not questions

RAM, disk and the selected profile are read and **shown**, not asked. A
question whose answer is already determined is a question that teaches an
operator their answers do not matter.

## An option that cannot be chosen is shown with its reason

Never removed. A screen where options quietly vanish is a screen where an
operator spends an hour looking for one. Every operation here carries
`available` and a `reason`, and the reason is present whether it is available
or not -- "why yes" is as useful as "why no" when the next step is a
confirmation somebody has to stand behind.

## Every confirmation is its own operation and its own audit transition

Profile, remote opt-in, licence acknowledgement, model import, model
acquisition and provider admission are **separate**. Collapsed into one
"yes", an operator consents to six things believing they consented to one.
Each is its own row here with its own transition, and a new one is added as
a new member rather than folded into an existing one's wording -- which is
how `model acquisition` arrived (#96).

## Three vocabularies that must not merge

`CatalogState` says what the node was told and what it holds:
`absent` / `empty` / `declared` / `present`.

`ProviderState` says whether anything may run: `unavailable` / `not admitted`
/ `not activated`.

They answer different questions and a `present` artifact is routinely
`not admitted`. This module keeps them in separate sections with separate
enums; there is no type here that can hold either.

## Reading this screen does nothing

The view is a **pure function of facts it is handed**. It opens no file,
hashes nothing, fetches nothing, admits nothing and starts nothing, and it
writes no audit event -- not by a guard that could be edited, but because
this module performs no I/O at all. `gather_facts` is the one function that
touches a service, and it may call only an allow-list of read verbs, which
`tests/unit/test_operator_view.py` checks by reading this file's syntax tree.

A screen that changes something when looked at is a screen an operator stops
looking at, and this one is the screen they are meant to consult before every
irreversible step.

## A fact this account could not read is said so

The status read model builds this screen as whichever account runs
`status` -- the read-only UI's `azui` reads none of the model store, the
remote consent or the commissioning proposal (ADR-0007). A fact the caller
could not read is passed as `None` (or `catalog_access` other than `read`),
and the row says *not read* with a code: never `absent`, `empty`, `refused`
or zero, which would each be an answer to a question nobody could ask.

## The provider row follows the admission gates

`ProviderState` is derived from the gates that actually decide admission on
this node (`AdmissionFacts`): the build switch
(`model_admission.LOCAL_MODEL_ADMISSION_ENABLED`, off until the hardware
gates close), the measured Core reserve (HG-05), and what the M.I.O. entry
service last recorded for the local and remote routes. Every gate that
refuses is listed by code (`reason_codes`); none is inferred from a profile
or from an installed artifact.

## The sentence does not move

`STATUS_SENTENCE` is what this build says about M.I.O., on every path through
this module. `fastest-permitted` does not change it, an imported artifact does
not change it, and a node with every prerequisite met does not change it,
because what is missing is hardware evidence (`HG-05`) and a provider
integration -- neither of which a screen can supply.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Sequence

from .model_catalog import CatalogState, ModelReading, Refusal
from .mio_profile import MioProfile, RemoteOptIn, profile_rows
from .resource_profile import (
    PROFILE_ORDER,
    ResourceProfile,
    select_profile,
)
# The floors are the selector's, deliberately imported rather than restated:
# `support-matrix.md` forbids these numbers appearing with different values
# anywhere, and a screen that carried its own copy would be the place they
# first diverged.
from .resource_profile import _FLOORS as _SELECTOR_FLOORS

__all__ = [
    "Confirmation",
    "NodeResources",
    "Operation",
    "OperatorView",
    "Possibility",
    "AdmissionFacts",
    "PROVIDER_REASON_CODES",
    "ProviderState",
    "STATUS_SENTENCE",
    "Section",
    "ViewFacts",
    "build_view",
    "gather_facts",
    "possibilities",
]

#: What this build says about M.I.O., unchanged by anything on this screen.
STATUS_SENTENCE = (
    "M.I.O. routing and commissioning control plane implemented; provider "
    "execution unavailable pending hardware evidence and provider integration"
)

#: The nominal memory classes an operator sees as possibilities. These are
#: the Core reserve's classes -- the selector's three floors -- and not the
#: four that performance and retention targets are recorded against, which
#: include 64 GB. `docs/hardware-gates.md` HG-05 holds why those two counts
#: differ without contradicting.
NOMINAL_CLASS_GIB = (8, 16, 32)


class ProviderState(str, Enum):
    """Whether anything may run. Never what the catalog holds.

    Deliberately disjoint from `CatalogState`: no member is spelled the same,
    so a value of one can never be displayed in the other's row and read as
    an answer to the other's question.
    """

    #: No provider integration is installed on this node.
    UNAVAILABLE = "unavailable"
    #: An admission gate refuses. Which one is a separate fact.
    NOT_ADMITTED = "not admitted"
    #: Admitted and not started. Unreachable in this build.
    NOT_ACTIVATED = "not activated"


class Confirmation(str, Enum):
    """The five things an operator may be asked to stand behind.

    A new thing to consent to is added **here**, where it is visible and
    where it gets its own row, its own reason and its own audit transition --
    never folded into an existing member's wording. `model acquisition`
    arrived that way (#96): downloading gibibytes onto this disk is not
    covered by having consented to route a sanitised question off-node, and a
    member whose text had grown to cover both would have been one consent
    wearing two names.
    """

    PROFILE = "profile"
    REMOTE_OPT_IN = "remote opt-in"
    LICENSE_ACKNOWLEDGEMENT = "license acknowledgement"
    MODEL_IMPORT = "model import"
    MODEL_ACQUISITION = "model acquisition"
    PROVIDER_ADMISSION = "provider admission"


#: The audit transition each confirmation would write **if it were performed**.
#: Naming it on the screen is what makes "these are five separate consents"
#: checkable rather than asserted: five confirmations that wrote one event
#: would be one confirmation with five labels.
TRANSITION_FOR = {
    Confirmation.PROFILE: "mio.profile.commissioned",
    Confirmation.REMOTE_OPT_IN: "mio.remote.opt_in",
    Confirmation.LICENSE_ACKNOWLEDGEMENT: "mio.model.license_acknowledged",
    Confirmation.MODEL_IMPORT: "mio.model.import.promoted",
    Confirmation.MODEL_ACQUISITION: "mio.model.acquisition.planned",
    Confirmation.PROVIDER_ADMISSION: "mio.provider.admitted",
}


@dataclass(frozen=True)
class NodeResources:
    """What was read from the host, for display only.

    Not an admission input. `capability-model.md` §2 is explicit that a
    hardware class is never evidence that a capability fits, and this screen
    is the most likely place for that to be forgotten.
    """

    usable_mib: Optional[int]
    disk_total_mib: Optional[int]
    disk_free_mib: Optional[int]

    @property
    def profile(self) -> Optional[ResourceProfile]:
        if self.usable_mib is None:
            return None
        return select_profile(self.usable_mib)


@dataclass(frozen=True)
class Possibility:
    """What a host of some class would select. A statement about hardware.

    It is not an offer, not a recommendation and not a thing to act on: no
    model is chosen, fetched or started because a class appears here.
    """

    nominal_gib: int
    profile: ResourceProfile
    is_this_node: bool

    def as_row(self) -> dict:
        return {
            "nominal_gib": self.nominal_gib,
            "profile": self.profile.value,
            "is_this_node": self.is_this_node,
            "note": (
                "what a host of this class selects. A class is not evidence "
                "that any capability fits, and nothing is chosen, fetched or "
                "started because it appears here"
            ),
        }


@dataclass(frozen=True)
class Operation:
    """One thing an operator may do next, available or not, always with why."""

    confirmation: Confirmation
    available: bool
    reason: str

    def __post_init__(self) -> None:
        if not str(self.reason).strip():
            raise ValueError(
                "an operation carries a reason whether or not it is available. "
                "An option that is merely absent is one somebody goes looking for"
            )

    @property
    def transition(self) -> str:
        """The audit event performing it would write. Reading writes none."""

        return TRANSITION_FOR[self.confirmation]

    def as_row(self) -> dict:
        return {
            "confirmation": self.confirmation.value,
            "available": self.available,
            "reason": self.reason,
            "transition": self.transition,
        }


@dataclass(frozen=True)
class Section:
    """One block of the screen. Rows are already display-ready."""

    key: str
    title: str
    rows: tuple

    def as_document(self) -> dict:
        return {"key": self.key, "title": self.title, "rows": [dict(r) for r in self.rows]}


#: Why a provider is not admitted, one code per gate that refuses.
PROVIDER_REASON_CODES = frozenset({
    "admission_switched_off_in_build",   # LOCAL_MODEL_ADMISSION_ENABLED is False
    "core_reserve_unmeasured",           # HG-05: no measured reserve record
    "core_reserve_unread",               # the record could not be read here
    "local_not_admitted", "local_no_admission_evidence", "local_unavailable",
    "local_observation_invalid",         # entryd's recorded local route
    "admission_record_unread",           # entryd's record could not be read here
})


@dataclass(frozen=True)
class AdmissionFacts:
    """The admission gates as read, for the provider row. Display only.

    `build_enabled` is the build switch; `local` is the local route's health
    reason as the M.I.O. entry service last recorded it (`not_admitted`,
    `no_admission_evidence`, `unavailable`, `invalid_observation`), or
    `None` when that record could not be read by this account.
    """

    build_enabled: bool
    local: Optional[str]


@dataclass(frozen=True)
class ViewFacts:
    """Everything the screen is built from, read by the caller.

    Gathered once and passed in, so that building the view cannot read
    anything -- see the module docstring.
    """

    #: `None`: the commissioned ceiling could not be read by this account.
    profile: Optional[MioProfile]
    #: `None`: the remote consent record could not be read by this account.
    opt_in: Optional[RemoteOptIn]
    #: `None`: the Core reserve record could not be read by this account.
    reserve_measured: Optional[bool]
    resources: NodeResources
    catalog_state: CatalogState
    #: Per model, what this node holds. Empty when the catalog is absent.
    readings: tuple
    #: Inbox entries awaiting an operator, by display name.
    inbox: tuple
    quarantined: int
    installed: Mapping[str, str]
    #: The generation that a rollback would restore, or `None` when none.
    rollback_target: Optional[int]
    #: `read`, or why the model store was not read (`permission_denied`,
    #: `refused`). Anything but `read` and the catalog, import and their
    #: operations say "not read" rather than absent, empty or zero.
    catalog_access: str = "read"
    #: The admission gates, when the caller read them (`AdmissionFacts`).
    admission: Optional[AdmissionFacts] = None


@dataclass(frozen=True)
class OperatorView:
    """The screen. A value, produced by a pure function, that writes nothing."""

    sections: tuple
    operations: tuple
    status_sentence: str = STATUS_SENTENCE

    def operation(self, confirmation: Confirmation) -> Operation:
        for operation in self.operations:
            if operation.confirmation is confirmation:
                return operation
        raise KeyError(confirmation)

    def section(self, key: str) -> Section:
        for section in self.sections:
            if section.key == key:
                return section
        raise KeyError(key)

    def as_document(self) -> dict:
        return {
            "status_sentence": self.status_sentence,
            "sections": [section.as_document() for section in self.sections],
            "operations": [operation.as_row() for operation in self.operations],
        }


#: The only methods `gather_facts` may call on a service. Read verbs, checked
#: by a test that reads this module's syntax tree rather than trusting the
#: name of the function it is in.
READ_ONLY_VERBS = (
    "current_generation",
    "list_inbox",
    "reading_for",
)


def gather_facts(
    service,
    *,
    profile: MioProfile,
    opt_in: RemoteOptIn,
    reserve_measured: bool,
    resources: NodeResources,
    model_ids: Sequence[str] = (),
    quarantined: int = 0,
) -> ViewFacts:
    """Read the node through `service`, calling read verbs and nothing else.

    `model_ids` comes from the caller rather than from an enumeration here:
    which models to show is a display decision, and a screen that enumerated
    a catalog would have to read one.
    """

    readings = tuple(service.reading_for(model_id) for model_id in model_ids)
    generation = service.current_generation()
    inbox = tuple(entry.display_name for entry in service.list_inbox())
    catalog_state = readings[0].state if readings else CatalogState.ABSENT
    if readings and all(r.state is CatalogState.ABSENT for r in readings):
        catalog_state = CatalogState.ABSENT
    elif readings:
        # The strongest thing the node holds, so that one unknown model does
        # not make a stocked node look empty.
        order = (
            CatalogState.ABSENT,
            CatalogState.EMPTY,
            CatalogState.DECLARED,
            CatalogState.PRESENT,
        )
        catalog_state = max((r.state for r in readings), key=order.index)
    return ViewFacts(
        profile=profile,
        opt_in=opt_in,
        reserve_measured=reserve_measured,
        resources=resources,
        catalog_state=catalog_state,
        readings=readings,
        inbox=inbox,
        quarantined=quarantined,
        installed=dict(generation.installed) if generation else {},
        rollback_target=(
            generation.number - 1
            if generation is not None and generation.number > 1
            else None
        ),
    )


def build_view(facts: ViewFacts) -> OperatorView:
    """The screen, from facts. Reads nothing, writes nothing, decides nothing."""

    return OperatorView(
        sections=(
            _cognition_section(facts),
            _resources_section(facts),
            _catalog_section(facts),
            _import_section(facts),
        ),
        operations=_operations(facts),
    )


# -- sections --------------------------------------------------------------


def _cognition_section(facts: ViewFacts) -> Section:
    """Profile, consent and admission as three facts, never one word."""

    if None in (facts.profile, facts.opt_in, facts.reserve_measured):
        rows = [
            {"axis": "mio_profile",
             "value": facts.profile.value if facts.profile is not None else None,
             "reason": ("the ceiling on what route selection may consider; it admits "
                        "nothing by itself") if facts.profile is not None
             else "the commissioned ceiling was not read by this account",
             **({} if facts.profile is not None else {"reason_code": "not_read"})},
            {"axis": "mio_remote_consent",
             "value": None if facts.opt_in is None else (
                 "permitted" if facts.opt_in.active()
                 else ("withdrawn" if facts.opt_in.withdrawn else "not-given")),
             "reason": "the remote consent record was not read by this account"
             if facts.opt_in is None else facts.opt_in.reason(),
             **({"reason_code": "not_read"} if facts.opt_in is None else {})},
        ]
    else:
        rows = [row for row in profile_rows(
            profile=facts.profile,
            opt_in=facts.opt_in,
            reserve_measured=facts.reserve_measured,
        ) if row["axis"] != "mio_provider_admission"]
    rows.append(
        {
            "axis": "provider_state",
            "value": _provider_state(facts).value,
            "reason": _provider_reason(facts),
            "reason_codes": list(_provider_codes(facts)),
        }
    )
    rows.append({"axis": "mio_summary", "value": STATUS_SENTENCE, "reason": ""})
    return Section("cognition", "M.I.O.", tuple(rows))


def _resources_section(facts: ViewFacts) -> Section:
    """Read and shown, never asked -- and never an admission input."""

    resources = facts.resources
    profile = resources.profile
    rows = [
        {
            "axis": "usable_memory_mib",
            "value": resources.usable_mib,
            "reason": "what the OS reports, read once and displayed",
        },
        {
            "axis": "resource_profile",
            "value": profile.value if profile else None,
            "reason": (
                "the hardware class this node selects. A class is never "
                "evidence that a capability fits (capability model §2)"
            ),
        },
        {
            "axis": "disk_total_mib",
            "value": resources.disk_total_mib,
            "reason": "displayed; an import checks free space for itself",
        },
        {
            "axis": "disk_free_mib",
            "value": resources.disk_free_mib,
            "reason": "displayed; an import checks free space for itself",
        },
    ]
    rows.extend(p.as_row() for p in possibilities(resources))
    return Section("resources", "Resources", tuple(rows))


def _catalog_section(facts: ViewFacts) -> Section:
    """`absent` / `empty` / `declared` / `present` -- and nothing else."""

    if facts.catalog_access != "read":
        return Section("catalog", "Catalog", ({
            "axis": "catalog_state", "value": None,
            "reason": _unread_store_reason(facts.catalog_access),
            "reason_code": "catalog_" + facts.catalog_access,
        },))
    rows = [
        {
            "axis": "catalog_state",
            "value": facts.catalog_state.value,
            "reason": _catalog_reason(facts.catalog_state),
        }
    ]
    for reading in facts.readings:
        rows.append(
            {
                "axis": "model",
                "model_id": reading.model_id,
                "value": reading.state.value,
                "refused_by": (
                    reading.refused_by.value if reading.refused_by else None
                ),
                "reason": reading.reason,
                # Spelled out rather than left to inference, because this is
                # the pair the screen exists to keep apart.
                "admitted": False,
            }
        )
    return Section("catalog", "Catalog", tuple(rows))


def _unread_store_reason(access: str) -> str:
    if access == "permission_denied":
        return "the model store was not read by this account"
    # Refused (unsigned, invalid, unreadable): never "not presented" (R389-06).
    return ("the catalog was refused; nothing from it is shown, and it is not "
            "shown as absent")


def _import_section(facts: ViewFacts) -> Section:
    if facts.catalog_access != "read":
        return Section("import", "Offline import", tuple(
            {"axis": axis, "value": None,
             "reason": _unread_store_reason(facts.catalog_access),
             "reason_code": "catalog_" + facts.catalog_access}
            for axis in ("inbox", "quarantine", "promoted", "rollback_target")))
    rows = [
        {
            "axis": "inbox",
            "value": len(facts.inbox),
            "entries": list(facts.inbox),
            "reason": "artifacts an operator has placed; listing reads none of them",
        },
        {
            "axis": "staging",
            "value": 0,
            "reason": (
                "staging holds nothing between imports; anything found there "
                "is debris and is swept when the next import starts"
            ),
        },
        {
            "axis": "quarantine",
            "value": facts.quarantined,
            "reason": (
                "held and nothing else: never executed, extracted, served or "
                "retried"
            ),
        },
        {
            "axis": "promoted",
            "value": len(facts.installed),
            "entries": sorted(facts.installed),
            "reason": (
                "installed in the current generation. Installed is not "
                "admitted and not activated"
            ),
        },
        {
            "axis": "rollback_target",
            "value": facts.rollback_target,
            "reason": (
                "the generation a rollback would restore, retained for that "
                "purpose"
                if facts.rollback_target is not None
                else "no earlier generation is retained, so there is nothing to restore"
            ),
        },
    ]
    return Section("import", "Offline import", tuple(rows))


# -- operations ------------------------------------------------------------


def _operations(facts: ViewFacts) -> tuple:
    return (
        Operation(
            confirmation=Confirmation.PROFILE,
            available=True,
            reason=(
                "an operator may set the ceiling at any time. It admits "
                "nothing by itself"
            ),
        ),
        _remote_operation(facts),
        _license_operation(facts),
        _import_operation(facts),
        _acquisition_operation(facts),
        _admission_operation(facts),
    )


def _remote_operation(facts: ViewFacts) -> Operation:
    if facts.profile is None or facts.opt_in is None:
        return Operation(
            confirmation=Confirmation.REMOTE_OPT_IN,
            available=False,
            reason=("not shown: the profile or the remote consent was not read by "
                    "this account. Run azazel-nexus status as root on the terminal"),
        )
    if facts.profile in (MioProfile.CORE, MioProfile.REMOTE_DISABLED):
        return Operation(
            confirmation=Confirmation.REMOTE_OPT_IN,
            available=False,
            reason=(
                f"the profile is {facts.profile.value}, which excludes the "
                "remote route regardless of consent. Widening the profile is "
                "a separate confirmation"
            ),
        )
    if facts.opt_in.active():
        return Operation(
            confirmation=Confirmation.REMOTE_OPT_IN,
            available=True,
            reason="given, and revocable at any time with immediate effect",
        )
    return Operation(
        confirmation=Confirmation.REMOTE_OPT_IN,
        available=True,
        reason=facts.opt_in.reason(),
    )


def _license_operation(facts: ViewFacts) -> Operation:
    if facts.catalog_access != "read":
        return _unread_store_operation(Confirmation.LICENSE_ACKNOWLEDGEMENT, facts.catalog_access)
    waiting = [
        r.model_id
        for r in facts.readings
        if r.refused_by is Refusal.LICENSE_NOT_ACKNOWLEDGED
    ]
    if waiting:
        return Operation(
            confirmation=Confirmation.LICENSE_ACKNOWLEDGEMENT,
            available=True,
            reason=f"{sorted(waiting)} require an acknowledgement before import",
        )
    return Operation(
        confirmation=Confirmation.LICENSE_ACKNOWLEDGEMENT,
        available=False,
        reason="no model shown here is waiting on an acknowledgement",
    )


def _unread_store_operation(confirmation: Confirmation, access: str) -> Operation:
    if access != "permission_denied":
        return Operation(confirmation=confirmation, available=False,
                         reason=("not available: the catalog was refused. Inspect it on the "
                                 "terminal before any import"))
    return Operation(
        confirmation=confirmation,
        available=False,
        reason=("not shown: the model store was not read by this account. Run "
                "azazel-nexus status as root on the terminal"),
    )


def _import_operation(facts: ViewFacts) -> Operation:
    if facts.catalog_access != "read":
        return _unread_store_operation(Confirmation.MODEL_IMPORT, facts.catalog_access)
    if facts.catalog_state is CatalogState.ABSENT:
        return Operation(
            confirmation=Confirmation.MODEL_IMPORT,
            available=False,
            reason=(
                "no catalog has been presented, so there is no model an "
                "operator could select. A catalog is not the same as an empty one"
            ),
        )
    if facts.catalog_state is CatalogState.EMPTY:
        return Operation(
            confirmation=Confirmation.MODEL_IMPORT,
            available=False,
            reason="the catalog is trusted and offers nothing",
        )
    if not facts.inbox:
        return Operation(
            confirmation=Confirmation.MODEL_IMPORT,
            available=False,
            reason=(
                "the catalog declares a model and the inbox is empty. An "
                "operator places the artifact; nothing fetches it"
            ),
        )
    return Operation(
        confirmation=Confirmation.MODEL_IMPORT,
        available=True,
        reason=f"{len(facts.inbox)} artifact(s) placed and a catalog that declares a model",
    )


def _acquisition_operation(facts: ViewFacts) -> Operation:
    """Unavailable: no acquisition path is commissioned/startable on this node."""

    return Operation(
        confirmation=Confirmation.MODEL_ACQUISITION,
        available=False,
        reason=(
            "no acquisition path is commissioned/startable on this node. "
            "It is absent rather than switched off. "
            "The offline import route is unaffected: install from an operator's media"
        ),
    )


def _admission_operation(facts: ViewFacts) -> Operation:
    """Never available in this build, and the profile does not change that."""

    return Operation(
        confirmation=Confirmation.PROVIDER_ADMISSION,
        available=False,
        reason=_provider_reason(facts),
    )


def _provider_codes(facts: ViewFacts) -> tuple:
    """Every admission gate that refuses, by code. Empty only if none does."""

    codes = []
    admission = facts.admission
    if admission is not None and not admission.build_enabled:
        codes.append("admission_switched_off_in_build")
    if facts.reserve_measured is None:
        codes.append("core_reserve_unread")
    elif not facts.reserve_measured:
        codes.append("core_reserve_unmeasured")
    if admission is not None:
        if admission.local is None:
            codes.append("admission_record_unread")
        elif admission.local in ("not_admitted", "no_admission_evidence", "unavailable"):
            codes.append("local_" + admission.local)
        else:
            codes.append("local_observation_invalid")
    return tuple(codes)


def _provider_state(facts: ViewFacts) -> ProviderState:
    if _provider_codes(facts) or facts.admission is None:
        # Without the gates read, admission is never claimed: a reserve
        # alone admits nothing.
        return ProviderState.NOT_ADMITTED
    # Every gate read and none refusing: admitted, not started by this screen.
    return ProviderState.NOT_ACTIVATED


def _provider_reason(facts: ViewFacts) -> str:
    codes = _provider_codes(facts)
    if "core_reserve_unmeasured" in codes:
        return (
            "the resource gate refuses for want of a measured Core reserve "
            "(HG-05). This holds on every profile: selecting "
            f"{MioProfile.FASTEST_PERMITTED.value} does not admit a provider, "
            "and M.I.O. is not functional"
        )
    if "admission_switched_off_in_build" in codes:
        return (
            "local model admission is switched off in this build until the "
            "hardware gates close; no provider is admitted"
        )
    if codes:
        return "an admission gate refuses or could not be read; no provider is admitted"
    if facts.admission is None:
        return (
            "a measured reserve is not an admission: the admission gates were not "
            "read, so no provider is shown as admitted"
        )
    return "every admission gate read passes; nothing on this screen starts a provider"


def _catalog_reason(state: CatalogState) -> str:
    return {
        CatalogState.ABSENT: "no catalog has been presented; the node was told nothing",
        CatalogState.EMPTY: "a trusted catalog offers nothing. Different from absent",
        CatalogState.DECLARED: "a trusted catalog names a model; no artifact is verified",
        CatalogState.PRESENT: (
            "an artifact matches its declaration. Present is not admitted and "
            "not activated"
        ),
    }[state]


def possibilities(resources: NodeResources) -> tuple:
    """What each memory class selects, with this node's class marked.

    Derived from the selector's own floors, so a floor that moves moves this
    display with it rather than leaving a second set of numbers behind.
    """

    selected = resources.profile
    rows = []
    for nominal in NOMINAL_CLASS_GIB:
        floor = _floor_for(nominal)
        profile = select_profile(floor) if floor is not None else PROFILE_ORDER[0]
        rows.append(
            Possibility(
                nominal_gib=nominal,
                profile=profile,
                is_this_node=selected is not None and profile is selected,
            )
        )
    return tuple(rows)


def _floor_for(nominal_gib: int):
    """The selector floor a host of this nominal class clears, if any."""

    target = nominal_gib * 1024
    for floor, _profile in _SELECTOR_FLOORS:
        if floor <= target:
            return floor
    return None
