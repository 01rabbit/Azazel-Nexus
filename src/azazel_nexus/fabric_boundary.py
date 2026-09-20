"""The only place Azazel-Nexus imports `azazel_fabric` (ADR-0001).

Fabric is pinned to exactly one verified tag and consumed through this module
alone. Containing the import in one file is what makes its absence a bounded,
testable condition instead of an import error somewhere unpredictable;
`tests/unit/test_boundary_static.py` scans the package and fails if a second
import site appears.

Fabric is an **optional extra**, never a dependency. Nexus must be useful as
`CORE` with no external Knowledge, no Deception, no remote cognition and no
cloud connectivity, and a `CORE` path that fails when a contract library is
missing is not a `CORE` path. So every failure mode here returns a `Projection`
marked unavailable with a reason, and nothing propagates an exception to a
caller that only wanted to know what this node can currently do.

Three things this module structurally cannot do
-----------------------------------------------
*It cannot raise a capability.* A projection renders
`capability.CapabilityState` and the capability set it was handed. It adds no
capability, and it never writes back into what it was given. Whether Fabric is
present changes how the state can be *shown*, and nothing about what is true.

*It cannot issue an enforcement intent.* `StatusView.current_action` carries
`ActionIntent` — an enforcement intent issued by an arbiter. Nexus integrates
released components without creating another decision authority, so this module
leaves that field `None` in every case and a test pins that it does.

*It cannot report a capability state as an operating mode.* `ModeState.name`
is the series' operating-mode vocabulary (`portal`, `shield`, `scapegoat`,
`observe`, `lockdown`) and those are Azazel-Edge's modes. `CORE` / `LITE` /
`FULL` are capability states, which is a different question with a different
owner — publishing one as the other is the confusion Nexus#OF-04 already had to
correct once. The capability state travels in `product_view`, Nexus's own
namespace, and a test refuses it anywhere in `mode`.

Interface identity, and why the rules are not restated here
-----------------------------------------------------------
`azazel_nexus.inventory` reads a host's interfaces into plain mappings and
never defines a record for one. This module turns a readout into Fabric's
`InterfaceIdentity`, and answers "which interface does this selector mean?"
by calling Fabric's `resolve_interface_assignment` rather than implementing
the rule again.

That matters more than it looks. `docs/commissioning.md` §3 states the rule --
exactly one match identifies, zero and several are the same fail-closed answer
-- and Fabric's resolver states it too. A third statement in Nexus would be a
third thing to keep in step, and the series has already paid for that: two
products each kept an independent copy of `outcome_contracts`' rules and both
were missing the same two keys Fabric had added.

What a present Fabric does and does not prove
---------------------------------------------
A successful projection attests **one** mapping in
`docs/contract-ownership.md` §3.1 — capability/mode publication through
`ModeState` / `StatusView`. It attests nothing about the other rows, and a
module existing in the pinned tag is not evidence that any mapping onto it
holds. `PLANNED_FABRIC_MODULES` below is a presence probe for the families §3
maps, reported and never assumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from azazel_nexus.capability import CapabilityState
from azazel_nexus.inventory import InterfaceReadout

__all__ = [
    "FABRIC_PIN",
    "PLANNED_FABRIC_MODULES",
    "REQUIRED_FABRIC_MODULES",
    "IdentityUnavailable",
    "InventoryProjection",
    "Projection",
    "CONFIRMATION_METHODS",
    "CommissioningRecordUnavailable",
    "confirm_role",
    "identify_interface",
    "inventory_digest",
    "project_capability",
    "project_interface_identity",
    "project_inventory",
]


class IdentityUnavailable(Exception):
    """An interface identity could not be produced, and why.

    Distinct from Fabric's own resolution error: this one means Nexus could
    not build the record at all, because the host did not give up the facts or
    because Fabric is absent. Collapsing the two would make "we never read it"
    indistinguishable from "we read it and it matched nothing".
    """

#: The exact tag this module is written against (ADR-0001). No branch pin, no
#: submodule, no copied source. `v0.9.0rc2` is the newest published candidate
#: and it is signed; Azazel-Edge, Azazel-Deception and Azazel-Knowledge are all
#: on it. A release candidate is still an exact tag — it promises no
#: stability, so this moves to `v0.9.0` when Fabric cuts it.
FABRIC_PIN = "v0.9.0rc2"

#: What this module needs to produce a projection at all.
REQUIRED_FABRIC_MODULES = ("azazel_fabric.view", "azazel_fabric.schema.mode")

#: Fabric families that `docs/contract-ownership.md` §3 maps Nexus records onto
#: and that no Nexus code consumes yet. Listed because an unmet requirement is
#: only trackable while something names it: §2 asserted for months that two of
#: these did not exist in Fabric, after they did.
PLANNED_FABRIC_MODULES = (
    "azazel_fabric.cti_contracts",
    "azazel_fabric.deception_contracts",
    "azazel_fabric.mio_contracts",
    "azazel_fabric.provisioning_contracts",
)

#: A constant, not a clock read. This module produces the same bytes for the
#: same input, so its output can be compared across runs and machines; a
#: timestamp would make every projection differ from every other for a reason
#: that has nothing to do with the node.
_FIXED_INSTANT = "1970-01-01T00:00:00Z"

#: Nexus holds no operating mode. `ModeState.name` is required, so the
#: projection names the absence rather than picking one of Edge's modes.
_MODE_NAME = "not_operational"
_MODE_REASON = (
    "Azazel-Nexus holds no operating mode; Azazel-Edge's deterministic arbiter "
    "does. This field names that absence rather than claiming one of Edge's modes."
)

#: Likewise for defensive posture, which is Edge's to report.
_POSTURE = "unknown"


@dataclass(frozen=True)
class Projection:
    """The outcome of rendering Nexus's capability state through Fabric."""

    available: bool
    #: Why a projection could not be produced. Empty exactly when available.
    reason: str
    #: Fabric's own version string when it could be read, else None.
    fabric_version: str | None = None
    #: The projected view, when one was produced. Deliberately typed `Any`:
    #: this module must import cleanly with Fabric absent, so it cannot name a
    #: Fabric type in an annotation evaluated at import time.
    view: Any = None
    #: Mapped-but-unconsumed families the pinned tag does not provide.
    #: Reported, never treated as an error: `CORE` does not need them.
    missing_planned: tuple[str, ...] = ()


def _import_fabric() -> tuple[Any | None, str]:
    try:
        import azazel_fabric  # noqa: PLC0415 -- deliberately deferred
    except ImportError as exc:
        return None, f"azazel_fabric is not installed ({exc})"
    return azazel_fabric, ""


def _missing_planned() -> tuple[str, ...]:
    import importlib.util  # noqa: PLC0415

    missing = []
    for name in PLANNED_FABRIC_MODULES:
        try:
            if importlib.util.find_spec(name) is None:
                missing.append(name)
        except (ImportError, ValueError):
            missing.append(name)
    return tuple(missing)


def project_capability(
    state: CapabilityState, available: frozenset[str] | set[str] | None = None
) -> Projection:
    """Render a capability state through Fabric's shared view model, if present.

    Returns a `Projection` in every case. A caller that needs the truth about
    this node reads `capability`; this is only how that truth can be shown
    alongside the other Azazel products.
    """

    capabilities = tuple(sorted(available or ()))

    fabric, failure = _import_fabric()
    if fabric is None:
        return Projection(available=False, reason=failure)

    version = getattr(fabric, "__version__", None)

    try:
        from azazel_fabric.schema.mode import ModeState  # noqa: PLC0415
        from azazel_fabric.view import StatusView  # noqa: PLC0415
    except ImportError as exc:
        return Projection(
            available=False,
            reason=f"a required Fabric module is unavailable at the pinned tag ({exc})",
            fabric_version=version,
            missing_planned=_missing_planned(),
        )

    try:
        view = StatusView(
            schema_version="1.0",
            product="Azazel-Nexus",
            generated_at=_FIXED_INSTANT,
            mode=ModeState(
                name=_MODE_NAME, since=_FIXED_INSTANT, reason=_MODE_REASON
            ),
            posture=_POSTURE,
            headline=f"Azazel-Nexus capability state: {state.value}",
            reasons=[f"capability: {name}" for name in capabilities],
            # Left empty on purpose. Nexus issues no enforcement intent.
            next_actions=[],
            health=[],
            evidence_ids=[],
            product_view={
                # Nexus's own namespace. The capability state lives here and
                # not in `mode`, because a capability state is not an
                # operating mode and must not be readable as one.
                "capability_state": state.value,
                "capabilities": list(capabilities),
                "authority": [],
                "authority_note": (
                    "Azazel-Nexus holds no decision or enforcement authority in "
                    "any capability state."
                ),
            },
        )
    except Exception as exc:  # noqa: BLE001 -- a projection must not crash a caller
        # Fabric's models may tighten between tags. A view Nexus cannot build
        # is a presentation problem, never a correctness one: the node's own
        # capability state is unchanged and is what a caller should read.
        return Projection(
            available=False,
            reason=f"projection failed against the pinned tag ({type(exc).__name__}: {exc})",
            fabric_version=version,
            missing_planned=_missing_planned(),
        )

    return Projection(
        available=True,
        reason="",
        fabric_version=version,
        view=view,
        missing_planned=_missing_planned(),
    )


@dataclass(frozen=True)
class InventoryProjection:
    """Which interfaces became identities, and which could not, with reasons.

    The refusals travel with the result rather than being dropped. An inventory
    that silently omitted the interfaces it could not identify would read as a
    complete inventory of a smaller machine, and an operator would have no way
    to tell that the adapter they are looking for was seen and discarded.
    """

    available: bool
    reason: str
    identities: tuple[Any, ...] = ()
    #: `(kernel_name, reasons)` for each interface no role may be confirmed
    #: against. Every one of these is a `COMMISSIONING_REQUIRED` answer.
    refused: tuple[tuple[str, tuple[str, ...]], ...] = ()


def _interface_key(identity: Any) -> str:
    """A stable key for one identity, derived from the identity itself.

    Built from Fabric's own `interface_composite_key`, so the key cannot
    disagree with the tuple Fabric matches on: anything that would change which
    interface a selector resolves to changes the key too. The kernel name is
    excluded because that function excludes it.
    """

    import hashlib  # noqa: PLC0415
    from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
        interface_composite_key,
    )

    material = "\x1f".join("" if part is None else str(part)
                           for part in interface_composite_key(identity))
    return "if-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def project_interface_identity(readout: InterfaceReadout) -> Any:
    """Render one readout as `InterfaceIdentity`, or refuse and say why.

    An incomplete readout is refused rather than filled in. Fabric requires a
    `driver` this host may not expose and an identity Nexus may not have read,
    and any plausible default here would let a role be confirmed against an
    identity nobody established -- which is the one thing
    `docs/commissioning.md` §3 exists to prevent.
    """

    if readout.incomplete_reasons:
        raise IdentityUnavailable(
            f"{readout.kernel_name}: {'; '.join(readout.incomplete_reasons)}"
        )

    fabric, failure = _import_fabric()
    if fabric is None:
        raise IdentityUnavailable(failure)
    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            InterfaceIdentity,
        )
    except ImportError as exc:
        raise IdentityUnavailable(
            f"provisioning_contracts is unavailable at the pinned tag ({exc})"
        ) from exc

    fields = dict(readout.fields)
    driver = fields.pop("driver", None)
    if not driver:
        raise IdentityUnavailable(
            f"{readout.kernel_name}: Fabric's identity requires a driver name "
            "and this host exposed none"
        )

    partial = InterfaceIdentity(
        interface_key="if-pending",
        driver=driver,
        driver_version=readout.driver_version,
        kernel_name_observed=readout.kernel_name,
        **fields,
    )
    return partial.model_copy(update={"interface_key": _interface_key(partial)})


def project_inventory(readouts: Sequence[InterfaceReadout]) -> InventoryProjection:
    """Project a whole inventory, keeping the refusals."""

    fabric, failure = _import_fabric()
    if fabric is None:
        return InventoryProjection(available=False, reason=failure)

    identities: list[Any] = []
    refused: list[tuple[str, tuple[str, ...]]] = []
    for readout in readouts:
        try:
            identities.append(project_interface_identity(readout))
        except IdentityUnavailable as exc:
            reasons = readout.incomplete_reasons or (str(exc),)
            refused.append((readout.kernel_name, reasons))
    return InventoryProjection(
        available=True,
        reason="",
        identities=tuple(identities),
        refused=tuple(refused),
    )


def identify_interface(identities: Sequence[Any], selector: Any) -> Any:
    """Return the one interface a composite selector means. Fail closed.

    The rule -- exactly one identifies, zero and several are the same answer --
    is **Fabric's**, applied by calling its resolver. Nexus does not implement
    it here, does not wrap it in a softer one, and does not add a fallback:
    `docs/commissioning.md` §3 says the node refuses to choose, and a resolver
    that picked the first of several would be that fallback.

    Raises Fabric's `InterfaceResolutionError` for a selector that is not
    composite, matches nothing, or matches more than one.
    """

    fabric, failure = _import_fabric()
    if fabric is None:
        raise IdentityUnavailable(failure)
    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            resolve_interface_assignment,
        )
    except ImportError as exc:
        raise IdentityUnavailable(
            f"provisioning_contracts is unavailable at the pinned tag ({exc})"
        ) from exc

    return resolve_interface_assignment(
        {"interfaces": tuple(identities)}, {"selector": selector}
    )


#: How an operator may confirm a role, as Fabric registers it.
#:
#: Mirrored for the same reason the role list is, and pinned by the same kind
#: of test. Every one of these describes a person doing something physical or
#: signing something; none of them can be satisfied by the node observing
#: itself, which is what keeps confirmation a human act.
CONFIRMATION_METHODS = (
    "physical_port_label_confirmed",
    "port_identify_blink_confirmed",
    "operator_console_confirmed",
    "signed_site_approval",
)


class CommissioningRecordUnavailable(Exception):
    """Nexus cannot yet produce the record Fabric describes, and why."""


def inventory_digest(identities: Sequence[Any]) -> str:
    """The digest an assignment cites, computed by Fabric over Fabric's records.

    An assignment names the inventory it was confirmed against, so that a
    record made on one machine cannot be read as describing another. The digest
    is over the projected `InterfaceIdentity` records in a fixed order -- not
    over the local readouts -- because the identities are what the assignment's
    selector matches against, and a digest of something else would vouch for
    the wrong thing.

    It covers **the composite identity and nothing else**, via Fabric's own
    `interface_composite_key` -- the same tuple a selector matches on.

    That is narrower than it first looks, and the narrowing is the point. The
    obvious implementation digests the whole `InterfaceIdentity`, which carries
    `kernel_name_observed`; a kernel rename would then change the inventory
    digest, every assignment citing it would read as stale, and the node would
    ask for re-commissioning because an interface got a different name. That is
    the rebinding-by-name failure `docs/commissioning.md` §3 exists to prevent,
    reintroduced through the back door. (It was the first implementation here,
    and a test caught it.)

    `driver_version` is excluded for the same reason: it is not a composite
    identity field, so a driver update must not invalidate a commissioning.
    `firmware_version` *is* one, so a firmware change does -- which §3 states.

    Sorted by the tuple itself, so the order cannot move when a name does.
    """

    fabric, failure = _import_fabric()
    if fabric is None:
        raise IdentityUnavailable(failure)
    from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
        COMPOSITE_IDENTITY_FIELDS,
        content_digest,
        interface_composite_key,
    )

    covered = [
        dict(zip(COMPOSITE_IDENTITY_FIELDS, interface_composite_key(identity)))
        for identity in identities
    ]
    ordered = sorted(
        covered,
        key=lambda payload: tuple(
            "" if value is None else value for value in payload.values()
        ),
    )
    return content_digest({"interfaces": ordered})


def confirm_role(
    readout: InterfaceReadout,
    *,
    role: str,
    node_id: str,
    operator_ref: str,
    method: str,
    confirmed_at: str,
    inventory_digest: str,
    evidence_refs: Sequence[str] = (),
) -> Any:
    """Record that an operator confirmed one role against one interface.

    Every argument is required and none has a default. That is the whole
    design: a confirmation Nexus could produce without being told who
    confirmed, how, and when is a confirmation Nexus made on the operator's
    behalf, and `docs/commissioning.md` §4 exists to forbid exactly that.

    The selector is built from the interface's composite identity, so what the
    assignment refers to is the physical adapter rather than the name it had
    when the operator was looking at it.
    """

    fabric, failure = _import_fabric()
    if fabric is None:
        raise IdentityUnavailable(failure)
    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            InterfaceAssignment,
            InterfaceIdentitySelector,
            OperatorConfirmation,
            assert_no_role_inference,
        )
    except ImportError as exc:
        raise IdentityUnavailable(
            f"provisioning_contracts is unavailable at the pinned tag ({exc})"
        ) from exc

    identity = project_interface_identity(readout)

    selector = InterfaceIdentitySelector(
        **{
            name: getattr(identity, name)
            for name in InterfaceIdentitySelector.model_fields
            if name != "schema_version"
        }
    )
    assignment = InterfaceAssignment(
        assignment_id=f"assignment:{identity.interface_key.removeprefix('if-')}.{role}",
        node_id=node_id,
        role=role,
        selector=selector,
        inventory_digest=inventory_digest,
        confirmation=OperatorConfirmation(
            operator_ref=operator_ref,
            method=method,
            confirmed_at=confirmed_at,
            evidence_refs=tuple(evidence_refs),
        ),
        assigned_at=confirmed_at,
    )
    # Fabric refuses the concepts §4 forbids by name. Nothing here supplies
    # one, so this can only ever pass -- which is the point of running it: it
    # is what would notice if something started to.
    assert_no_role_inference(assignment.model_dump(mode="json"))
    return assignment


def build_commissioning_record(**_fields: Any) -> Any:
    """Refused. Nexus cannot produce this record honestly yet.

    `CommissioningRecord` requires three digests -- `hardware_inventory_digest`,
    `resource_profile_digest` and `topology_profile_digest` -- and Nexus
    produces one of them. There is no `ResourceProfile` and no
    `TopologyProfile` in this repository: Phase 0b's first row covered
    interfaces only.

    A placeholder for the two missing digests would make the record claim to
    cover profiles that do not exist, and the record's own `record_digest`
    would then vouch for that claim. A commissioning record is the artifact an
    operator and an auditor read to decide what this node was commissioned as;
    a digest over a fiction is worse than no record.

    So this refuses and names what is missing. It becomes possible when the two
    profiles do.
    """

    raise CommissioningRecordUnavailable(
        "a CommissioningRecord requires resource_profile_digest and "
        "topology_profile_digest; Nexus produces neither yet (no ResourceProfile, "
        "no TopologyProfile). A placeholder would make the record's own digest "
        "vouch for profiles that do not exist"
    )
