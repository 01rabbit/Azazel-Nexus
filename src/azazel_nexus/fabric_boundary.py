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

`project_edge_evidence` projects an Edge intake evidence record onto
`schema.evidence.EvidenceRef`. It is tested against the pin and has no
production caller of its own: intake never needs Fabric. The explanation path
names the same records by the pointers it carries (see `project_explanation`).

`project_explanation` projects one explanation-ledger record onto
`mio_contracts.ClaimSet`: the Edge decision as a `deterministic_core` claim
citing the incident's Edge evidence as `EvidenceRef`s, the M.I.O. answer with
its recorded generation method and model, and each cited Knowledge reference
as a `knowledge_advisory` claim. The explainer
calls it for every record it writes and keeps the result in its own ledger,
beside the record, when the pinned Fabric is present. That is an internal
record: nothing sends, displays or serves it, so it attests that the ledger
projects onto the pinned contract, not that Nexus speaks M.I.O. to anyone.

`project_tested_tuple` and `check_tested_tuple` relate a Nexus
`compatibility.TestedTuple` to Fabric's `TestedCompatibilityTuple`
(ADR-0006). Fabric's record is a descriptive claim -- "recording that a tuple
was tested is not admitting it" -- and both functions keep it one: neither
builds a `TestedTuple` from a Fabric record, and a tuple that conforms is
admitted, if at all, only by the commissioned `TestedTupleSet`, which refuses
every lab-purpose tuple. Fabric's ``arm64`` reads as the lab profile's CPU.
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
    "ExplanationProjection",
    "TupleConformance",
    "check_tested_tuple",
    "confirm_role",
    "identify_interface",
    "inventory_digest",
    "project_capability",
    "project_edge_evidence",
    "project_explanation",
    "unique_citations",
    "project_interface_identity",
    "project_inventory",
    "project_resource_profile",
    "project_reviewed_topology",
    "project_hardware_inventory",
    "project_tested_tuple",
    "KnowledgeContextUnavailable",
    "KnowledgeContextInvalid",
    "canonical_knowledge_context_request",
    "validate_knowledge_context_request",
    "validate_knowledge_context_response",
]


class IdentityUnavailable(Exception):
    """An interface identity could not be produced, and why.

    Distinct from Fabric's own resolution error: this one means Nexus could
    not build the record at all, because the host did not give up the facts or
    because Fabric is absent. Collapsing the two would make "we never read it"
    indistinguishable from "we read it and it matched nothing".
    """

#: The exact tag this module is written against (ADR-0001). No branch pin, no
#: submodule, no copied source. A release candidate is still an exact tag — it
#: promises no stability, so this moves to `v0.9.0` when Fabric cuts it.
#:
#: What this comment does *not* say is as deliberate as what it does. Where
#: this tag stands among Fabric's releases, and what any other product pins,
#: are facts about repositories Nexus cannot read. It stated both anyway, as
#: facts, and both had stopped being true before anyone re-read them.
#: `azazel_nexus.status` now reports them as `unknown` and points at Fabric's
#: `docs/release-compatibility.md`, which holds the answer (#23).
#: `tests/unit/test_status_claims.py` keeps the retired phrasing out.
FABRIC_PIN = "v0.9.0rc5"

#: What this module needs to produce a projection at all.
REQUIRED_FABRIC_MODULES = ("azazel_fabric.view", "azazel_fabric.schema.mode",
                           "azazel_fabric.schema.evidence")

#: Fabric families that `docs/contract-ownership.md` §3 maps Nexus records onto
#: and that no Nexus code consumes yet. Listed because an unmet requirement is
#: only trackable while something names it: §2 asserted for months that two of
#: these did not exist in Fabric, after they did.
PLANNED_FABRIC_MODULES = (
    "azazel_fabric.cti_contracts",
    "azazel_fabric.deception_contracts",
    "azazel_fabric.mio_contracts",
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


class KnowledgeContextUnavailable(Exception):
    """The pinned optional Fabric release does not expose Knowledge Context v1."""


class KnowledgeContextInvalid(ValueError):
    """Fabric rejected a Knowledge Context v1 payload or correlation."""


def canonical_knowledge_context_request(request: Any) -> bytes:
    """Serialize one exact Fabric v1 request with Fabric's canonical encoder."""
    if _import_fabric()[0] is None:
        raise KnowledgeContextUnavailable("pinned Fabric is unavailable")
    try:
        from azazel_fabric.knowledge_context import (  # noqa: PLC0415
            KnowledgeContextRequestV1,
            canonical_knowledge_context_bytes,
        )
    except ImportError as exc:
        raise KnowledgeContextUnavailable(
            "pinned Fabric does not provide Knowledge Context v1"
        ) from exc
    if type(request) is not KnowledgeContextRequestV1:
        raise KnowledgeContextInvalid("Fabric refused Knowledge Context request")
    try:
        return canonical_knowledge_context_bytes(request)
    except (TypeError, ValueError, RecursionError) as exc:
        raise KnowledgeContextInvalid(
            "Fabric could not canonicalize Knowledge Context request"
        ) from exc


def validate_knowledge_context_request(payload: dict) -> Any:
    """Validate with Fabric's semantic request model, or fail as unavailable.

    The new contract is developed separately from the currently released pin.
    Until Nexus adopts a released Fabric tag containing it, this optional path
    stays unavailable; CORE and the existing capability projection still work.
    """
    if _import_fabric()[0] is None:
        raise KnowledgeContextUnavailable("pinned Fabric is unavailable")
    try:
        from azazel_fabric.knowledge_context import (  # noqa: PLC0415
            KnowledgeContextRequestV1,
        )
    except ImportError as exc:
        raise KnowledgeContextUnavailable(
            "pinned Fabric does not provide Knowledge Context v1"
        ) from exc
    try:
        return KnowledgeContextRequestV1.model_validate(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise KnowledgeContextInvalid("Fabric refused Knowledge Context request") from exc


def validate_knowledge_context_response(request: Any, payload: dict) -> Any:
    """Validate and correlate a response through Fabric's exact v1 models."""
    if _import_fabric()[0] is None:
        raise KnowledgeContextUnavailable("pinned Fabric is unavailable")
    try:
        from azazel_fabric.knowledge_context import (  # noqa: PLC0415
            KnowledgeContextRequestV1,
            KnowledgeContextResponseV1,
            assert_response_correlates,
        )
    except ImportError as exc:
        raise KnowledgeContextUnavailable(
            "pinned Fabric does not provide Knowledge Context v1"
        ) from exc
    try:
        if type(request) is not KnowledgeContextRequestV1:
            raise TypeError
        response = KnowledgeContextResponseV1.model_validate(payload)
        assert_response_correlates(request, response)
        return response
    except (TypeError, ValueError, RecursionError) as exc:
        raise KnowledgeContextInvalid(
            "Fabric refused or could not correlate Knowledge Context response"
        ) from exc


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


def project_hardware_inventory(*, readouts: Sequence[InterfaceReadout], platform: dict,
                               storage_devices: Sequence[dict], limitations: Sequence[str],
                               node_id: str, inventory_id: str, collected_at: str) -> Any:
    """Project collected metadata; caller owns independent node identity.

    Raw content/digests belong only in protected commissioning storage. No
    identity is minted, signed or authenticated by this serialization step.
    Refused interfaces prevent a claim that the complete set was projected.
    """
    fabric, _ = _import_fabric()
    if fabric is None or getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        raise CommissioningRecordUnavailable("pinned Fabric is required")
    from .activation import ActivationRefused, _utc_lease_time  # noqa: PLC0415

    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            HardwareInventory, PlatformIdentity, StorageDeviceIdentity, content_digest,
        )
        _utc_lease_time(collected_at)
        projected = project_inventory(readouts)
        if not projected.available or projected.refused:
            raise ValueError
        allowed = {"read-only-snapshot-not-authenticated", "snapshot-not-atomic",
                   "kernel-loopback-excluded",
                   "platform-fields-unavailable", "virtual-storage-and-partitions-excluded",
                   "storage-optional-identity-unavailable"}
        if (any(type(item) is not str for item in limitations)
                or not set(limitations).issubset(allowed)
                or not {"read-only-snapshot-not-authenticated", "snapshot-not-atomic"}.issubset(limitations)
                or len(set(limitations)) != len(limitations)):
            raise ValueError
        devices, paths = [], set()
        for source in storage_devices:
            if type(source) is not dict or set(source) != {
                "bus_path", "size_bytes", "rotational", "removable", "model_name", "serial"
            }:
                raise ValueError
            if (type(source["size_bytes"]) is not int or source["size_bytes"] <= 0
                    or type(source["rotational"]) is not bool or type(source["removable"]) is not bool
                    or source["bus_path"] in paths):
                raise ValueError
            paths.add(source["bus_path"])
            devices.append(StorageDeviceIdentity(device_key=f"storage-{len(devices) + 1}", **source))
        checked_platform = PlatformIdentity(**platform)
        if (any(getattr(checked_platform, name) is None for name in
                ("vendor", "product_name", "board_serial", "firmware_vendor", "firmware_version"))
                and "platform-fields-unavailable" not in limitations):
            raise ValueError
        if (any(item.model_name is None or item.serial is None for item in devices)
                and "storage-optional-identity-unavailable" not in limitations):
            raise ValueError
        draft = HardwareInventory(inventory_id=inventory_id, product="azazel-nexus",
            node_id=node_id, collected_at=collected_at, platform=checked_platform,
            interfaces=projected.identities, storage_devices=tuple(devices),
            limitations=tuple(limitations), inventory_digest="sha256:" + "0" * 64)
        return draft.model_copy(update={"inventory_digest": content_digest(draft, digest_field="inventory_digest")})
    except (ImportError, ValueError, TypeError, KeyError, AttributeError, ActivationRefused):
        raise CommissioningRecordUnavailable("hardware inventory inputs unavailable or inconsistent") from None


def project_resource_profile(*, observation: dict, inventory: Any, profile_id: str) -> Any:
    """Project actual observations onto Fabric's descriptive resource record.

    Requires a complete, internally digest-consistent HardwareInventory, not
    the interface-only digest returned by inventory_digest(). This verifies
    structural consistency, not inventory authenticity, recency or admission.
    Missing storage is not zero and memory is never adjusted a second time.
    """
    fabric, failure = _import_fabric()
    if fabric is None or getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        raise CommissioningRecordUnavailable("pinned Fabric is required")
    from .activation import ActivationRefused, _utc_lease_time  # noqa: PLC0415

    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            HardwareInventory, ResourceProfile, assert_content_digest,
        )

        if type(inventory) is not HardwareInventory:
            raise ValueError
        # Revalidate even model_copy/model_construct inputs, which may bypass
        # the model's constructor. A supplied digest alone is not evidence.
        checked = HardwareInventory.model_validate(inventory.model_dump(mode="json"))
        assert_content_digest(checked, digest_field="inventory_digest")
        if type(observation) is not dict or set(observation) != {
            "schema", "observed_at", "architecture", "measurements", "unavailable", "limitations", "admission"
        }:
            raise ValueError
        if (observation["schema"] != "azazel-nexus/resource-observation/v1"
                or observation["admission"] != "not-evaluated"
                or observation["unavailable"] != []):
            raise ValueError
        _utc_lease_time(observation["observed_at"])
        readings = observation["measurements"]
        names = {"usable_memory_mib", "online_logical_cpus", "mission_available_mib"}
        if type(readings) is not dict or set(readings) != names:
            raise ValueError
        for name, value in readings.items():
            if type(value) is not int or value < 0 or (name != "mission_available_mib" and value == 0):
                raise ValueError
        limitations = observation["limitations"]
        if type(limitations) is not list or any(type(item) is not str for item in limitations):
            raise ValueError
        required = {"gpu-unmeasured", "throughput-unmeasured", "thermal-power-unmeasured",
                    "cgroup-limits-unmeasured", "storage-trust-unverified"}
        if set(limitations) != required or len(limitations) != len(required):
            raise ValueError
        return ResourceProfile(
            profile_id=profile_id, node_id=checked.node_id,
            hardware_inventory_digest=checked.inventory_digest,
            measured_at=observation["observed_at"],
            measurement_method="measured_usable_after_firmware_reservation",
            cpu_architecture=observation["architecture"],
            cpu_logical_cores=readings["online_logical_cpus"],
            usable_memory_mib=readings["usable_memory_mib"],
            usable_storage_mib=readings["mission_available_mib"],
            limitations=tuple(dict.fromkeys((*limitations,
                "storage-is-caller-available-filesystem-space", "cpu-is-online-logical-count",
                "unsigned-observation-not-admission"))),
        )
    except (ImportError, ValueError, TypeError, KeyError, AttributeError, ActivationRefused):
        raise CommissioningRecordUnavailable("resource profile inputs unavailable or inconsistent") from None


def project_reviewed_topology(*, payload: bytes, signature: bytes, operator: str,
                             trust: Any, current: Any, inventory: Any,
                             profile_id: str, observed_at: str) -> Any:
    """Project reviewed roles, not a signed topology or activation permission.

    The signature covers the original draft only. Node/snapshot/profile fields
    added here are not signed. Returned raw identities belong only in protected
    commissioning storage, never terminal output or general audit logs.
    """
    fabric, _ = _import_fabric()
    if fabric is None or getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        raise CommissioningRecordUnavailable("pinned Fabric is required")
    from .activation import ActivationRefused, _utc_lease_time  # noqa: PLC0415
    from .commissioning_draft import (  # noqa: PLC0415
        DraftRefused, _decode_draft, verify_draft_review,
    )

    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            HardwareInventory, TopologyProfile, assert_content_digest,
        )
        _utc_lease_time(observed_at)
        if type(inventory) is not HardwareInventory:
            raise ValueError
        checked = HardwareInventory.model_validate(inventory.model_dump(mode="json"))
        assert_content_digest(checked, digest_field="inventory_digest")
        verify_draft_review(payload=payload, signature=signature, operator=operator,
                            trust=trust, current=current)
        record = _decode_draft(payload)
        if current.refused:
            raise ValueError
        projected = project_inventory(current.commissionable)
        if not projected.available or projected.refused:
            raise ValueError
        observed = {item.interface_key: item.model_dump(mode="json") for item in projected.identities}
        expected = {item.interface_key: item.model_dump(mode="json") for item in checked.interfaces}
        if len(observed) != len(projected.identities) or observed != expected:
            raise ValueError
        assignments, assigned_keys = [], set()
        for role in record.roles:
            matches = [readout for readout in current.commissionable
                       if tuple(sorted(readout.fields.items())) == role.composite]
            if len(matches) != 1:
                raise ValueError
            assignment = confirm_role(
                matches[0], role=role.role, node_id=checked.node_id,
                operator_ref=operator, method="signed_site_approval",
                confirmed_at=role.confirmed_at, inventory_digest=checked.inventory_digest,
            )
            resolved = identify_interface(checked.interfaces, assignment.selector)
            if resolved.interface_key in assigned_keys:
                raise ValueError
            assigned_keys.add(resolved.interface_key)
            assignments.append(assignment)
        return TopologyProfile(
            profile_id=profile_id, node_id=checked.node_id,
            hardware_inventory_digest=checked.inventory_digest, observed_at=observed_at,
            commissioned_assignments=tuple(assignments),
            unassigned_interface_keys=tuple(sorted(set(expected) - assigned_keys)),
            management_reachability="unknown", capture_support=(), isolation_properties=(),
            limitations=("management-reachability-unmeasured", "capture-support-unmeasured",
                         "isolation-unmeasured", "signature-covers-draft-only-not-this-profile",
                         "platform-storage-freshness-unverified", "not-activation-admission"),
        )
    except (ImportError, ValueError, TypeError, KeyError, AttributeError,
            ActivationRefused, DraftRefused, IdentityUnavailable):
        raise CommissioningRecordUnavailable("reviewed topology inputs unavailable or inconsistent") from None


def assert_current_inventory_matches(*, retained: Any, current: Any) -> None:
    """Compare complete hardware contents without rewriting signed metadata.

    The current observation keeps its own inventory ID, collection time and
    digest. Those three snapshot metadata fields are excluded only from this
    comparison; every other schema field, identity, limitation and ordering
    must match. This is not resource freshness, policy admission or proof of a
    trusted clock. Caller must authenticate the retained snapshot separately.
    """
    fabric, _ = _import_fabric()
    if fabric is None or getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        raise CommissioningRecordUnavailable("pinned Fabric is required")
    from .activation import ActivationRefused, _utc_lease_time

    try:
        from azazel_fabric.provisioning_contracts import HardwareInventory, assert_content_digest

        checked = []
        for value in (retained, current):
            if type(value) is not HardwareInventory:
                raise ValueError
            item = HardwareInventory.model_validate(value.model_dump(mode="json"))
            assert_content_digest(item, digest_field="inventory_digest")
            checked.append(item)
        if _utc_lease_time(checked[1].collected_at.isoformat().replace("+00:00", "Z")) < _utc_lease_time(
                checked[0].collected_at.isoformat().replace("+00:00", "Z")):
            raise ValueError
        documents = [item.model_dump(mode="json") for item in checked]
        for document in documents:
            for name in ("inventory_id", "collected_at", "inventory_digest"):
                document.pop(name)
        if documents[0] != documents[1]:
            raise ValueError
    except (ImportError, ValueError, TypeError, KeyError, AttributeError, ActivationRefused):
        raise CommissioningRecordUnavailable("current hardware inventory does not match retained evidence") from None


def assert_local_record_matches_full_proposal(*, document: dict, record: Any) -> None:
    """Refuse a lossy compatibility view used for unrelated role bindings.

    This checks correspondence only. The caller must retain and authenticate
    the full proposal, including limitations; matching does not grant readiness.
    """
    from .commissioning import CommissioningRecord, REQUIRED_PROFILES
    from .inventory import IDENTITY_FIELDS

    try:
        context = restore_commissioning_inputs(document)
        if (type(record) is not CommissioningRecord
                or record.created_at != document["record"]["created_at"]
                or len(record.profiles_present) != len(REQUIRED_PROFILES)
                or set(record.profiles_present) != set(REQUIRED_PROFILES)):
            raise ValueError
        assignments = context["topology_profile"].commissioned_assignments
        if len(record.roles) != len(assignments):
            raise ValueError
        remaining = list(assignments)
        for role in record.roles:
            fields = dict(role.composite)
            if len(fields) != len(role.composite) or not set(fields).issubset(IDENTITY_FIELDS):
                raise ValueError
            matches = []
            for index, assignment in enumerate(remaining):
                identity = identify_interface(context["inventory"].interfaces, assignment.selector)
                confirmation = assignment.confirmation.model_dump(mode="json")
                if (role.role == assignment.role
                        and role.confirmed_by == confirmation["operator_ref"]
                        and role.confirmed_at == confirmation["confirmed_at"]
                        and all(fields.get(name) == getattr(identity, name) for name in IDENTITY_FIELDS)):
                    matches.append(index)
            if len(matches) != 1:
                raise ValueError
            remaining.pop(matches[0])
    except (ValueError, TypeError, KeyError, AttributeError, IdentityUnavailable):
        raise CommissioningRecordUnavailable("local commissioning view does not match full evidence") from None


def deception_scope_assignments(inventory: Any, topology_profile: Any) -> tuple[tuple[str, str], ...]:
    """`(interface_key, role)` for every commissioned assignment (#196 G1a).

    What `decoy_scope.decode_deception_scope` counts the `deception_bridge`
    interfaces from. Each selector is resolved by Fabric's rule
    (`identify_interface`), so an interface is named by role and identity,
    never by a kernel name. Raises on any assignment that does not resolve.
    """

    return tuple((identify_interface(inventory.interfaces, assignment.selector).interface_key,
                  assignment.role) for assignment in topology_profile.commissioned_assignments)


def restore_commissioning_inputs(document: dict) -> dict:
    """Decode retained local expectations, not an imported candidate's authority.

    Caller must enforce provenance/bounds and compare canonical reconstruction.
    No filesystem, signature or admission decision belongs in this decoder.
    """
    fabric, _ = _import_fabric()
    if fabric is None or getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        raise CommissioningRecordUnavailable("pinned Fabric is required")
    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            HardwareInventory, ResourceProfile, TopologyProfile,
        )
        schema = document["schema"]
        if schema not in {"azazel-nexus/commissioning-proposal/v1",
                          "azazel-nexus/commissioning-proposal/v2",
                          "azazel-nexus/commissioning-proposal/v3"}:
            raise ValueError
        selection = {}
        if schema != "azazel-nexus/commissioning-proposal/v1":
            # v2 and v3 carry the M.I.O. selection; it is required in both.
            profile = document["mio_profile"]
            if type(profile) is not str or profile not in {"CORE", "LITE", "FULL"}:
                raise ValueError
            selection["mio_profile"] = profile
        context = dict(inventory=HardwareInventory.model_validate(document["inventory"]),
                       resource_profile=ResourceProfile.model_validate(document["resource"]),
                       topology_profile=TopologyProfile.model_validate(document["topology"]),
                       record_id=document["record"]["record_id"], operator=document["operator"],
                       confirmed_at=document["record"]["created_at"], **selection)
        if schema == "azazel-nexus/commissioning-proposal/v3":
            # Required in v3, as `mio_profile` is in v2 (#196 G1a, grant §4.1):
            # decoded whole here, so a retained view never holds a partial scope.
            from .decoy_scope import decode_deception_scope  # noqa: PLC0415

            section = document["deception_scope"]
            decode_deception_scope(section, assignments=deception_scope_assignments(
                context["inventory"], context["topology_profile"]))
            context["deception_scope"] = section
        return context
    except (ImportError, ValueError, TypeError, KeyError, AttributeError, IdentityUnavailable):
        raise CommissioningRecordUnavailable("retained commissioning inputs unavailable") from None


def build_commissioning_record(*, inventory=None, resource_profile=None,
                               topology_profile=None, record_id=None,
                               operator_ref=None, confirmed_at=None) -> dict:
    """Assemble an explicitly unsigned proposal, never completed commissioning.

    All full constituent records are retained for external operator review.
    The proposed confirmation becomes attributable only after a NEW signature
    covers this entire wrapper. A role-draft signature does not suffice.
    Raw content is confidential; this function neither prints nor persists it.
    """
    fabric, _ = _import_fabric()
    if fabric is None or getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        raise CommissioningRecordUnavailable("pinned Fabric is required")
    from .activation import ActivationRefused, _utc_lease_time  # noqa: PLC0415

    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            HardwareInventory, ResourceProfile, TopologyProfile, CommissioningRecord,
            OperatorConfirmation, assert_content_digest, content_digest,
        )
        models = []
        for value, expected_type in ((inventory, HardwareInventory),
                                     (resource_profile, ResourceProfile),
                                     (topology_profile, TopologyProfile)):
            if type(value) is not expected_type:
                raise ValueError
            models.append(expected_type.model_validate(value.model_dump(mode="json")))
        inventory, resource, topology = models
        instant = _utc_lease_time(confirmed_at)
        assert_content_digest(inventory, digest_field="inventory_digest")
        if inventory.product != "azazel-nexus":
            raise ValueError
        for profile in (resource, topology):
            if (profile.node_id != inventory.node_id
                    or profile.hardware_inventory_digest != inventory.inventory_digest):
                raise ValueError
        times = [inventory.collected_at, resource.measured_at, topology.observed_at]
        assigned = set()
        for assignment in topology.commissioned_assignments:
            if assignment.node_id != inventory.node_id:
                raise ValueError
            resolved = identify_interface(inventory.interfaces, assignment.selector)
            if resolved.interface_key in assigned:
                raise ValueError
            assigned.add(resolved.interface_key)
            times.extend((assignment.assigned_at, assignment.confirmation.confirmed_at))
        all_keys = {item.interface_key for item in inventory.interfaces}
        capture_keys = [item.interface_key for item in topology.capture_support]
        property_ids = [item.property_id for item in topology.isolation_properties]
        if (len(set(capture_keys)) != len(capture_keys) or not set(capture_keys).issubset(all_keys)
                or len(set(property_ids)) != len(property_ids)):
            raise ValueError
        times.extend(item.observed_at for item in topology.capture_support)
        times.extend(item.observed_at for item in topology.isolation_properties)
        unassigned = topology.unassigned_interface_keys
        if (len(set(unassigned)) != len(unassigned)
                or set(unassigned) != all_keys - assigned):
            raise ValueError
        if any(time.tzinfo is None or time.utcoffset().total_seconds() != 0 or time > instant for time in times):
            raise ValueError
        limitations = tuple(dict.fromkeys((*inventory.limitations, *resource.limitations,
            *topology.limitations, "unsigned-proposal-pending-full-operator-signature",
            "not-activation-admission")))
        record = CommissioningRecord(record_id=record_id, product="azazel-nexus",
            node_id=inventory.node_id, created_at=confirmed_at,
            hardware_inventory_digest=inventory.inventory_digest,
            resource_profile_digest=content_digest(resource), topology_profile_digest=content_digest(topology),
            assignments=topology.commissioned_assignments,
            operator_confirmation=OperatorConfirmation(operator_ref=operator_ref,
                method="signed_site_approval", confirmed_at=confirmed_at),
            limitations=limitations, record_digest="sha256:" + "0" * 64)
        record = record.model_copy(update={"record_digest": content_digest(record, digest_field="record_digest")})
        assert_content_digest(record, digest_field="record_digest")
        return {"schema": "azazel-nexus/commissioning-proposal/v1", "status": "unsigned-proposal",
                "confirmation_is": "proposed-until-full-signature-verified", "operator": operator_ref,
                "inventory": inventory.model_dump(mode="json"), "resource": resource.model_dump(mode="json"),
                "topology": topology.model_dump(mode="json"), "record": record.model_dump(mode="json")}
    except (ImportError, ValueError, TypeError, KeyError, AttributeError,
            ActivationRefused, IdentityUnavailable):
        raise CommissioningRecordUnavailable(
            "complete consistent inventory, resource_profile_digest and topology_profile_digest inputs required"
        ) from None


def project_edge_evidence(record) -> Projection:
    """Project a pointer only; Fabric absence never prevents local intake."""
    fabric, failure = _import_fabric()
    if fabric is None:
        return Projection(available=False, reason=failure)
    if getattr(fabric, '__version__', None) != FABRIC_PIN.lstrip('v'):
        return Projection(available=False, reason='pinned Fabric is required')
    try:
        from datetime import UTC, datetime
        from azazel_fabric.schema.evidence import EvidenceRef
        view = EvidenceRef(evidence_id=record.digest, source='edge-core',
            trace_id=record.event.as_dict()['enforcement']['trace_id'],
            observed_at=datetime.fromtimestamp(record.received_at, UTC).isoformat().replace('+00:00', 'Z'))
    except (ImportError, ValueError, TypeError, AttributeError, KeyError, OverflowError):
        return Projection(available=False, reason='edge evidence projection unavailable')
    return Projection(available=True, reason='', fabric_version=fabric.__version__, view=view)


def project_tested_tuple(tested, *, tuple_id: str, product_version: str,
                         evidence_ref: str | None = None,
                         deployment_profile: str | None = None) -> Projection:
    """Describe a Nexus tested tuple as Fabric's `TestedCompatibilityTuple`.

    The shared fields come from `compatibility.fabric_shared_fields`; the
    claim's identity (`tuple_id`, `product_version`, `evidence_ref`,
    `deployment_profile`) is the caller's, because Nexus's tuple has none.
    Nexus-only fields (`compatibility.NEXUS_ONLY_FIELDS`) are not carried --
    Fabric's record has no place for them -- so the projection describes the
    tuple and cannot stand in for it. A lab-purpose tuple projects to
    ``arm64`` with `deployment_profile` set to the lab profile id (``...-lab``),
    so the Fabric record alone shows it is lab; a different caller-supplied
    value is refused. Unavailable, with a reason, when Fabric is absent,
    not the pin, or refuses the record.
    """

    from . import platform_profile as pp  # noqa: PLC0415
    from .compatibility import (  # noqa: PLC0415
        FABRIC_TUPLE_PRODUCT, CompatibilityRefused, fabric_shared_fields)

    fabric, failure = _import_fabric()
    if fabric is None:
        return Projection(available=False, reason=failure)
    if getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        return Projection(available=False, reason="pinned Fabric is required")
    try:
        shared = fabric_shared_fields(tested)
    except CompatibilityRefused as refused:
        return Projection(available=False, reason=f"tested tuple not projectable: {refused}")
    if tested.purpose != pp.PURPOSE_DEPLOYMENT_BASELINE:
        # Fabric's tuple has no purpose field, so a lab tuple names the lab
        # profile here: a reader of the Fabric record alone can tell it apart.
        lab_profile = pp.profile_for_architecture(
            pp.from_boundary("kernel", tested.architecture)).profile_id
        if deployment_profile not in (None, lab_profile):
            return Projection(
                available=False,
                reason=f"a {tested.purpose} tuple projects as deployment_profile "
                       f"{lab_profile!r}, not {deployment_profile!r}")
        deployment_profile = lab_profile
    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            TestedCompatibilityTuple)
        view = TestedCompatibilityTuple(
            tuple_id=tuple_id, product=FABRIC_TUPLE_PRODUCT,
            product_version=product_version, deployment_profile=deployment_profile,
            evidence_ref=evidence_ref, **shared)
    except (ImportError, ValueError, TypeError):
        return Projection(available=False, reason="Fabric refused the tested tuple projection")
    return Projection(available=True, reason="", fabric_version=fabric.__version__, view=view)


@dataclass(frozen=True)
class TupleConformance:
    """Whether a Fabric tuple claim describes the same tested combination.

    Descriptive only. `conforms` says the shared fields agree after the
    vocabulary step; it is not an admission and nothing reads it as one.
    `purpose` is the purpose the reviewed profile table gives the claim's
    CPU (``arm64`` is ``lab-software-verification``), when the claim could
    be read at all.
    """

    conforms: bool
    #: Why not. Empty exactly when `conforms`.
    reason: str
    purpose: str | None = None
    fabric_version: str | None = None


def check_tested_tuple(tested, claim) -> TupleConformance:
    """Compare a Nexus tested tuple with a Fabric `TestedCompatibilityTuple`.

    `claim` is a Fabric model or its JSON mapping; either is validated by
    Fabric's own model (closed, so an unknown field is Fabric's refusal, not
    ours). Each shared field is compared exactly after the one vocabulary step
    for it (`compatibility.fabric_shared_fields`); a feature list that
    repeats an entry is refused rather than folded into a set, and the claim
    must be about `azazel-nexus`. The first field that differs is the reason.
    """

    from . import platform_profile as pp  # noqa: PLC0415
    from .compatibility import (  # noqa: PLC0415
        FABRIC_SHARED_FIELDS, FABRIC_TUPLE_PRODUCT, CompatibilityRefused,
        fabric_shared_fields)

    fabric, failure = _import_fabric()
    if fabric is None:
        return TupleConformance(False, failure)
    if getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        return TupleConformance(False, "pinned Fabric is required")
    version = fabric.__version__
    try:
        from azazel_fabric.provisioning_contracts import (  # noqa: PLC0415
            TestedCompatibilityTuple)
        if type(claim) is TestedCompatibilityTuple:
            # Re-validated, not trusted: `model_construct` builds an instance
            # that never passed Fabric's validators.
            claim = claim.model_dump(warnings=False)
        if not isinstance(claim, dict):
            return TupleConformance(False, "not a Fabric tested tuple", None, version)
        claim = TestedCompatibilityTuple.model_validate(claim)
    except Exception:  # noqa: BLE001 -- every failure is a reasoned refusal
        return TupleConformance(False, "Fabric refused the tested tuple claim", None, version)
    try:
        purpose = pp.purpose_for_architecture(
            pp.from_boundary("fabric", claim.architecture))
    except pp.PlatformRefused as refused:
        return TupleConformance(False, f"claim architecture refused: {refused.reason}",
                                None, version)
    if claim.product != FABRIC_TUPLE_PRODUCT:
        return TupleConformance(
            False, f"the claim is about {claim.product!r}, not {FABRIC_TUPLE_PRODUCT!r}",
            purpose, version)
    fields = dict(claim)  # a pydantic model iterates as (field, value)
    for name in ("cpu_features", "schema_features"):
        values = fields[name]
        if len(set(values)) != len(values):
            return TupleConformance(
                False, f"the claim's {name} repeats an entry; a tested tuple is exact",
                purpose, version)
    try:
        expected = fabric_shared_fields(tested)
    except CompatibilityRefused as refused:
        return TupleConformance(False, f"tested tuple not comparable: {refused}",
                                purpose, version)
    for nexus_name, fabric_name in FABRIC_SHARED_FIELDS:
        theirs = fields[fabric_name]
        if fabric_name in ("cpu_features", "schema_features"):
            theirs = tuple(sorted(theirs))
        if theirs != expected[fabric_name]:
            return TupleConformance(
                False, f"{nexus_name} differs from the claim's {fabric_name}", purpose, version)
    return TupleConformance(True, "", purpose, version)


#: The Edge decision's claim id after the incident id, and the prefix of each
#: cited reference's claim id. `incident_explain` states the same two words
#: for its reader; `test_fabric_explanation_projection` keeps them equal.
EDGE_CLAIM_SUFFIX = ":edge"
KNOWLEDGE_CLAIM_PREFIX = "knowledge:"


def unique_citations(refs) -> list:
    """The cited references with each claim id once, first occurrence kept.

    A `ClaimSet` refuses a repeated claim id, and a lookup may cite one
    technique twice; without this the whole projection would fail and be
    dropped without a word. The Edge claim records that a merge happened.
    `incident_explain` applies the same rule when it reads the projection back.
    """
    seen = set()
    out = []
    for ref in refs:
        if ref["claim_id"] not in seen:
            seen.add(ref["claim_id"])
            out.append(ref)
    return out


@dataclass(frozen=True)
class ExplanationProjection:
    """One explanation-ledger record as Fabric `mio_contracts` claims.

    `claim_set` is a Fabric `ClaimSet` and `evidence_refs` a tuple of Fabric
    `EvidenceRef`. Typed `Any` for the reason `Projection.view` is.
    """

    claim_set: Any
    evidence_refs: tuple = ()

    def as_ledger(self) -> dict:
        """The internal ledger form: Fabric's own JSON dumps, never re-shaped.

        A `ClaimSet` has no place for the `EvidenceRef`s its claims cite by
        id, so they are kept beside it, each as Fabric dumps it.
        """
        value = {"fabric_version": FABRIC_PIN.lstrip("v"),
                 "claim_set": self.claim_set.model_dump(mode="json")}
        if self.evidence_refs:
            value["evidence_refs"] = [ref.model_dump(mode="json") for ref in self.evidence_refs]
        return value


def project_explanation(record) -> Projection:
    """Project one explanation-ledger record onto Fabric's `ClaimSet`.

    `record` must already have been read by `incident_explain.read_record`.

    Internal only. The result is kept in the explanation ledger beside the
    record it was made from (`incident_explaind`); it is not sent, displayed
    or returned by any socket, and Fabric's absence leaves the record exactly
    as it was. The claims describe; none of them is a decision:

    - the Edge decision as reported by Edge Core, `source="deterministic_core"`;
    - each cited `KnowledgeRef` as `source="knowledge_advisory"`, with the
      verified bundle digest as its only input reference and the Lite
      freshness (`static` or `current`) as its freshness;
    - the record's Edge evidence pointers (`incident_explain.EVIDENCE_FIELD`,
      carried from the incident transition through the durable pending
      queue) as Fabric `EvidenceRef`s -- the digest intake stored the record
      under, `edge-core`, the incident id as the trace (the id the audit
      events carry; Edge's own trace id is producer text and is not carried),
      and the receive instant -- cited by id from the Edge claim, whose
      limitations say why a pointer may not lead to a stored record
      (`evidence_not_stored`, `evidence_retention_elapsed`). A record from
      before the pointers says `evidence_refs_not_carried` instead;
    - the M.I.O. answer, when the record names its generation method
      (`explanation_claims.mio_claims`): the candidate it ranked and the
      alternatives -- `local_model` with the admitted model's id as
      `model_ref` when embedding matching ranked them, `deterministic_core`
      for keyword matching -- and a model's own validated explanation as a
      second `local_model` claim. The fixed delivery banner is not a claim.
      The delivery names no model generation, so `model_generation` stays
      None and a model's claims say `model_generation_not_delivered`. A
      record without the method (from before it, or with no local answer)
      has no such claims.
    """
    fabric, failure = _import_fabric()
    if fabric is None:
        return Projection(available=False, reason=failure)
    if getattr(fabric, "__version__", None) != FABRIC_PIN.lstrip("v"):
        return Projection(available=False, reason="pinned Fabric is required")
    try:
        from datetime import UTC, datetime

        from azazel_fabric.mio_contracts import Claim, ClaimSet
        from azazel_fabric.schema.evidence import EvidenceRef

        # The record is read by `incident_explain.read_record` before it gets
        # here; importing that module from this one would pull the whole
        # explanation plane into everything that imports the Fabric boundary.
        # The words both state live in `explanation_claims`.
        from azazel_nexus.explanation_claims import (
            EVIDENCE_FIELD, EVIDENCE_SOURCE, PROVENANCE_FIELD, edge_claim_limitations,
            evidence_observed_at, mio_claims,
        )

        r = record
        cited = unique_citations(r["knowledge_refs"])
        refs = tuple(
            EvidenceRef(evidence_id=ref["evidence_id"], source=EVIDENCE_SOURCE,
                        trace_id=r["incident_id"],
                        observed_at=evidence_observed_at(ref["observed_at"]))
            for ref in (r[EVIDENCE_FIELD]["refs"] if EVIDENCE_FIELD in r else ()))
        pointers = tuple(ref.evidence_id for ref in refs)
        edge = Claim(
            claim_id=r["incident_id"] + EDGE_CLAIM_SUFFIX,
            statement=f"Edge would {r['edge_would']}; policy_reason={r['policy_reason']}",
            source="deterministic_core",
            input_refs=pointers,
            limitations=tuple(edge_claim_limitations(r, len(cited) != len(r["knowledge_refs"]))),
        )
        claims = [edge]
        provenance = r["mio"].get(PROVENANCE_FIELD)
        if provenance is not None:
            claims += [Claim(**{**c, "input_refs": tuple(c["input_refs"]),
                                "limitations": tuple(c["limitations"])})
                       for c in mio_claims(r["incident_id"], provenance, pointers)]
        for ref in cited:
            statement = ref["name"] + (f": {ref['summary']}" if ref["summary"] else "")
            limitations = (f"source_kind={ref['source_kind']}", f"generation={ref['generation']}",
                           f"as_of={ref['as_of']}", f"trust_check={ref['trust_check']}")
            if ref["citation"]:
                limitations += (f"citation={ref['citation']}",)
            claims.append(Claim(
                claim_id=KNOWLEDGE_CLAIM_PREFIX + ref["claim_id"],
                statement=statement,
                source="knowledge_advisory",
                input_refs=(ref["bundle_digest"],),
                freshness=ref["freshness"],
                limitations=limitations,
            ))
        frozen_at = datetime.fromtimestamp(r["explained_at"], UTC)
        view = ClaimSet(
            claim_set_id=f"{r['incident_id']}:{r['transition']}:{frozen_at.isoformat()}",
            trace_id=r["incident_id"],
            frozen_at=frozen_at,
            claims=tuple(claims),
        )
    except (ImportError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return Projection(available=False, reason="explanation claim projection unavailable")
    return Projection(available=True, reason="", fabric_version=fabric.__version__,
                      view=ExplanationProjection(claim_set=view, evidence_refs=refs))
