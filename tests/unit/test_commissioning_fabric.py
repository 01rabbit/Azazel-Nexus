"""The parts of commissioning that are Fabric's: the assignment and the record.

Split from `test_commissioning.py` so that a missing Fabric extra skips only
these. A module-level `pytest.importorskip` skips every test in its module,
including the ones above it that need nothing optional; while they shared a
file, the checks on Nexus's own vocabulary ran only on the job that installs
Fabric, and two retired role words reached `main` unnoticed. The "Fabric extra
at the pinned tag" CI job refuses a skip here.
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "azazel_fabric",
    reason="the Fabric extra is optional; proposing must not need it",
)

from azazel_fabric.provisioning_contracts import (  # noqa: E402
    BANNED_ROLE_INFERENCE_FIELDS,
    INTERFACE_ROLES as FABRIC_ROLES,
    InterfaceAssignment,
    OperatorConfirmation,
)
from pydantic import ValidationError  # noqa: E402

from azazel_nexus.commissioning import INTERFACE_ROLES  # noqa: E402
from azazel_nexus.fabric_boundary import (  # noqa: E402
    CONFIRMATION_METHODS,
    CommissioningRecordUnavailable,
    build_commissioning_record,
    confirm_role,
    inventory_digest,
    project_interface_identity,
)
from azazel_nexus.inventory import InterfaceReadout  # noqa: E402


def a_readout(**overrides) -> InterfaceReadout:
    fields = {
        "bus_path": "pci0000:00/0000:04:00.0",
        "permanent_mac": "aa:bb:cc:dd:ee:ff",
        "pci_id": "0x8086:0x15b7",
        "usb_vid_pid": None,
        "serial": None,
        "driver": "e1000e",
        "firmware_version": "0.2-4",
        "wireless_phy": None,
        "physical_label": "LAN1",
    }
    fields.update(overrides.pop("fields", {}))
    data = {
        "kernel_name": "enp4s0",
        "fields": fields,
        "driver_version": "3.2.6",
        "incomplete_reasons": (),
    }
    data.update(overrides)
    return InterfaceReadout(**data)


def a_digest(*readouts) -> str:
    return inventory_digest(
        tuple(project_interface_identity(r) for r in (readouts or (a_readout(),)))
    )


def confirm(**overrides):
    readout = overrides.pop("readout", a_readout())
    data = {
        "role": "observation",
        "node_id": "nexus-1",
        "operator_ref": "operator:mao",
        "method": "physical_port_label_confirmed",
        "confirmed_at": "2026-09-20T12:00:00+00:00",
        "inventory_digest": a_digest(),
    }
    data.update(overrides)
    return confirm_role(readout, **data)


def test_the_local_role_mirror_still_matches_fabrics():
    assert INTERFACE_ROLES == FABRIC_ROLES


def test_the_confirmation_method_mirror_still_matches_fabrics():
    assert set(CONFIRMATION_METHODS) == set(
        OperatorConfirmation.model_fields["method"].annotation.__args__
    )


def test_a_confirmed_role_becomes_a_fabric_assignment():
    assignment = confirm()

    assert isinstance(assignment, InterfaceAssignment)
    assert assignment.role == "observation"
    assert assignment.authority == "descriptive_only"
    assert assignment.confirmation.operator_ref == "operator:mao"


def test_the_assignment_refers_to_the_adapter_not_to_the_name_it_had():
    """A selector built from the composite identity survives a rename."""

    assignment = confirm()

    assert assignment.selector.bus_path == "pci0000:00/0000:04:00.0"
    assert "enp4s0" not in assignment.selector.model_dump_json()


def test_nexus_cannot_confirm_on_an_operators_behalf():
    """Every argument is required; none has a default.

    A confirmation Nexus could produce without being told who confirmed, how,
    and when is a confirmation Nexus made for them.
    """

    import inspect

    signature = inspect.signature(confirm_role)
    for name in ("role", "node_id", "operator_ref", "method", "confirmed_at", "inventory_digest"):
        assert signature.parameters[name].default is inspect.Parameter.empty, name


def test_a_role_fabric_does_not_register_is_refused():
    with pytest.raises(ValidationError):
        confirm(role="decoy")
    with pytest.raises(ValidationError):
        confirm(role="protected")


def test_a_confirmation_method_the_node_could_satisfy_alone_does_not_exist():
    """Every registered method describes a person doing something.

    None can be satisfied by the node observing itself, which is what keeps
    confirmation a human act rather than a formality the node completes.
    """

    with pytest.raises(ValidationError):
        confirm(method="autodetected")
    assert all(
        "operator" in m or "physical" in m or "blink" in m or "signed" in m
        for m in CONFIRMATION_METHODS
    )


def test_an_assignment_carries_nothing_role_inference_forbids():
    payload = confirm().model_dump(mode="json")

    assert set(payload) & BANNED_ROLE_INFERENCE_FIELDS == set()
    assert "enp4s0" not in str(payload.get("selector", {}))


def test_the_inventory_digest_moves_with_the_inventory_and_not_with_a_name():
    base = a_digest(a_readout())
    renamed = a_digest(a_readout(kernel_name="eth7"))
    changed = a_digest(a_readout(fields={"pci_id": "0x8086:0x15bb"}))

    assert renamed == base, "a kernel rename must not change the inventory digest"
    assert changed != base, "a changed adapter must change it"


def test_an_uncommissionable_interface_cannot_be_confirmed_against():
    from azazel_nexus.fabric_boundary import IdentityUnavailable

    with pytest.raises(IdentityUnavailable):
        confirm(readout=a_readout(incomplete_reasons=("no permanent_mac",)))


# --------------------------------------------------------------------------
# Missing linked inputs must not produce a commissioning record
# --------------------------------------------------------------------------


def test_a_commissioning_record_is_refused_and_names_what_is_missing():
    """`CommissioningRecord` needs three genuine, linked input digests.

    Production inventory and authenticated profile linkage are still missing -- Phase 0b's
    first row covered interfaces only. A placeholder for missing
    digests would make the record claim to cover profiles that do not exist,
    and its own `record_digest` would then vouch for that claim.
    """

    with pytest.raises(CommissioningRecordUnavailable, match="resource_profile_digest"):
        build_commissioning_record()


def test_the_three_digests_the_record_requires_are_still_three():
    """Pin the required linked profiles separately from proposal assembly.

    If `CommissioningRecord` ever stops requiring these linked profiles,
    this test identifies the contract change for review.
    """

    from azazel_fabric.provisioning_contracts import CommissioningRecord

    required = {
        name
        for name, f in CommissioningRecord.model_fields.items()
        if f.is_required() and name.endswith("_digest")
    }
    assert required == {
        "hardware_inventory_digest",
        "resource_profile_digest",
        "topology_profile_digest",
        "record_digest",
    }
