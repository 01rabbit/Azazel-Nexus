"""The parts of the inventory that are Fabric's: the record and the matching rule.

Split from `test_inventory.py` so that a missing Fabric extra skips only these.
A module-level `pytest.importorskip` skips every test in its module, including
the ones above it that read sysfs and need nothing optional. The "Fabric extra
at the pinned tag" CI job refuses a skip here.
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "azazel_fabric",
    reason="the Fabric extra is optional; reading an inventory must not need it",
)

from azazel_fabric.provisioning_contracts import (  # noqa: E402
    COMPOSITE_IDENTITY_FIELDS,
    INTERFACE_ROLES,
    InterfaceIdentity,
    InterfaceIdentitySelector,
    InterfaceResolutionError,
)

from azazel_nexus.fabric_boundary import (  # noqa: E402
    IdentityUnavailable,
    identify_interface,
    project_interface_identity,
    project_inventory,
)
from azazel_nexus.inventory import (  # noqa: E402
    DISCRIMINATOR_FIELDS,
    IDENTITY_FIELDS,
    REQUIRED_IDENTITY_FIELDS,
    InterfaceReadout,
)


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


def test_the_local_field_list_still_matches_fabrics():
    """Two statements of one list; this is what keeps them the same one.

    `inventory.py` cannot import Fabric -- it is the CORE path and Fabric is an
    optional extra -- so it names the fields itself. That is the shape that
    drifts, so it is the shape that gets a test.
    """

    assert IDENTITY_FIELDS == COMPOSITE_IDENTITY_FIELDS
    assert set(REQUIRED_IDENTITY_FIELDS) < set(COMPOSITE_IDENTITY_FIELDS)
    assert set(DISCRIMINATOR_FIELDS) < set(COMPOSITE_IDENTITY_FIELDS)


def test_a_complete_readout_becomes_a_fabric_identity():
    identity = project_interface_identity(a_readout())

    assert isinstance(identity, InterfaceIdentity)
    assert identity.bus_path == "pci0000:00/0000:04:00.0"
    assert identity.kernel_name_observed == "enp4s0"
    assert identity.driver_version == "3.2.6"


def test_an_incomplete_readout_is_refused_rather_than_filled_in():
    """A default here would let a role be confirmed against an identity nobody
    established, which is what §3 exists to prevent."""

    with pytest.raises(IdentityUnavailable, match="permanent_mac"):
        project_interface_identity(
            a_readout(incomplete_reasons=("permanent_mac could not be read",))
        )


def test_the_interface_key_follows_the_composite_identity_and_not_the_name():
    """A rename must not change which interface an assignment refers to.

    The key is derived from Fabric's own `interface_composite_key`, so it moves
    exactly when the matching tuple moves -- never on a kernel rename, always
    on a slot move or an adapter swap.
    """

    base = project_interface_identity(a_readout())
    renamed = project_interface_identity(a_readout(kernel_name="eth7"))
    moved = project_interface_identity(
        a_readout(fields={"bus_path": "pci0000:00/0000:05:00.0"})
    )

    assert renamed.interface_key == base.interface_key
    assert moved.interface_key != base.interface_key


def test_the_projection_keeps_the_interfaces_it_could_not_identify():
    """An inventory that silently dropped them would read as a complete
    inventory of a smaller machine."""

    projection = project_inventory(
        (a_readout(), a_readout(kernel_name="eth9", incomplete_reasons=("no bus_path",)))
    )

    assert projection.available is True
    assert len(projection.identities) == 1
    assert projection.refused == (("eth9", ("no bus_path",)),)


# --------------------------------------------------------------------------
# The matching rule is Fabric's
# --------------------------------------------------------------------------


def a_selector(**overrides):
    data = {
        "bus_path": "pci0000:00/0000:04:00.0",
        "permanent_mac": "aa:bb:cc:dd:ee:ff",
        "pci_id": "0x8086:0x15b7",
    }
    data.update(overrides)
    return InterfaceIdentitySelector(**data)


def test_exactly_one_match_identifies_the_interface():
    identity = project_interface_identity(a_readout())

    assert identify_interface((identity,), a_selector()) is identity


@pytest.mark.parametrize(
    "count,fragment", [(0, "no inventory interface"), (2, "ambiguous")]
)
def test_zero_and_several_matches_are_the_same_fail_closed_answer(count, fragment):
    """`docs/commissioning.md` §3, and the error is raised by Fabric.

    Asserting Fabric's exception type is the point: it shows the rule was
    applied by the contract layer, not reimplemented here in a form that could
    quietly soften.
    """

    identity = project_interface_identity(a_readout())
    identities = (identity,) * count

    with pytest.raises(InterfaceResolutionError, match=fragment):
        identify_interface(identities, a_selector())


def test_a_mac_only_selector_never_reaches_the_resolver():
    """Refused one layer earlier than expected, and the layer matters.

    `assert_selector_is_composite` is the resolver's guard, so the obvious
    reading is that a MAC-only selector is caught when a match is attempted.
    Measured, it is caught by the **model**, at construction: such a selector
    cannot be built, so no caller can hold one to pass in. That is the stronger
    placement -- a guard at the call site protects the calls that reach it.
    """

    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="MAC-only"):
        InterfaceIdentitySelector(
            bus_path="pci0000:00/0000:04:00.0",
            permanent_mac="aa:bb:cc:dd:ee:ff",
        )

    # And the resolver still refuses one that got past construction some other
    # way, which is what keeps the two layers independent.
    from types import SimpleNamespace

    with pytest.raises(InterfaceResolutionError, match="MAC-only"):
        identify_interface(
            (project_interface_identity(a_readout()),),
            SimpleNamespace(
                bus_path="pci0000:00/0000:04:00.0",
                permanent_mac="aa:bb:cc:dd:ee:ff",
                pci_id=None,
                usb_vid_pid=None,
                serial=None,
            ),
        )


# --------------------------------------------------------------------------
# A measurement, recorded
# --------------------------------------------------------------------------


#: What each product called an interface role **before** the reconciliation,
#: copied literally. History now, kept so the correction stays legible.
#:
#: There were four lists, not three: Azazel-Boot's `architecture.md` named a
#: fifth-column set that its own `commissioning.py` did not hold.
#: `management` was the only value all four shared.
RETIRED_NEXUS_ROLES = ("protected", "observation", "management", "decoy", "egress/module")
RETIRED_BOOT_ROLES = ("observe", "internal", "external", "management", "capture", "decoy")


def test_the_role_vocabularies_were_reconciled_onto_fabrics():
    """The measurement this file used to record, and what came of it.

    It read "the three vocabularies still disagree" and was written to fail
    when any of them moved. They moved: Azazel-Nexus and Azazel-Boot both
    adopted Fabric's registered list, and Fabric's own list did not change --
    the reconciliation cost nothing in the released contract because the words
    that did not fit were never roles.

    `protected`, `internal`, `external`, `egress` answer *which side of the
    boundary does this interface face*. That is topology, it is product-local,
    and it never crossed a product boundary as a role. What remained --
    observation, management, deception bridging, asset acquisition -- is what
    another product needs to know, which is what Fabric registers.
    """

    assert set(INTERFACE_ROLES) == {
        "asset_acquisition", "deception_bridge", "management", "observation", "unassigned"
    }

    zones = {"protected", "internal", "external", "egress/module"}
    assert set(RETIRED_NEXUS_ROLES) & zones
    assert set(RETIRED_BOOT_ROLES) & zones
    assert zones & set(INTERFACE_ROLES) == set(), (
        "a topology word is back in the role list; that merge is how four "
        "vocabularies came to disagree"
    )


def test_nexus_now_names_roles_and_they_are_exactly_fabrics():
    """The successor to a guard that has fired.

    This file used to assert that Nexus named **no** role in code, because
    naming its documented five would have created a fourth vocabulary and
    settled the question by accident. The question is settled now, deliberately
    and in Fabric's favour, so the guard's job is done. A guard whose event has
    happened is replaced by one for the invariant that matters next -- here,
    that the local mirror is still a mirror.
    """

    from azazel_nexus.commissioning import INTERFACE_ROLES as LOCAL

    assert LOCAL == INTERFACE_ROLES
