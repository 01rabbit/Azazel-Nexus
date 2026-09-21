"""What an operator confirmed, and what a node may claim from it (#27).

Two claims are separated here on purpose, because collapsing them is how a
node comes to say it can enforce when it cannot:

*observe-only* is the state of having no confirmed role. It is not an error
and not an absence of a record — a record with no roles means every interface
was seen and none was given one.

*enforcement-ready* needs **both** all three profiles and a confirmed role
(§2.3). Either alone is a node that has established one half of what it needs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from azazel_nexus.commissioning import (
    REQUIRED_PROFILES,
    CommissioningRefused,
    ConfirmedRole,
    confirm_roles,
    propose,
)
from azazel_nexus.inventory import read_interfaces

T0 = "2026-09-20T00:00:00+00:00"

#: Two adapters on distinct PCI functions, each with its own permanent MAC.
#:
#: Built here rather than shared, so that a change to one test's topology
#: cannot silently change another's. The addresses differ because two
#: interfaces sharing a composite identity is a separate case with its own
#: test in `test_commissioning.py`.
_ADAPTERS = (
    ("enp3s0", "0000:03:00.0", "a2:b1:c2:d3:e4:f5", "LAN1"),
    ("enp4s0", "0000:04:00.0", "02:11:22:33:44:55", "LAN2"),
)


def _sysfs(tmp_path: Path) -> Path:
    net = tmp_path / "sys" / "class" / "net"
    for name, slot, _mac, label in _ADAPTERS:
        bus = tmp_path / "sys" / "devices" / "pci0000:00" / slot
        bus.mkdir(parents=True)
        (bus / "vendor").write_text("0x8086\n")
        (bus / "device").write_text("0x15b7\n")
        (bus / "label").write_text(label + "\n")
        interface = net / name
        interface.mkdir(parents=True)
        (interface / "device").symlink_to(f"../../../devices/pci0000:00/{slot}")
        # The current MAC, one directory up from anything identity reads.
        (interface / "address").write_text("02:00:00:00:00:01\n")
    return net


def _mac_reader(kernel_name: str):
    for name, _slot, mac, _label in _ADAPTERS:
        if name == kernel_name:
            return mac
    return None


@pytest.fixture()
def proposal(tmp_path):
    return propose(read_interfaces(_sysfs(tmp_path), permanent_mac_reader=_mac_reader))


def _record(proposal, roles=(), profiles=REQUIRED_PROFILES):
    pairs = tuple(
        (proposal.commissionable[index], role) for index, role in roles
    )
    return confirm_roles(
        proposal, pairs, operator="op-1", at=T0, profiles_present=profiles
    )


# -- the operator is the only source of a role ------------------------------


def test_a_role_comes_only_from_an_operator_confirmation(proposal):
    record = _record(proposal, roles=((0, "observation"),))
    (confirmed,) = record.roles
    assert (confirmed.role, confirmed.confirmed_by) == ("observation", "op-1")


def test_an_interface_the_proposal_refused_cannot_acquire_a_role(tmp_path, proposal):
    """Passing it in here would route around the ambiguity check.

    `docs/commissioning.md` §3 makes zero matches and several matches the same
    answer. An interface that failed that check is not commissionable, and a
    caller cannot make it so by handing it to the confirmation step.
    """

    bare = tmp_path / "bare" / "class" / "net" / "eth0"
    bare.mkdir(parents=True)
    (bare / "address").write_text("de:ad:be:ef:00:01\n")
    refused = read_interfaces(bare.parent, permanent_mac_reader=lambda _n: "de:ad:be:ef:00:01")

    with pytest.raises(CommissioningRefused, match="not offered"):
        confirm_roles(
            proposal,
            ((refused[0], "observation"),),
            operator="op-1",
            at=T0,
            profiles_present=REQUIRED_PROFILES,
        )


def test_the_same_interface_cannot_be_confirmed_twice(proposal):
    with pytest.raises(CommissioningRefused, match="confirmed twice"):
        _record(proposal, roles=((0, "observation"), (0, "management")))


@pytest.mark.parametrize("role", ["unassigned", "internal", "external", "decoy", ""])
def test_a_role_outside_the_offerable_list_is_refused(role, proposal):
    with pytest.raises(CommissioningRefused, match="not a role an operator may confirm"):
        _record(proposal, roles=((0, role),))


def test_a_confirmation_without_an_operator_is_refused():
    with pytest.raises(CommissioningRefused, match="who confirmed it"):
        ConfirmedRole(
            composite=(("permanent_mac", "a2:b1:c2:d3:e4:f5"),),
            role="observation",
            confirmed_by="   ",
            confirmed_at=T0,
        )


def test_the_record_binds_to_a_composite_identity_and_not_a_kernel_name(proposal):
    """A role bound to `enp3s0` is bound to one boot's enumeration."""

    record = _record(proposal, roles=((0, "observation"),))
    (confirmed,) = record.roles
    keys = dict(confirmed.composite)

    assert "kernel_name" not in keys
    assert keys, "the composite identity is empty"
    for name in keys:
        assert not name.startswith("kernel"), name


# -- observe-only vs enforcement-ready --------------------------------------


def test_a_record_with_no_roles_is_observe_only(proposal):
    record = _record(proposal, roles=())
    assert record.observe_only is True
    assert record.enforcement_ready is False


def test_a_confirmed_role_leaves_observe_only(proposal):
    record = _record(proposal, roles=((0, "observation"),))
    assert record.observe_only is False


@pytest.mark.parametrize("missing", REQUIRED_PROFILES)
def test_enforcement_is_not_claimed_while_any_profile_is_missing(missing, proposal):
    """Named rather than counted, so a reader learns *which* one is absent."""

    present = tuple(p for p in REQUIRED_PROFILES if p != missing)
    record = _record(proposal, roles=((0, "observation"),), profiles=present)

    assert record.enforcement_ready is False
    assert record.missing_profiles == (missing,)


def test_enforcement_is_not_claimed_on_profiles_alone(proposal):
    """All three profiles and nothing confirmed is a node with nothing to act on."""

    record = _record(proposal, roles=(), profiles=REQUIRED_PROFILES)
    assert record.missing_profiles == ()
    assert record.enforcement_ready is False


def test_enforcement_is_claimed_only_with_both(proposal):
    record = _record(proposal, roles=((0, "observation"),), profiles=REQUIRED_PROFILES)
    assert record.enforcement_ready is True


# -- the digest -------------------------------------------------------------


def test_the_digest_is_the_same_for_the_same_confirmations(proposal):
    """A generation names the commissioning it was rendered from."""

    first = _record(proposal, roles=((0, "observation"),))
    second = _record(proposal, roles=((0, "observation"),))
    assert first.digest() == second.digest()


def test_the_digest_changes_when_a_role_changes(proposal):
    observation = _record(proposal, roles=((0, "observation"),))
    management = _record(proposal, roles=((0, "management"),))
    assert observation.digest() != management.digest()


def test_the_digest_does_not_depend_on_confirmation_order(proposal):
    forward = _record(proposal, roles=((0, "observation"), (1, "management")))
    reverse = _record(proposal, roles=((1, "management"), (0, "observation")))
    assert forward.digest() == reverse.digest()


def test_an_empty_record_still_has_a_digest(proposal):
    """observe-only is a state a generation can be rendered from."""

    assert _record(proposal, roles=()).digest().startswith("sha256:")
