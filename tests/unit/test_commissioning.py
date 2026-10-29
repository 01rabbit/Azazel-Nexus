"""Roles come from the operator, ambiguity fails closed, and missing inputs refuse.

Phase 0b's second row (`docs/roadmap.md`, `docs/commissioning.md` §4). The
proposal reports what an operator would have to settle. It confirms nothing on
their behalf and grants no authority, so most of what follows is about what is
refused and what is left for a person.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from azazel_nexus.commissioning import (
    INTERFACE_ROLES,
    OFFERABLE_ROLES,
    describe_for_operator,
    propose,
)
from azazel_nexus.inventory import InterfaceReadout

ROOT = Path(__file__).resolve().parents[2]

#: What `docs/commissioning.md` §4 named before adopting Fabric's list, and
#: what Azazel-Boot held, copied literally. Kept so the correction stays
#: legible instead of becoming invisible the moment it is made.
RETIRED_ROLE_WORDS = ("protected", "egress", "decoy", "observe", "capture", "internal", "external")

#: Not interface roles. Edge Core's defense actions are recorded verbatim as
#: Edge's decision (docs/integration-loop.md §1), so its vocabulary is spelled
#: as Edge spells it.
EDGE_DECISION_VOCABULARY = {"edge_intake.py": {"observe"}}
#: Not roles: the intake status key of the Deception Lite decoy socket (#196
#: P2, #269/#270) and the readers that render it -- `edge_loop_status.py`, and
#: `status_view.py`, the status read model (#358), which carries the same key
#: into `status --json`. The key names the decoy's own counters; it never
#: carries an interface's role across a product boundary.
STATUS_KEY_NOT_A_ROLE = {
    "edge_intake.py": {"decoy"},
    "edge_loop_status.py": {"decoy"},
    "status_view.py": {"decoy"},
}
#: Not a role: the field name older HIL acquisition records gave the embedded
#: capture, read for compatibility and refused alongside `acquisition` (#374).
#: It names a document key, not what an interface is for.
LEGACY_RECORD_KEY_NOT_A_ROLE = {"hil_records/__init__.py": {"capture"}}
#: Every exemption, keyed by path under `src/azazel_nexus` -- not by file name,
#: which would let one `__init__.py` exempt every other.
NOT_A_ROLE = (EDGE_DECISION_VOCABULARY, STATUS_KEY_NOT_A_ROLE, LEGACY_RECORD_KEY_NOT_A_ROLE)


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


# --------------------------------------------------------------------------
# The proposal settles nothing
# --------------------------------------------------------------------------


def test_a_proposal_carries_no_role_for_any_interface():
    """The structural version of "roles come from the operator".

    Not "the mapping is empty" -- there is no mapping. A proposal that paired
    an interface with a role would be a suggestion, and a suggestion made from
    the only facts available would be an inference from one of them.
    """

    proposal = propose((a_readout(),))

    assert proposal.offerable_roles == OFFERABLE_ROLES
    payload = repr(proposal)
    for readout in proposal.commissionable:
        for role in OFFERABLE_ROLES:
            assert f"{readout.kernel_name}', '{role}" not in payload


def test_unassigned_is_never_offered_as_something_to_confirm():
    """It is what an interface is before anyone confirms anything."""

    assert "unassigned" in INTERFACE_ROLES
    assert "unassigned" not in OFFERABLE_ROLES
    assert set(OFFERABLE_ROLES) == set(INTERFACE_ROLES) - {"unassigned"}


def test_an_interface_without_an_identity_cannot_carry_a_role():
    proposal = propose((a_readout(incomplete_reasons=("permanent_mac could not be read",)),))

    assert proposal.commissioning_required is True
    assert proposal.refused == (("enp4s0", ("permanent_mac could not be read",)),)


def test_two_interfaces_sharing_an_identity_make_both_uncommissionable():
    """Zero matches and several are the same answer (§3).

    The tempting bug is to keep one of them -- they are, after all,
    indistinguishable, so either would do. Either would also be wrong half the
    time, and the node would have chosen without saying so.
    """

    proposal = propose((a_readout(), a_readout(kernel_name="enp5s0")))

    assert proposal.commissionable == ()
    assert proposal.commissioning_required is True
    assert len(proposal.refused) == 2
    assert all("ambiguous" in reasons[0] for _, reasons in proposal.refused)


def test_a_distinct_second_interface_stays_commissionable():
    """The other half of the same rule: distinct identities are not ambiguity."""

    proposal = propose(
        (a_readout(), a_readout(kernel_name="enp5s0", fields={"pci_id": "0x8086:0x15bb"}))
    )

    assert len(proposal.commissionable) == 2
    assert proposal.refused == ()
    assert proposal.commissioning_required is False


def test_an_empty_inventory_is_commissioning_required_not_an_error():
    proposal = propose(())

    assert proposal.commissioning_required is True
    assert proposal.commissionable == ()


# --------------------------------------------------------------------------
# What an operator is shown
# --------------------------------------------------------------------------


def test_the_operator_never_sees_the_kernel_name():
    """They confirm "the port with the blue tag", not `enp4s0`.

    A name the operator cannot check against the machine in front of them
    invites a confirmation that means nothing, and it is not stable enough to
    mean anything anyway.
    """

    described = describe_for_operator(a_readout())

    assert "enp4s0" not in described.values()
    assert "kernel_name" not in described
    assert described["physical_label"] == "LAN1"


def test_only_facts_that_are_present_are_shown():
    """An empty field offered as blank invites confirming against nothing."""

    described = describe_for_operator(a_readout(fields={"physical_label": None}))

    assert "physical_label" not in described
    assert described["bus_path"] == "pci0000:00/0000:04:00.0"


def test_nothing_role_inference_forbids_is_even_read():
    """§4's list, checked against the source rather than promised.

    Fabric refuses these by name in a payload. Nexus's stronger position is
    that `inventory.py` never reads them, so there is nothing to refuse: a
    module that held the carrier state and promised not to use it would be one
    edit away from using it.
    """

    source = (ROOT / "src" / "azazel_nexus" / "inventory.py").read_text(encoding="utf-8")
    for forbidden in ("operstate", "carrier", "default_route", "link_state", "ifindex"):
        assert forbidden not in source, f"inventory.py reads {forbidden!r}"


# --------------------------------------------------------------------------
# The vocabulary is Fabric's
# --------------------------------------------------------------------------


def _string_values(path: Path) -> set[str]:
    """Every string a module *uses*, excluding prose.

    Comments and docstrings are skipped. Naming a retired word in order to
    record that it is retired is the opposite of using it, and a scan that
    could not tell the difference would push the correction's own explanation
    out of the file.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    }


@pytest.mark.parametrize("retired", RETIRED_ROLE_WORDS)
def test_no_retired_role_word_survives_as_a_value(retired):
    """The near-misses are the dangerous ones.

    `observe` against `observation`, `decoy` against `deception_bridge`: both
    read as agreement to anyone skimming, and a reader who saw one and expected
    the other would not notice.
    """

    package = ROOT / "src" / "azazel_nexus"
    offenders = [
        relative
        for relative, path in (
            (path.relative_to(package).as_posix(), path)
            for path in sorted(package.rglob("*.py"))
        )
        if retired in _string_values(path)
        and not any(retired in exempt.get(relative, ()) for exempt in NOT_A_ROLE)
    ]
    assert offenders == [], (
        f"{offenders} use the retired role {retired!r} as a value; Nexus uses "
        "Fabric's registered vocabulary"
    )


def test_every_exemption_still_names_a_word_its_file_holds():
    """An exemption outlives its reason silently unless something checks it.

    A file that is renamed, or that stops using the word, leaves an entry that
    would exempt whatever arrives at that path next.
    """

    package = ROOT / "src" / "azazel_nexus"
    for exempt in NOT_A_ROLE:
        for relative, words in exempt.items():
            values = _string_values(package / relative)
            assert set(words) <= values, f"{relative} no longer uses {sorted(set(words) - values)}"


def test_topology_is_not_readmitted_as_a_role():
    """`protected` and `egress` answered a different question.

    Which side of the boundary an interface faces is topology, it is Nexus's
    own, and it never crosses a product boundary as a role. Putting either back
    into the role list would merge the two axes again -- which is how four
    vocabularies came to disagree in the first place.
    """

    for zone in ("protected", "egress", "egress/module", "internal", "external"):
        assert zone not in OFFERABLE_ROLES
        assert zone not in INTERFACE_ROLES
