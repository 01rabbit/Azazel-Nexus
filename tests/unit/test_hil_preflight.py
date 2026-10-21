"""The preflight answers one question, and says nothing else (#115).

Every identifier in this file is synthetic. The MACs are in the
locally-administered range, the serials say so in their text, and none of them
came off a machine -- `test_no_device_identity_reaches_the_production_tree`
is what keeps it that way for the tree that ships.

What is driven here:

- the two outcomes, and that there is no third
- each `A-` and `B-` item blocking on its own, so a preflight that passed
  because two gaps cancelled would fail here
- that a refusal writes nothing, which is the whole point of refusing before
  the write rather than after it
- that no raw identity and no key material reaches any rendered surface
- that running a preflight changes nothing about Edge authority, leases,
  activation or enforcement
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from azazel_nexus import hil_preflight as preflight
from azazel_nexus.audit import AuditLedger
from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole, propose
from azazel_nexus.hil_preflight import (
    BLOCKED,
    READY,
    OperatorDecisions,
    PreflightRefused,
    PreflightResult,
    Protection,
    ReadonlyInventory,
    anonymous_host_id,
    audit_event,
    evaluate,
    fingerprint,
    persist_commissioning_record,
)
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.wizard import Answer

#: Locally administered (the second nibble is 2), so it cannot collide with a
#: real adapter's burned-in address.
SYNTHETIC_MAC = "02:00:00:00:00:11"
SYNTHETIC_MAC_TWO = "02:00:00:00:00:22"
SYNTHETIC_SERIAL = "SYNTHETIC-SERIAL-0001"
SYNTHETIC_ASSET = "SYNTHETIC-ASSET-0001"
KEY = b"synthetic-commissioning-secret"

#: 8 GiB class: above the CORE floor and below the LITE one.
EIGHT_GIB_MIB = 7900


def readout(mac: str, *, serial: str = SYNTHETIC_SERIAL) -> InterfaceReadout:
    return InterfaceReadout(
        kernel_name="if-synthetic",
        fields={
            "bus_path": "pci-0000:00:1f.6",
            "permanent_mac": mac,
            "pci_id": "8086:15bb",
            "serial": serial,
            "physical_label": "port with the blue tag",
        },
    )


def record(*, roles=("management", "observation")) -> CommissioningRecord:
    return CommissioningRecord(
        roles=tuple(
            ConfirmedRole(
                composite=(("permanent_mac", mac),),
                role=role,
                confirmed_by="operator",
                confirmed_at="2026-09-21T00:00:00Z",
            )
            for role, mac in zip(roles, (SYNTHETIC_MAC, SYNTHETIC_MAC_TWO))
        ),
        profiles_present=("hardware", "resource", "topology"),
        created_at="2026-09-21T00:00:00Z",
    )


def inventory(**overrides) -> ReadonlyInventory:
    base = ReadonlyInventory(
        usable_mib=EIGHT_GIB_MIB,
        architecture="x86_64",
        distribution="Debian GNU/Linux 13 (trixie)",
        os_id="debian",
        os_version_id="13",
        kernel_release="6.1.0-synthetic",
        storage_total_gib=256,
        storage_free_gib=200,
        luks_available=True,
        tpm_available=True,
        interfaces=(readout(SYNTHETIC_MAC), readout(SYNTHETIC_MAC_TWO)),
        wireless_enumerated=True,
        link_observed=True,
    )
    return replace(base, **overrides)


def decisions(**overrides) -> OperatorDecisions:
    base = OperatorDecisions(
        record=record(),
        answers=(Answer("if-1", "management"), Answer("if-2", "observation")),
        external_communication_forbidden=True,
        responsible="operator",
        at="2026-09-21T00:00:00Z",
        host_label=SYNTHETIC_ASSET,
        approval_id="approval-synthetic-1",
        reboot_approved=True,
        administrative_rights=True,
    )
    return replace(base, **overrides)


def run(inv=None, dec=None, *, protection=None, generation=7) -> PreflightResult:
    return evaluate(
        inv or inventory(),
        dec or decisions(),
        protection=protection or Protection(luks_backed=True, key_available=True),
        generation=generation,
        key=KEY,
    )


# -- two answers, and no third --------------------------------------------


def test_the_vocabulary_has_exactly_two_outcomes():
    """A middle value is one somebody proceeds from."""

    assert preflight.OUTCOMES == (READY, BLOCKED)
    for absent in ("PARTIAL", "READY_WITH_WARNINGS", "UNKNOWN", "INCONCLUSIVE"):
        assert absent not in preflight.__dict__


def test_a_third_outcome_cannot_be_constructed():
    with pytest.raises(ValueError):
        PreflightResult(outcome="HIL_PREFLIGHT_MAYBE", missing=("A-1",))


def test_a_blocked_result_must_name_what_is_missing():
    with pytest.raises(ValueError):
        PreflightResult(outcome=BLOCKED)


def test_a_ready_result_cannot_carry_something_missing():
    with pytest.raises(ValueError):
        PreflightResult(outcome=READY, missing=("A-1",))


def test_a_complete_node_is_ready():
    result = run()
    assert result.outcome == READY
    assert result.missing == ()
    assert result.eight_gib_class is True


# -- each item blocks on its own ------------------------------------------


@pytest.mark.parametrize(
    "code,override",
    [
        ("A-1", {"usable_mib": 32000}),
        ("A-2", {"architecture": None}),
        ("A-3", {"distribution": None}),
        ("A-4", {"kernel_release": None}),
        ("A-5", {"storage_total_gib": None}),
        ("A-6", {"storage_free_gib": None}),
        ("A-7", {"luks_available": False}),
        ("A-8", {"tpm_available": False}),
        ("A-9", {"interfaces": ()}),
        ("A-10", {"wireless_enumerated": False}),
        ("A-11", {"link_observed": None}),
    ],
)
def test_every_readonly_item_blocks_on_its_own(code, override):
    """Driven one at a time. A preflight checked only in aggregate is one
    where a second gap can hide behind the first."""

    result = run(inventory(**override))
    assert result.outcome == BLOCKED
    assert code in result.missing


@pytest.mark.parametrize(
    "code,override",
    [
        ("B-1", {"record": record(roles=("observation",))}),
        ("B-2", {"record": record(roles=("management",))}),
        ("B-3", {"answers": (Answer("if-1", "management"),)}),
        ("B-4", {"external_communication_forbidden": None}),
        ("B-5", {"responsible": "  "}),
        ("B-6", {"at": ""}),
        ("B-7", {"host_label": ""}),
        ("B-8", {"reboot_approved": False}),
        ("B-9", {"administrative_rights": False}),
        ("B-9", {"approval_id": ""}),
    ],
)
def test_every_operator_item_blocks_on_its_own(code, override):
    result = run(dec=decisions(**override))
    assert result.outcome == BLOCKED
    assert code in result.missing


def test_the_codes_cover_the_published_item_lists():
    """A code that blocks and is not in the list is a code an operator cannot
    look up."""

    assert set(preflight.READONLY_ITEMS) == {f"A-{n}" for n in range(1, 12)}
    assert set(preflight.OPERATOR_ITEMS) == {f"B-{n}" for n in range(1, 10)}


def test_no_record_at_all_is_blocked_rather_than_treated_as_observe_only():
    result = run(dec=decisions(record=None))
    assert result.outcome == BLOCKED
    assert "B-1" in result.missing


# -- no role is ever inferred ---------------------------------------------


def test_an_interface_with_no_answer_is_unanswered_and_not_unassigned():
    """`unassigned` is what an operator chose; silence is not a choice."""

    result = run(dec=decisions(answers=(Answer("if-1", "management"),)))
    assert result.outcome == BLOCKED
    assert "B-3" in result.missing


def test_an_explicit_skip_counts_as_an_answer_and_is_reported_as_unassigned():
    result = evaluate(
        inventory(interfaces=(readout(SYNTHETIC_MAC), readout(SYNTHETIC_MAC_TWO), readout("02:00:00:00:00:33"))),
        decisions(
            answers=(
                Answer("if-1", "management"),
                Answer("if-2", "observation"),
                Answer("if-3", None),
            )
        ),
        protection=Protection(luks_backed=True, key_available=True),
        generation=1,
        key=KEY,
    )
    assert result.outcome == READY
    assert result.unassigned == 1


def test_the_preflight_calls_nothing_that_assigns_a_role():
    """Read as a syntax tree, not as prose: a scan that cannot tell a
    docstring from a call is one the next explanation silences."""

    import ast

    tree = ast.parse(Path(preflight.__file__).read_text(encoding="utf-8"))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                called.add(target.id)
            elif isinstance(target, ast.Attribute):
                called.add(target.attr)
    assert "confirm_roles" not in called, "the preflight confirmed a role"
    assert "propose" not in called, "the preflight built its own proposal"


def test_the_connectivity_reading_is_not_handed_to_the_role_path():
    """`A-11` is a fact about the node. `docs/commissioning.md` §4 forbids
    resolving a role from carrier or link state, so the value must not reach
    the proposal."""

    proposal = propose((readout(SYNTHETIC_MAC),))
    assert not any("carrier" in str(field) for field in proposal.commissionable)
    assert "link_observed" not in str(proposal)


# -- a refusal writes nothing ---------------------------------------------


@pytest.mark.parametrize(
    "protection",
    [
        Protection(luks_backed=False, key_available=True),
        Protection(luks_backed=True, key_available=False),
        Protection(luks_backed=False, key_available=False),
    ],
)
def test_without_protected_storage_the_answer_is_blocked(protection):
    result = run(protection=protection)
    assert result.outcome == BLOCKED
    assert {"A-7", "A-8"} <= set(result.missing)


@pytest.mark.parametrize(
    "protection",
    [
        Protection(luks_backed=False, key_available=True),
        Protection(luks_backed=True, key_available=False),
    ],
)
def test_a_refused_write_leaves_the_directory_empty(tmp_path, protection):
    """The raw inventory has nowhere it may go, so it goes nowhere. A write
    followed by a complaint would already have done the thing refused."""

    directory = tmp_path / "commissioning"
    with pytest.raises(PreflightRefused):
        persist_commissioning_record(
            record(), directory=directory, protection=protection
        )
    assert not directory.exists()


def test_a_protected_write_stores_the_existing_record_format(tmp_path):
    """One format. The document is built from the fields the digest covers,
    so a stored record and its digest cannot disagree."""

    directory = tmp_path / "commissioning"
    path = persist_commissioning_record(
        record(),
        directory=directory,
        protection=Protection(luks_backed=True, key_available=True),
    )
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["digest"] == record().digest()
    assert sorted(stored) == [
        "created_at",
        "digest",
        "generation",
        "profiles_present",
        "roles",
    ]


# -- nothing raw and nothing secret reaches a reader ----------------------


def _rendered_surfaces(result: PreflightResult) -> tuple[str, ...]:
    return (
        "\n".join(result.lines()),
        json.dumps(audit_event(result, approval_id="approval-synthetic-1")),
        repr(result),
    )


@pytest.mark.parametrize("secret", [SYNTHETIC_MAC, SYNTHETIC_SERIAL, SYNTHETIC_ASSET])
def test_no_raw_identity_reaches_any_rendered_surface(secret):
    for result in (run(), run(inventory(architecture=None))):
        for surface in _rendered_surfaces(result):
            assert secret not in surface, f"{secret} reached: {surface}"


def test_no_key_material_reaches_any_rendered_surface():
    """Including through an exception, which is the surface people forget."""

    readable = KEY.decode()
    for result in (run(), run(inventory(usable_mib=32000))):
        for surface in _rendered_surfaces(result):
            assert readable not in surface
    try:
        persist_commissioning_record(
            record(),
            directory=Path("/nonexistent"),
            protection=Protection(luks_backed=False, key_available=True),
        )
    except PreflightRefused as exc:
        assert readable not in str(exc)


def test_a_blocked_answer_shows_classifications_and_no_values():
    result = run(inventory(architecture=None, kernel_release=None))
    lines = result.lines()
    assert lines[0] == BLOCKED
    assert set(lines[1:]) == {"missing: A-2", "missing: A-4"}


def test_a_ready_answer_shows_exactly_the_permitted_fields():
    """Compared whole, not by prefix. A check that read only the label of
    each line would pass on a line that carried a second value after it, and
    a second value is how the one that must not be shown gets shown.
    """

    result = run()
    assert result.lines() == (
        READY,
        f"host: {result.anonymous_host_id}",
        "record generation: 7",
        f"fingerprint: {result.fingerprint}",
        "roles approved: management=1, observation=1",
        "unassigned interfaces: 0",
        "memory class: core (8 GiB class)",
        f"runbook: {result.runbook_id}",
    )
    assert result.anonymous_host_id not in result.fingerprint
    assert result.runbook_id not in result.fingerprint


def test_the_audit_event_holds_only_the_closed_list():
    ready = audit_event(run(), approval_id="approval-synthetic-1")
    assert set(ready) == {
        "event_type",
        "transition",
        "outcome",
        "approval_id",
        "anonymous_host_id",
        "record_generation",
        "fingerprint",
        "runbook_id",
    }
    blocked = audit_event(run(inventory(architecture=None)), approval_id="a")
    assert set(blocked) == {
        "event_type",
        "transition",
        "outcome",
        "approval_id",
        "missing",
    }
    assert blocked["missing"] == ["A-2"]


def test_the_audit_event_chains_like_every_other_event(tmp_path):
    """The existing ledger, not a second one."""

    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append(audit_event(run(), approval_id="approval-synthetic-1"))
    ledger.verify()


# -- the derived identity is keyed ----------------------------------------


def test_the_fingerprint_is_keyed_and_refuses_to_be_a_bare_hash():
    with pytest.raises(ValueError):
        fingerprint("anything", key=b"")
    assert fingerprint("x", key=b"a") != fingerprint("x", key=b"b")


def test_the_anonymous_host_id_does_not_carry_the_label_it_names():
    host = anonymous_host_id(SYNTHETIC_ASSET, key=KEY)
    assert SYNTHETIC_ASSET not in host
    assert host != anonymous_host_id(SYNTHETIC_ASSET, key=b"another-key")


def test_the_runbook_id_changes_with_the_generation():
    """A runbook that named two generations would be one an operator cannot
    tell apart from the run it belongs to."""

    assert run(generation=1).runbook_id != run(generation=2).runbook_id


# -- what the module may not do -------------------------------------------


# lab_host only reads the absolute refusal marker; it cannot grant admission,
# activate a unit, write a measurement or import the separate lab distribution.
ALLOWED_PACKAGE_IMPORTS = {"commissioning", "inventory", "resource_profile", "wizard", "lab_host"}


def test_the_preflight_reaches_only_the_modules_it_reuses():
    """Named so that a later edit that admits a provider, activates a unit or
    writes a measurement has to change this set first."""

    import ast

    tree = ast.parse(Path(preflight.__file__).read_text(encoding="utf-8"))
    reached = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            reached.add(node.module.split(".")[0])
    assert reached <= ALLOWED_PACKAGE_IMPORTS, (
        f"{sorted(reached - ALLOWED_PACKAGE_IMPORTS)} is outside what the "
        "preflight reuses; a preflight that reached them could admit a "
        "provider, activate a unit or write a measurement"
    )


@pytest.mark.parametrize(
    "forbidden",
    ["provider_registry", "source_registry", "model_runtime", "model_import",
     "activation", "signature", "core_reserve", "spki"],
)
def test_the_preflight_cannot_admit_run_activate_or_measure(forbidden):
    assert forbidden not in Path(preflight.__file__).read_text(encoding="utf-8")


def test_the_preflight_never_samples():
    """`docs/core-reserve-measurement.md` is the campaign. This is the gate
    in front of it, and a gate that sampled would be producing the evidence
    it is supposed to authorise."""

    source = Path(preflight.__file__).read_text(encoding="utf-8")
    for word in ("Sample(", "resident_mib", "MEASURED", "provenance"):
        assert word not in source


# -- Edge authority, leases, activation and enforcement are unchanged ------


def test_a_preflight_changes_nothing_about_edge_authority(tmp_path):
    """The doctrine: the deterministic arbiter from Azazel-Edge holds the
    final authority. A preflight is an observation and an operator's
    decisions; it grants nothing, and the node's answers are the same after
    it as before."""

    from azazel_nexus.capability import CORE_CAPABILITIES, state_for

    before = (
        state_for(frozenset(CORE_CAPABILITIES)),
        record().enforcement_ready,
        record().observe_only,
        record().digest(),
    )
    directory = tmp_path / "commissioning"
    result = run()
    persist_commissioning_record(
        record(),
        directory=directory,
        protection=Protection(luks_backed=True, key_available=True),
    )
    AuditLedger(tmp_path / "audit.jsonl").append(
        audit_event(result, approval_id="approval-synthetic-1")
    )
    after = (
        state_for(frozenset(CORE_CAPABILITIES)),
        record().enforcement_ready,
        record().observe_only,
        record().digest(),
    )
    assert before == after


def test_a_preflight_writes_only_the_record_and_the_audit(tmp_path):
    """Everything it may write, it writes where it was told. A file anywhere
    else is a side effect nobody asked for."""

    root = tmp_path / "root"
    (root / "commissioning").mkdir(parents=True)
    (root / "elsewhere").mkdir()
    before = sorted(p.relative_to(root) for p in root.rglob("*"))

    result = run()
    persist_commissioning_record(
        record(),
        directory=root / "commissioning",
        protection=Protection(luks_backed=True, key_available=True),
    )
    AuditLedger(root / "commissioning" / "audit.jsonl").append(
        audit_event(result, approval_id="approval-synthetic-1")
    )

    after = sorted(p.relative_to(root) for p in root.rglob("*"))
    added = set(after) - set(before)
    assert added == {
        Path("commissioning/commissioning.json"),
        Path("commissioning/audit.jsonl"),
    }


# -- the readings themselves ----------------------------------------------


def test_luks_is_read_from_device_mapper_and_nothing_is_executed(tmp_path):
    sysfs = tmp_path / "block"
    (sysfs / "254:0" / "dm").mkdir(parents=True)
    (sysfs / "254:0" / "dm" / "uuid").write_text("CRYPT-LUKS2-synthetic\n")

    class _Stat:
        st_dev = os.makedev(254, 0)

    assert preflight.luks_backed(
        tmp_path, stat=lambda _p: _Stat(), sysfs_dev_block=sysfs
    )


def test_a_plain_device_is_not_luks_backed(tmp_path):
    sysfs = tmp_path / "block"
    (sysfs / "8:1").mkdir(parents=True)

    class _Stat:
        st_dev = os.makedev(8, 1)

    assert not preflight.luks_backed(
        tmp_path, stat=lambda _p: _Stat(), sysfs_dev_block=sysfs
    )


def test_an_unreadable_sysfs_is_not_read_as_encrypted(tmp_path):
    """The wrong answer in the one direction that matters."""

    class _Stat:
        st_dev = os.makedev(254, 0)

    assert not preflight.luks_backed(
        tmp_path, stat=lambda _p: _Stat(), sysfs_dev_block=tmp_path / "absent"
    )


# -- the three-valued diagnostic reader (#242 §4) -------------------------------


def _sysfs_case(tmp_path, case):
    """A synthetic /sys/dev/block for device 254:3, and the stat to use."""
    sysfs = tmp_path / "block"
    entry = sysfs / "254:3"
    if case != "anonymous":
        entry.mkdir(parents=True)
    if case in ("luks", "lvm", "empty_uuid", "uuid_unreadable", "uuid_missing"):
        (entry / "dm").mkdir()
    if case == "luks":
        (entry / "dm" / "uuid").write_text("CRYPT-LUKS2-synthetic-azn-commissioning\n")
    elif case == "lvm":
        (entry / "dm" / "uuid").write_text("LVM-synthetic\n")
    elif case == "empty_uuid":
        (entry / "dm" / "uuid").write_text("\n")
    elif case == "uuid_unreadable":
        (entry / "dm" / "uuid").mkdir()  # reading it raises IsADirectoryError

    def stat(_path):
        if case == "stat_fails":
            raise PermissionError("synthetic")
        return os.stat_result((0o40755, 0, os.makedev(254, 3), 1, 0, 0, 0, 0, 0, 0))
    return sysfs, stat


#: case: (luks_backing, luks_backed -- unchanged, the refusal paths' answer)
_BACKING_CASES = {
    "luks": (True, True),
    "lvm": (False, False),
    "empty_uuid": (False, False),
    "plain_device": (False, False),
    "anonymous": (None, False),
    "stat_fails": (None, False),
    "uuid_unreadable": (None, False),
    "uuid_missing": (None, False),
}


@pytest.mark.parametrize("case", sorted(_BACKING_CASES))
def test_luks_backing_says_none_when_it_cannot_tell_and_luks_backed_is_unchanged(
        tmp_path, case):
    """`anonymous`: no /sys/dev/block entry, as for a btrfs subvolume or tmpfs."""
    sysfs, stat = _sysfs_case(tmp_path, case)
    backing, backed = _BACKING_CASES[case]
    assert preflight.luks_backing(tmp_path, stat=stat, sysfs_dev_block=sysfs) is backing
    assert preflight.luks_backed(tmp_path, stat=stat, sysfs_dev_block=sysfs) is backed


def test_an_unreadable_sysfs_tree_is_undetermined_for_the_label(tmp_path):
    """The whole /sys/dev/block missing (not mounted, hidden): no answer."""

    class _Stat:
        st_dev = os.makedev(254, 0)

    assert preflight.luks_backing(
        tmp_path, stat=lambda _p: _Stat(), sysfs_dev_block=tmp_path / "absent"
    ) is None


def test_a_tpm_is_presence_only(tmp_path):
    (tmp_path / "tpm0").mkdir()
    assert preflight.tpm_present(tmp_path)
    assert not preflight.tpm_present(tmp_path / "absent")


def test_the_distribution_falls_back_but_never_invents(tmp_path):
    pretty = tmp_path / "pretty"
    pretty.write_text('PRETTY_NAME="Synthetic Linux 1"\n')
    assert preflight.read_os_release(pretty) == "Synthetic Linux 1"

    parts = tmp_path / "parts"
    parts.write_text('ID=synthetic\nVERSION_ID="1"\n')
    assert preflight.read_os_release(parts) == "synthetic 1"

    empty = tmp_path / "empty"
    empty.write_text("NAME=something\n")
    assert preflight.read_os_release(empty) is None
    assert preflight.read_os_release(tmp_path / "absent") is None


# -- the collection itself ------------------------------------------------


def _collect(tmp_path, **overrides):
    node_net = tmp_path / "net"
    node_net.mkdir(exist_ok=True)
    (node_net / "enp4s0").mkdir(exist_ok=True)
    (node_net / "enp4s0" / "carrier").write_text("1\n")
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(f"MemTotal:       {EIGHT_GIB_MIB * 1024} kB\n")
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n'
    )
    arguments = {
        "interfaces": (readout(SYNTHETIC_MAC),),
        "sysfs_net": node_net,
        "meminfo": meminfo,
        "os_release": os_release,
        "record_directory": tmp_path,
        "sysfs_dev_block": tmp_path / "absent-block",
        "sysfs_tpm": tmp_path / "absent-tpm",
    }
    arguments.update(overrides)
    return preflight.collect_readonly_inventory(**arguments)


def test_an_unreadable_sysfs_is_not_an_enumeration_that_found_nothing(tmp_path):
    """`A-10` asks whether this node could say what wireless adapters it has.
    "None" is an answer; "the directory could not be read" is not, and the two
    must not collapse into the same `False`."""

    collected = _collect(tmp_path, sysfs_net=tmp_path / "absent-net")
    assert collected.wireless_enumerated is False
    assert "A-10" in collected.missing
    assert collected.link_observed is None
    assert "A-11" in collected.missing


def test_a_readable_sysfs_answers_both_the_wireless_and_the_link_questions(tmp_path):
    collected = _collect(tmp_path)
    assert collected.wireless_enumerated is True
    assert collected.link_observed is True
    assert "A-10" not in collected.missing
    assert "A-11" not in collected.missing


def test_an_interface_with_no_carrier_file_leaves_the_question_unanswered(tmp_path):
    net = tmp_path / "quiet-net"
    (net / "enp4s0").mkdir(parents=True)
    collected = _collect(tmp_path, sysfs_net=net)
    assert collected.link_observed is None


def test_a_link_that_is_down_is_an_answer_rather_than_a_gap(tmp_path):
    net = tmp_path / "down-net"
    (net / "enp4s0").mkdir(parents=True)
    (net / "enp4s0" / "carrier").write_text("0\n")
    collected = _collect(tmp_path, sysfs_net=net)
    assert collected.link_observed is False
    assert "A-11" not in collected.missing


def test_an_unreadable_meminfo_blocks_rather_than_reading_as_a_small_machine(tmp_path):
    collected = _collect(tmp_path, meminfo=tmp_path / "absent-meminfo")
    assert collected.usable_mib is None
    assert "A-1" in collected.missing


def test_the_collection_classifies_the_eight_gib_band(tmp_path):
    assert _collect(tmp_path).eight_gib_class is True
    big = tmp_path / "big-meminfo"
    big.write_text(f"MemTotal:       {32000 * 1024} kB\n")
    assert _collect(tmp_path, meminfo=big).eight_gib_class is False
    small = tmp_path / "small-meminfo"
    small.write_text("MemTotal:       2000000 kB\n")
    assert _collect(tmp_path, meminfo=small).eight_gib_class is False



# -- no device identity in the tree that ships ----------------------------


PRODUCTION_TREES = ("src", "runtime/src", "docs", "packaging", "contract", "tests/fixtures")
MAC_SHAPED = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
#: The all-zero address is a constant `azazel_nexus.inventory` compares
#: against, not a device's address.
PERMITTED = {"00:00:00:00:00:00"}
REPO = Path(__file__).resolve().parents[2]


def test_no_device_identity_reaches_the_production_tree():
    """Synthetic identity is a test fixture. A real one in the tree that
    ships is an identifier published to everyone who clones it."""

    found: dict[str, list[str]] = {}
    for tree in PRODUCTION_TREES:
        for path in sorted((REPO / tree).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            offenders = [m for m in MAC_SHAPED.findall(text) if m not in PERMITTED]
            if offenders:
                found[str(path.relative_to(REPO))] = sorted(set(offenders))
    assert found == {}, f"hardware addresses in the shipped tree: {found}"


def test_every_address_in_the_suite_is_locally_administered():
    """A synthetic address has to be one that cannot collide with a real
    adapter: the locally-administered bit is what says so."""

    offenders: dict[str, list[str]] = {}
    for path in sorted((REPO / "tests").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        bad = [
            mac
            for mac in MAC_SHAPED.findall(text)
            if mac not in PERMITTED
            and not (int(mac.split(":")[0], 16) & 0b10)
        ]
        if bad:
            offenders[path.name] = sorted(set(bad))
    assert offenders == {}, (
        f"addresses that are not locally administered: {offenders}. A "
        "fixture address must be one no real adapter can have"
    )


# -- one command, run on the target ---------------------------------------
#
# The point of the command: an operator runs it and reads two words, instead
# of transcribing twenty facts into a conversation where each one is a copy of
# an identifier somewhere it does not belong.


KERNEL_NAMES = ("enp4s0", "enp5s0")


def _sysfs_tree(tmp_path: Path) -> Path:
    root = tmp_path / "sys"
    net = root / "class" / "net"
    for index, name in enumerate(KERNEL_NAMES):
        slot = f"0000:0{index + 4}:00.0"
        bus = root / "devices" / "pci0000:00" / slot
        bus.mkdir(parents=True)
        (bus / "vendor").write_text("0x8086\n")
        (bus / "device").write_text(f"0x15b{index}\n")
        (bus / "label").write_text(f"LAN{index + 1}\n")
        interface = net / name
        interface.mkdir(parents=True)
        (interface / "device").symlink_to(f"../../../devices/pci0000:00/{slot}")
        (interface / "carrier").write_text("1\n")
    return net


def _protected_node(tmp_path: Path) -> dict:
    """A node that can protect what it is about to be asked to store."""

    meminfo = tmp_path / "meminfo"
    meminfo.write_text(f"MemTotal:       {EIGHT_GIB_MIB * 1024} kB\n")
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n'
    )

    record_dir = tmp_path / "commissioning"
    record_dir.mkdir()
    stat = os.stat(record_dir)
    dev_block = tmp_path / "dev-block"
    (dev_block / f"{os.major(stat.st_dev)}:{os.minor(stat.st_dev)}" / "dm").mkdir(
        parents=True
    )
    (
        dev_block
        / f"{os.major(stat.st_dev)}:{os.minor(stat.st_dev)}"
        / "dm"
        / "uuid"
    ).write_text("CRYPT-LUKS2-synthetic\n")

    tpm = tmp_path / "tpm"
    (tpm / "tpm0").mkdir(parents=True)

    key = tmp_path / "key"
    key.write_bytes(KEY)

    boot_id = tmp_path / "boot-id"
    boot_id.write_text("00000000-0000-4000-8000-000000000001\n")

    return {
        "boot_id": boot_id,
        "meminfo": meminfo,
        "os_release": os_release,
        "record_dir": record_dir,
        "dev_block": dev_block,
        "tpm": tpm,
        "key": key,
    }


def _cli(tmp_path, node, *, answers, texts, confirms, audit=None, architecture="x86_64"):
    import io

    from azazel_nexus.cli import main

    out = io.StringIO()
    answered = iter(answers)
    confirmed = iter(confirms)
    written = iter(texts)
    argv = [
        "--sysfs",
        str(_sysfs_tree(tmp_path)),
        "hil-preflight",
        "--record-dir",
        str(node["record_dir"]),
        "--key",
        str(node["key"]),
        "--meminfo",
        str(node["meminfo"]),
        "--os-release",
        str(node["os_release"]),
        "--sysfs-dev-block",
        str(node["dev_block"]),
        "--sysfs-tpm",
        str(node["tpm"]),
        "--boot-id",
        str(node["boot_id"]),
    ]
    if audit is not None:
        argv += ["--audit", str(audit)]
    # This helper already supplies synthetic OS, RAM, TPM and storage. Do not
    # accidentally combine those fixtures with the test runner's real CPU.
    # Production detection/gates remain unchanged, including ARM64 refusal.
    def collect(**kwargs):
        return preflight.collect_readonly_inventory(**kwargs, uname=lambda: os.uname_result(
            ("Linux", "synthetic", "synthetic-kernel", "synthetic", architecture)))
    with patch("azazel_nexus.cli.collect_readonly_inventory", side_effect=collect):
        code = main(
            argv,
            out=out,
            ask=lambda prompt, choices: next(answered),
            confirm=lambda prompt: next(confirmed),
            text=lambda prompt: next(written),
            permanent_mac_reader=lambda name: f"02:00:00:00:00:{KERNEL_NAMES.index(name):02x}",
        )
    return code, out.getvalue()


def test_the_command_answers_ready_on_a_protected_node(tmp_path):
    node = _protected_node(tmp_path)
    audit = tmp_path / "audit.jsonl"
    code, text = _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
        audit=audit,
    )
    assert code == 0
    assert READY in text
    assert "runbook: hil-8gib-" in text
    assert (node["record_dir"] / "commissioning.json").is_file()
    AuditLedger(audit).verify()


def test_arm64_cannot_pass_the_amd64_hil_campaign_gate(tmp_path):
    node = _protected_node(tmp_path)
    code, text = _cli(tmp_path, node, answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"], confirms=[True, True, True, True],
        architecture="aarch64")
    assert code == 1
    assert BLOCKED in text and "A-2" in text
    assert READY not in text
    assert not (node["record_dir"] / "commissioning.json").exists()


def test_the_command_prints_no_identity_on_the_ready_path(tmp_path):
    """The rows an operator chooses from are on their screen. What the
    command *returns* carries none of it -- and neither does the kernel name,
    which `docs/commissioning.md` §4 keeps off an operator's screen too."""

    node = _protected_node(tmp_path)
    _, text = _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
    )
    result = text.split(READY, 1)[1]
    for secret in (SYNTHETIC_ASSET, KEY.decode(), *KERNEL_NAMES):
        assert secret not in result
    assert not MAC_SHAPED.search(result)


def test_an_unprotected_node_is_blocked_and_stores_nothing(tmp_path):
    """No LUKS: the raw inventory has nowhere to go, so the command answers
    blocked and the directory stays empty."""

    node = _protected_node(tmp_path)
    for uuid in node["dev_block"].rglob("uuid"):
        uuid.write_text("LVM-synthetic\n")
    code, text = _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
    )
    assert code == 1
    assert BLOCKED in text
    assert "missing: A-7" in text
    assert list(node["record_dir"].iterdir()) == []


def test_a_node_of_another_memory_class_is_blocked(tmp_path):
    """A 16 GiB machine is not this campaign's target, and a reserve measured
    on one class says nothing about another."""

    node = _protected_node(tmp_path)
    node["meminfo"].write_text(f"MemTotal:       {16000 * 1024} kB\n")
    code, text = _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
    )
    assert code == 1
    assert "missing: A-1" in text
    assert list(node["record_dir"].iterdir()) == []


def test_without_a_prompt_the_command_settles_nothing(tmp_path):
    import io

    from azazel_nexus.cli import main

    out = io.StringIO()
    code = main(
        ["--sysfs", str(_sysfs_tree(tmp_path)), "hil-preflight"],
        out=out,
    )
    assert code == 2
    assert READY not in out.getvalue()


# -- the document says what the code does ---------------------------------


DOC = REPO / "docs" / "hil-preflight.md"


def _doc() -> str:
    return " ".join(DOC.read_text(encoding="utf-8").split())


@pytest.mark.parametrize(
    "statement",
    [
        "It takes no sample, reboots nothing, activates no unit, admits no provider, runs no model and reaches no network.",
        "**Nothing else.** No operator, no timestamp, no identifier.",
        "An audit whose instants were chosen by the thing being audited records a story rather than a sequence",
        "A terminal is not one of the two places raw identity may go.",
        "**a preflight with a middle value is a preflight somebody proceeds from.**",
        "**No role is inferred.**",
        "**No value from the inventory appears on either path.**",
        "**so it goes nowhere**: the record is not written at all",
        "A second format would be a second identity policy.",
        "A ready preflight says a campaign **may begin**.",
    ],
)
def test_the_document_keeps_the_statements_the_code_is_built_on(statement):
    assert statement in _doc(), f"the document lost: {statement}"


def test_the_document_agrees_with_the_vocabulary_it_describes():
    text = _doc()
    for outcome in preflight.OUTCOMES:
        assert outcome in text
    for absent in ("PARTIAL", "READY_WITH_WARNINGS", "PROBABLY"):
        assert f"no `{absent}`" in text or f"`{absent}`" in text


def test_the_document_carries_no_identity():
    text = DOC.read_text(encoding="utf-8")
    assert not MAC_SHAPED.search(text)
    assert re.findall(r"\b[0-9a-fA-F]{16,}\b", text) == []


# -- the command line carries nothing about anybody -----------------------
#
# A command line is read by everyone on the host: `ps`, `/proc/<pid>/cmdline`
# and the shell's history file. An identifier passed as an argument is an
# identifier published to all three, by the operator, in the act of asking
# whether they may begin.


def _preflight_parser_options() -> set[str]:
    import argparse
    import io
    import contextlib

    from azazel_nexus.cli import main

    # The parser is built inside `main`; the usage line is what it will
    # accept, so it is read rather than reconstructed.
    out = io.StringIO()
    with contextlib.suppress(SystemExit), contextlib.redirect_stdout(out):
        main(["hil-preflight", "--help"])
    return set(re.findall(r"--[a-z0-9-]+", out.getvalue()))


@pytest.mark.parametrize(
    "rejected",
    ["--operator", "--at", "--asset-id", "--serial", "--mac", "--tpm-identity",
     "--host", "--approval-id", "--generation"],
)
def test_no_identity_or_instant_can_be_passed_on_the_command_line(rejected, tmp_path):
    import io

    from azazel_nexus.cli import main

    with pytest.raises(SystemExit):
        main(["hil-preflight", rejected, "anything"], out=io.StringIO())


def test_the_published_command_is_the_bare_one():
    """Everything the command still accepts is a path the node reads itself
    from, and every one of them is hidden. What an operator types is
    `azazel-nexus hil-preflight`."""

    assert _preflight_parser_options() <= {"--help"}


def test_the_operator_is_the_local_principal_and_not_a_name():
    """Credentials the kernel already knows, so nobody types a name."""

    principal = preflight.local_principal(getuid=lambda: 1000, getgid=lambda: 1000)
    assert principal == "uid:1000/gid:1000"
    assert "@" not in principal


def test_the_instant_comes_from_the_node_and_not_from_a_caller():
    """An audit whose instants were chosen by the thing being audited records
    a story rather than a sequence."""

    stamp, boot = preflight.node_clock(
        clock=lambda: 1_600_000_000.0, boot_id_path=Path("/nonexistent")
    )
    assert stamp == "2020-09-13T12:26:40Z"
    assert boot is None


def test_the_boot_is_inside_the_fingerprint_and_never_beside_it(tmp_path):
    """Two runs on separate boots must be distinguishable in the audit, and
    the boot ID itself is raw identity that may not appear there."""

    first = evaluate(
        inventory(),
        decisions(),
        protection=Protection(luks_backed=True, key_available=True),
        generation=1,
        key=KEY,
        boot_id="00000000-0000-4000-8000-000000000001",
    )
    second = evaluate(
        inventory(),
        decisions(),
        protection=Protection(luks_backed=True, key_available=True),
        generation=1,
        key=KEY,
        boot_id="00000000-0000-4000-8000-000000000002",
    )
    assert first.fingerprint != second.fingerprint
    for surface in _rendered_surfaces(first):
        assert "00000000-0000-4000-8000-000000000001" not in surface


def test_the_generation_is_read_from_the_node_rather_than_supplied(tmp_path):
    """A counter a caller could reset is a record that can claim to be the
    first one."""

    directory = tmp_path / "commissioning"
    assert preflight.next_generation(directory) == 1
    persist_commissioning_record(
        record(),
        directory=directory,
        protection=Protection(luks_backed=True, key_available=True),
        generation=1,
    )
    assert preflight.next_generation(directory) == 2


def test_an_unreadable_record_does_not_restart_the_count_silently(tmp_path):
    directory = tmp_path / "commissioning"
    directory.mkdir()
    (directory / "commissioning.json").write_text("{ this is not json")
    assert preflight.next_generation(directory) == 1


def test_the_screen_shows_no_raw_identity():
    """`describe_for_operator` is the wider set and carries the serial and
    the device ids. A terminal is not one of the two places raw identity may
    go."""

    from azazel_nexus.commissioning import describe_for_operator

    shown = preflight.describe_for_screen(readout(SYNTHETIC_MAC))
    wider = describe_for_operator(readout(SYNTHETIC_MAC))
    assert set(shown) == {"physical_label", "bus_path"}
    assert "serial" in wider and "serial" not in shown
    assert SYNTHETIC_SERIAL not in json.dumps(shown)
    assert SYNTHETIC_MAC not in json.dumps(shown)


def test_the_whole_session_prints_nothing_about_the_operator(tmp_path):
    """Every line the command writes, from the interface rows to the answer:
    no principal, no serial, no MAC, no timestamp, no boot ID."""

    node = _protected_node(tmp_path)
    _, text = _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
    )
    assert not MAC_SHAPED.search(text)
    for forbidden in (
        SYNTHETIC_ASSET,
        SYNTHETIC_SERIAL,
        KEY.decode(),
        "uid:",
        "gid:",
        node["boot_id"].read_text().strip(),
    ):
        assert forbidden not in text, f"{forbidden!r} reached the terminal"
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", text), (
        "a raw instant reached the terminal"
    )


def test_the_audit_carries_no_principal_and_no_instant(tmp_path):
    """The closed list has no room for either, and a run that added one
    would be adding it to the append-only store."""

    node = _protected_node(tmp_path)
    audit = tmp_path / "audit.jsonl"
    _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
        audit=audit,
    )
    text = audit.read_text(encoding="utf-8")
    for forbidden in ("uid:", "gid:", SYNTHETIC_ASSET, node["boot_id"].read_text().strip()):
        assert forbidden not in text
    assert not MAC_SHAPED.search(text)
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", text)


def test_the_principal_and_the_instant_reach_the_encrypted_record(tmp_path):
    """They are not discarded -- they are *placed*. The record is the one
    place they may be, and an audit that could not be tied back to a
    principal at all would be an audit nobody could act on."""

    node = _protected_node(tmp_path)
    _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[SYNTHETIC_ASSET, "approval-synthetic-1"],
        confirms=[True, True, True, True],
    )
    stored = json.loads(
        (node["record_dir"] / "commissioning.json").read_text(encoding="utf-8")
    )
    assert stored["roles"][0]["confirmed_by"].startswith("uid:")
    assert stored["boot_id"] == node["boot_id"].read_text().strip()
    assert stored["generation"] == 1


def test_the_document_publishes_only_the_bare_command():
    """The line an operator is given. A document that showed a richer one
    would be the instruction that puts a name in `ps`."""

    text = DOC.read_text(encoding="utf-8")
    assert "```\nazazel-nexus hil-preflight\n```" in text
    # The removed options may be *named* -- the document explains what the
    # node uses instead -- but never shown as something to type.
    assert re.search(r"hil-preflight\s+--", text) is None


def test_no_document_or_test_instructs_the_removed_options():
    """The options are gone from the parser; an instruction that still names
    one is an instruction that fails in front of an operator."""

    offenders = {}
    for tree in ("docs", "packaging", "README.md"):
        target = REPO / tree
        paths = [target] if target.is_file() else sorted(target.rglob("*.md"))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            if "hil-preflight" not in text:
                continue
            found = [
                option
                for option in ("--operator", "--at", "--generation", "--profiles")
                if f"hil-preflight {option}" in text
            ]
            if found:
                offenders[str(path.relative_to(REPO))] = found
    assert offenders == {}


def _bare_sysfs(tmp_path: Path) -> Path:
    """Interfaces the inventory cannot identify: no bus path, no permanent
    MAC. Their refusal reasons name the kernel names, which is why what the
    refusal prints matters."""

    net = tmp_path / "bare" / "class" / "net"
    for name in KERNEL_NAMES:
        (net / name).mkdir(parents=True)
    return net


def test_a_refusal_prints_a_classification_and_not_what_it_refused(tmp_path):
    """The refusal's own message quotes the interfaces it could not
    identify, by kernel name. An operator needs to know the preflight
    stopped; they do not need it spelled in the terminal."""

    import io

    from azazel_nexus.cli import main

    node = _protected_node(tmp_path)
    out = io.StringIO()
    code = main(
        [
            "--sysfs", str(_bare_sysfs(tmp_path)), "hil-preflight",
            "--record-dir", str(node["record_dir"]),
            "--key", str(node["key"]),
            "--meminfo", str(node["meminfo"]),
            "--os-release", str(node["os_release"]),
            "--sysfs-dev-block", str(node["dev_block"]),
            "--sysfs-tpm", str(node["tpm"]),
            "--boot-id", str(node["boot_id"]),
        ],
        out=out,
        ask=lambda prompt, choices: "skip",
        confirm=lambda prompt: True,
        text=lambda prompt: "unused",
        permanent_mac_reader=lambda name: None,
    )
    text = out.getvalue()
    assert code == 2
    assert BLOCKED in text
    assert "missing: B-3" in text
    for name in KERNEL_NAMES:
        assert name not in text, f"the refusal named {name}"
    assert list(node["record_dir"].iterdir()) == []


def test_an_abandoned_set_writes_nothing_and_says_so_in_classifications(tmp_path):
    node = _protected_node(tmp_path)
    code, text = _cli(
        tmp_path,
        node,
        answers=["management", "observation"],
        texts=[],
        confirms=[False],
    )
    assert code == 2
    assert BLOCKED in text
    assert list(node["record_dir"].iterdir()) == []


def test_the_preflight_command_never_binds_an_exception_it_reports():
    """Structural, because the prose version depends on what today's
    refusal happens to say.

    `CommissioningRefused` currently quotes `proposal.reasons`, which carry
    no kernel names -- the names are in `proposal.refused`, which it does not
    include. That is a fact about the refusal as it stands, and the next edit
    to `propose` can change it without anybody thinking about this command.
    So the handler cannot reach the exception at all: an unbound handler has
    nothing to print.
    """

    import ast

    from azazel_nexus import cli

    tree = ast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    command = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_cmd_hil_preflight"
    )
    bound = [
        handler.name
        for handler in ast.walk(command)
        if isinstance(handler, ast.ExceptHandler) and handler.name is not None
    ]
    assert bound == [], (
        f"the preflight binds {bound}; a bound exception is one a later edit "
        "prints, and a refusal's message quotes what it refused"
    )


# -- one platform, and the campaign is for that platform ------------------
#
# `HG-05` measures a reserve under one kernel, one allocator and one service
# manager, and those belong to the distribution. A record taken on another is
# a record of another platform, and this build has no way to say by how much.


@pytest.mark.parametrize(
    "code,override",
    [
        ("A-3", {"os_id": "ubuntu", "os_version_id": "24.04"}),
        ("A-3", {"os_id": "debian", "os_version_id": "12"}),
        ("A-3", {"os_id": "fedora", "os_version_id": "43"}),
        ("A-3", {"os_id": None, "os_version_id": None}),
        ("A-2", {"architecture": "aarch64"}),
        ("A-2", {"architecture": None}),
    ],
)
def test_a_host_off_the_baseline_platform_is_blocked(code, override):
    result = run(inventory(**override))
    assert result.outcome == BLOCKED
    assert code in result.missing


def test_the_baseline_is_matched_on_the_identifier_and_not_on_the_prose():
    """`PRETTY_NAME` is a sentence a vendor may rewrite between point
    releases; a host whose prose was edited would pass or fail for a reason
    that has nothing to do with what is installed."""

    lying = inventory(distribution="Debian GNU/Linux 13 (trixie)", os_id="ubuntu")
    assert "A-3" in lying.missing
    honest = inventory(distribution="a name nobody recognises")
    assert "A-3" not in honest.missing


def test_the_baseline_names_one_distribution_and_one_architecture():
    """Two would be a campaign whose result names neither."""

    assert preflight.BASELINE_OS_ID == "debian"
    assert preflight.BASELINE_OS_VERSION_ID == "13"
    assert preflight.BASELINE_ARCHITECTURE == "x86_64"
    assert inventory().on_the_baseline_platform is True


def test_the_identity_is_read_from_os_release(tmp_path):
    path = tmp_path / "os-release"
    path.write_text('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n')
    assert preflight.read_os_identity(path) == ("debian", "13")
    assert preflight.read_os_identity(tmp_path / "absent") == (None, None)

    partial = tmp_path / "partial"
    partial.write_text("ID=debian\n")
    assert preflight.read_os_identity(partial) == ("debian", None)


def test_a_host_that_cannot_protect_raw_identity_is_refused_and_writes_nothing(tmp_path):
    """The LUKS2 rule, stated as the disposition it produces: such a host is
    refused for HIL and for operational deployment, and the preflight leaves
    no raw identity behind on it. What it may still be used for is
    diagnostics, which need no record."""

    result = run(inventory(luks_available=False))
    assert result.outcome == BLOCKED
    assert "A-7" in result.missing

    directory = tmp_path / "commissioning"
    with pytest.raises(PreflightRefused):
        persist_commissioning_record(
            record(),
            directory=directory,
            protection=Protection(luks_backed=False, key_available=True),
        )
    assert not directory.exists()
