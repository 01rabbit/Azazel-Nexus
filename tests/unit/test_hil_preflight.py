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
        distribution="Synthetic Linux 1",
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
    assert sorted(stored) == ["created_at", "digest", "profiles_present", "roles"]


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
    """The list is closed. A field added here is a field somebody has to
    argue for."""

    lines = run().lines()
    assert lines[0] == READY
    assert [line.split(":")[0] for line in lines[1:]] == [
        "host",
        "record generation",
        "fingerprint",
        "roles approved",
        "unassigned interfaces",
        "memory class",
        "runbook",
    ]


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


ALLOWED_PACKAGE_IMPORTS = {"commissioning", "inventory", "resource_profile", "wizard"}


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
    os_release.write_text('PRETTY_NAME="Synthetic Linux 1"\n')
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
    os_release.write_text('PRETTY_NAME="Synthetic Linux 1"\n')

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

    return {
        "meminfo": meminfo,
        "os_release": os_release,
        "record_dir": record_dir,
        "dev_block": dev_block,
        "tpm": tpm,
        "key": key,
    }


def _cli(tmp_path, node, *, answers, texts, confirms, audit=None):
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
        "--operator",
        "operator@console",
        "--at",
        "2026-09-21T00:00:00Z",
        "--profiles",
        "hardware",
        "resource",
        "topology",
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
        "--generation",
        "3",
    ]
    if audit is not None:
        argv += ["--audit", str(audit)]
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
        ["--sysfs", str(_sysfs_tree(tmp_path)), "hil-preflight",
         "--operator", "operator@console", "--at", "2026-09-21T00:00:00Z"],
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
