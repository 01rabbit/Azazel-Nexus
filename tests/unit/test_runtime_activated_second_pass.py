"""#251 M-5: a pass that meets a governed unit already running, through a fake bus.

What the VM rehearsal of 2026-10-22 showed (a VM, not hardware evidence): a
copy of the test started the controller again in the same boot; the preflight
found the Deception Lite exposure units (nsd, netd, decoyd) running without a
grant; it recorded ``activation.evidence_preflight_masked``, the remask failed
with ``UnitOperationFailed``, it recorded ``activation.rollback_failed`` with
``masked unit has no confirmed inactive state`` and the process ended with
``az-activated failed before completing a safe pass: RollbackFailed``.

These tests pin that path below the real client (``SystemdUnitCalls`` over a
fake ``exchange``): the order, the two ledger records with exactly their
fields (unit names and fixed reasons, nothing else), that the controller never
asks for anything beyond mask and read (no StopUnit, no start, no unmask), and
what a second pass in the same boot does with the first pass's grant markers
and the bootstrap once-marker. The grant-bearing behaviour on systemd 257 is
still for the VM, with the operator's signature (``docs/activation-observe-baseline.md``
§10.2, M-5).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import activation_markers
from azazel_nexus_runtime.activated import (
    ActivationDaemon,
    ManagedUnitController,
    RollbackFailed,
    _failure_label,
    _run_once,
)
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
    SystemdUnitCalls,
    _Reply as Reply,
    _unit_object_path,
)
from azazel_nexus_runtime.units import DbusUnitManager, UnitOperationFailed, UnitState

from azazel_nexus.activation import CORE_UNITS, DECEPTION_EXPOSURE_UNITS
from azazel_nexus.audit import AuditLedger
from azazel_nexus.generation import GenerationStore

NOW = "2026-10-22T00:00:00Z"
ACTOR = "azazel-activated"
NAMES = [definition.name for definition in CORE_UNITS]
RUNNING = sorted(DECEPTION_EXPOSURE_UNITS)
#: What the first pass of this boot would have marked (SUPPORTING units).
FIRST_PASS_MARKERS = ["azazel-edge-intaked.service", "azazel-edge-probed.service"]
NOT_INACTIVE = "masked unit has no confirmed inactive state"
#: The only members a pass may send: masking and reading. Anything else
#: (StopUnit, StartUnit, UnmaskUnitFiles, EnableUnitFiles) fails the test.
READ_AND_MASK = {"GetUnitFileState", "MaskUnitFiles", "GetUnit", "Get"}


class FakeSystemd:
    """Unit-file states and loaded units, as the manager would answer them.

    A running unit is loaded with ``ActiveState=active``; masking changes its
    file state only, exactly as ``MaskUnitFiles`` does. Everything else is
    not loaded. Any member outside ``READ_AND_MASK`` raises.
    """

    def __init__(self, *, running, file_state="enabled"):
        self.files = {name: file_state for name in NAMES}
        self.active = set(running)
        self.members: list[str] = []
        self._by_path = {_unit_object_path(name): name for name in NAMES}

    def exchange(self, interface, member, signature, body, **kwargs):
        self.members.append(member)
        if member not in READ_AND_MASK:
            raise AssertionError(f"the pass asked for {member}")
        if member == "MaskUnitFiles":
            assert interface == MANAGER_INTERFACE and signature == "asbb"
            self.files[body[0][0]] = "masked"
            return Reply("a(sss)", [[]])
        if member == "GetUnitFileState":
            return Reply("s", [self.files[body[0]]])
        if member == "GetUnit":
            if body[0] in self.active:
                return Reply("o", [_unit_object_path(body[0])])
            return Reply("", [], no_such_unit=True)
        assert interface == PROPERTIES_INTERFACE
        assert body == [UNIT_INTERFACE, "ActiveState"]
        unit = self._by_path[kwargs["path"]]
        return Reply("v", [SimpleNamespace(
            signature="s", value="active" if unit in self.active else "inactive")])

    def manager(self) -> DbusUnitManager:
        return DbusUnitManager(call=SystemdUnitCalls(self.exchange))


@pytest.fixture
def first_pass_root(tmp_path, monkeypatch):
    """A root as the first pass of this boot left it: its grant markers."""

    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    parent = tmp_path / "run" / "azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    assert activation_markers.write_grant_markers(FIRST_PASS_MARKERS, tmp_path)
    return tmp_path


def _events(root):
    return [entry.event for entry in
            AuditLedger(root / "var/lib/azazel/state/activation.jsonl")]


def test_running_ungranted_units_end_the_pass_in_rollback_failed(first_pass_root):
    systemd = FakeSystemd(running=RUNNING)

    with pytest.raises(RollbackFailed) as raised:
        _run_once(manager=systemd.manager(), root=first_pass_root, now=NOW, actor=ACTOR)

    # The line main() prints is the class name only (not a reviewed literal).
    assert _failure_label(raised.value) == "RollbackFailed"
    # Exactly two records, with exactly these fields: unit names and fixed
    # reasons, nothing a bus or an exception could add.
    assert _events(first_pass_root) == [
        {
            "event_type": "activation.evidence_preflight_masked",
            "error_type": "preflight",
            "remask_failures": [f"{unit}: UnitOperationFailed" for unit in RUNNING],
            "occurred_at": NOW,
            "actor": ACTOR,
        },
        {
            "event_type": "activation.rollback_failed",
            "after": [f"{unit}: UnitOperationFailed" for unit in RUNNING],
            "still_unreachable": [f"{unit}: {NOT_INACTIVE}" for unit in RUNNING],
            "occurred_at": NOW,
            "actor": ACTOR,
        },
    ]
    # Every governed unit is masked; the running ones keep running, because
    # the controller has no StopUnit (G6 (b) is not taken here).
    assert all(state == "masked" for state in systemd.files.values())
    assert systemd.active == set(RUNNING)
    assert set(systemd.members) <= READ_AND_MASK
    # Preflight, then the wider narrowing: two rounds over every governed
    # unit, and nothing after them (no evidence collection, no decision).
    assert systemd.members.count("MaskUnitFiles") == 2 * len(NAMES)


def test_the_second_pass_removes_the_first_pass_markers_and_keeps_no_state(
        first_pass_root):
    systemd = FakeSystemd(running=RUNNING)

    with pytest.raises(RollbackFailed):
        _run_once(manager=systemd.manager(), root=first_pass_root, now=NOW, actor=ACTOR)

    # The first pass's markers are gone before anything else happens, so a
    # granted unit that stops cannot be started again this boot.
    assert not (first_pass_root / "run/azazel-activation/granted").exists()
    # The ordinary path neither writes nor reads the bootstrap once-marker:
    # a second start is possible (that is M-5), and it leaves none behind.
    assert not (first_pass_root / "run/azazel-nexus-bootstrap").exists()
    # It fails before evidence collection: no lease is consumed, no floor is
    # raised and no generation is touched.
    types = [event["event_type"] for event in _events(first_pass_root)]
    assert "activation.high_water_raised" not in types
    assert "activation.inputs_incomplete" not in types
    assert not (first_pass_root / "var/lib/azazel/generations").exists()


def test_a_second_pass_with_nothing_running_withholds_and_drops_the_markers(
        first_pass_root):
    """The contrast: the first pass's grants not running, nothing to contain."""

    systemd = FakeSystemd(running=())
    outcome = _run_once(
        manager=systemd.manager(), root=first_pass_root, now=NOW, actor=ACTOR)

    assert outcome.granted == ()
    assert not (first_pass_root / "run/azazel-activation/granted").exists()
    assert all(state == "masked" for state in systemd.files.values())
    events = _events(first_pass_root)
    assert events[0]["event_type"] == "activation.evidence_preflight_masked"
    assert events[0]["remask_failures"] == []
    assert "activation.rollback_failed" not in [e["event_type"] for e in events]
    assert set(systemd.members) <= READ_AND_MASK


class _Unprintable(Exception):
    def __str__(self):
        raise RuntimeError("an exception that cannot be printed")


class _FailingManager:
    """Masks every unit, then fails the inactivity read with ``error``."""

    def __init__(self, error):
        self.error = error
        self.states = {name: UnitState.ENABLED for name in NAMES}

    def state(self, unit):
        return self.states[unit]

    def mask(self, unit):
        self.states[unit] = UnitState.MASKED

    def is_inactive(self, unit):
        raise self.error


@pytest.mark.parametrize("error,reason", [
    (UnitOperationFailed(NOT_INACTIVE), NOT_INACTIVE),
    (RuntimeError("/run/peer said: something else"), "RuntimeError"),
    (OSError(13, "Permission denied", "/var/lib/azazel/x"), "PermissionError"),
    (UnitOperationFailed("two", "arguments"), "UnitOperationFailed"),
    (_Unprintable(), "_Unprintable"),
])
def test_narrowing_records_a_unit_and_a_fixed_reason_only(tmp_path, error, reason):
    """The reason is the message of a one-string UnitOperationFailed, else the class.

    Before #251 M-5 the escalation recorded ``str(exc)`` of anything: text an
    exception carried reached the ledger, and an exception that could not be
    printed escaped the narrowing before its record and its RollbackFailed.
    """

    ledger = AuditLedger(tmp_path / "activation.jsonl")
    manager = _FailingManager(error)
    daemon = ActivationDaemon(GenerationStore(tmp_path / "generations"), ledger, manager)

    with pytest.raises(RollbackFailed):
        daemon._narrow_everything(now=NOW, actor=ACTOR, after=["x: UnitOperationFailed"])
    units = ManagedUnitController(manager)
    units.widened.append(RUNNING[0])
    with pytest.raises(RollbackFailed):
        daemon._roll_back(units, now=NOW, actor=ACTOR, outcome=None)

    events = [entry.event for entry in ledger]
    assert events[0]["still_unreachable"] == sorted(f"{name}: {reason}" for name in NAMES)
    assert events[1]["event_type"] == "activation.rolled_back"
    assert events[1]["could_not_mask"] == [f"{RUNNING[0]}: {reason}"]
    assert events[2]["event_type"] == "activation.rollback_failed"
