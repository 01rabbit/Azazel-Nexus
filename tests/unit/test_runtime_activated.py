"""Activation as a transaction, and three tiers that are not one (#39).

Two things are established here and they are different claims.

**The tiers.** A node whose ledger and watchdog are running can account for
itself. That is not a node that may claim a deterministic baseline or enforce
anything, and one readiness condition covering all three would let the easiest
of them speak for the other two.

**The rollback.** A pass that enables three units and fails on the fourth has
left the node in a state nobody chose. Either the whole set is granted or none
of it is.

What no test here establishes is that systemd does any of it. The adapter is
injected and the tests read the call log; `HG-01` and `HG-02` stay open.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from azazel_nexus.activation import (
    CORE_UNITS,
    ActivationLease,
    ActivationOutcome,
    ActivationRefused,
    EdgeBaselineState,
    UnitDefinition,
    UnitState,
    UnitTier,
    UnitVerdict,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole
from azazel_nexus.generation import GenerationStore
from azazel_nexus_runtime.activated import ActivationDaemon, RollbackFailed
from azazel_nexus_runtime.units import (
    UNIT_NAMES,
    DbusUnitManager,
    RecordingUnitManager,
    UnitKey,
    UnitOperationFailed,
    resolve,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME = REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime"

NOW = "2026-09-20T12:00:00Z"
ACTOR = "operator@console"
DIGEST = "sha256:" + "0" * 64

EDGE_UNIT = UnitDefinition(
    "azazel-edge-core.service", UnitTier.EDGE_BASELINE, "root", "the local Edge Core"
)
ENFORCING = UnitDefinition(
    "azazel-enforced.service", UnitTier.ENFORCEMENT, "azenforce", "applies one intent"
)


def _lease(**kwargs) -> ActivationLease:
    kwargs.setdefault("granted_by", ACTOR)
    kwargs.setdefault("granted_at", "2026-09-19T00:00:00Z")
    kwargs.setdefault("expires_at", "2026-09-21T00:00:00Z")
    kwargs.setdefault("generation_digest", DIGEST)
    return ActivationLease(**kwargs)


def _store(tmp_path: Path) -> GenerationStore:
    store = GenerationStore(tmp_path / "generations")
    store.create(
        {"suricata.yaml": b"role: observation\n"},
        created_at=NOW,
        commissioning_digest=DIGEST,
    )
    return store


def _record(*, roles=(), profiles=("hardware", "resource", "topology")):
    return CommissioningRecord(
        roles=tuple(roles), profiles_present=tuple(profiles), created_at=NOW
    )


def _role():
    return ConfirmedRole(
        composite=(("mac", "00:11:22:33:44:55"),),
        role="observation",
        confirmed_by=ACTOR,
        confirmed_at=NOW,
    )


def _ready_edge() -> EdgeBaselineState:
    return EdgeBaselineState(True, True, True, True, True)


def _daemon(tmp_path, definitions=CORE_UNITS, **kwargs):
    manager = RecordingUnitManager((d.name for d in definitions), **kwargs)
    daemon = ActivationDaemon(
        generations=_store(tmp_path),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        manager=manager,
        definitions=definitions,
    )
    return daemon, manager


def _events(tmp_path):
    return [e.event["event_type"] for e in AuditLedger(tmp_path / "ledger.jsonl")]


# -- the tiers are three answers -----------------------------------------


def test_supporting_units_run_before_anything_else_is_established(tmp_path):
    daemon, manager = _daemon(tmp_path)
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease())
    assert set(outcome.granted) == {d.name for d in CORE_UNITS}


def test_supporting_units_running_does_not_make_edge_baseline_ready(tmp_path):
    """The whole reason the tiers are separate.

    A node with a ledger and a watchdog can account for itself. It has not
    said anything about an Edge Core, and must not be read as having.
    """

    daemon, _ = _daemon(tmp_path)
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease())
    assert outcome.granted
    assert outcome.edge_baseline_ready is False
    assert outcome.enforcement_ready is False


def test_an_empty_edge_tier_is_not_vacuously_ready(tmp_path):
    """"All units in this tier were granted" over an empty tier is true.

    Which would make a node with no Edge Core at all the most confident node
    on the network. The readiness is derived from the Edge state instead, and
    unknown never grants.
    """

    daemon, _ = _daemon(tmp_path)
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease(), edge=None)
    assert not any(d.tier is UnitTier.EDGE_BASELINE for d in CORE_UNITS)
    assert outcome.edge_baseline_ready is False


def test_an_edge_unit_is_withheld_while_nothing_is_known_about_edge(tmp_path):
    daemon, _ = _daemon(tmp_path, CORE_UNITS + (EDGE_UNIT,))
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease(), edge=None)
    verdict = next(v for v in outcome.verdicts if v.unit == EDGE_UNIT.name)
    assert not verdict.granted
    assert verdict.reason.startswith("edge_unknown")


def test_an_edge_that_is_present_but_mismatched_names_which_check_failed(tmp_path):
    """"Edge is not ready" and "Edge's digest does not match" differ.

    The second is a security finding, and an operator acts on it differently.
    """

    daemon, _ = _daemon(tmp_path, CORE_UNITS + (EDGE_UNIT,))
    edge = EdgeBaselineState(
        package_present=True,
        version_matches=True,
        digest_matches=False,
        health_endpoint_healthy=True,
        running=True,
    )
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease(), edge=edge)
    verdict = next(v for v in outcome.verdicts if v.unit == EDGE_UNIT.name)
    assert "digest_matches" in verdict.reason
    assert outcome.edge_baseline_ready is False


def test_edge_baseline_ready_needs_all_five_checks(tmp_path):
    for index in range(5):
        flags = [True] * 5
        flags[index] = False
        state = EdgeBaselineState(*flags)
        assert state.ready is False
        assert len(state.missing()) == 1
    assert EdgeBaselineState(*([True] * 5)).ready is True


def test_an_enforcement_unit_needs_commissioning_that_edge_readiness_does_not(tmp_path):
    """A ready Edge does not make the node enforcement-ready."""

    daemon, _ = _daemon(tmp_path, CORE_UNITS + (EDGE_UNIT, ENFORCING))
    outcome = daemon.activate(
        now=NOW, actor=ACTOR, lease=_lease(), edge=_ready_edge(), record=_record()
    )
    assert EDGE_UNIT.name in outcome.granted
    assert ENFORCING.name in outcome.withheld
    assert outcome.edge_baseline_ready is True
    assert outcome.enforcement_ready is False


def test_enforcement_ready_needs_a_record_and_a_granted_unit(tmp_path):
    """A record says an operator settled things. It does not say anything runs."""

    daemon, _ = _daemon(tmp_path)
    complete = _record(roles=(_role(),))
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease(), record=complete)
    assert complete.enforcement_ready is True
    assert outcome.enforcement_ready is False, (
        "no enforcement unit is governed, so nothing is running that could act"
    )


def test_enforcement_is_ready_when_both_halves_hold(tmp_path):
    daemon, _ = _daemon(tmp_path, CORE_UNITS + (ENFORCING,))
    outcome = daemon.activate(
        now=NOW, actor=ACTOR, lease=_lease(), record=_record(roles=(_role(),))
    )
    assert outcome.enforcement_ready is True


def test_an_outcome_built_by_hand_is_not_enforcement_ready():
    """The safe direction for a field nobody supplied."""

    outcome = ActivationOutcome(
        generation=1,
        verdicts=(UnitVerdict("azazel-enforced.service", True, "granted"),),
        record=CommissioningRecord(
            roles=(_role(),),
            profiles_present=("hardware", "resource", "topology"),
            created_at=NOW,
        ),
    )
    assert outcome.enforcement_ready is False


# -- the lease -----------------------------------------------------------


def test_nothing_is_widened_without_a_lease(tmp_path):
    daemon, manager = _daemon(tmp_path)
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=None)
    assert outcome.granted == ()
    assert all(call[0] == "mask" for call in manager.calls)
    assert all(v.reason.startswith("lease_absent") for v in outcome.verdicts)


def test_an_expired_lease_widens_nothing(tmp_path):
    daemon, manager = _daemon(tmp_path)
    expired = _lease(
        granted_at="2026-09-01T00:00:00Z", expires_at="2026-09-02T00:00:00Z"
    )
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=expired)
    assert outcome.granted == ()
    assert all(v.reason.startswith("lease_expired") for v in outcome.verdicts)


def test_a_lease_that_has_not_begun_widens_nothing(tmp_path):
    daemon, _ = _daemon(tmp_path)
    future = _lease(
        granted_at="2026-12-01T00:00:00Z", expires_at="2026-12-02T00:00:00Z"
    )
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=future)
    assert outcome.granted == ()


def test_a_lease_that_expires_before_it_begins_cannot_be_built():
    """It would be refused on every boot and read as a fault."""

    with pytest.raises(ActivationRefused):
        _lease(granted_at="2026-09-21T00:00:00Z", expires_at="2026-09-20T00:00:00Z")


def test_a_lease_must_name_who_granted_it():
    with pytest.raises(ActivationRefused):
        _lease(granted_by="   ")


def test_the_lease_reads_the_clock_it_is_given(tmp_path):
    """A component that decided its own permission's expiry from its own clock."""

    lease = _lease()
    assert lease.valid_at("2026-09-20T00:00:00Z")
    assert not lease.valid_at("2026-09-25T00:00:00Z")
    assert not lease.valid_at("2026-09-01T00:00:00Z")


def test_health_that_was_not_established_widens_nothing(tmp_path):
    daemon, _ = _daemon(tmp_path)
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease(), healthy=False)
    assert outcome.granted == ()
    assert all(v.reason.startswith("health_not_established") for v in outcome.verdicts)


# -- activation is a transaction -----------------------------------------


def test_a_failure_part_way_through_takes_back_what_succeeded(tmp_path):
    """Either the whole set is granted or none of it is.

    Three units enabled and a fourth that failed is a state nobody chose.
    """

    daemon, manager = _daemon(tmp_path, fail_on="azazel-watchdog.service")
    outcome = daemon.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert "azazel-watchdog.service" in outcome.withheld
    for definition in CORE_UNITS:
        assert manager.state(definition.name) is UnitState.MASKED, (
            f"{definition.name} was left widened after a failed pass"
        )


def test_the_rollback_is_recorded_with_what_it_took_back(tmp_path):
    daemon, _ = _daemon(tmp_path, fail_on="azazel-watchdog.service")
    daemon.activate(now=NOW, actor=ACTOR, lease=_lease())

    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    rollback = next(
        e for e in ledger if e.event["event_type"] == "activation.rolled_back"
    )
    assert "azazel-commissiond.service" in rollback.event["masked_again"]
    assert rollback.event["could_not_mask"] == []
    assert "azazel-watchdog.service" in rollback.event["widened"], (
        "the unit whose widening failed part way is not listed as widened. "
        "It was: the call changed the unit before it raised, and a record "
        "that omits it describes a rollback of something else"
    )


def test_a_unit_withheld_by_policy_does_not_trigger_a_rollback(tmp_path):
    """A withheld unit is the decision working, not the manager failing."""

    daemon, manager = _daemon(tmp_path, CORE_UNITS + (ENFORCING,))
    daemon.activate(now=NOW, actor=ACTOR, lease=_lease(), record=None)
    assert "activation.rolled_back" not in _events(tmp_path)
    assert manager.state("azazel-auditd.service") is UnitState.ENABLED


def test_a_rollback_whose_own_masking_fails_narrows_further_and_raises(tmp_path):
    """There is no failure of a rollback whose answer is to widen.

    Isolated from the escalation below on purpose. Both paths end in
    `RollbackFailed`, so a single test that only asserted the exception was
    satisfied by *either* guard -- and each of them could then be deleted
    while the test stayed green. This one arranges for the library's own
    narrowing to succeed and only the rollback's masking to fail.
    """

    class FailsOnSecondMask(RecordingUnitManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._masked_once: set[str] = set()

        def mask(self, unit):
            self.calls.append(("mask", unit))
            if unit in self._masked_once:
                raise UnitOperationFailed(f"{unit} will not mask a second time")
            self._masked_once.add(unit)

    manager = FailsOnSecondMask(
        (d.name for d in CORE_UNITS), fail_on="azazel-watchdog.service"
    )
    daemon = ActivationDaemon(
        generations=_store(tmp_path),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        manager=manager,
    )
    with pytest.raises(RollbackFailed):
        daemon.activate(now=NOW, actor=ACTOR, lease=_lease())

    types = _events(tmp_path)
    assert "activation.rollback_failed" in types
    assert "activation.unit_would_not_mask" not in types, (
        "the library's own narrowing was supposed to succeed here; this test "
        "is about the rollback's masking and nothing else"
    )


def test_a_narrowing_the_library_could_not_do_is_escalated(tmp_path):
    """The other guard, on its own.

    Nothing was widened -- there is no generation, so the pass withholds
    everything -- and the masking that withholding requires is what fails.
    No rollback is due, so only the escalation can report this.
    """

    class WontMask(RecordingUnitManager):
        def mask(self, unit):
            self.calls.append(("mask", unit))
            raise UnitOperationFailed(f"{unit} will not mask")

    manager = WontMask(d.name for d in CORE_UNITS)
    daemon = ActivationDaemon(
        generations=GenerationStore(tmp_path / "nothing-promoted"),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        manager=manager,
    )
    with pytest.raises(RollbackFailed):
        daemon.activate(now=NOW, actor=ACTOR, lease=_lease())

    types = _events(tmp_path)
    assert "activation.unit_would_not_mask" in types
    assert "activation.rolled_back" not in types, (
        "nothing was widened, so there was nothing to roll back"
    )
    escalation = next(
        e
        for e in AuditLedger(tmp_path / "ledger.jsonl")
        if e.event["event_type"] == "activation.rollback_failed"
    )
    assert escalation.event["still_unreachable"]


def test_a_unit_half_widened_is_still_taken_back(tmp_path):
    """The recorder notes the attempt before the call, not after.

    A rollback that only knew about calls that returned cleanly would leave
    behind exactly the unit whose widening failed part way.
    """

    daemon, manager = _daemon(tmp_path, fail_on="azazel-auditd.service")
    daemon.activate(now=NOW, actor=ACTOR, lease=_lease())
    assert manager.state("azazel-auditd.service") is UnitState.MASKED


# -- no caller-supplied strings ------------------------------------------


def test_a_unit_is_addressed_by_key_and_never_by_name():
    assert resolve("auditd") == "azazel-auditd.service"
    for attempt in (
        "azazel-auditd.service",
        "../../etc/systemd/system/evil.service",
        "sshd.service",
        "auditd; rm -rf /",
        "",
    ):
        with pytest.raises(UnitOperationFailed):
            resolve(attempt)


def test_the_key_table_covers_exactly_the_governed_units():
    assert set(UNIT_NAMES.values()) == {d.name for d in CORE_UNITS}
    assert set(UNIT_NAMES) == set(UnitKey)


def test_the_controllers_own_unit_has_no_key():
    """A key for it would be a way to ask for it."""

    from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT

    assert ACTIVATION_CONTROLLER_UNIT not in UNIT_NAMES.values()


def test_the_dbus_adapter_passes_a_method_and_a_unit_and_nothing_else():
    calls = []
    manager = DbusUnitManager(call=lambda method, unit: calls.append((method, unit)))
    manager.unmask_and_enable("azazel-auditd.service")
    manager.mask("azazel-auditd.service")
    assert calls == [
        ("UnmaskUnitFiles", "azazel-auditd.service"),
        ("EnableUnitFiles", "azazel-auditd.service"),
        ("MaskUnitFiles", "azazel-auditd.service"),
    ]
    assert all(method in DbusUnitManager.METHODS for method, _ in calls)


def test_the_adapter_cannot_start_a_unit():
    """Activation decides what runs at the next boot.

    Starting a service now is a different act with a different blast radius,
    and this daemon does not have the verb for it.
    """

    assert "StartUnit" not in DbusUnitManager.METHODS
    assert not hasattr(DbusUnitManager, "start")


#: The one module allowed to start a process, contained the way
#: `fabric_boundary.py` contains the Fabric import.
#:
#: `az-edge-probed` has to run the Edge health contract; there is no D-Bus
#: method for "execute this binary", and Nexus#72 fixed that the health answer
#: is obtained by running the contract. Containing it in one module keeps the
#: property this scan exists for -- that you can name the places that execute
#: -- instead of trading it away. `tests/unit/test_edge_probed.py` holds the
#: narrower rules that apply inside it.
EXECUTING_MODULE = "edge_probed.py"


def test_the_runtime_builds_no_command_line_anywhere_but_the_probe():
    """No `subprocess`, no shell, no argument list assembled from input.

    The D-Bus route takes a unit name as a typed parameter to a typed method,
    so there is no `PATH` lookup, no argument splitting and no environment to
    inherit. That holds for every module here except `edge_probed.py`, and
    the exemption is by name: a new module cannot acquire it by accident.
    """

    offenders: dict[str, list[str]] = {}
    for path in sorted(RUNTIME.rglob("*.py")):
        if path.name == EXECUTING_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(
                    alias.name
                    for alias in node.names
                    if alias.name.split(".")[0] in {"subprocess", "shlex", "pty", "os"}
                    and alias.name.split(".")[0] != "os"
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in {"subprocess", "shlex", "pty"}:
                    found.add(node.module)
            elif isinstance(node, ast.Attribute) and node.attr in {
                "system",
                "popen",
                "execv",
                "execve",
                "spawnv",
            }:
                found.add(node.attr)
        if found:
            offenders[path.name] = sorted(found)
    assert offenders == {}, f"{offenders} can execute something"


def test_the_exempt_module_exists_and_still_executes():
    """A named exemption for a module that stopped executing is dead weight.

    Worse, it is dead weight that silently re-arms: the next module given
    that name inherits an exemption nobody meant it to have.
    """

    exempt = RUNTIME / EXECUTING_MODULE
    assert exempt.is_file(), f"{EXECUTING_MODULE} is exempted and does not exist"
    tree = ast.parse(exempt.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "subprocess" in imported, (
        f"{EXECUTING_MODULE} no longer executes anything; remove its exemption "
        "rather than leaving it for the next module with that name"
    )
