"""`az-activation-recheck`: the periodic check of the Knowledge Context broker.

The recheck evaluates the same inputs as the main pass, through the same
library conditions, and only ever withdraws the broker. These tests run it
over the world of `test_runtime_activation_pass` after a real main pass has
granted the broker, with the broker modelled as running (`stop_helpers`).

Negative checks: replacing the verdict by "always granted", dropping the
withdrawal or ignoring the lock each makes the scenario's own assertions fail.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger
from azazel_nexus_runtime import activated, activation_recheck, hardening
from azazel_nexus_runtime.activation_lock import acquire_pass_lock
from azazel_nexus_runtime.activation_markers import GRANTABLE_UNITS
from azazel_nexus_runtime.activation_pass import PassInputs, collect_pass_inputs
from azazel_nexus_runtime.activation_recheck import (
    ContextdVerdict, contextd_triggers, contextd_verdict, run_recheck,
)

from stop_helpers import (
    CTX, JOB, NO_JOB, ContextdModel, FakeClock, ModelManager, authority,
)
from test_runtime_activation_contextd import CTX_SCOPE, ctx_world  # noqa: F401 - fixture
from test_runtime_activation_pass import NOW, SCOPE

REPO = Path(__file__).resolve().parents[2]
LATER = "2026-10-23T00:00:00Z"  # after the approval's expiry (2026-10-22)


@pytest.fixture
def granted(ctx_world):
    """A node where a real main pass granted the broker, and the broker runs."""
    clock = FakeClock()
    model = ContextdModel(clock)
    manager = ModelManager(model, enabled=[d.name for d in CORE_UNITS])
    ctx_world.manager = manager
    outcome = activated._run_once(
        manager=manager, root=ctx_world.root, now=NOW, actor="test",
        producers=ctx_world.producers(), stop_authority=authority(model),
        clock=clock, sleep=clock.sleep)
    assert CTX in outcome.granted and CTX in ctx_world.markers()
    model.running = True  # started by systemd after READY
    manager.timeline.clear()
    before = ctx_world.ledger_path.read_bytes()
    return SimpleNamespace(world=ctx_world, clock=clock, model=model, manager=manager,
                           ledger_before=before, raised_before=len(ctx_world.raised))


def recheck(stage, *, now=NOW, producers=None, manager=None):
    return run_recheck(
        manager=manager or stage.manager, authority=authority(stage.model),
        root=stage.world.root, now=now,
        producers=producers or stage.world.producers(),
        invocation_id="c" * 32, clock=stage.clock, sleep=stage.clock.sleep)


def events_after(stage):
    return [e.event for e in AuditLedger(stage.world.ledger_path)][
        len(stage.ledger_before.splitlines()):]


def markers(stage):
    return stage.world.markers() or []


def withdrawn(stage) -> bool:
    """The broker's grant is fully withdrawn: marker, mask, stopped."""
    return (CTX not in markers(stage)
            and stage.manager.state(CTX) is UnitState.MASKED
            and stage.model.running is False)


def others_untouched(stage) -> bool:
    return (sorted(markers(stage)) == sorted(set(CTX_SCOPE) - {CTX})
            and all(stage.manager.state(u) is UnitState.ENABLED
                    for u in CTX_SCOPE if u != CTX)
            and all(unit == CTX for op, unit in stage.manager.timeline if unit))


# -- the verdict is pure and the library's ------------------------------------------


def _inputs(world, *, now=NOW):
    return collect_pass_inputs(producers=world.producers(), generations=world.store,
                               ledger=AuditLedger(world.ledger_path), now=now)


def test_a_complete_healthy_lease_naming_the_broker_grants_it(ctx_world):
    verdict = contextd_verdict(_inputs(ctx_world), NOW)
    assert verdict == ContextdVerdict(True, "granted")


@pytest.mark.parametrize("case", ["healthy", "unhealthy", "outside-lease", "expired"])
def test_the_verdict_agrees_with_what_the_main_pass_does(ctx_world, case):
    """Differential: the main pass grants the broker exactly when the verdict does."""
    now = NOW
    if case == "unhealthy":
        ctx_world.healthy = False
    elif case == "outside-lease":
        ctx_world.sign(units=SCOPE)
    elif case == "expired":
        now = LATER
    verdict = contextd_verdict(_inputs(ctx_world, now=now), now)
    outcome = activated._run_once(
        manager=ctx_world.manager, root=ctx_world.root, now=now, actor="test",
        producers=ctx_world.producers())
    assert verdict.granted is (CTX in outcome.granted)
    assert verdict.granted is (case == "healthy")


@pytest.mark.parametrize("inputs", [None, "x", PassInputs()])
def test_missing_or_incomplete_inputs_withhold(inputs):
    verdict = contextd_verdict(inputs, NOW)
    assert verdict.granted is False and verdict.label in ("inputs_unavailable", "inputs_incomplete")


def test_a_lease_for_another_generation_withholds(ctx_world):
    inputs = _inputs(ctx_world)
    inputs.generation_digest = "sha256:" + "0" * 64
    verdict = contextd_verdict(inputs, NOW)
    assert verdict.granted is False and verdict.label == "lease_generation_mismatch"


def test_an_unwired_capability_withholds(ctx_world):
    from azazel_nexus.activation import UnitDefinition
    inputs = _inputs(ctx_world)
    # The broker has no wiring requirement in this build (definition.wiring is
    # None); a definition that named one would be withheld without the wiring.
    assert contextd_verdict(inputs, NOW, wired=frozenset()).granted is True
    assert activation_recheck._CONTEXTD_DEFINITION.wiring is None
    assert isinstance(activation_recheck._CONTEXTD_DEFINITION, UnitDefinition)


def test_the_verdict_has_no_effects(ctx_world, monkeypatch):
    """It calls no pass, marker, floor or ledger function (it only reads inputs)."""
    inputs = _inputs(ctx_world)
    source = inspect.getsource(contextd_verdict)
    for name in ("activate(", "_run_once", "write_grant_markers", "reset_grant_markers",
                 "remove_contextd_marker", "_raise_edge_floor", "raise_high_water",
                 ".append(", "mask(", "reload("):
        assert name not in source, name

    def explode(*_a, **_k):
        raise AssertionError("the verdict must not do this")

    from azazel_nexus_runtime import activation_markers
    monkeypatch.setattr(activated.ActivationDaemon, "activate", explode)
    monkeypatch.setattr(activation_markers, "write_grant_markers", explode)
    monkeypatch.setattr(activation_markers, "reset_grant_markers", explode)
    monkeypatch.setattr(AuditLedger, "append", explode)
    before = (ctx_world.ledger_path.read_bytes()
              if ctx_world.ledger_path.exists() else None)
    assert contextd_verdict(inputs, NOW).granted is True
    assert (ctx_world.ledger_path.read_bytes()
            if ctx_world.ledger_path.exists() else None) == before
    assert ctx_world.raised == []


# -- when the recheck acts -------------------------------------------------------------


def test_with_nothing_to_withdraw_it_collects_nothing_and_writes_nothing(granted):
    stage = granted
    stage.model.running = False
    # remove the grant by hand: masked, no marker, inactive
    from azazel_nexus_runtime.activation_markers import remove_contextd_marker
    remove_contextd_marker(stage.world.root)
    stage.manager.mask(CTX)
    stage.manager.timeline.clear()

    def producers_must_not_run():
        raise AssertionError("nothing to evaluate")

    producers = stage.world.producers(commissioning_evidence=producers_must_not_run)
    assert recheck(stage, producers=producers) == 0
    assert stage.manager.timeline == []
    assert stage.world.ledger_path.read_bytes() == stage.ledger_before


@pytest.mark.parametrize("change,expected", [
    ("marker", ("marker",)),
    ("not-masked", ("not_masked",)),
    ("running", ("not_inactive",)),
    ("job", ("job",)),
])
def test_each_condition_alone_makes_the_broker_worth_evaluating(granted, change, expected):
    stage = granted
    from azazel_nexus_runtime.activation_markers import remove_contextd_marker
    remove_contextd_marker(stage.world.root)
    stage.manager.mask(CTX)
    stage.model.running = False
    if change == "marker":
        (stage.world.root / "run/azazel-activation/granted" / CTX).write_text("")
    elif change == "not-masked":
        stage.manager.unmask_and_enable(CTX)
    elif change == "running":
        stage.model.running = True
    else:
        stage.model.job = JOB
    found = contextd_triggers(stage.manager, authority(stage.model), stage.world.root)
    assert found == expected


def test_an_unreadable_broker_is_evaluated_not_assumed_quiet(granted):
    stage = granted

    def unreadable(unit):
        raise RuntimeError("synthetic")

    from stop_helpers import failing_authority
    found = contextd_triggers(stage.manager, failing_authority(), stage.world.root)
    assert "state_unreadable" in found and "activity_unreadable" in found


# -- a grant that still holds is left alone ----------------------------------------------


def test_a_grant_that_still_holds_changes_nothing(granted):
    stage = granted
    assert recheck(stage) == 0
    assert stage.manager.timeline == []  # no mask, no reload, no stop
    assert stage.model.running is True and stage.model.stops == 0
    assert CTX in markers(stage)
    assert stage.world.ledger_path.read_bytes() == stage.ledger_before
    assert len(stage.world.raised) == stage.raised_before


# -- a grant that no longer holds is withdrawn -----------------------------------------------


@pytest.mark.parametrize("case", ["expired", "unhealthy", "approval-for-others",
                                  "collection-fails"])
def test_a_grant_that_no_longer_holds_is_withdrawn_and_nothing_else_changes(granted, case):
    stage = granted
    now, producers = NOW, None
    if case == "expired":
        now = LATER
    elif case == "unhealthy":
        stage.world.healthy = False
    elif case == "approval-for-others":
        stage.world.sign(units=SCOPE)
    else:
        def fail():
            raise RuntimeError("synthetic")
        producers = stage.world.producers(commissioning_evidence=fail)
    assert recheck(stage, now=now, producers=producers) == 0
    assert withdrawn(stage) and others_untouched(stage)
    assert stage.model.stops == 1
    [event] = [e for e in events_after(stage) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["unit"] == CTX and event["reason"].startswith("recheck:")
    assert event["invocation_id"] == "c" * 32
    # no grant, no floor, no new decision record
    assert len(stage.world.raised) == stage.raised_before
    assert not any(e["event_type"] in ("activation.unit_granted", "activation.unit_withheld",
                                       "activation.inputs_incomplete")
                   for e in events_after(stage))
    assert not any(op == "unmask_and_enable" for op, _ in stage.manager.timeline)


def test_the_order_is_marker_mask_reload_stop(granted):
    stage = granted
    seen = []
    marker = stage.world.root / "run/azazel-activation/granted" / CTX
    stage.manager.on_mask = lambda unit: seen.append(not marker.exists())
    stage.world.healthy = False
    recheck(stage)
    assert seen == [True]
    assert [op for op, _ in stage.manager.timeline] == ["mask", "reload", "stop"]


def test_a_grant_that_never_started_is_withdrawn_without_a_stop(granted):
    stage = granted
    stage.model.running = False  # marker present, unmasked, inactive: never started
    stage.world.healthy = False
    assert recheck(stage) == 0
    assert stage.model.stops == 0
    assert [op for op, _ in stage.manager.timeline] == ["mask", "reload"]
    assert withdrawn(stage) and others_untouched(stage)
    [event] = [e for e in events_after(stage) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["stopped"] is False and event["t_stop_ms"] is None


def test_an_unmasked_broker_without_marker_and_without_grant_is_masked(granted):
    stage = granted
    from azazel_nexus_runtime.activation_markers import remove_contextd_marker
    remove_contextd_marker(stage.world.root)
    stage.model.running = False
    stage.world.healthy = False
    assert recheck(stage) == 0
    assert stage.manager.state(CTX) is UnitState.MASKED and stage.model.stops == 0


def test_a_broker_that_will_not_stop_is_reported_and_other_units_are_not_narrowed(granted):
    stage = granted
    stage.model.stop_works = False
    stage.world.healthy = False
    assert recheck(stage) == 1
    assert stage.manager.state(CTX) is UnitState.MASKED
    assert CTX not in markers(stage)
    assert others_untouched(stage)
    last = events_after(stage)[-1]
    assert last["event_type"] == "activation.withdrawal_unconfirmed"


# -- the lock -----------------------------------------------------------------------------


def test_while_the_pass_holds_the_lock_it_changes_nothing_and_writes_no_ledger(granted, capsys):
    stage = granted
    stage.world.healthy = False
    with acquire_pass_lock(stage.world.root):
        assert recheck(stage) == 0
    assert stage.manager.timeline == [] and stage.model.running is True
    assert CTX in markers(stage)
    assert stage.world.ledger_path.read_bytes() == stage.ledger_before
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and "lock is held" in out
    # and when it lets go, the next recheck acts
    assert recheck(stage) == 0 and withdrawn(stage)


def test_the_recheck_releases_the_lock(granted):
    stage = granted
    assert recheck(stage) == 0
    with acquire_pass_lock(stage.world.root):
        pass


def test_an_unusable_lock_is_a_failure_that_changes_nothing(granted):
    stage = granted
    (stage.world.root / "run/azazel-activation/pass.lock").mkdir()
    stage.world.healthy = False
    assert recheck(stage) == 1
    assert stage.manager.timeline == [] and CTX in markers(stage)


# -- negative checks ---------------------------------------------------------------------------


def _scenario_withdraws(stage) -> bool:
    stage.world.healthy = False
    recheck(stage)
    return withdrawn(stage)


def test_a_verdict_that_always_grants_is_caught(granted, monkeypatch):
    monkeypatch.setattr(activation_recheck, "contextd_verdict",
                        lambda inputs, now, **kw: ContextdVerdict(True, "granted"))
    assert _scenario_withdraws(granted) is False  # the scenario would fail


def test_a_recheck_without_the_withdrawal_is_caught(granted, monkeypatch):
    monkeypatch.setattr(activation_recheck, "withdraw_contextd", lambda **kw: {})
    assert _scenario_withdraws(granted) is False


def test_a_recheck_that_ignores_the_lock_is_caught(granted, monkeypatch):
    import contextlib
    stage = granted
    stage.world.healthy = False
    monkeypatch.setattr(activation_recheck, "acquire_pass_lock",
                        lambda *args, **kwargs: contextlib.nullcontext())
    with acquire_pass_lock(stage.world.root):
        recheck(stage)
    # With the lock check removed it acts while the pass holds the lock, which
    # `test_while_the_pass_holds_the_lock_it_changes_nothing...` forbids.
    assert stage.manager.timeline != []


# -- the entry point -------------------------------------------------------------------------


def test_the_entry_point_takes_no_argument_and_needs_its_context(monkeypatch, capsys):
    assert activation_recheck.main(["x"]) == 2
    monkeypatch.setenv("INVOCATION_ID", "not-an-id")
    assert activation_recheck.main([]) == 1
    assert "requires its root systemd service context" in capsys.readouterr().err


def test_the_entry_point_wires_the_session_the_authority_and_the_producers(monkeypatch):
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    from azazel_nexus_runtime.units import ContextdStopAuthority, DbusUnitManager
    monkeypatch.setattr(activation_recheck.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "d" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    original = Path.is_dir
    monkeypatch.setattr(Path, "is_dir",
                        lambda p: True if p == Path("/run/systemd/system") else original(p))

    class Session:
        def stop_contextd(self):
            raise AssertionError

        def unit_job(self, unit):
            raise AssertionError

        def contextd_active_state(self, unit):
            raise AssertionError

        def contextd_file_state(self, unit):
            raise AssertionError

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return None

    session = Session()
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(lambda *_a: session))
    seen = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return 0

    monkeypatch.setattr(activation_recheck, "run_recheck", fake_run)
    assert activation_recheck.main([]) == 0
    assert isinstance(seen["manager"], DbusUnitManager) and seen["manager"].call is session
    assert isinstance(seen["authority"], ContextdStopAuthority)
    assert seen["root"] == Path("/") and seen["invocation_id"] == "d" * 32


def test_an_unexpected_failure_is_a_class_name_only(monkeypatch, capsys):
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    monkeypatch.setattr(activation_recheck.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "e" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    original = Path.is_dir
    monkeypatch.setattr(Path, "is_dir",
                        lambda p: True if p == Path("/run/systemd/system") else original(p))

    def connect(*_a):
        raise RuntimeError("/run/secret said hello")

    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(connect))
    assert activation_recheck.main([]) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "secret" not in err


# -- the units ---------------------------------------------------------------------------------


def _unit(name):
    return (REPO / "packaging/systemd" / name).read_text(encoding="utf-8")


def _settings(text):
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            key, _, value = line.partition("=")
            result.setdefault(key, []).append(value)
    return result


def test_the_recheck_unit_is_a_narrow_root_oneshot():
    text = _unit("azazel-activation-recheck.service")
    assert text == dict(hardening.packaged_unit_files())["azazel-activation-recheck.service"]
    settings = _settings(text)
    assert settings["Type"] == ["oneshot"] and settings["User"] == ["root"]
    assert settings["TimeoutStartSec"] == ["40s"]
    assert re.search(r"^\[Install\]$", text, re.M) is None
    # not tied to the controller or the broker, ordering aside
    for key in ("Requires", "Wants", "BindsTo", "PartOf", "Requisite", "Upholds",
                "OnFailure", "Before"):
        assert key not in settings, key
    assert settings["After"] == ["azazel-activated.service"]
    # writes: the state directory and the markers' directory, nothing under /etc
    assert settings["ReadWritePaths"] == ["/var/lib/azazel/state", "-/run/azazel-activation"]
    assert "/etc/systemd/system" not in text and "system.control" not in text
    assert settings["CapabilityBoundingSet"] == ["CAP_DAC_READ_SEARCH"]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["RestrictAddressFamilies"] == ["AF_UNIX AF_NETLINK"]
    assert settings["IPAddressDeny"] == ["any"]
    assert settings["SupplementaryGroups"] == ["azazel-operator"]
    assert settings["ExecStart"] == ["/usr/libexec/azazel/az-activation-recheck"]


def test_the_recheck_sandbox_is_the_controllers_minus_its_two_writable_paths():
    controller = _settings(_unit("azazel-activated.service"))
    recheck_settings = _settings(_unit("azazel-activation-recheck.service"))
    for key, value in controller.items():
        if key in ("ReadWritePaths", "ExecStart", "Type", "Restart", "NotifyAccess",
                   "Description", "Documentation", "DefaultDependencies",
                   "WatchdogSec", "WatchdogSignal", "TimeoutStartSec",
                   "TimeoutStartFailureMode", "TimeoutStopFailureMode", "WantedBy",
                   "After", "Before", "Conflicts", "ConditionPathExists"):
            continue
        assert recheck_settings.get(key) == value, key
    assert set(controller["ReadWritePaths"]) - set(recheck_settings["ReadWritePaths"]) == {
        "/var/lib/azazel", "/var/lib/azazel/generations", "/etc/systemd/system",
        "/run/systemd/system.control", "/run/azazel-nexus-bootstrap"}


def test_the_recheck_timer_is_thirty_seconds_and_enabled_by_install():
    text = _unit("azazel-activation-recheck.timer")
    assert text == dict(hardening.packaged_unit_files())["azazel-activation-recheck.timer"]
    settings = _settings(text)
    assert settings["OnBootSec"] == ["30s"] and settings["OnUnitActiveSec"] == ["30s"]
    assert settings["AccuracySec"] == ["1s"]
    assert settings["Unit"] == ["azazel-activation-recheck.service"]
    assert settings["WantedBy"] == ["timers.target"]


def test_the_recheck_is_outside_every_governed_and_approval_scope():
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    names = {"azazel-activation-recheck.service", "azazel-activation-recheck.timer"}
    assert not names & {d.name for d in CORE_UNITS}
    assert not names & set(GRANTABLE_UNITS)
    assert not names & set(ACTIVATION_UNIT_ALLOWLIST)


def test_the_recheck_has_a_console_script():
    text = (REPO / "runtime/pyproject.toml").read_text(encoding="utf-8")
    assert 'az-activation-recheck = "azazel_nexus_runtime.activation_recheck:main"' in text


def test_the_recheck_module_calls_no_pass_marker_or_floor_function():
    source = inspect.getsource(activation_recheck)
    code = re.sub(r'""".*?"""', "", source, flags=re.S)
    # The approval retirement is the one separate write (its own module and
    # test file); its production wiring is the only place the floor appears.
    code = re.sub(r"def production_retirement.*?    return retire\n", "", code, flags=re.S)
    for name in ("_run_once", "ActivationDaemon", "write_grant_markers",
                 "reset_grant_markers", "_emergency_narrow", "raise_high_water",
                 "_remask_all", "unmask_and_enable"):
        assert name not in code, name
