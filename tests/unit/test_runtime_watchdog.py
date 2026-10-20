"""The watchdog narrows, and has no way to widen (#41).

Three conditions that are three different things, a fence that survives the
process, and a static scan proving this module cannot reach the widening
path. Nothing here sleeps: a deadline is a counter the test advances.
"""

from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

import azazel_nexus_runtime.principal as principal
import azazel_nexus_runtime.runtime_paths as runtime_paths
import azazel_nexus_runtime.serve as serve
import azazel_nexus_runtime.watchdog as watchdog_module
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.generation import GenerationStore
from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager
from azazel_nexus_runtime.watchdog import (
    REGISTRY,
    VERBS,
    FenceReason,
    FenceStore,
    WatchdogService,
)
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.transport import Request

REPO_ROOT = Path(__file__).resolve().parents[2]
WATCHDOG_SOURCE = REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "watchdog.py"

NOW = "2026-09-20T12:00:00Z"
DIGEST = "sha256:" + "0" * 64
OPERATOR = Principal(uid=1000, gid=1000, pid=9, classes=frozenset({PrincipalClass.OPERATOR}))


def _ticks(*values):
    """A monotonic clock that returns each value in turn."""

    iterator = iter(values)
    return lambda: next(iterator)


def _service(tmp_path, *, clock=None, generations=None) -> WatchdogService:
    return WatchdogService(
        manager=RecordingUnitManager(UNIT_NAMES.values()),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        fences=FenceStore(tmp_path / "fences.json"),
        generations=generations,
        clock=clock or _ticks(0, 0),
    )


def _events(tmp_path):
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    ledger.verify()
    return [e.event for e in ledger]


def test_first_fence_records_reason_and_prior_state_not_only_post_value(tmp_path):
    service = _service(tmp_path)
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)

    [event] = _events(tmp_path)
    assert event["event_type"] == "watchdog.fenced"
    assert event["unit"] == "azazel-auditd.service"
    assert event["reason"] == "unhealthy"
    assert event["previous_state"] == "in_service"
    assert event["previous_reason"] is None
    assert event["state"] == "fenced"
    assert event["reason"] != event["state"]
    assert event["previous_state"] != event["state"]
    assert event["occurred_at"] == NOW
    assert event["detail"] == "the daemon reported itself unwell"


def test_identical_observation_masks_again_without_another_record(tmp_path):
    service = _service(tmp_path, clock=lambda: 0)
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    original = _events(tmp_path)
    assert len(original) == 1
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    assert _events(tmp_path) == original
    assert service.manager.calls == [("mask", "azazel-auditd.service")] * 2


def test_reason_only_change_records_previous_reason(tmp_path):
    service = _service(tmp_path, clock=_ticks(0, 10, 20, 10_000))
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: True)
    first, changed = _events(tmp_path)
    assert first["previous_state"] == "in_service"
    assert changed["previous_state"] == changed["state"] == "fenced"
    assert changed["previous_reason"] == "unhealthy"
    assert changed["reason"] == "deadline_exceeded"
    assert service.fenced["azazel-auditd.service"] == "deadline_exceeded"
    assert service.fences.load() == service.fenced


def test_generation_mismatch_records_each_unit_once(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    store.create(
        {"suricata.yaml": b"role: observation\n"},
        created_at=NOW,
        commissioning_digest=DIGEST,
    )
    service = _service(tmp_path, generations=store)
    (store.root / "1" / "tree" / "suricata.yaml").write_bytes(b"tampered\n")
    assert service.check_generation(now=NOW) is False
    original = _events(tmp_path)
    assert len(original) == len(UNIT_NAMES)
    assert {event["unit"] for event in original} == set(UNIT_NAMES.values())
    assert all(
        event["reason"] == "generation_mismatch"
        and event["previous_state"] == "in_service"
        and event["previous_reason"] is None
        and event["state"] == "fenced"
        for event in original
    )
    assert service.check_generation(now=NOW) is False
    assert _events(tmp_path) == original
    assert service.manager.calls == [
        ("mask", unit) for unit in sorted(UNIT_NAMES.values())
    ] * 2


def test_failed_audit_retries_original_transition_on_identical_observation(tmp_path):
    service = _service(tmp_path, clock=lambda: 0)
    append = service.ledger.append

    def refuse(event):
        raise AuditUnavailable("read-only ledger")

    service.ledger.append = refuse
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    assert service.fenced["azazel-auditd.service"] == "unhealthy"
    assert service.fences.load() == service.fenced
    assert service.manager.calls == [("mask", "azazel-auditd.service")]
    assert _events(tmp_path) == []
    service.ledger.append = append
    service.probe("auditd", budget_ms=250, now="later", call=lambda: False)
    [event] = _events(tmp_path)
    assert event["previous_state"] == "in_service"
    assert event["previous_reason"] is None
    assert event["reason"] == "unhealthy"
    assert event["state"] == "fenced"
    assert event["occurred_at"] == NOW
    service.probe("auditd", budget_ms=250, now="later still", call=lambda: False)
    assert _events(tmp_path) == [event]


def test_failed_audit_preserves_transitions_across_reason_changes(tmp_path):
    service = _service(tmp_path)
    append = service.ledger.append

    def refuse(event):
        raise AuditUnavailable("read-only ledger")

    service.ledger.append = refuse
    service.note_interrupted_restart("auditd", now=NOW, detail="interrupted")
    service.note_restart_budget_spent("auditd", now="later", detail="spent")
    assert _events(tmp_path) == []
    service.ledger.append = append
    service.note_restart_budget_spent("auditd", now="retry", detail="still spent")
    first, changed = _events(tmp_path)
    assert first["previous_state"] == "in_service"
    assert first["previous_reason"] is None
    assert first["reason"] == changed["previous_reason"] == "restart_interrupted"
    assert changed["previous_state"] == "fenced"
    assert changed["reason"] == "restart_budget_spent"
    assert first["detail"] == "interrupted"
    assert changed["detail"] == "spent"


def test_restart_remasks_without_recording_reload_or_identical_observation(tmp_path):
    first = _service(tmp_path)
    first.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    original = _events(tmp_path)
    assert len(original) == 1
    second = _service(tmp_path)
    assert second.manager.calls == [("mask", "azazel-auditd.service")]
    assert _events(tmp_path) == original
    second.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    assert second.manager.calls == [("mask", "azazel-auditd.service")] * 2
    assert _events(tmp_path) == original


def test_status_reads_stay_read_only_regression(tmp_path):
    service = _service(tmp_path)
    service.note_interrupted_restart("auditd", now=NOW, detail="interrupted")
    original = _events(tmp_path)
    ledger_bytes = service.ledger.path.read_bytes()
    fence_bytes = service.fences.path.read_bytes()
    request = Request(
        verb=REGISTRY.resolve("watchdog.status", OPERATOR),
        arguments={},
        principal=OPERATOR,
    )
    for _ in range(10):
        assert service.handle(request) == {"fenced": service.fenced}
    assert service.ledger.path.read_bytes() == ledger_bytes
    assert service.fences.path.read_bytes() == fence_bytes
    assert _events(tmp_path) == original


# -- three conditions, three records -------------------------------------


def test_a_daemon_that_does_not_answer_in_time_is_fenced_without_waiting(tmp_path):
    """The `hanging` model: a counter past the budget, and no real time spent."""

    started = time.monotonic()
    service = _service(tmp_path, clock=_ticks(0, 10_000))
    answered = service.probe(
        "auditd", budget_ms=250, now=NOW, call=lambda: True
    )
    assert answered is False
    assert time.monotonic() - started < 0.5
    assert service.fenced["azazel-auditd.service"] == "deadline_exceeded"


def test_a_daemon_that_answers_unwell_is_fenced_for_a_different_reason(tmp_path):
    """An unanswered probe and a negative answer are both "not established".

    Neither is "fine", and the operator's next step differs, so they are
    recorded as different reasons.
    """

    service = _service(tmp_path, clock=_ticks(0, 10))
    assert service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False) is False
    assert service.fenced["azazel-auditd.service"] == "unhealthy"


def test_a_daemon_that_answers_well_in_time_is_not_fenced(tmp_path):
    service = _service(tmp_path, clock=_ticks(0, 10))
    assert service.probe("auditd", budget_ms=250, now=NOW, call=lambda: True) is True
    assert service.fenced == {}


def test_a_generation_whose_tree_moved_fences_everything(tmp_path):
    """Not one unit. The configuration they are *all* running under is wrong.

    Narrowing a single unit would leave the rest running under exactly the
    tree that failed to verify.
    """

    store = GenerationStore(tmp_path / "generations")
    store.create(
        {"suricata.yaml": b"role: observation\n"},
        created_at=NOW,
        commissioning_digest=DIGEST,
    )
    service = _service(tmp_path, generations=store)
    assert service.check_generation(now=NOW) is True

    (store.root / "1" / "tree" / "suricata.yaml").write_bytes(b"tampered\n")
    assert service.check_generation(now=NOW) is False
    assert set(service.fenced) == set(UNIT_NAMES.values())
    assert all(
        reason == "generation_mismatch" for reason in service.fenced.values()
    )


def test_an_interrupted_restart_is_its_own_reason(tmp_path):
    service = _service(tmp_path)
    service.note_interrupted_restart("watchdog", now=NOW, detail="host rebooted")
    assert service.fenced["azazel-watchdog.service"] == "restart_interrupted"


def test_all_fence_reasons_are_distinct():
    values = [reason.value for reason in FenceReason.__members__.values()]
    assert len(set(values)) == len(values)
    assert "fence_store_unreadable" in values


def test_each_fence_is_recorded_with_its_own_reason(tmp_path):
    service = _service(tmp_path, clock=_ticks(0, 10, 0, 10_000))
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    service.probe("watchdog", budget_ms=250, now=NOW, call=lambda: True)

    reasons = [event["reason"] for event in _events(tmp_path)]
    assert reasons == ["unhealthy", "deadline_exceeded"], (
        "two different failures were recorded as one kind of thing"
    )


# -- it cannot widen ------------------------------------------------------


def test_this_module_cannot_reach_the_widening_path():
    """The same rule the library applies to itself, applied here.

    A watchdog that concluded a masked unit ought to be running would have no
    way to act on it. Returning a unit to service is the activation
    controller's decision, against a revalidated generation and a valid lease.
    """

    source = WATCHDOG_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    for forbidden in ("ActivationAuthorization", "unmask_and_enable", "_MINT"):
        assert forbidden not in names, f"{forbidden} is reachable from the watchdog"


def test_the_watchdog_has_no_verb_that_returns_a_unit_to_service():
    for verb in VERBS:
        assert "unmask" not in verb.name
        assert "start" not in verb.name
        assert "restart" not in verb.name


def test_the_status_verb_is_read_only_and_the_probe_verb_is_not_an_operators():
    status = next(v for v in VERBS if v.name == "watchdog.status")
    probe = next(v for v in VERBS if v.name == "watchdog.probe")
    assert PrincipalClass.OPERATOR in status.admits
    assert PrincipalClass.OPERATOR not in probe.admits


def test_watchdog_composition_uses_its_private_state_and_audit_leaf(monkeypatch, tmp_path):
    captured = {}
    expected_state = tmp_path / "state" / "watchdog"

    def sink_for(service):
        captured["audit_service"] = service
        return lambda _event: None

    monkeypatch.setattr(runtime_paths, "watchdog_state_dir", lambda: expected_state)
    monkeypatch.setattr(runtime_paths, "socket_path", lambda name: tmp_path / f"{name}.sock")
    monkeypatch.setattr(
        runtime_paths,
        "audit_sink",
        sink_for,
    )
    monkeypatch.setattr(
        principal.PrincipalPolicy,
        "resolve",
        classmethod(lambda cls: object()),
    )
    monkeypatch.setattr(
        serve,
        "serve_forever",
        lambda **kwargs: captured.update(kwargs) or 17,
    )

    assert watchdog_module.main(stop=lambda: True) == 17
    service = captured["handler"].__self__
    assert service.ledger.path == expected_state / "watchdog.jsonl"
    assert service.fences.path == expected_state / "fences.json"
    assert captured["audit_service"] == "watchdog"
    assert captured["path"] == tmp_path / "watchdog.sock"
    assert service.refusal_log is captured["audit"]


def test_the_status_verb_reports_the_refusal_log_counters(tmp_path):
    from azazel_nexus_runtime.refusal_log import BoundedRefusalLog

    log = BoundedRefusalLog(tmp_path / "refusals.jsonl")
    log({"event_type": "runtime.request_refused", "reason": "malformed_frame", "uid": 5})
    log({"event_type": "runtime.request_refused", "reason": "malformed_frame", "uid": 5})
    service = _service(tmp_path)
    service.refusal_log = log
    answer = service.handle(Request(verb=REGISTRY.resolve("watchdog.status", OPERATOR),
                                    arguments={}, principal=OPERATOR))
    assert answer == {"fenced": {}, "refusal_log": {
        "written": 1, "suppressed": 1, "unrecorded": 0, "rotations": 0}}


# -- a fence survives the watchdog ---------------------------------------


def test_a_fence_is_still_there_after_a_restart(tmp_path):
    """A fence a process restart cleared would be one the failure could clear.

    By taking the watchdog down with it -- which is the failure most likely
    to take a watchdog down.
    """

    first = _service(tmp_path, clock=_ticks(0, 10))
    first.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)

    second = _service(tmp_path)
    assert second.fenced["azazel-auditd.service"] == "unhealthy"


def test_a_restarted_watchdog_masks_again_rather_than_only_remembering(tmp_path):
    """Persisting a fence is bookkeeping. Re-applying it is the fence.

    Found by a mutation: a watchdog that loaded its fences and left the units
    running would have survived the restart holding a list of things it
    believes are stopped. The list was all the previous test checked.
    """

    from azazel_nexus.activation import UnitState

    first = _service(tmp_path, clock=_ticks(0, 10))
    first.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)

    # A fresh manager, as a restart would have: nothing is masked yet.
    manager = RecordingUnitManager(UNIT_NAMES.values())
    for unit in UNIT_NAMES.values():
        manager.unmask_and_enable(unit)
    manager.calls.clear()

    WatchdogService(
        manager=manager,
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        fences=FenceStore(tmp_path / "fences.json"),
        clock=_ticks(0, 0),
    )
    assert ("mask", "azazel-auditd.service") in manager.calls
    assert manager.state("azazel-auditd.service") is UnitState.MASKED
    assert manager.state("azazel-watchdog.service") is UnitState.ENABLED, (
        "a unit that was never fenced must not be masked by the reconciliation"
    )


@pytest.mark.parametrize("contents", ["{ this is not json", "[]"])
def test_an_unreadable_fence_file_fences_everything_rather_than_nothing(tmp_path, contents):
    """A corrupt file must not silently return a node to service."""

    (tmp_path / "fences.json").write_text(contents, encoding="utf-8")
    service = _service(tmp_path)
    assert service.fenced == {
        unit: "fence_store_unreadable" for unit in UNIT_NAMES.values()
    }
    assert service.manager.calls == [("mask", unit) for unit in sorted(UNIT_NAMES.values())]
    assert _events(tmp_path) == []


def test_unreadable_fences_record_first_real_observation_and_keep_it_on_restart(tmp_path):
    (tmp_path / "fences.json").write_text("{ not json", encoding="utf-8")
    service = _service(tmp_path)
    assert service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False) is False

    [event] = _events(tmp_path)
    assert event["unit"] == "azazel-auditd.service"
    assert event["previous_state"] == "fenced"
    assert event["previous_reason"] == "fence_store_unreadable"
    assert event["reason"] == "unhealthy"
    assert event["state"] == "fenced"
    expected = {unit: "fence_store_unreadable" for unit in UNIT_NAMES.values()}
    expected["azazel-auditd.service"] = "unhealthy"
    assert service.fences.load() == expected
    restarted = _service(tmp_path)
    assert restarted.fenced == expected
    assert restarted.manager.calls == [("mask", unit) for unit in sorted(UNIT_NAMES.values())]
    assert _events(tmp_path) == [event]


def test_a_fence_file_naming_a_unit_this_daemon_does_not_govern_is_ignored(tmp_path):
    (tmp_path / "fences.json").write_text(
        json.dumps({"sshd.service": "unhealthy", "azazel-auditd.service": "unhealthy"}),
        encoding="utf-8",
    )
    service = _service(tmp_path)
    assert set(service.fenced) == {"azazel-auditd.service"}


def test_a_missing_fence_file_is_no_fences(tmp_path):
    """Distinct from an unreadable one. Nothing has been fenced yet."""

    service = _service(tmp_path)
    assert service.fenced == {}


# -- narrowing needs no permission ---------------------------------------


def test_corrupt_ledger_does_not_interrupt_fencing_all_units_and_retries(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    store.create(
        {"suricata.yaml": b"role: observation\n"},
        created_at=NOW,
        commissioning_digest=DIGEST,
    )
    service = _service(tmp_path, generations=store)
    service.ledger.path.write_text("not a ledger record\n", encoding="utf-8")
    (store.root / "1" / "tree" / "suricata.yaml").write_bytes(b"tampered\n")

    assert service.check_generation(now=NOW) is False
    expected = {unit: "generation_mismatch" for unit in UNIT_NAMES.values()}
    assert service.fenced == service.fences.load() == expected
    assert service.manager.calls == [("mask", unit) for unit in sorted(UNIT_NAMES.values())]
    assert service.ledger.path.read_text(encoding="utf-8") == "not a ledger record\n"

    service.ledger.path.unlink()
    assert service.check_generation(now="later") is False
    events = _events(tmp_path)
    assert len(events) == len(UNIT_NAMES)
    assert {event["unit"] for event in events} == set(UNIT_NAMES.values())
    assert all(
        event["previous_state"] == "in_service"
        and event["previous_reason"] is None
        and event["reason"] == "generation_mismatch"
        and event["occurred_at"] == NOW
        for event in events
    )


def test_unwritable_ledger_path_retries_once_on_identical_observation(tmp_path):
    service = _service(tmp_path, clock=lambda: 0)
    service.ledger.path.mkdir()
    assert service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False) is False
    assert service.fenced == service.fences.load() == {"azazel-auditd.service": "unhealthy"}
    assert service.manager.calls == [("mask", "azazel-auditd.service")]
    assert list(service.ledger.path.iterdir()) == []

    service.ledger.path.rmdir()
    service.ledger.path.touch()
    assert _events(tmp_path) == []
    service.probe("auditd", budget_ms=250, now="later", call=lambda: False)
    [event] = _events(tmp_path)
    assert event["previous_state"] == "in_service"
    assert event["previous_reason"] is None
    assert event["reason"] == "unhealthy"
    assert event["occurred_at"] == NOW
    service.probe("auditd", budget_ms=250, now="later still", call=lambda: False)
    assert _events(tmp_path) == [event]


def test_a_fence_happens_even_when_the_ledger_cannot_be_written(tmp_path):
    """Refusing to narrow because nobody can write it down leaves the node
    wide *and* unrecorded, which is worse on both counts."""

    service = _service(tmp_path, clock=_ticks(0, 10))

    def refuse(event, **kwargs):
        raise AuditUnavailable("the ledger volume is read-only")

    service.ledger.append = refuse  # type: ignore[assignment]
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    assert service.fenced["azazel-auditd.service"] == "unhealthy"


def test_a_fence_happens_even_when_the_unit_will_not_mask(tmp_path):
    """It will not be returned to service, and the failure is in the record."""

    class WontMask(RecordingUnitManager):
        def mask(self, unit):
            raise OSError("stuck")

    service = WatchdogService(
        manager=WontMask(UNIT_NAMES.values()),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        fences=FenceStore(tmp_path / "fences.json"),
        clock=_ticks(0, 10),
    )
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    assert service.fenced["azazel-auditd.service"] == "unhealthy"
    [first] = _events(tmp_path)
    assert first["unit"] == "azazel-auditd.service"
    assert first["previous_state"] == "in_service"
    assert first["previous_reason"] is None
    assert first["reason"] == "unhealthy"
    service.note_interrupted_restart("auditd", now="later", detail="interrupted")
    first_again, changed = _events(tmp_path)
    assert first_again == first
    assert changed["unit"] == "azazel-auditd.service"
    assert changed["previous_state"] == "fenced"
    assert changed["previous_reason"] == "unhealthy"
    assert changed["reason"] == "restart_interrupted"


def test_a_fence_happens_even_when_it_cannot_be_persisted(tmp_path):
    service = _service(tmp_path, clock=_ticks(0, 10))

    def refuse(fences):
        raise OSError("read-only")

    service.fences.save = refuse  # type: ignore[assignment]
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    assert service.fenced["azazel-auditd.service"] == "unhealthy"


# -- nothing waits --------------------------------------------------------


def test_this_module_never_sleeps():
    """Parsed, not searched: a text scan would match its own explanation."""

    tree = ast.parse(WATCHDOG_SOURCE.read_text(encoding="utf-8"))
    sleeps = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            getattr(node.func, "attr", "") == "sleep"
            or getattr(node.func, "id", "") == "sleep"
        )
    ]
    assert sleeps == []


def test_the_watchdog_reads_no_clock_of_its_own():
    """A component that timed its own deadline from a clock it read itself."""

    tree = ast.parse(WATCHDOG_SOURCE.read_text(encoding="utf-8"))
    forbidden = {"now", "monotonic", "time_ns", "utcnow", "perf_counter"}
    found = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden
    }
    assert found == set(), f"{sorted(found)} is a clock this module read itself"


def test_the_status_verb_answers_with_what_is_fenced(tmp_path):
    service = _service(tmp_path, clock=_ticks(0, 10))
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    verb = REGISTRY.resolve("watchdog.status", OPERATOR)
    answer = service.handle(
        Request(verb=verb, arguments={}, principal=OPERATOR)
    )
    assert answer == {"fenced": {"azazel-auditd.service": "unhealthy"}}


@pytest.mark.parametrize("exception,operation,expected", [
    (watchdog_module.DeadlineExceeded, "probe", "probe_deadline_exceeded"),
    (watchdog_module.GenerationRefused, "generation", "generation_verification_refused"),
])
def test_exception_details_use_fixed_codes(tmp_path, monkeypatch, exception, operation, expected):
    from types import SimpleNamespace

    def refused(*args, **kwargs):
        raise exception("private-path-secret-sentinel" * 1000)

    if operation == "probe":
        service = _service(tmp_path)
        monkeypatch.setattr(watchdog_module, "call_with_deadline", refused)
        assert not service.probe("auditd", budget_ms=1, now=NOW, call=lambda: True)
    else:
        generations = SimpleNamespace(current=lambda: SimpleNamespace(number=1), verify=refused)
        service = _service(tmp_path, generations=generations)
        assert not service.check_generation(now=NOW)
    assert all(event["detail"] == expected for event in _events(tmp_path))
    assert "sentinel" not in repr(_events(tmp_path))


@pytest.mark.parametrize("method", ["note_interrupted_restart", "note_restart_budget_spent"])
def test_restart_details_are_bounded_and_printable(tmp_path, method):
    service = _service(tmp_path)
    getattr(service, method)("auditd", now=NOW, detail="restart\n\x00\t\u2603" + "x" * 1000)
    [event] = _events(tmp_path)
    assert event["detail"] == "restart    " + "x" * (watchdog_module.DETAIL_MAX_LENGTH - 11)


# -- watchdog.probe is refused, never a crash ------------------------------

ROOT_PRINCIPAL = Principal(uid=0, gid=0, pid=1, classes=frozenset({PrincipalClass.ROOT}))


def test_root_probe_is_a_fixed_refusal_not_an_exception(tmp_path):
    """`watchdog.probe` is declared but driven by #42's service loop. Until
    then root's call is refused with a fixed reason; an exception escaping the
    handler would take the daemon -- and the fences it holds -- down."""

    from azazel_nexus_runtime.protocol import Refusal, RequestRefused

    service = _service(tmp_path)
    service.note_interrupted_restart("auditd", now=NOW, detail="interrupted")
    fence_bytes = service.fences.path.read_bytes()
    verb = REGISTRY.resolve("watchdog.probe", ROOT_PRINCIPAL)
    request = Request(
        verb=verb,
        arguments=verb.bind({"unit": "auditd", "budget_ms": 100}),
        principal=ROOT_PRINCIPAL,
    )
    with pytest.raises(RequestRefused) as refused:
        service.handle(request)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    assert refused.value.detail == "watchdog.probe"
    # Nothing was probed or fenced, and status still answers afterwards.
    assert service.fences.path.read_bytes() == fence_bytes
    status = Request(
        verb=REGISTRY.resolve("watchdog.status", ROOT_PRINCIPAL),
        arguments={}, principal=ROOT_PRINCIPAL,
    )
    assert service.handle(status) == {"fenced": service.fenced}


def test_the_probe_refusal_does_not_widen_who_may_call_it():
    """The fix changes the answer, not the policy: an operator is still denied
    before the handler runs."""

    from azazel_nexus_runtime.protocol import Refusal, RequestRefused

    with pytest.raises(RequestRefused) as refused:
        REGISTRY.resolve("watchdog.probe", OPERATOR)
    assert refused.value.refusal is Refusal.PRINCIPAL_DENIED
    probe = next(v for v in VERBS if v.name == "watchdog.probe")
    assert probe.admits == frozenset({PrincipalClass.ROOT})


def test_root_probe_over_the_socket_gets_a_refusal_reply_and_is_recorded(
    tmp_path, monkeypatch
):
    """Through the real per-connection engine: the reply is a refusal frame,
    the refusal is recorded, and `serve_connection` returns normally -- which
    is what keeps `serve_forever` accepting the next connection."""

    import socket

    from azazel_nexus_runtime import transport
    from azazel_nexus_runtime.transport import SocketServer, read_frame, send_frame

    class RootPolicy:
        operator_gid = None

        def classify(self, uid, gid, pid, groups=()):
            return ROOT_PRINCIPAL

    monkeypatch.setattr(transport, "peer_credentials", lambda _c: (1, 0, 0))
    monkeypatch.setattr(transport, "peer_supplementary_groups", lambda _c: ())
    recorded: list[dict] = []
    engine = SocketServer(registry=REGISTRY, policy=RootPolicy(),
                          audit=recorded.append, deadline=0.5)
    service = _service(tmp_path)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    left.settimeout(5)
    with left, right:
        send_frame(left, {"verb": "watchdog.probe",
                          "arguments": {"unit": "auditd", "budget_ms": 100}})
        left.shutdown(socket.SHUT_WR)
        engine.serve_connection(right, service.handle)
        right.close()  # the server side ends the exchange, as serve_forever does
        reply = read_frame(left)
    assert json.loads(reply) == {"ok": False, "refusal": "verb_unavailable"}
    assert [e["reason"] for e in recorded] == ["verb_unavailable"]
    assert recorded[0].get("verb") == "watchdog.probe"
