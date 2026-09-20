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

from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.generation import GenerationStore
from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager, UnitKey
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
    return [e.event for e in AuditLedger(tmp_path / "ledger.jsonl")]


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


def test_the_four_reasons_are_distinct():
    assert len({reason.value for reason in FenceReason}) == len(FenceReason)


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


def test_an_unreadable_fence_file_fences_everything_rather_than_nothing(tmp_path):
    """A corrupt file must not silently return a node to service."""

    (tmp_path / "fences.json").write_text("{ this is not json", encoding="utf-8")
    service = _service(tmp_path)
    assert set(service.fenced) == set(UNIT_NAMES.values())


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
    assert _events(tmp_path)[0]["unit"] == "azazel-auditd.service"


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
