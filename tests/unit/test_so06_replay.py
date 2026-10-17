"""Real Nexus consumer execution; missing Edge paths never become a pass."""

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from azazel_nexus import integration
from tools import so06_replay
from tools.service_objectives import CASES, PATHS, RecordRefused, validate_record


def scenarios():
    return [{"id": "nexus-consumer", "inputs": [{"event_id": "e1", "value": 7}]}]


def emit(bundle):
    return so06_replay.replay(
        bundle, commit="a" * 40, product_configuration="test only"
    )


def test_real_adapter_all_faults_audit_and_monotonic_intervals():
    ticks = iter(range(32))
    bundle = so06_replay.capture_replays(scenarios(), clock=lambda: next(ticks))
    runs = bundle["scenarios"][0]["runs"]
    assert list(runs) == list(CASES)
    for index, (case, run) in enumerate(runs.items()):
        assert (run["start_ns"], run["end_ns"]) == (2 * index, 2 * index + 1)
        assert run["observed"]["expected_behaviour"]
        assert run["paths"]["audit_chain"][0]["event"] == scenarios()[0]["inputs"][0]
        assert set(run["not_driven"]) == set(PATHS) - {"audit_chain"}
        if case != "healthy":
            assert (
                run["observed"]["disposition"]
                == so06_replay.EXPECTED[case.split("/")[1]]
            )
    record = emit(bundle)
    assert validate_record(record) == "shape_only"
    assert record["execution_result"] == "FAIL"
    assert "verdict" not in record
    assert record["evaluation"]["failed_comparisons"] == 15
    assert all(s["paths"]["audit_chain"]["byte_identical"] for s in record["samples"])


def test_hanging_deadline_is_checked_by_harness(monkeypatch):
    clock = so06_replay.FaultClock()
    assert so06_replay.observe_fault("hanging", clock).value == "hanging"
    assert clock.ms > so06_replay.BUDGET_MS
    # Removing deadline enforcement must no longer produce the expected result.
    monkeypatch.setattr(
        so06_replay.degradation, "call_with_deadline", lambda call, **kw: call()
    )
    with pytest.raises(ValueError, match="healthy response"):
        so06_replay.observe_fault("hanging", so06_replay.FaultClock())


def test_adapter_observes_real_integration_divergence_and_records_fail(monkeypatch):
    original = integration.build_view

    def broken_view(**kwargs):
        view = original(**kwargs)
        return replace(
            view,
            rows=tuple(
                replace(row, continues=("lost audit",))
                if row.axis == "capability"
                else row
                for row in view.rows
            ),
        )

    monkeypatch.setattr(integration, "build_view", broken_view)
    record = emit(so06_replay.capture_replays(scenarios()))
    observations = record["configuration"]["replay_inputs"]["scenarios"][0]["runs"]
    assert all(
        not run["observed"]["expected_behaviour"] for run in observations.values()
    )
    assert record["execution_result"] == "FAIL"
    assert all(not sample["passed"] for sample in record["samples"])


def test_timestamps_excluded_from_stream_identity():
    first = so06_replay.capture_replays(scenarios(), clock=lambda: 100)
    second = so06_replay.capture_replays(scenarios(), clock=lambda: 200)
    a, b = emit(first), emit(second)
    assert a != b
    assert [s["paths"] for s in a["samples"]] == [s["paths"] for s in b["samples"]]


def test_audit_divergence_and_dropped_records_are_reported():
    bundle = so06_replay.capture_replays(scenarios())
    bundle["scenarios"][0]["runs"][CASES[1]]["paths"]["audit_chain"].clear()
    record = emit(bundle)
    result = record["samples"][0]["paths"]["audit_chain"]
    assert result["dropped_records"] == 1
    assert not result["byte_identical"]
    assert record["execution_result"] == "FAIL"


def test_validator_refuses_edited_sample_and_null_time():
    record = emit(so06_replay.capture_replays(scenarios()))
    record["samples"][0]["start_ns"] = None
    with pytest.raises(RecordRefused, match="reproduce"):
        validate_record(record)


def test_cli_executes_scenarios_and_returns_failure_for_missing_paths(tmp_path):
    source, output = tmp_path / "inputs.json", tmp_path / "record.json"
    source.write_text(json.dumps({"scenarios": scenarios()}))
    assert (
        so06_replay.main(
            [
                str(source),
                str(output),
                "--commit",
                "a" * 40,
                "--configuration",
                "test only",
            ]
        )
        == 1
    )
    record = json.loads(output.read_text())
    assert record["clock"] == "CLOCK_MONOTONIC"
    assert record["execution_result"] == "FAIL"
    assert validate_record(record) == "shape_only"
