"""Real Nexus consumer execution; missing Edge paths never become a pass."""

import copy
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from azazel_nexus import integration
from azazel_nexus.edge_intake import parse_edge_event
from azazel_nexus_runtime import edge_intaked, incident_explaind
from tools import so06_loop, so06_replay
from tools.service_objectives import CASES, PATHS, RecordRefused, validate_record

DRIVEN = {"evidence_records", "audit_chain"}


def scenarios():
    return [{"id": "nexus-consumer", "inputs": [{"event_id": "e1", "value": 7}]}]


def emit(bundle):
    return so06_replay.replay(
        bundle, commit="a" * 40, product_configuration="test only"
    )


@pytest.fixture(scope="module")
def captured():
    return so06_replay.capture_replays(scenarios())


def fresh(captured):
    return copy.deepcopy(captured)


def test_real_adapter_all_faults_audit_and_monotonic_intervals():
    ticks = iter(range(32))
    bundle = so06_replay.capture_replays(scenarios(), clock=lambda: next(ticks))
    runs = bundle["scenarios"][0]["runs"]
    assert list(runs) == list(CASES)
    for index, (case, run) in enumerate(runs.items()):
        assert (run["start_ns"], run["end_ns"]) == (2 * index, 2 * index + 1)
        assert run["observed"]["expected_behaviour"]
        assert run["paths"]["audit_chain"][0]["event"] == scenarios()[0]["inputs"][0]
        assert set(run["not_driven"]) == set(PATHS) - DRIVEN
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
    for sample in record["samples"]:
        for name in DRIVEN:
            result = sample["paths"][name]
            assert result["byte_identical"] and result["dropped_records"] == 0
            assert result["healthy_count"] > 0
        assert not sample["passed"]
        assert set(sample["not_driven"]) == set(PATHS) - DRIVEN


def test_driven_paths_carry_the_loop_records(captured):
    healthy = captured["scenarios"][0]["runs"]["healthy"]
    lines = so06_loop.golden_lines()
    evidence = healthy["paths"]["evidence_records"]
    assert [r["event"] for r in evidence] == [
        parse_edge_event(line).as_dict() for line in lines
    ]
    assert all(r["received_at"] == so06_loop.FIXED_NOW for r in evidence)
    assert [e["event"].get("event_type") for e in healthy["paths"]["audit_chain"]] == [
        None,
        "edge.incident.opened",
        "edge.incident.escalated",
        "edge.incident.closed",
    ]
    assert [r["edge_would"] for r in healthy["observed"]["consumer_loop"]["explanations"]] == [
        "notify",
        "isolate",
    ]
    for path in PATHS:
        if path not in DRIVEN:
            assert healthy["paths"][path] == []
            assert so06_replay.NOT_DRIVEN[path] in healthy["not_driven"][path]


def test_each_fault_is_consumed_where_it_is_injected(captured):
    runs = captured["scenarios"][0]["runs"]
    for case in CASES[1:]:
        dependency, mode = case.split("/")
        loop = runs[case]["observed"]["consumer_loop"]
        assert loop["boundary_calls"] == {"knowledge-read": 2, "mio-advise": 2}
        assert loop["unexpected_boundary_calls"] == 0
        states = {r["knowledge_state"] for r in loop["explanations"]}
        routes = {tuple(r["mio"]) for r in loop["explanations"]}
        if dependency == "knowledge_node_absent":
            assert states == {so06_loop.EXPECTED_KNOWLEDGE[mode][0]}
        else:
            assert states == {"available"}
        if dependency == "remote_path_unreachable":
            assert routes == {so06_loop.EXPECTED_MIO[mode][:2]}
        else:
            assert routes == {("deterministic handoff", "answered")}
        listening, accepted, code = so06_loop.EXPECTED_DECOY[
            mode if dependency == "deception_node_absent" else "healthy"
        ]
        assert loop["decoy"] == {"listening": listening, "accepted": accepted}
        refused = loop["intake"]["refused"]
        assert code is None or refused[code] == 1
        assert loop["intake"]["accepted"] == 2 and not loop["intake"]["storage_failed"]


def test_changed_production_mapping_fails_the_oracle(monkeypatch):
    # Knowledge refs silently dropped: every run becomes no_context.
    monkeypatch.setattr(incident_explaind, "read_knowledge_refs", lambda rows: ())
    record = emit(so06_replay.capture_replays(scenarios()))
    runs = record["configuration"]["replay_inputs"]["scenarios"][0]["runs"]
    assert not runs["healthy"]["observed"]["expected_behaviour"]
    assert record["execution_result"] == "FAIL"


def test_decoy_stored_as_edge_evidence_is_detected(monkeypatch):
    original = edge_intaked.IntakeServer._store_decoy

    def leaking(self, record):
        original(self, record)
        self.store.append(record)

    monkeypatch.setattr(edge_intaked.IntakeServer, "_store_decoy", leaking)
    record = emit(so06_replay.capture_replays(scenarios()))
    for sample in record["samples"]:
        if sample["case"].startswith("deception_node_absent/"):
            evidence = sample["paths"]["evidence_records"]
            assert evidence["dropped_records"] == 1
            assert not evidence["byte_identical"]
    assert record["execution_result"] == "FAIL"


def test_audit_record_depending_on_knowledge_is_detected(monkeypatch):
    original = incident_explaind.Explainer.explain

    def coupled(self, t, sequence):
        original(self, t, sequence)
        if self.knowledge_available is False:
            self.audit_pending.put_nowait({"event_type": "edge.incident.knowledge_lost"})

    monkeypatch.setattr(incident_explaind.Explainer, "explain", coupled)
    record = emit(so06_replay.capture_replays(scenarios()))
    lost = {"absent", "refusing", "hanging", "corrupt"}
    for sample in record["samples"]:
        dependency, mode = sample["case"].split("/")
        audit = sample["paths"]["audit_chain"]
        diverged = dependency == "knowledge_node_absent" and mode in lost
        assert audit["byte_identical"] is not diverged
        assert audit["fault_count"] - audit["healthy_count"] == (2 if diverged else 0)


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


def test_timestamps_excluded_from_stream_identity(captured):
    first = fresh(captured)
    second = fresh(captured)
    for case, run in second["scenarios"][0]["runs"].items():
        run["start_ns"] += 100
        run["end_ns"] += 100
    a, b = emit(first), emit(second)
    assert a != b
    assert [s["paths"] for s in a["samples"]] == [s["paths"] for s in b["samples"]]


def test_separate_captures_produce_identical_streams(captured):
    again = so06_replay.capture_replays(scenarios())
    assert [s["paths"] for s in emit(fresh(captured))["samples"]] == [
        s["paths"] for s in emit(again)["samples"]
    ]


def test_audit_divergence_and_dropped_records_are_reported(captured):
    bundle = fresh(captured)
    bundle["scenarios"][0]["runs"][CASES[1]]["paths"]["audit_chain"].clear()
    record = emit(bundle)
    result = record["samples"][0]["paths"]["audit_chain"]
    assert result["dropped_records"] == 4
    assert not result["byte_identical"]
    assert record["execution_result"] == "FAIL"


def test_evidence_dropped_records_are_reported(captured):
    bundle = fresh(captured)
    bundle["scenarios"][0]["runs"][CASES[1]]["paths"]["evidence_records"].pop()
    result = emit(bundle)["samples"][0]["paths"]["evidence_records"]
    assert result["dropped_records"] == 1 and not result["byte_identical"]


def records_in_undriven_path(runs):
    runs["healthy"]["paths"]["evaluation_outcomes"].append({})


def audit_declared_undriven(runs):
    for run in runs.values():
        run["not_driven"]["audit_chain"] = "x"


def empty_path_claimed_driven(runs):
    for run in runs.values():
        del run["not_driven"]["evaluation_outcomes"]


def one_run_claims_more(runs):
    del runs[CASES[3]]["not_driven"]["evaluation_outcomes"]


def healthy_evidence_missing(runs):
    runs["healthy"]["paths"]["evidence_records"].clear()


@pytest.mark.parametrize(
    "edit, message",
    [
        (records_in_undriven_path, "not_driven path carries no records"),
        (audit_declared_undriven, "audit is always driven"),
        (empty_path_claimed_driven, "driven path must carry records"),
        (one_run_claims_more, "same not_driven paths"),
        (healthy_evidence_missing, "driven path must carry records"),
    ],
)
def test_driven_and_not_driven_paths_are_enforced(captured, edit, message):
    bundle = fresh(captured)
    edit(bundle["scenarios"][0]["runs"])
    with pytest.raises(RecordRefused, match=message):
        emit(bundle)


def test_validator_refuses_edited_sample_and_null_time(captured):
    record = emit(fresh(captured))
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
    assert record["configuration"]["replay_inputs"]["evidence_source"] == (
        so06_replay.EVIDENCE_SOURCE
    )
