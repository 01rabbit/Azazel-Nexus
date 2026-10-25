"""SO-06 `evaluation_outcomes` on a pinned Edge clock.

CI has no Edge binary, so these runs execute a stand-in producer that stamps
the two clock fields exactly as Edge does, from its own process's wall clock.
The preload pin acts on that process just as on the real binary; the real
binary is checked with `python -m tools.so06_edge --edge-core PATH`.
"""

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import so06_edge, so06_loop, so06_replay
from tools.service_objectives import CASES, RecordRefused, validate_record

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not (shutil.which("cc") or shutil.which("gcc")),
    reason="the pinned Edge clock is a Linux preload library built with a C compiler",
)

LEASE = "enforcement_lease_records"
OUTCOMES = "evaluation_outcomes"

#: A producer shaped like Edge Core on the wire: one connection per line, a
#: forward-count report first, then one observation per alert in `eve.json`,
#: each stamped from this process's wall clock; then it runs until stopped.
PRODUCER = """\
import json, os, socket, sys, time
golden = [json.loads(line) for line in json.loads(open(sys.argv[1]).read())]
def send(value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(os.environ["AZAZEL_AI_SOCKET"])
        connection.sendall(json.dumps(value).encode() + b"\\n")
send({"schema": "azazel-edge/forward-stats/v1", "dropped": 0, "failed": 0, "sent": 0,
      "since": int(time.time())})
alerts = [json.loads(line) for line in open(os.environ["AZAZEL_EVE_PATH"])]
alerts = [e for e in alerts if e["event_type"] == "alert"]
for observation, _ in zip(golden, alerts):
    now = time.time()
    observation["normalized"]["ingest_epoch"] = now
    metadata = observation["enforcement"]["metadata"]
    if metadata["release_due_epoch"] is not None:
        metadata["release_due_epoch"] = now + 300
    send(observation)
while True:
    time.sleep(1)
"""


@pytest.fixture(scope="module")
def producer(tmp_path_factory):
    directory = tmp_path_factory.mktemp("producer")
    golden = directory / "golden.json"
    golden.write_text(json.dumps([line.decode() for line in so06_loop.golden_lines()]))
    script = directory / "edge-core"
    script.write_text(f"#!{sys.executable}\n" + PRODUCER.replace(
        "sys.argv[1]", repr(str(golden))))
    script.chmod(0o755)
    return script


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    return so06_edge.build_shim(tmp_path_factory.mktemp("shim"))


def scenarios():
    return [{"id": "nexus-consumer", "inputs": [{"event_id": "e1", "value": 7}]}]


@pytest.fixture(scope="module")
def captured(producer):
    return so06_replay.capture_replays(scenarios(), edge_core=producer)


def emit(bundle):
    return so06_replay.replay(bundle, commit="a" * 40, product_configuration="test only")


def alerts():
    from tools.e2e_loop import eve_events

    events = eve_events()
    return events, sum(e["event_type"] == "alert" for e in events)


def test_preload_pins_only_the_wall_clock(shim):
    code = ("import time; a = time.monotonic(); time.sleep(0.05); "
            "print(time.time(), int(time.monotonic() > a), time.strftime('%Y', time.gmtime()))")
    pinned = subprocess.run([sys.executable, "-c", code], env={"LD_PRELOAD": str(shim)},
                            capture_output=True, text=True, check=True).stdout.split()
    assert pinned == [f"{so06_edge.PINNED_EPOCH}.0", "1", "2026"]
    wall = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          check=True).stdout.split()
    assert float(wall[0]) != so06_edge.PINNED_EPOCH


def test_separate_pinned_runs_are_byte_identical(producer, shim):
    events, expected = alerts()
    runs = [so06_edge.run_edge(producer, events, expected=expected, shim=shim) for _ in range(2)]
    assert len(runs[0]) == expected == 2
    assert runs[0] == runs[1]
    # The forward-count report is not an observation and is never compared.
    assert all("schema" not in json.loads(line) for line in runs[0])


def test_mutation_unpinned_runs_differ(producer):
    events, expected = alerts()
    runs = [so06_edge.run_edge(producer, events, expected=expected, shim=None) for _ in range(2)]
    assert runs[0] != runs[1]
    # ... in the two clock fields only.
    assert so06_edge.without_clock(runs[0]) == so06_edge.without_clock(runs[1])


def test_a_pin_that_did_not_take_effect_is_refused(producer):
    events, expected = alerts()
    # A preload that is set but does not reach the clock: the run is refused,
    # never compared.
    with pytest.raises(so06_edge.EdgeUnavailable, match="not pinned"):
        so06_edge.run_edge(producer, events, expected=expected, shim=Path("/nonexistent.so"))
    line = json.loads(so06_loop.golden_lines()[1])
    line["normalized"]["ingest_epoch"] = so06_edge.PINNED_EPOCH
    line["enforcement"]["metadata"]["release_due_epoch"] = so06_edge.PINNED_EPOCH + 1
    with pytest.raises(so06_edge.EdgeUnavailable, match="not pinned"):
        so06_edge.require_pinned([json.dumps(line).encode()])


def test_the_clock_is_recorded_not_decided(producer, shim):
    events, expected = alerts()
    pinned = so06_edge.run_edge(producer, events, expected=expected, shim=shim)
    wall = so06_edge.run_edge(producer, events, expected=expected, shim=None)
    assert pinned != wall
    assert so06_edge.decisions_ignore_clock(pinned, wall)
    changed = json.loads(wall[1])
    changed["defense"]["action"] = "notify"
    assert not so06_edge.decisions_ignore_clock(pinned, [wall[0], json.dumps(changed).encode()])


def test_pinned_edge_drives_evaluation_outcomes_in_every_run(captured):
    assert captured["evidence_source"] == so06_replay.EDGE_EVIDENCE_SOURCE
    runs = captured["scenarios"][0]["runs"]
    assert list(runs) == list(CASES)
    healthy = runs["healthy"]["paths"][OUTCOMES]
    assert [o["defense"]["action"] for o in healthy] == ["notify", "isolate"]
    for run in runs.values():
        assert set(run["not_driven"]) == {LEASE}
        assert run["paths"][OUTCOMES] == healthy
        assert run["observed"]["expected_behaviour"]
        # Edge's observations are what the intake stored as evidence.
        assert len(run["paths"]["evidence_records"]) == len(healthy)
    record = emit(copy.deepcopy(captured))
    assert validate_record(record) == "shape_only"
    assert len(record["samples"]) == 15
    for sample in record["samples"]:
        outcome = sample["paths"][OUTCOMES]
        assert outcome["byte_identical"] and outcome["dropped_records"] == 0
        assert outcome["healthy_count"] == outcome["fault_count"] == 2
        # Every sample fails only because the lease path is not driven.
        assert all(p["byte_identical"] and p["dropped_records"] == 0
                   for p in sample["paths"].values())
        assert sample["expected_behaviour"] and set(sample["not_driven"]) == {LEASE}
        assert not sample["passed"]
    assert record["execution_result"] == "FAIL"


def test_mutation_unpinned_capture_diverges(producer, monkeypatch):
    monkeypatch.setattr(so06_edge, "build_shim", lambda directory: None)
    record = emit(so06_replay.capture_replays(scenarios(), edge_core=producer))
    diverged = [s for s in record["samples"] if not s["paths"][OUTCOMES]["byte_identical"]]
    assert len(diverged) == 15
    assert record["execution_result"] == "FAIL"


def test_validator_on_driven_evaluation_outcomes(captured):
    def edited(edit):
        bundle = copy.deepcopy(captured)
        edit(bundle["scenarios"][0]["runs"])
        return bundle

    def empty_healthy(runs):
        runs["healthy"]["paths"][OUTCOMES] = []

    with pytest.raises(RecordRefused, match="driven path must carry records"):
        emit(edited(empty_healthy))

    def one_undriven(runs):
        run = runs["knowledge_node_absent/hanging"]
        run["not_driven"][OUTCOMES] = "claimed"
        run["paths"][OUTCOMES] = []

    with pytest.raises(RecordRefused, match="same not_driven paths"):
        emit(edited(one_undriven))

    def dropped(runs):
        runs["remote_path_unreachable/corrupt"]["paths"][OUTCOMES].pop()

    record = emit(edited(dropped))
    sample = next(s for s in record["samples"] if s["case"] == "remote_path_unreachable/corrupt")
    assert sample["paths"][OUTCOMES]["dropped_records"] == 1
    assert not sample["paths"][OUTCOMES]["byte_identical"]

    def nested_clock(runs):
        runs["deception_node_absent/expired"]["paths"][OUTCOMES][0]["normalized"][
            "ingest_epoch"] += 1

    record = emit(edited(nested_clock))
    sample = next(s for s in record["samples"] if s["case"] == "deception_node_absent/expired")
    # The clock fields stay significant: no exclusion was added.
    assert not sample["paths"][OUTCOMES]["byte_identical"]
