"""SO-06 `enforcement_lease_records`: an enforcing Edge in a harness netns.

CI has no Edge binary and no network namespace, so the replay tests replace
the one enforcing run (`so06_lease.run_lease`) with a lease shaped exactly as
Edge's ledger and observations are. The namespace itself is checked where it
can be built: as root with `ip` and `nft` (the container the real binary is
checked in, `python -m tools.so06_lease --edge-core PATH`); elsewhere those
tests skip, as the root E2E stages do.
"""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import so06_edge, so06_lease, so06_loop, so06_replay
from tools.service_objectives import validate_record

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not (shutil.which("cc") or shutil.which("gcc")),
    reason="the pinned Edge clock is a Linux preload library built with a C compiler",
)

LEASE = "enforcement_lease_records"
PINNED = so06_edge.PINNED_EPOCH
DUE = PINNED + so06_edge.EDGE_ACTION_TTL_S

from tests.unit.test_so06_edge import producer  # noqa: E402,F401  (fixture)


def scenarios():
    return [{"id": "nexus-consumer", "inputs": [{"event_id": "e1", "value": 7}]}]


def emit(bundle):
    return so06_replay.replay(bundle, commit="a" * 40, product_configuration="test only")


def task(status="active", now=PINNED, attempts=0):
    """One release task in the ledger's own schema (`release.rs`)."""
    return {
        "task_id": "release-05ac29a474216a82", "trace_id": "trace-0x1", "action": "isolate",
        "resource_key": "nft:inet:azazel_edge:input:192.0.2.1",
        "owner_token": "azazel-edge:release-05ac29a474216a82", "iface": so06_lease.LEASE_IFACE,
        "tc_handle": "", "source_ip": "192.0.2.1", "destination_port": 22, "redirect_port": 2222,
        "expected_rate_bps": 0, "expected_burst_bytes": 0, "expected_latency_us": 0,
        "due_epoch": now + 300, "next_attempt_epoch": now + 300, "created_epoch": now,
        "updated_epoch": now, "status": status, "attempts": attempts,
        "last_error": "" if status == "active" else "provider_apply_failed",
    }


def enforcing(lines, state="active", task_id="release-05ac29a474216a82"):
    """The golden observations as an enforcing Edge reports them."""
    out = []
    for raw in lines:
        line = json.loads(raw)
        line["enforcement_status"].update(enforce_enabled=True, dry_run=False,
                                          enforce_level="full-auto")
        metadata = line["enforcement"]["metadata"]
        if metadata["release_task_id"] is not None:
            line["enforcement"]["mode"] = "enforced"
            metadata.update(release_task_id=task_id, release_ledger_state=state)
        out.append(json.dumps(line).encode())
    return out


def lease(status="active", now=PINNED):
    tasks = [task(status, now)]
    return {"observations": enforcing(so06_loop.golden_lines(), status),
            "tasks": tasks,
            "owned": [t["owner_token"] for t in tasks if t["status"] == "active"]}


def two_leases(keep=2):
    """Two active leases, one enforced observation naming each; `keep` of them held."""
    isolate = so06_loop.golden_lines()[1]
    tasks = [{**task(), "task_id": f"release-{i}", "owner_token": f"azazel-edge:release-{i}"}
             for i in range(keep)]
    lines = [enforcing([isolate], task_id=t["task_id"])[0] for t in tasks]
    return {"observations": lines, "tasks": tasks, "owned": sorted(t["owner_token"] for t in tasks)}


def capture(monkeypatch, producer, make):  # noqa: F811
    """A replay whose enforcing run returns `make(call_number)`."""
    calls = []

    def fake(binary, events, *, expected, shim, isolation=None):
        assert isinstance(shim, Path), "the lease run is on the pinned clock"
        calls.append(binary)
        return make(len(calls))

    monkeypatch.setattr(so06_lease, "run_lease", fake)
    bundle = so06_replay.capture_replays(scenarios(), edge_core=producer, lease_netns=True)
    assert len(calls) == 16
    return bundle


def test_a_driven_lease_path_passes_when_all_four_paths_match(monkeypatch, producer):  # noqa: F811
    bundle = capture(monkeypatch, producer, lambda n: lease())
    assert bundle["evidence_source"] == so06_replay.LEASE_EVIDENCE_SOURCE
    for run in bundle["scenarios"][0]["runs"].values():
        assert run["not_driven"] == {}
        assert run["paths"][LEASE] == [task()]
        assert run["observed"]["lease"] == {
            "states": [["isolate", "active", ""]], "intake_refused": True}
    record = emit(copy.deepcopy(bundle))
    assert validate_record(record) == "shape_only"
    assert all(s["passed"] and s["not_driven"] == {} for s in record["samples"])
    assert record["execution_result"] == "PASS"
    # The record names the binary it ran; no binary digest is pinned by Nexus.
    identity = record["configuration"]["replay_inputs"]["edge_core"]
    assert identity == {"sha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
                        "pinned_edge": False}


def test_a_lease_never_held_active_is_not_driven(monkeypatch, producer):  # noqa: F811
    # What the real binary does on nftables 1.1: it writes the lease, the apply
    # fails, it cancels it. Byte-identical in every run, and still not driven.
    bundle = capture(monkeypatch, producer, lambda n: lease("cancelled"))
    for run in bundle["scenarios"][0]["runs"].values():
        assert run["paths"][LEASE] == []
        assert run["not_driven"][LEASE].startswith(so06_lease.NO_ACTIVE_LEASE)
        assert run["observed"]["lease"]["records"] == [task("cancelled")]
        assert run["observed"]["lease"]["states"] == [
            ["isolate", "cancelled", "provider_apply_failed"]]
        assert run["observed"]["expected_behaviour"]
    record = emit(bundle)
    assert not any(s["passed"] for s in record["samples"])
    assert record["execution_result"] == "FAIL"


def test_one_run_without_an_active_lease_undrives_the_path(monkeypatch, producer):  # noqa: F811
    bundle = capture(monkeypatch, producer, lambda n: lease("cancelled" if n == 9 else "active"))
    runs = bundle["scenarios"][0]["runs"].values()
    assert all(set(run["not_driven"]) == {LEASE} for run in runs)
    assert emit(bundle)["execution_result"] == "FAIL"


def test_mutation_without_the_lease_run_the_path_is_not_driven(producer):  # noqa: F811
    bundle = so06_replay.capture_replays(scenarios(), edge_core=producer)
    for run in bundle["scenarios"][0]["runs"].values():
        assert set(run["not_driven"]) == {LEASE}
        assert "--lease-netns" in run["not_driven"][LEASE]
        assert run["paths"][LEASE] == []
    record = emit(bundle)
    assert not any(s["passed"] for s in record["samples"])
    assert record["execution_result"] == "FAIL"


def test_mutation_an_unpinned_lease_diverges_in_every_sample(monkeypatch, producer):  # noqa: F811
    # Each run's ledger stamped from the wall clock, as without the pin.
    bundle = capture(monkeypatch, producer, lambda n: lease(now=time.time() + n))
    record = emit(bundle)
    assert sum(not s["paths"][LEASE]["byte_identical"] for s in record["samples"]) == 15
    assert record["execution_result"] == "FAIL"


def test_mutation_a_lost_lease_is_a_dropped_record(monkeypatch, producer):  # noqa: F811
    # One fault run whose ledger, report and netns all lost one of two leases.
    record = emit(capture(monkeypatch, producer, lambda n: two_leases(1 if n == 5 else 2)))
    failed = [s for s in record["samples"] if not s["passed"]]
    assert len(failed) == 1
    assert failed[0]["paths"][LEASE]["dropped_records"] == 1
    assert record["execution_result"] == "FAIL"


def test_a_lease_the_netns_disagrees_with_is_not_expected_behaviour(monkeypatch, producer):  # noqa: F811
    # One fault run whose ledger says active while its netns holds no rule:
    # the records still match byte for byte, the behaviour does not.
    def make(n):
        return {**lease(), "owned": []} if n == 7 else lease()

    record = emit(capture(monkeypatch, producer, make))
    failed = [s for s in record["samples"] if not s["passed"]]
    assert len(failed) == 1 and not failed[0]["expected_behaviour"]
    assert all(p["byte_identical"] for p in failed[0]["paths"].values())
    assert record["execution_result"] == "FAIL"


def test_lease_run_requires_edge_core():
    with pytest.raises(so06_edge.EdgeUnavailable, match="needs --edge-core"):
        so06_replay.capture_replays(scenarios(), lease_netns=True)


def test_the_lease_run_refuses_a_host_without_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(so06_edge.EdgeUnavailable, match="needs root"):
        so06_lease.run_lease(Path("/nonexistent"), [], expected=1, shim=None)


def test_an_unpinned_ledger_is_refused():
    so06_lease.require_pinned_ledger([task()])
    for field, value in (("created_epoch", PINNED + 1), ("updated_epoch", PINNED - 1),
                         ("due_epoch", PINNED), ("next_attempt_epoch", DUE + 1)):
        with pytest.raises(so06_edge.EdgeUnavailable, match="not pinned"):
            so06_lease.require_pinned_ledger([{**task(), field: value}])
    missing = task()
    del missing["owner_token"]
    with pytest.raises(so06_edge.EdgeUnavailable, match="lacks"):
        so06_lease.require_pinned_ledger([missing])
    # A later Edge's CLOCK_BOOTTIME deadline is not fixed by the pin: refused,
    # never compared, and no exclusion is added for it.
    with pytest.raises(so06_edge.EdgeUnavailable, match="due_boottime_ns"):
        so06_lease.require_pinned_ledger([{**task(), "due_boottime_ns": 1, "due_boot_id": "b"}])


def test_lease_expected_needs_the_intake_refusal(monkeypatch):
    assert so06_lease.lease_expected(lease())
    monkeypatch.setattr(so06_lease, "refused_by_intake", lambda lines: False)
    assert not so06_lease.lease_expected(lease())


def test_a_refusal_for_another_reason_is_not_the_posture_refusal():
    from azazel_nexus.edge_intake import EdgeEventRefused, parse_edge_event

    line = json.loads(lease()["observations"][1])
    del line["defense"]
    raw = json.dumps(line).encode()
    with pytest.raises(EdgeEventRefused) as refused:
        parse_edge_event(raw)
    assert "EDGE_NOT_OBSERVE_ONLY" not in str(refused.value)
    assert not so06_lease.refused_by_intake([raw])
    assert not so06_lease.refused_by_intake([lease()["observations"][0], raw])


def test_a_lease_named_by_an_unenforced_observation_is_not_expected():
    run = lease()
    line = json.loads(run["observations"][1])
    line["enforcement"]["mode"] = "dry_run"
    run["observations"][1] = json.dumps(line).encode()
    assert so06_lease.refused_by_intake(run["observations"])
    assert not so06_lease.lease_expected(run)


def test_the_ledger_holds_exactly_one_task_per_named_lease():
    run = lease()
    run["tasks"] = [task(), task()]
    run["owned"] = [task()["owner_token"]] * 2
    assert not so06_lease.lease_expected(run)


def test_the_ledger_state_is_the_one_edge_reported():
    # Edge reports it active; the ledger says cancelled and nothing is owned.
    run = {**lease(), "tasks": [task("cancelled")], "owned": []}
    assert not so06_lease.lease_expected(run)


def test_no_named_lease_is_not_an_expected_lease():
    notify = so06_loop.golden_lines()[0]
    run = {"observations": enforcing([notify]), "tasks": [], "owned": []}
    assert so06_lease.refused_by_intake(run["observations"])
    assert not so06_lease.lease_expected(run)


def test_the_enforcing_posture_is_the_one_edge_applies_under():
    # Edge applies only with enforce on, dry run off and a level that permits
    # the action (`should_execute_action`); dry run on only plans.
    posture = so06_lease.ENFORCE_POSTURE
    assert posture["AZAZEL_DEFENSE_ENFORCE"] == "true"
    assert posture["AZAZEL_DEFENSE_DRY_RUN"] == "false"
    assert posture["AZAZEL_DEFENSE_ENFORCE_LEVEL"] == "full-auto"
    assert "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO" not in posture


class FakeIsolation:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def wrap(self, argv):
        return argv

    def owned_tokens(self):
        return []


def test_run_lease_refuses_an_unpinned_ledger(monkeypatch):
    lines = lease()["observations"]
    monkeypatch.setattr(so06_edge, "run_edge_in", lambda *a, **k: (
        lines, ([task(now=PINNED + 1)], [])))
    with pytest.raises(so06_edge.EdgeUnavailable, match="not pinned"):
        so06_lease.run_lease(Path("/x"), [], expected=2, shim=Path("/x.so"),
                             isolation=FakeIsolation())
    # The wall-clock run (mutation checks only) is returned, not refused.
    assert so06_lease.run_lease(Path("/x"), [], expected=2, shim=None,
                                isolation=FakeIsolation())["tasks"] == [task(now=PINNED + 1)]


def test_an_enforcing_posture_outside_isolation_is_refused():
    with pytest.raises(so06_edge.EdgeUnavailable, match="inside the harness's isolation"):
        so06_edge.run_edge_in(Path("/nonexistent"), [], expected=1, shim=None,
                              environment=so06_lease.ENFORCE_POSTURE)


def test_a_ledger_with_another_top_level_is_refused(tmp_path):
    ledger = tmp_path / so06_lease.LEDGER
    ledger.write_text(json.dumps({"schema_version": "v", "tasks": [task()]}))
    assert so06_lease.read_ledger(tmp_path) == [task()]
    ledger.write_text(json.dumps({"schema_version": "v", "tasks": [], "extra": 1}))
    with pytest.raises(so06_edge.EdgeUnavailable, match="top level"):
        so06_lease.read_ledger(tmp_path)
    assert so06_lease.read_ledger(tmp_path / "absent") == []


def test_signals_unwind_like_an_interrupt():
    import signal

    before = signal.getsignal(signal.SIGTERM)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        with pytest.raises(KeyboardInterrupt), so06_lease.signals_as_interrupt():
            os.kill(os.getpid(), sig)
    assert signal.getsignal(signal.SIGTERM) == before


def test_lease_expected_checks_ledger_report_and_owned_state():
    assert so06_lease.lease_expected(lease())
    assert so06_lease.lease_expected(lease("cancelled"))
    # The observation reports a state the ledger does not hold.
    run = lease()
    run["tasks"][0]["status"] = "prepared"
    assert not so06_lease.lease_expected(run)
    # An active lease with no rule in the netns, or a rule nobody leased.
    assert not so06_lease.lease_expected({**lease(), "owned": []})
    assert not so06_lease.lease_expected({**lease("cancelled"), "owned": ["azazel-edge:x"]})
    # A ledger task no observation names.
    run = lease()
    run["tasks"].append({**task(), "task_id": "release-other"})
    assert not so06_lease.lease_expected(run)
    # No lease at all is not a driven lease.
    assert not so06_lease.lease_expected({"observations": so06_loop.golden_lines(),
                                          "tasks": [], "owned": []})


def test_the_intake_still_refuses_an_enforcing_edge():
    assert so06_lease.refused_by_intake(lease()["observations"])
    # The observe-only golden lines are accepted, so this is not a blanket refusal.
    assert not so06_lease.refused_by_intake(so06_loop.golden_lines())
    assert not so06_lease.refused_by_intake([])


def test_the_pin_hides_no_release():
    pinned, wall = [task()], [task(now=time.time())]
    assert so06_lease.lease_ignores_clock(pinned, wall)
    assert not so06_lease.lease_ignores_clock(pinned, [{**wall[0], "status": "released"}])
    assert not so06_lease.lease_ignores_clock(pinned, [{**wall[0], "attempts": 1}])
    # A release attempted in both runs is not hidden by their agreeing.
    assert not so06_lease.lease_ignores_clock([task(attempts=1)], [task(now=time.time(), attempts=1)])
    released = {**task(), "status": "released"}
    assert not so06_lease.lease_ignores_clock([released], [{**released, "created_epoch": 1.0}])
    assert not so06_lease.lease_ignores_clock([], [])


def _netns_available():
    if os.geteuid() != 0 or not (shutil.which("ip") and shutil.which("nft")):
        return False
    probe = f"azso06l-probe-{os.getpid()}"
    made = subprocess.run(["ip", "netns", "add", probe], capture_output=True).returncode == 0
    if made:
        subprocess.run(["ip", "netns", "del", probe], capture_output=True)
    return made


needs_netns = pytest.mark.skipif(
    not _netns_available(), reason="root, ip, nft and a network namespace are needed")


def _host_has_table():
    out = subprocess.run(["nft", "list", "table", "inet", "azazel_edge"], capture_output=True)
    return out.returncode == 0


@needs_netns
def test_the_netns_is_built_used_and_removed_without_touching_the_host():
    host_before = _host_has_table()
    with so06_lease.Netns() as netns:
        name = netns.name
        assert name in subprocess.run(["ip", "netns", "list"], capture_output=True,
                                      text=True).stdout
        assert netns.owned_tokens() == []
        rule = ["nft", "insert", "rule", "inet", "azazel_edge", "input", "ip", "saddr",
                "192.0.2.1", "drop", "comment", '"azazel-edge:release-x"']
        subprocess.run(netns.wrap(rule), check=True)
        assert netns.owned_tokens() == ["azazel-edge:release-x"]
        links = subprocess.run(netns.wrap(["ip", "-o", "link"]), capture_output=True,
                               text=True).stdout
        assert so06_lease.LEASE_IFACE in links
        assert _host_has_table() == host_before
    assert name not in subprocess.run(["ip", "netns", "list"], capture_output=True,
                                      text=True).stdout


#: A producer shaped like an enforcing Edge Core: per disruptive alert it
#: writes the release task (from this process's wall clock) to the ledger,
#: inserts the owned rule with `nft` -- quoting the comment, so the apply
#: succeeds -- marks the task active and reports `enforced`.
ENFORCING = """\
import json, os, socket, subprocess, sys, time
golden = [json.loads(line) for line in json.loads(open(sys.argv[1]).read())]
def send(value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(os.environ["AZAZEL_AI_SOCKET"])
        connection.sendall(json.dumps(value).encode() + b"\\n")
enforce = os.environ["AZAZEL_DEFENSE_ENFORCE"] == "true"
applies = enforce and os.environ["AZAZEL_DEFENSE_DRY_RUN"] == "false"
tasks = []
for observation in golden:
    now = time.time()
    observation["normalized"]["ingest_epoch"] = now
    observation["enforcement_status"].update(
        enforce_enabled=enforce, dry_run=os.environ["AZAZEL_DEFENSE_DRY_RUN"] == "true",
        enforce_level=os.environ["AZAZEL_DEFENSE_ENFORCE_LEVEL"])
    enforcement = observation["enforcement"]
    metadata = enforcement["metadata"]
    if metadata["release_task_id"] is not None and applies:
        metadata["release_due_epoch"] = now + 300
        task = {"task_id": metadata["release_task_id"], "trace_id": enforcement["trace_id"],
                "action": enforcement["selected_action"],
                "resource_key": metadata["release_resource_key"],
                "owner_token": metadata["release_owner_token"],
                "iface": os.environ["AZAZEL_DEFENSE_IFACE"], "tc_handle": "",
                "source_ip": "192.0.2.1", "destination_port": 22, "redirect_port": 2222,
                "expected_rate_bps": 0, "expected_burst_bytes": 0, "expected_latency_us": 0,
                "due_epoch": now + 300, "next_attempt_epoch": now + 300,
                "created_epoch": now, "updated_epoch": now, "status": "active",
                "attempts": 0, "last_error": ""}
        subprocess.run(["nft", "insert", "rule", "inet", "azazel_edge", "input", "ip", "saddr",
                        "192.0.2.1", "drop", "comment", '"' + task["owner_token"] + '"'],
                       check=True)
        tasks.append(task)
        with open(os.environ["AZAZEL_DEFENSE_RELEASE_LEDGER"], "w") as ledger:
            json.dump({"schema_version": "test", "tasks": tasks}, ledger)
        enforcement["mode"] = "enforced"
        metadata["release_ledger_state"] = "active"
    send(observation)
while True:
    time.sleep(1)
"""


@pytest.fixture(scope="module")
def enforcing_producer(tmp_path_factory):
    directory = tmp_path_factory.mktemp("enforcing")
    golden = directory / "golden.json"
    golden.write_text(json.dumps([line.decode() for line in so06_loop.golden_lines()]))
    script = directory / "edge-core"
    script.write_text(f"#!{sys.executable}\n" + ENFORCING.replace(
        "sys.argv[1]", repr(str(golden))))
    script.chmod(0o755)
    return script


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    return so06_edge.build_shim(tmp_path_factory.mktemp("shim"))


@needs_netns
def test_an_enforcing_run_in_the_netns_records_its_lease(enforcing_producer, shim):
    from tools.e2e_loop import eve_events

    events = eve_events()
    expected = sum(e["event_type"] == "alert" for e in events)
    host_before = _host_has_table()
    runs = [so06_lease.run_lease(enforcing_producer, events, expected=expected, shim=shim)
            for _ in range(2)]
    assert runs[0]["tasks"] == runs[1]["tasks"]
    assert [t["status"] for t in runs[0]["tasks"]] == ["active"]
    assert runs[0]["owned"] == [runs[0]["tasks"][0]["owner_token"]]
    assert all(so06_lease.lease_expected(run) for run in runs)
    # The enforcing posture reached only the netns.
    assert _host_has_table() == host_before
    # Mutation: on the wall clock the ledger differs, in its epochs only, and
    # no release fell due inside the run.
    wall = so06_lease.run_lease(enforcing_producer, events, expected=expected, shim=None)
    assert wall["tasks"] != runs[0]["tasks"]
    assert so06_lease.lease_ignores_clock(runs[0]["tasks"], wall["tasks"])
    # A preload that does not reach the clock is refused, never compared.
    with pytest.raises(so06_edge.EdgeUnavailable, match="not pinned"):
        so06_lease.run_lease(enforcing_producer, events, expected=expected,
                             shim=Path("/nonexistent.so"))


#: Stands in for an Edge that never reports: the harness waits on it.
HANGING = """\
import time
while True:
    time.sleep(1)
"""


def _azso06l_netns():
    listed = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    return sorted(n for n in listed.split() if so06_lease.NETNS_NAME.fullmatch(n))


def _running(path):
    for proc in Path("/proc").iterdir():
        try:
            if str(path) in (proc / "cmdline").read_bytes().decode(errors="replace"):
                return True
        except OSError:
            continue
    return False


@needs_netns
@pytest.mark.parametrize("sig", ["SIGTERM", "SIGHUP"])
def test_a_terminated_lease_run_leaves_no_namespace_or_edge(tmp_path, sig):
    import signal

    script = tmp_path / "edge-core"
    script.write_text(f"#!{sys.executable}\n" + HANGING)
    script.chmod(0o755)
    before = _azso06l_netns()
    harness = subprocess.Popen([sys.executable, "-m", "tools.so06_lease", "--edge-core",
                                str(script)], cwd=ROOT, env=dict(os.environ),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 30
        while not (set(_azso06l_netns()) - set(before) and _running(script)):
            assert harness.poll() is None and time.monotonic() < until
            time.sleep(0.05)
        harness.send_signal(getattr(signal, sig))
        harness.wait(30)
    finally:
        if harness.poll() is None:
            harness.kill()
    assert _azso06l_netns() == before
    assert not _running(script)


@needs_netns
def test_a_namespace_left_by_a_killed_run_is_swept():
    stale = "azso06l-0badc0de"
    subprocess.run(["ip", "netns", "add", stale], check=True)
    sleeper = subprocess.Popen(["ip", "netns", "exec", stale, "sleep", "300"])
    try:
        assert stale in so06_lease.sweep_stale_netns()
        assert stale not in _azso06l_netns()
        assert sleeper.wait(10) is not None
    finally:
        if sleeper.poll() is None:
            sleeper.kill()
        subprocess.run(["ip", "netns", "del", stale], capture_output=True)


@needs_netns
def test_a_namespace_that_cannot_be_deleted_is_an_error():
    with pytest.raises(so06_edge.EdgeUnavailable, match="not deleted"):
        so06_lease.delete_netns(shutil.which("ip"), "azso06l-notthere")
