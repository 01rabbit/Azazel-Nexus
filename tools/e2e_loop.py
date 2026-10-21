"""I5: real account/daemon integration, with a real Edge or golden observations.

All relocation and credential handling lives in test tooling. No product peer
policy is replaced. The binary path needs Linux strace to verify its network
syscalls, rather than inferring its connections from files left on disk.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from tools.e2e_harness import Daemon, Harness, NotExecuted, ROOT, account_credentials, request

#: Edge's stdout for eve_events(): the two alerts' decisions, in order, and
#: their Suricata severities (lower is more severe; the second escalates).
EDGE_DECISIONS = ["notify", "isolate"]
EDGE_SEVERITIES = [4, 1]
#: Stopping intake makes the explainer forward a close; confirmed on its own
#: budget, so a slow observation phase does not starve the shutdown check.
CLOSE_SECONDS = 10
#: Edge reports its forward counts at start and then every 10 s when they
#: changed; the intake publishes them in its next 5 s status snapshot.
FORWARD_SECONDS = 16


def golden_lines() -> list[bytes]:
    lines = (ROOT / "tests/fixtures/edge/rust_event_engine_v1.jsonl").read_bytes().splitlines()
    # Producer-shaped notify -> isolate, with verbatim rule-supplied techniques.
    return [lines[3], lines[5]]


def forward_stats_line(sent: int) -> bytes:
    """Edge's forward counts after delivering `sent` events and losing none."""
    from azazel_nexus.edge_intake import FORWARD_STATS_SCHEMA
    return json.dumps({"schema": FORWARD_STATS_SCHEMA, "dropped": 0, "failed": 0,
                       "sent": sent, "since": int(time.time())}).encode()


def eve_events() -> list[dict]:
    events = []
    for line in golden_lines():
        n = json.loads(line)["normalized"]
        events.append({
            "timestamp": n["ts"], "event_type": "alert", "src_ip": n["src_ip"],
            "dest_ip": n["dst_ip"], "dest_port": n["target_port"], "proto": n["protocol"],
            "alert": {"signature_id": n["sid"], "signature": n["attack_type"],
                      "category": n["category"], "severity": n["severity"],
                      "action": n["action"], "confidence": n["confidence"],
                      "metadata": {"mitre_technique_id": n["technique_ids"]}},
        })
    events.insert(1, {"event_type": "flow", "src_ip": "192.0.2.100",
                      "dest_ip": "198.51.100.200", "flow": {"pkts_toserver": 1}})
    return events


def edge_environment(harness: Harness, intake: Path, state: Path) -> dict:
    """The unit profile's Environment= values, with test paths relocated.

    Only the socket, eve and release ledger paths and AZAZEL_EVE_FROM_START
    differ; with --edge-redirect-policy, so does AZAZEL_REDIRECT_POLICY_PATH
    (a copy inside the root). Otherwise that path stays the shipped one, which
    normally does not exist here, so Edge takes its no-policy default.
    """
    from azazel_nexus_runtime.hardening import PROFILES

    profile = next(p for p in PROFILES if p.unit == "azazel-edge-core.service")
    # Do not inherit caller AZAZEL_* knobs, loaders or optional Edge clients.
    environment = dict(value.split("=", 1) for key, value in profile.extra if key == "Environment")
    environment.update(AZAZEL_AI_SOCKET=str(intake), AZAZEL_EVE_PATH=str(state / "eve.json"),
                       AZAZEL_DEFENSE_RELEASE_LEDGER=str(state / "release-ledger.json"),
                       AZAZEL_EVE_FROM_START="true")
    if harness.edge_redirect_policy is not None:
        environment["AZAZEL_REDIRECT_POLICY_PATH"] = str(state / "redirect_policy.yaml")
    return environment


def wait_until(deadline, check, processes=(), what="observation"):
    """Poll until check() passes or the deadline.

    Only "not there yet" is retried: an assertion, or a file not yet created.
    Live JSONL is read as complete lines (`complete`), and status snapshots are
    replaced atomically, so a decode or chain error is a real defect and is
    raised at once rather than waited out.
    """
    last = "condition not reached"
    while time.monotonic() < deadline:
        for daemon in processes:
            assert daemon.process.poll() is None, f"{daemon.module} exited during the loop"
        try:
            return check()
        except (AssertionError, FileNotFoundError) as exc:
            last = str(exc)
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    raise AssertionError(f"integrated loop {what} deadline: {last}")


def complete(data: bytes) -> bytes:
    """Up to the last newline: a writer may be mid-append while we poll."""
    return data[:data.rfind(b"\n") + 1]


def json_lines(directory: Path) -> list[dict]:
    return [json.loads(line) for path in sorted(directory.glob("*.jsonl"))
            for line in complete(path.read_bytes()).splitlines()]


def ledger_events(directory: Path) -> list[dict]:
    """Verify and read a live ledger's complete records.

    A torn final append is not a record yet; it is left out of a copy rather
    than retried around. Every complete line is still verified strictly.
    """
    from azazel_nexus_runtime.auditd import SegmentedLedger

    with tempfile.TemporaryDirectory() as scratch:
        for segment in sorted(directory.glob("*.jsonl")):
            (Path(scratch) / segment.name).write_bytes(complete(segment.read_bytes()))
        ledger = SegmentedLedger(Path(scratch))
        ledger.verify()
        return [entry.event for entry in ledger]


def sockets(root: Path) -> set[Path]:
    found = set()
    for path in root.rglob("*"):
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue  # removed while walking: no longer a socket that exists
        if stat.S_ISSOCK(mode):
            found.add(path)
    return found


def prepare_accounts(harness: Harness):
    """Give earlier harness-written files back to their declared service owners.

    Prior stages intentionally run as the harness uid. This stage exercises
    actual service uids, so existing synthetic ledgers/imports need the same
    ownership as installed/imported data. Trust remains root-owned/read-only.
    """
    import grp
    import pwd
    from azazel_nexus.layout import LAYOUT

    harness.root.chmod(stat.S_IMODE(harness.root.stat().st_mode) | 0o111)
    trees = {"/var/lib/azazel/state/audit", "/var/lib/azazel/state/mio",
             "/var/lib/azazel/knowledge"}
    for spec in LAYOUT:
        if spec.path not in trees:
            continue
        path = harness.root / spec.path.lstrip("/")
        uid, gid = pwd.getpwnam(spec.owner).pw_uid, grp.getgrnam(spec.group).gr_gid
        for child in [path, *path.rglob("*")]:
            assert not child.is_symlink(), "synthetic service data contains a symlink"
            os.chown(child, uid, gid)
    trust = harness.root / "var/lib/azazel/lite-trust"
    for child in [trust, *trust.rglob("*")]:
        assert not child.is_symlink()
        os.chown(child, 0, grp.getgrnam("azknowledge").gr_gid)
        child.chmod(0o750 if child.is_dir() else 0o640)


def assert_observations(harness: Harness, observations: list[bytes], events: list[dict],
                        expected_sockets: set[Path]) -> str:
    """The same assertions for replay and the binary's actual stdout decisions."""
    from azazel_nexus.edge_intake import EvidenceRecord, parse_edge_event
    from azazel_nexus.incident_explain import read_record, read_recent_incidents
    from azazel_nexus.routing import Route
    from tools.e2e_stages import _cli

    base = harness.root / "var/lib/azazel"
    count = sum(e["event_type"] == "alert" for e in events)
    assert len(observations) == count
    expected = [EvidenceRecord.receive(parse_edge_event(line), lambda: 0.0) for line in observations]
    intake = json.loads((base / "run/edge-intake-status/status.json").read_bytes())
    assert intake["accepted"] == count, "intake alert count"
    assert not any(intake["refused"].values()), "intake refused events"
    assert intake["storage_failed"] is False
    evidence = json_lines(base / "edge-intake/evidence")
    assert [r["digest"] for r in evidence] == [r.digest for r in expected], "evidence digests"
    assert [r["event"] for r in evidence] == [r.event.as_dict() for r in expected]
    transitions = [e for e in ledger_events(base / "edge-incidents") if e["event_type"] in
                   {"edge.incident.opened", "edge.incident.updated"}]
    assert len(transitions) == count, "opened/escalated intake transitions"
    ident = transitions[0]["incident_id"]
    assert [t["event_type"] for t in transitions] == ["edge.incident.opened", "edge.incident.updated"]
    for t, r in zip(transitions, expected, strict=True):
        event = r.event.as_dict()
        assert t["incident_id"] == ident
        assert t["edge_would"] == event["defense"]["action"], "Edge decision changed"
        assert t["most_severe"] == event["normalized"]["severity"]
        assert t["technique_ids"] == sorted(event["normalized"]["technique_ids"])
        assert t["latest_evidence"] == r.digest
    assert transitions[1]["most_severe"] < transitions[0]["most_severe"]
    records = [read_record(r) for r in json_lines(base / "incident-explain/explanations")]
    assert len(records) == count, "opening and escalation explanations"
    for record, t in zip(records, transitions, strict=True):
        assert record["incident_id"] == ident
        assert record["edge_would"] == t["edge_would"]
        assert record["mio"]["route"] == Route.DETERMINISTIC_HANDOFF.value
        assert record["knowledge_state"] == "available"
        assert any(r["technique_id"] in t["technique_ids"] for r in record["knowledge_refs"])
    recent_raw = (base / "run/incident-explain-status/recent.json").read_bytes()
    recent = read_recent_incidents(recent_raw)
    assert recent is not None
    rows = [r for r in recent["incidents"] if r["incident_id"] == ident]
    assert len(rows) == 1 and rows[0]["count"] == count
    assert rows[0]["explanation"]["knowledge_refs"], "recent citations not published"
    assert any(r["technique_id"] == "T1110" for r in rows[0]["explanation"]["knowledge_refs"]), \
        "T1110 citation"
    forwarded = [e for e in ledger_events(base / "state/audit") if e.get("incident_id") == ident]
    assert [e["event_type"] for e in forwarded] == ["edge.incident.opened", "edge.incident.escalated"]
    assert [e["edge_would"] for e in forwarded] == [t["edge_would"] for t in transitions]
    # auditd authenticates the sole incident writer; unit tests cover every
    # other uid's refusal. Here these records must arrive through that daemon.
    status = _cli(harness, ["status"])
    assert "edge loop:" in status and ident in status
    assert f"Edge would {transitions[-1]['edge_would']} (observe-only, not executed)" in status
    for ref in rows[0]["explanation"]["knowledge_refs"]:
        assert f"{ref['technique_id']} {ref['name']} [claim {ref['claim_id']}]" in status
    assert_private(harness, events, status)
    assert sockets(harness.root) == expected_sockets, "unexpected socket created"
    return ident


def assert_forward_stats(harness: Harness, sent: int) -> dict:
    """Edge's forward counts reached status, and only status.

    They are neither evidence nor an accepted event, nor a refusal, and the
    operator sees them as Edge's own report.
    """
    from azazel_nexus.edge_intake import read_intake_status
    from tools.e2e_stages import _cli

    base = harness.root / "var/lib/azazel"
    intake = read_intake_status((base / "run/edge-intake-status/status.json").read_bytes())
    assert intake is not None, "intake status refused"
    forward = intake.get("edge_forward")
    assert forward is not None, "Edge forward counts not in intake status"
    assert (forward["dropped"], forward["failed"], forward["sent"], forward["restarts"]) == \
        (0, 0, sent, 0), f"Edge forward counts {forward}"
    assert intake["accepted"] == intake["processed"] == sent, "forward counts taken as an event"
    assert not any(intake["refused"].values()), "intake refused the forward counts"
    assert len(json_lines(base / "edge-intake/evidence")) == sent, "forward counts stored as evidence"
    status = _cli(harness, ["status"])
    assert (f"Edge forward: dropped 0, failed 0 (as reported by Edge); sent {sent} "
            "since Edge start ") in status, "status does not show Edge's forward counts"
    return forward


def forward_reports(trace: str) -> int:
    """Lines Edge wrote carrying its forward counts (strace shows the bytes)."""
    import re
    return sum(bool(re.search(r"\bsendto\(.*forward-stats/v1", line))
               for line in joined_trace(trace))


def assert_private(harness: Harness, events: list[dict], status: str):
    """No eve address in status, recent.json, explanation records or the audit chain."""
    base = harness.root / "var/lib/azazel"
    public = [status, (base / "run/incident-explain-status/recent.json").read_text()]
    for directory in (base / "incident-explain/explanations", base / "state/audit"):
        public.extend(p.read_text() for p in directory.glob("*.jsonl"))
    for event in events:
        for field in ("src_ip", "dest_ip"):
            assert all(event[field] not in text for text in public), "EVE address leaked"


def joined_trace(trace: str) -> list[str]:
    """strace -f lines, with each `<unfinished ...>` call joined to its resumption.

    Another thread's syscall can interleave, so strace splits a call into
    `PID connect(... <unfinished ...>` and `PID <... connect resumed>) = 0`.
    """
    import re
    lines, pending = [], {}
    for line in trace.splitlines():
        line = line.rstrip()
        resumed = re.match(r"(\d*)\s*<\.\.\. \w+ resumed>(.*)$", line)
        if line.endswith("<unfinished ...>"):
            pending[re.match(r"\d*", line).group()] = len(lines)
            lines.append(line[:-len("<unfinished ...>")].rstrip())
        elif resumed and resumed.group(1) in pending:
            lines[pending.pop(resumed.group(1))] += resumed.group(2)
        else:
            lines.append(line)
    return lines


def assert_edge_trace(trace: str, intake: Path, count: int):
    """One connection per alert, plus one per forward-count report."""
    import re
    lines = joined_trace(trace)
    count += forward_reports(trace)
    trace = "\n".join(lines)
    calls = [line for line in lines if re.search(r"\bconnect\(", line)]
    assert all('sa_family=AF_UNIX' in line and f'sun_path="{intake}"' in line
               for line in calls), "Edge connected elsewhere"
    failed = [line for line in calls if not line.endswith("= 0")]
    assert not failed, f"Edge's intake connect failed: {failed[0][-80:]}"
    assert len(calls) == count, "Edge connected more/less than once per alert and report"
    assert not re.search(r"\b(bind|listen|accept4?|sendmsg|sendmmsg|socketpair)\(", trace), \
        "Edge network operation"
    # Rust writes to a connected stream with sendto(fd, ..., NULL, 0): data on
    # the intake connection. Any sendto naming a destination is a new peer.
    assert all(re.search(r", NULL, 0\) = ", line) for line in lines
               if re.search(r"\bsendto\(", line)), "Edge sent to an address"
    assert all("AF_UNIX" in line for line in lines
               if re.search(r"\bsocket\(", line)), "Edge non-Unix socket"


def assert_edge_decisions(stdout: bytes):
    """Edge's own stdout: one dry-run decision per alert, escalating."""
    lines = [json.loads(line) for line in complete(stdout).splitlines()]
    assert len(lines) == 2, "non-alert produced output"
    assert all(line["enforcement_status"]["dry_run"] is True for line in lines)
    assert [line["defense"]["action"] for line in lines] == EDGE_DECISIONS, "Edge decisions"
    assert [line["normalized"]["severity"] for line in lines] == EDGE_SEVERITIES, "severities"
    return len(lines)


def decoy_line() -> bytes:
    """One closed interaction, with placeholder identifiers only."""
    from azazel_nexus.decoy_interaction import build_interaction

    return build_interaction(
        decoy_name="ssh-decoy", bytes_received=12, truncated=False, responder="ssh-banner",
        observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())).line


def replay_decoy(path: Path, deadline: float):
    """As the decoy would: azdecoy, one line, one connection, nothing read back."""
    code = """import socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(2)
    connection.connect(sys.argv[1])
    connection.sendall(sys.stdin.buffer.read())
    connection.shutdown(socket.SHUT_WR)
    assert connection.recv(1) == b""
"""
    result = subprocess.run([sys.executable, "-c", code, str(path)], input=decoy_line(),
                            capture_output=True, timeout=max(0.1, deadline - time.monotonic()),
                            **account_credentials("azdecoy"))
    assert result.returncode == 0, f"azdecoy send exited {result.returncode}: {result.stderr[:200]!r}"


def decoy_baseline(harness: Harness) -> tuple[int, int]:
    """The audit chain's and the explainer's record counts before the decoy sends."""
    base = harness.root / "var/lib/azazel"
    return (len(ledger_events(base / "state/audit")),
            len(json_lines(base / "incident-explain/explanations")))


def assert_decoy_interaction(harness: Harness, alerts: int, baseline: tuple[int, int]):
    """Stored in its own leaf, labelled as not Edge's; Edge's records unchanged.

    Nor does it reach the explainer (no new explanation, so no M.I.O. handoff)
    or the audit chain (no new entry at all).
    """
    from azazel_nexus.decoy_interaction import RECORD_KIND
    from azazel_nexus.edge_intake import read_intake_status

    base = harness.root / "var/lib/azazel"
    records = json_lines(base / "edge-intake/decoy-evidence")
    assert len(records) == 1, "decoy interaction not stored yet"
    (record,) = records
    assert record["kind"] == RECORD_KIND and record["edge_observation"] is False
    assert record["environment_event"]["event_type"] == "interaction"
    assert len(json_lines(base / "edge-intake/evidence")) == alerts, "decoy stored as Edge evidence"
    intake = read_intake_status((base / "run/edge-intake-status/status.json").read_bytes())
    assert intake is not None and intake["decoy"]["accepted"] == 1
    assert intake["accepted"] == alerts and not any(intake["refused"].values())
    transitions = [e for e in ledger_events(base / "edge-incidents")
                   if e["event_type"] in {"edge.incident.opened", "edge.incident.updated"}]
    assert len(transitions) == alerts, "a decoy interaction reached the incident tracker"
    assert decoy_baseline(harness) == baseline, "a decoy interaction reached audit or the explainer"
    assert not any("environment_event" in r or r.get("incident_id", "").startswith("evt-")
                   for r in json_lines(base / "incident-explain/explanations")), \
        "a decoy interaction was explained"


def replay(harness: Harness, intake: Path, deadline: float):
    # stdin avoids granting azedge access to the repository or the fixture.
    code = """import socket, sys
for line in sys.stdin.buffer:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(sys.argv[1])
        connection.sendall(line)
"""
    result = subprocess.run([sys.executable, "-c", code, str(intake)],
                            input=b"\n".join(golden_lines() + [forward_stats_line(len(golden_lines()))])
                            + b"\n", capture_output=True,
                            timeout=max(0.1, deadline - time.monotonic()),
                            **account_credentials("azedge"))
    assert result.returncode == 0, f"azedge replay exited {result.returncode}: {result.stderr[:200]!r}"


def integrated_loop(harness: Harness) -> str:
    from tools.e2e_stages import _cli
    if os.geteuid() != 0 or sys.platform != "linux":
        raise NotExecuted("integrated loop needs Linux SO_PEERCRED and root for real service accounts")
    tracer = shutil.which("strace") if harness.edge_core else None
    if harness.edge_core and tracer is None:
        raise NotExecuted("real Edge Core connection assertions need strace (network syscalls)")
    base = harness.root / "var/lib/azazel"
    state = base / "edge-core"
    events = eve_events()
    prepare_accounts(harness)
    assert not (base / "incident-explain/cursor.json").exists(), "use a fresh harness root"
    expected = {base / "run" / name / f"{name}.sock" for name in
                ("audit", "audit-submit", "knowledge", "knowledge-read", "mio-entry", "mio-advise",
                 "edge-intake", "decoy-intake")}
    # Earlier stages stop their subprocesses by SIGTERM and can leave socket
    # inodes. Remove only those known, dead endpoints, before readiness polling.
    for path in expected & sockets(harness.root):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            try:
                client.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise AssertionError(f"prior stage left a listener at {path}")
    baseline_sockets = sockets(harness.root)
    if harness.edge_core:
        shutil.copyfile(harness.edge_core.resolve(), state / "azazel-edge-core")
        (state / "azazel-edge-core").chmod(0o755)
        if harness.edge_redirect_policy is not None:
            shutil.copyfile(harness.edge_redirect_policy, state / "redirect_policy.yaml")
            (state / "redirect_policy.yaml").chmod(0o644)
        (state / "eve.json").write_text("".join(json.dumps(e) + "\n" for e in events))
    deadline = time.monotonic() + 20
    daemons = []
    producer = None
    with ExitStack() as stack:
        for module, name, account in (("auditd", "audit", "azaudit"),
                                      ("knowledge_lited", "knowledge", "azknowledge"),
                                      ("mio_entryd", "mio-entry", "azmioentry"),
                                      ("edge_intaked", "edge-intake", "azintake"),
                                      ("incident_explaind", "incident-explain", "azexplain")):
            ready = base / "incident-explain/cursor.json" if module == "incident_explaind" else None
            daemon = stack.enter_context(Daemon(harness, module, name, account=account,
                                                 ready_path=ready, deadline=deadline))
            daemons.append(daemon)
        intake = daemons[3].path
        verify = request(daemons[0].path, {"verb": "audit.verify", "arguments": {}})
        assert verify["ok"] and verify["result"]["verified"]
        if harness.edge_core:
            stdout = stack.enter_context((state / "stdout.jsonl").open("w+b"))
            stderr = stack.enter_context((state / "stderr.log").open("w+b"))
            producer = subprocess.Popen(
                [tracer, "-f", "-s", "512", "-e", "trace=network", "-o", str(state / "network.trace"),
                 str(state / "azazel-edge-core")], env=edge_environment(harness, intake, state),
                stdout=stdout, stderr=stderr, cwd=state, start_new_session=True,
                **account_credentials("azedge"))
            def stop_producer():
                if producer.poll() is None:
                    os.killpg(producer.pid, signal.SIGTERM)
                try:
                    producer.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(producer.pid, signal.SIGKILL)
                    producer.wait(timeout=2)
            stack.callback(stop_producer)
            def observations():
                assert producer.poll() is None, "Edge/strace exited before completing the loop"
                return complete((state / "stdout.jsonl").read_bytes()).splitlines()
        else:
            replay(harness, intake, deadline)
            def observations():
                return golden_lines()
        ident = wait_until(deadline, lambda: assert_observations(
            harness, observations(), events, baseline_sockets | expected), daemons)
        forward_failure = None
        alerts = sum(e["event_type"] == "alert" for e in events)
        try:
            wait_until(time.monotonic() + FORWARD_SECONDS,
                       lambda: assert_forward_stats(harness, alerts), daemons,
                       what="Edge forward counts")
        except AssertionError as exc:
            forward_failure = exc
            if not producer:
                raise
        # #196 P2: one decoy interaction, sent as azdecoy on the decoy's own
        # socket, becomes Nexus evidence and nothing of Edge's changes.
        baseline = decoy_baseline(harness)
        replay_decoy(base / "run/decoy-intake/decoy-intake.sock",
                     time.monotonic() + FORWARD_SECONDS)
        wait_until(time.monotonic() + FORWARD_SECONDS,
                   lambda: assert_decoy_interaction(harness, alerts, baseline), daemons,
                   what="decoy interaction")
        # Once more after a pause, so a late write cannot pass unseen.
        time.sleep(1)
        assert_decoy_interaction(harness, alerts, baseline)
        if producer:
            stop_producer()
            count = assert_edge_decisions((state / "stdout.jsonl").read_bytes())
            trace = (state / "network.trace").read_text()
            assert_edge_trace(trace, intake, count)
            # An Edge Core built before it reports forward counts never sends
            # them; one that sent them must have had them accepted and shown.
            reported = forward_reports(trace)
            if forward_failure is not None and reported:
                raise forward_failure
            if forward_failure is not None:
                status = _cli(harness, ["status"])
                assert "Edge forward: not reported since the intake started" in status
        # Stop intake first; let the still-live explainer forward its close.
        daemons[3].__exit__()
        assert daemons[3].process.returncode == 0, "intake did not shut down cleanly"
        def closed():
            for directory in (base / "edge-incidents", base / "state/audit"):
                assert any(e.get("incident_id") == ident and
                           e["event_type"] == "edge.incident.closed" and
                           e["reason"] == "shutdown" for e in ledger_events(directory)), \
                    "shutdown close missing"
        wait_until(time.monotonic() + CLOSE_SECONDS, closed,
                   [d for d in daemons if d is not daemons[3]], what="shutdown close")
        # #211 S3: the whole loop stays inside auditd's per-writer limits, and
        # capacity is reported without anything being deleted.
        verify = request(daemons[0].path, {"verb": "audit.verify", "arguments": {}})
        assert verify["ok"] and verify["result"]["rate_limited"] == {}, "audit rate limit bound"
        assert verify["result"]["capacity"]["chain_bytes"] > 0
        assert not any(e["event_type"] == "audit.rate_limited"
                       for e in ledger_events(base / "state/audit")), "audit rate limit summary"
        status = _cli(harness, ["status"])
        # auditd's capacity snapshot reaches status through its installed
        # leaf, without the CLI reading the 0700 ledger or the socket.
        assert "    audit: ok -- chain verified at auditd start; chain " in status, "audit status line"
        assert_private(harness, events, status)
    assert all(d.process.returncode == 0 for d in daemons), "daemon shutdown failed"
    assert sockets(harness.root) == baseline_sockets, "stage sockets remain after shutdown"
    source = "real Edge Core binary" if producer else "golden fixture replay"
    forward = (f"Edge forward counts (0 dropped, 0 failed, {alerts} sent) reached intake status and "
               "`azazel-nexus status`, not evidence. " if forward_failure is None else
               "This Edge Core does not report forward counts (built before Azazel-Edge#432); "
               "status says they were not reported. ")
    return (f"{source}; {forward}azedge producer, azintake/azexplain/azaudit/azmioentry/azknowledge daemons "
            "with real uid/gid and unit supplementary groups; two alerts, escalation, evidence digests, "
            "deterministic handoff, T1110 citation, private status, verified audit and its capacity "
            "snapshot in status; one azdecoy interaction stored as Nexus evidence apart from "
            "Edge's, with no incident transition; shutdown close. "
            + ("Edge decided notify then isolate (dry run); network syscalls: intake only."
               if producer else
               "Replay sends only producer fixture lines; Edge's non-alert filtering is not exercised."))
