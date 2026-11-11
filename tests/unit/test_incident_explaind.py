"""Durable bounded consumer; optional explanations never affect intake."""
import ast
import json
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus.audit import AuditLedger
from azazel_nexus.incident_explain import read_record
from azazel_nexus_runtime import incident_explaind as daemon
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.hardening import PROFILES, SYSTEM_ACCOUNTS, render_unit
from azazel_nexus_runtime.principal import DAEMON_ACCOUNTS, PrincipalPolicy, PrincipalClass
from azazel_nexus_runtime.transport import bind_socket, read_frame, send_frame
from test_incident_explain import transition


def handoff():
    return {"route": "deterministic handoff", "outcome": "answered", "reason": "no admitted model",
            "ledger_seq": 1, "reference_status": "unavailable"}


def make(tmp_path, *, prepare=True, **kwargs):
    incidents = tmp_path / "incidents"
    incidents.mkdir(exist_ok=True)
    options = {"incidents": incidents, "state": tmp_path / "state",
               "status_path": tmp_path / "status.json", "clock": lambda: 0,
               "monotonic": lambda: 0, "mio": lambda _: handoff(),
               "knowledge": lambda _: ()}
    options.update(kwargs)
    e = daemon.Explainer(**options)
    if prepare:
        e.prepare()
    return e


def append(e, t=None, day="1970-01-01"):
    path = e.incidents / (day + ".jsonl")
    AuditLedger(path).append(t or transition())
    return path


def records(e):
    return [read_record(json.loads(line)) for p in sorted(e.store.directory.glob("*.jsonl"))
            for line in p.read_text().splitlines()]


def test_resume_and_pending_survive_restart(tmp_path):
    e = make(tmp_path)
    path = append(e)
    e.poll()
    first = records(e)
    assert len(first) == 1
    assert first[0]["incident_sequence"] == 1
    offset = e.cursor["offset"]
    restarted = make(tmp_path)
    restarted.poll()
    assert restarted.cursor["offset"] == offset == path.stat().st_size
    assert len(records(restarted)) == 1
    append(restarted, transition(1, "updated"))
    restarted.poll()
    assert len(restarted.selection.pending) == 1
    restarted.monotonic = lambda: 61
    restarted.poll()
    assert len(records(restarted)) == 2
    assert records(restarted)[1]["incident_sequence"] == 2
    restarted.monotonic = lambda: 66
    restarted.poll()
    status = json.loads(restarted.status_path.read_text())
    assert status["explained"] == 2
    assert status["last_explained_at"] == 0
    assert status["mio_available"] is True
    assert status["knowledge_available"] is True
    assert not status["chain_broken"] and not status["storage_failed"]
    assert status["cursor_lag"] >= 0


def test_slow_result_receipt_is_durable_before_poll_and_projected_once(tmp_path):
    t = transition()
    seq = 1
    trace = f"mio-{t['incident_id'][4:]}-{seq}"
    queued = {"state": "queued", "usage": "unknown", "generation_id": "generation-1",
              "frame_id": trace + ":frame", "trace_id": trace, "result_handle": "a" * 64}
    from azazel_nexus.incident_explain import read_mio_reply
    assert read_mio_reply({**handoff(), "slow_analysis": queued})["route"] == "deterministic handoff"

    def complete(receipt, *, deadline_s):
        assert deadline_s == .05
        return {**receipt, "state": "complete", "usage": "known",
                "calls": [{"usage": {"tokens_in": 1, "tokens_out": 2}, "timings": {}}],
                "assistance": {
            "schema_version": "mio.assistance.v1", "frame_id": receipt["frame_id"],
            "trace_id": receipt["trace_id"], "generation_method": "model",
            "hypotheses": [{"verification": "model_proposed_unverified",
                            "statement": "Observed symptoms may reflect a benign change."}],
            "unknowns": ["The approved change record is not present."],
            "next_checks": ["Check the authorized change record."]}}

    e = make(tmp_path, mio=lambda _: {**handoff(), "slow_analysis": queued}, mio_result=complete)
    append(e, t)
    e.poll()
    events = e.generation_store.events()
    assert [event["event_type"] for event in events] == [
        "mio.generation.receipt", "mio.generation.result"]
    assert events[0]["result_handle"] == "a" * 64
    assert events[1]["state"] == "complete"
    assert daemon.Explainer._generation_binding(events[0]) == daemon.Explainer._generation_binding(events[1])
    row = e.recent[0]["explanation"]["slow_analysis"]
    assert row['state'] == 'degraded'
    assert row['budget']['outcome'] == 'legacy_unverified'
    assert 'hypotheses' not in row
    encoded = (tmp_path / "recent.json").read_text()
    assert all(secret not in encoded for secret in ("a" * 64, "generation-1", trace, ":frame"))

    restarted = make(tmp_path, mio_result=lambda *_a, **_k: pytest.fail("terminal result polled twice"))
    assert restarted.recent[0]["explanation"]["slow_analysis"] == {
        **row, "recovery": {"status": "unavailable_after_restart", "unknowns": []}}
    assert [event["event_type"] for event in restarted.generation_store.events()] == [
        "mio.generation.receipt", "mio.generation.result"]


@pytest.mark.parametrize("polled", [
    {"state": "stale", "usage": "unknown"},
    {"state": "complete", "usage": "unknown", "trace_id": "mio-ffffffffffffffff-1"},
], ids=["revoked-or-expired", "binding-mismatch"])
def test_mismatched_or_revoked_slow_result_persists_status_only(tmp_path, polled):
    t = transition()
    trace = f"mio-{t['incident_id'][4:]}-1"
    queued = {"state": "queued", "usage": "unknown", "generation_id": "generation-1",
              "frame_id": trace + ":frame", "trace_id": trace, "result_handle": "8" * 64}
    e = make(tmp_path, mio=lambda _: {**handoff(), "slow_analysis": queued},
             mio_result=lambda _receipt, **_kw: polled)
    append(e, t)
    e.poll()
    events = e.generation_store.events()
    result, = [event for event in events if event["event_type"] == "mio.generation.result"]
    assert result["state"] == "stale" and "assistance" not in result
    projection = e.recent[0]["explanation"]["slow_analysis"]
    assert projection == {"state": "stale", "usage": "unknown"}
    encoded = (tmp_path / "recent.json").read_text()
    assert all(secret not in encoded for secret in ("8" * 64, "generation-1", trace, ":frame"))


def test_generation_terminal_stays_in_receipt_segment_across_midnight_and_retention(tmp_path):
    incident = "inc-0123456789abcdef"
    midnight = datetime(2026, 11, 2, tzinfo=UTC).timestamp()
    before_midnight = midnight - 1
    trace = "mio-0123456789abcdef-1"
    store = daemon.GenerationResultStore(tmp_path)
    store.monotonic = lambda: 0
    store.prepare(before_midnight)
    receipt = {"event_type": "mio.generation.receipt", "incident_id": incident,
               "incident_sequence": 1, "request_id": incident + ":1",
               "frame_id": trace + ":frame", "trace_id": trace,
               "generation_id": "generation-1", "result_handle": "e" * 64,
               "recorded_at": before_midnight}
    store.append_event(receipt)
    result = {**receipt, "event_type": "mio.generation.result", "state": "stale",
              "usage": "unknown", "recorded_at": midnight + 1}
    store.append_event(result, segment_at=receipt["recorded_at"])
    segment = store.path_at(before_midnight)
    assert segment != store.path_at(midnight + 1)
    assert list(store.directory.glob("*.jsonl")) == [segment]
    assert [event["event_type"] for event in store.events()] == [
        "mio.generation.receipt", "mio.generation.result"]

    # Once the ordinary 14-day retention window advances, the receipt and its
    # terminal event retire together as a whole daily segment.
    store.monotonic = lambda: 15 * 86400
    later = before_midnight + 15 * 86400
    trace2 = "mio-0123456789abcdef-2"
    receipt2 = {**receipt, "incident_sequence": 2, "request_id": incident + ":2",
                "frame_id": trace2 + ":frame", "trace_id": trace2,
                "result_handle": "f" * 64, "recorded_at": later}
    store.append_event(receipt2)
    assert not segment.exists()
    assert [event["result_handle"] for event in store.events()] == ["f" * 64]
    with pytest.raises(ValueError, match="receipt_segment_missing"):
        store.append_event(result, segment_at=receipt["recorded_at"])


def test_torn_generation_result_tail_disables_only_slow_lane_on_restart(tmp_path):
    e = make(tmp_path)
    t = transition()
    append(e, t)
    e.poll()
    trace = f"mio-{t['incident_id'][4:]}-1"
    receipt = {"event_type": "mio.generation.receipt", "incident_id": t["incident_id"],
               "incident_sequence": 1, "request_id": f"{t['incident_id']}:1",
               "frame_id": trace + ":frame", "trace_id": trace,
               "generation_id": "generation-1", "result_handle": "9" * 64,
               "recorded_at": 0}
    e.generation_store.append_event(receipt)
    path = e.generation_store.path_at(0)
    with path.open("ab") as stream:
        stream.write(b'{"event_type":"mio.generation.result"')
        stream.flush()
        os.fsync(stream.fileno())
    damaged = path.read_bytes()

    restarted = make(tmp_path, mio_result=lambda *_a, **_k: pytest.fail("torn receipt was polled"))
    assert restarted._generation_store_failed is True
    assert restarted.storage_failed is False
    assert restarted.snapshot()["slow_result_store"] == "unavailable"
    from azazel_nexus.incident_explain import read_explainer_status
    assert read_explainer_status(json.dumps(restarted.snapshot()).encode()) == restarted.snapshot()
    assert restarted._generation_receipts == {}
    restarted.poll()
    assert restarted.storage_failed is False
    assert path.read_bytes() == damaged
    assert restarted.snapshot()["refused"]["storage_failed"] == 1


def test_new_edge_sequence_invalidates_completed_slow_projection(tmp_path):
    t = transition()
    e = make(tmp_path)
    e.recent = [daemon.build_recent_incident(t)]
    trace = f"mio-{t['incident_id'][4:]}-1"
    receipt = {"event_type": "mio.generation.receipt", "incident_id": t["incident_id"],
               "incident_sequence": 1, "request_id": f"{t['incident_id']}:1",
               "frame_id": trace + ":frame", "trace_id": trace,
               "generation_id": "generation-1", "result_handle": "b" * 64,
               "recorded_at": 0}
    e._append_generation_event(receipt)
    e._generation_receipts["b" * 64] = daemon.read_generation_event(receipt)
    e._generation_current[t["incident_id"]] = "b" * 64
    complete = {"state": "complete", "usage": "known", "assistance": {
        "schema_version": "mio.assistance.v1", "frame_id": trace + ":frame",
        "trace_id": trace, "generation_method": "model", "hypotheses": [],
        "unknowns": [], "next_checks": []}}
    e._record_generation_terminal(e._generation_receipts["b" * 64], complete)

    changed = {**t, "event_type": "edge.incident.updated", "count": t["count"] + 1,
               "last_update": t["last_update"] + 1}
    e.observe_transition(changed, sequence=2)
    assert e._generation_terminal["b" * 64]["state"] == "complete"  # original result stays immutable
    assert e._generation_value("b" * 64)["state"] == "superseded"
    assert len(e._generation_superseded) == 1
    assert e.recent[0]["explanation"]["slow_analysis"] == {
        "state": "superseded", "usage": "unknown"}


def test_intake_reset_supersedes_pending_slow_result(tmp_path):
    e = make(tmp_path)
    t = transition()
    e.recent = [daemon.build_recent_incident(t)]
    trace = f"mio-{t['incident_id'][4:]}-1"
    receipt = {"event_type": "mio.generation.receipt", "incident_id": t["incident_id"],
               "incident_sequence": 1, "request_id": f"{t['incident_id']}:1",
               "frame_id": trace + ":frame", "trace_id": trace,
               "generation_id": "generation-1", "result_handle": "d" * 64,
               "recorded_at": 0}
    assert e._append_generation_event(receipt)
    e._generation_receipts["d" * 64] = daemon.read_generation_event(receipt)
    e._generation_current[t["incident_id"]] = "d" * 64
    e._set_generation_projection(e._generation_receipts["d" * 64],
                                 {"state": "queued", "usage": "unknown"})
    append(e, {"event_type": "edge.incident.reset", "at": 1, "reason": "intake_started"})
    e.poll()
    assert 'd' * 64 not in e._generation_terminal  # no invented result before runtime termination
    assert 'd' * 64 in e._generation_superseded
    assert e._generation_value('d' * 64)['state'] == 'superseded'
    assert e.recent[0]["explanation"]["slow_analysis"] == {
        "state": "superseded", "usage": "unknown"}


def test_chain_break_stops_linked_chain_across_days(tmp_path):
    e = make(tmp_path)
    path = append(e)
    with path.open("ab") as f:
        f.write(b'{"secret":"not a chain"}\n')
    with path.open("ab") as f:
        f.write(path.read_bytes().splitlines()[0] + b"\n")
    e.poll()
    assert len(records(e)) == 1
    assert e.chain_broken and e.refused["chain_broken"] == 1
    e.poll()
    assert e.refused["chain_broken"] == 1
    append(e, transition(incident_id="inc-2222222222222222"), "1970-01-02")
    e.poll()
    assert len(records(e)) == 1
    assert e.cursor["segment"] == "1970-01-01.jsonl"
    assert "secret" not in e.status_path.read_text()


@pytest.mark.parametrize("boundary", ["mio", "knowledge"])
def test_down_continues(tmp_path, boundary):
    e = make(tmp_path)
    def unavailable(*_):
        raise OSError("SECRET")
    setattr(e, boundary, unavailable)
    append(e)
    append(e, transition(incident_id="inc-2222222222222222"))
    e.poll()
    rows = records(e)
    assert len(rows) == 2
    assert all(boundary + "_unavailable" in r["failure_codes"] for r in rows)
    if boundary == "knowledge":
        assert rows[0]["knowledge_state"] == "unavailable"
    else:
        assert rows[0]["mio"]["outcome"] == "unavailable"
    assert "SECRET" not in json.dumps(rows)
    assert not e.storage_failed


@pytest.mark.parametrize("boundary", ["mio", "knowledge"])
def test_bad_reply_closed(tmp_path, boundary):
    e = make(tmp_path)
    setattr(e, boundary, lambda _: {"secret": "SECRET"})
    append(e)
    e.poll()
    assert records(e)[0]["failure_codes"] == (["mio_handoff"] if boundary == "knowledge" else []) + [boundary + "_reply_refused"]
    assert "SECRET" not in e.status_path.read_text()
    assert "SECRET" not in json.dumps(records(e))


def test_retention_and_startup_storage_failure(tmp_path):
    e = make(tmp_path, store_limits={"max_bytes": 1})
    append(e)
    e.poll()
    e.clock = lambda: 20 * 86400
    append(e, transition(incident_id="inc-2222222222222222", first_seen=20 * 86400))
    e.poll()
    assert len(list(e.store.directory.glob("*.jsonl"))) == 1
    broken = tmp_path / "bad"
    broken.mkdir()
    (broken / "state").write_text("not a directory")
    e = make(broken, prepare=False)
    ready = []
    assert e.serve(ready=lambda: ready.append(True)) == 1
    assert not ready and e.storage_failed


def test_partial_line_and_bounded_poll(tmp_path):
    e = make(tmp_path)
    path = append(e)
    raw = path.read_bytes()
    path.write_bytes(raw[:-1])
    e.poll()
    assert e.cursor["offset"] == 0 and not e.chain_broken
    path.write_bytes(raw)
    e.poll()
    assert len(records(e)) == 1
    for n in range(100):
        append(e, transition(incident_id=f"inc-{n+10:016x}"))
    before = e.cursor["sequence"]
    e.poll()
    assert e.cursor["sequence"] - before <= daemon.POLL_LINES
    assert len(e.selection.pending) <= 64


def test_registration_and_only_allowed_connections():
    profile = next(p for p in PROFILES if p.unit == "azazel-incident-explaind.service")
    assert profile.account == "azexplain"
    assert profile.unit_type == "notify"
    assert profile.address_families == ("AF_UNIX",)
    assert set(profile.supplementary_groups) == {"azincident-read", "azknowledge-read",
                                                 "azaudit-submit", "azmio-advise"}
    assert "azexplain" in DAEMON_ACCOUNTS and "azexplain" in SYSTEM_ACCOUNTS
    p = PrincipalPolicy(123, frozenset({42}), frozenset({42})).classify(42, 7, 1, (123,))
    assert p.classes == frozenset({PrincipalClass.SERVICE})
    assert render_unit(profile) == Path("packaging/systemd/" + profile.unit).read_text()
    text = Path(daemon.__file__).read_text()
    tree = ast.parse(text)
    exchanges = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_exchange"]
    assert {n.args[0].value for n in exchanges} == {"mio-advise", "audit-submit"}
    assert len(exchanges) == 4  # advise, generation poll, audit submit, observation-origin (unit C)
    assert 'lookup_context(ids, deadline_s=KNOWLEDGE_MAX_S)' in text
    assert not any(isinstance(n, ast.Attribute) and n.attr == "connect" for n in ast.walk(tree))
    assert not any(word in text for word in ("subprocess", "dbus", "systemctl", 'socket_path("edge'))


def test_fake_socket_servers(tmp_path, monkeypatch):
    # Same framed transport helpers as test_mio_entryd_socket; mock kernel peer
    # lookup only so the full exchange also runs on macOS.
    with tempfile.TemporaryDirectory(prefix="i2-", dir="/tmp") as directory:
        root = Path(directory)
        monkeypatch.setattr(runtime_paths, "ROOT", root)
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
        monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
        monkeypatch.setattr(client, "peer_credentials", lambda _: (1, os.getuid(), os.getgid()))
        threads, listeners, requests, errors = [], [], [], []
        for leaf, result in (("mio-advise", handoff()), ("knowledge-read", {"refs": [], "reason_code": "no_context"})):
            path = runtime_paths.socket_path(leaf)
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                listener = bind_socket(path, expected_gid=os.getgid())
            except PermissionError:
                for listener in listeners:
                    listener.close()
                pytest.skip("sandbox denies AF_UNIX bind")
            listener.settimeout(3)
            listeners.append(listener)
            def serve(listener=listener, result=result):
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        requests.append(json.loads(read_frame(connection)))
                        send_frame(connection, {"ok": True, "result": result})
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=serve)
            threads.append(thread)
            thread.start()
        try:
            e = daemon.Explainer(incidents=tmp_path / "incidents", state=tmp_path / "state",
                                 status_path=tmp_path / "status.json", clock=lambda: 0)
            e.incidents.mkdir()
            e.prepare()
            append(e)
            e.poll()
            assert records(e)[0]["knowledge_state"] == "no_context"
            assert records(e)[0]["failure_codes"] == ["mio_handoff"]
            assert {r["verb"] for r in requests} == {"mio.advise", "knowledge.lookup"}
        finally:
            for thread in threads:
                thread.join(4)
            for listener in listeners:
                listener.close()
        assert not errors and not any(t.is_alive() for t in threads)


def test_storage_failure_is_sticky_and_status_failure_is_separate(tmp_path, monkeypatch):
    e = make(tmp_path)
    append(e)
    def fail(*_):
        raise OSError("SECRET")
    monkeypatch.setattr(e.store, "append_record", fail)
    e.poll()
    assert e.storage_failed and e.explained == 0
    assert e.refused["storage_failed"] == 1
    e.poll()
    assert e.refused["storage_failed"] == 1
    assert "SECRET" not in e.status_path.read_text()
    other = tmp_path / "other"
    other.mkdir()
    e = make(other)
    e.status_path = other / "missing" / "status.json"
    append(e)
    e.poll()
    assert e.explained == 1 and not e.storage_failed
    assert e.refused["status_write_failed"] == 2


def test_corrupt_checkpoint_fails_before_ready(tmp_path):
    e = make(tmp_path)
    (e.state / "cursor.json").write_text('{"secret":"SECRET"}')
    resumed = make(tmp_path, prepare=False)
    called = []
    assert resumed.serve(ready=lambda: called.append(True)) == 1
    assert not called
    assert resumed.refused["cursor_refused"] == 1
    assert "SECRET" not in resumed.status_path.read_text()


def test_knowledge_refs_are_rechecked_and_bound_to_query(tmp_path):
    from azazel_nexus.lite_import import KnowledgeRef
    e = make(tmp_path)
    ref = KnowledgeRef("T1059", "Shell", "Check context", "T1059", "sha256:" + "a" * 64,
                       "static", "knowledge_lite", 1, "verified",
                       "2026-10-18T00:00:00Z", "MITRE ATT&CK technique")
    e.knowledge = lambda _: (ref,)
    append(e)
    e.poll()
    assert records(e)[0]["knowledge_state"] == "available"
    ref = KnowledgeRef("T1110", "Force", "", "T1110", "sha256:" + "a" * 64,
                       "static", "knowledge_lite", 1, "verified",
                       "2026-10-18T00:00:00Z", "MITRE ATT&CK technique")
    append(e, transition(incident_id="inc-2222222222222222"))
    e.poll()
    assert records(e)[-1]["knowledge_state"] == "unavailable"
    assert records(e)[-1]["failure_codes"] == ["mio_handoff", "knowledge_reply_refused"]


def test_incident_leaf_is_independent_and_files_group_readable(tmp_path):
    from azazel_nexus.layout import LAYOUT
    from azazel_nexus_runtime.edge_intaked import IntakeServer
    from azazel_nexus_runtime.runtime_paths import incident_segments_dir
    server = IntakeServer(path=tmp_path / "unused.sock", state=tmp_path / "private",
                          incident_root=tmp_path / "shared", status_path=tmp_path / "status.json",
                          edge_uid=123, clock=lambda: 0)
    server._open_storage()
    assert server.store.directory == tmp_path / "private" / "evidence"
    assert server.ledger.directory == tmp_path / "shared"
    assert server.ledger.current.stat().st_mode & 0o777 == 0o640
    assert server.state.stat().st_mode & 0o777 == 0o700
    specs = {s.path: s for s in LAYOUT}
    leaf = specs["/var/lib/azazel/edge-incidents"]
    assert (leaf.mode, leaf.owner, leaf.group) == (0o2750, "azintake", "azincident-read")
    assert str(incident_segments_dir()).endswith("/var/lib/azazel/edge-incidents")
    assert [p.unit for p in PROFILES if "azincident-read" in p.supplementary_groups] == ["azazel-incident-explaind.service"]


def test_explainer_reaches_only_its_own_listeners_not_operator_sockets():
    """#213 O1: azexplain holds no azazel-operator, so it reaches no operator
    socket leaf and no 2750 operator read area. Its audit and M.I.O. entry
    paths are dedicated, verb-restricted listeners no other unit can reach."""
    from azazel_nexus.layout import LAYOUT
    from azazel_nexus_runtime import auditd, mio_entryd
    from azazel_nexus_runtime.runtime_paths import socket_group, socket_path
    profile = next(p for p in PROFILES if p.unit == "azazel-incident-explaind.service")
    assert "azazel-operator" not in profile.supplementary_groups
    specs = {s.path: s for s in LAYOUT}
    for name, owner, group, unit in (
            ("audit-submit", "azaudit", "azaudit-submit", "azazel-auditd.service"),
            ("mio-advise", "azmioentry", "azmio-advise", "azazel-mio-entryd.service")):
        assert socket_path(name).parent.name == name
        spec = specs[f"/var/lib/azazel/run/{name}"]
        assert (spec.mode, spec.owner, spec.group) == (0o2710, owner, group)
        assert socket_group(name) == group
        # Only the explainer carries the advise client group. The audit-submit
        # group (append only) is also carried by the two daemons that record
        # Knowledge Lite imports and revocations (P4); neither is an operator
        # group. Only the owning daemon writes the leaf.
        holders = {p.unit for p in PROFILES if group in p.supplementary_groups}
        assert holders == ({profile.unit, "azazel-commissiond.service",
                            "azazel-knowledge-lited.service"}
                           if name == "audit-submit" else {profile.unit})
        # The ledger daemon writes its leaf in either lifetime (ADR 0008):
        # the bootstrap helper or the loop's writer, never both at once.
        writers = sorted(p.unit for p in PROFILES if spec.path in p.read_write_paths)
        assert writers == (["azazel-auditd-loop.service", unit]
                           if name == "audit-submit" else [unit])
    assert auditd.SUBMIT_REGISTRY.names() == ("audit.append",)
    assert mio_entryd.ADVISE_REGISTRY.names() == (
        "mio.advise", "mio.context.observe", "mio.generation.result")


@pytest.mark.parametrize("resume", [False, True])
def test_real_intake_chain_rollover_and_restart(tmp_path, resume):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0)
    ledger.append(transition(), 0)
    e.poll()
    if resume:
        e = make(tmp_path)
        e.monotonic = lambda: 61
    ledger.append(transition(incident_id="inc-2222222222222222"), 86400)
    e.poll()
    assert len(records(e)) == 2
    assert not e.chain_broken
    assert e.cursor["sequence"] == ledger.head[0]
    assert e.cursor["last_hash"] == ledger.head[1]


@pytest.mark.parametrize("resume", [False, True])
def test_retention_boundary_seeds_fresh_and_lagging_readers(tmp_path, resume):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0, max_bytes=1)
    ledger.append(transition(), 0)
    if resume:
        e.poll()
    retired_path = ledger.current
    retired = retired_path.read_bytes()
    ledger.append(transition(incident_id="inc-2222222222222222"), 86400)
    # Durable boundary takes effect even before the writer completes unlink.
    retired_path.write_bytes(retired)
    if not resume:
        (e.state / "cursor.json").unlink()
    e = make(tmp_path)
    e.monotonic = lambda: 61
    e.poll()
    assert len(records(e)) == (2 if resume else 0)
    assert e.refused["cursor_overtaken"] == int(resume)
    assert e.cursor["last_hash"] == ledger.head[1]
    assert not e.chain_broken and not e.refused["transition_refused"]
    assert ledger.boundary.stat().st_mode & 0o777 == 0o640


def test_unlinked_daily_chain_is_refused(tmp_path):
    e = make(tmp_path)
    append(e)
    append(e, transition(incident_id="inc-2222222222222222"), "1970-01-02")
    e.poll()
    assert len(records(e)) == 1
    assert e.chain_broken


@pytest.mark.parametrize("damage", ["hash", "oldest", "extra", "missing"])
def test_bad_retention_boundary_fails_closed(tmp_path, damage):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0, max_bytes=1)
    ledger.append(transition(), 0)
    ledger.append(transition(), 86400)
    value = json.loads(ledger.boundary.read_bytes())
    if damage == "missing":
        ledger.boundary.unlink()
    else:
        value[{"hash": "hash", "oldest": "oldest", "extra": "extra"}[damage]] = {
            "hash": "a" * 64, "oldest": "1970-01-03.jsonl", "extra": True}[damage]
        ledger.boundary.write_text(json.dumps(value))
    e.poll()
    assert e.chain_broken and not records(e)


def test_control_records_are_validated_without_explanations(tmp_path):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0)
    for event in (
        {"event_type": "edge.incident.reset", "at": 0, "reason": "intake_started"},
        {"event_type": "edge.incident.truncated", "at": 0, "reason": "incident_segment_full"},
        {"event_type": "edge.incident.retention", "oldest": "1970-01-02.jsonl",
         "deleted": "1970-01-01.jsonl", "sequence": 0, "hash": "0" * 64},
    ):
        ledger.append(event, 0)
    ledger.append(transition(), 86400)
    e.poll()
    assert len(records(e)) == 1
    assert not e.chain_broken and not e.refused["transition_refused"]
    ledger.append({"event_type": "edge.incident.truncated", "at": 0, "reason": "SECRET"}, 86400)
    e.poll()
    assert e.refused["transition_refused"] == 1
    assert "SECRET" not in e.status_path.read_text()


def test_explainer_continues_across_a_recovered_torn_tail(tmp_path):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0)
    ledger.append(transition(), 0)
    e.poll()
    with ledger.current.open("ab") as stream:
        stream.write(b'{"event":{"src_ip":"10.0.0.8"')
    e.poll()
    assert e.refused["ledger_tail_incomplete"] == 1
    recovered = IncidentLedger(tmp_path, 0, quarantine=tmp_path / "private")
    recovered.append(transition(incident_id="inc-2222222222222222"), 0)
    e.poll()
    assert len(records(e)) == 2
    assert not e.chain_broken and not e.refused["transition_refused"]
    assert e.cursor["last_hash"] == recovered.head[1]


@pytest.mark.parametrize("change", [
    {}, {"content": "10.0.0.8"}, {"torn_bytes": 0}, {"torn_bytes": 64 * 1024 + 1},
    {"segment": "../x"}, {"sha256": "A" * 64}, {"offset": -1}])
def test_ledger_recovered_control_record_shape(change):
    from azazel_nexus.incident_explain import read_control
    value = {"event_type": "edge.incident.ledger_recovered", "at": 0,
             "segment": "1970-01-01.jsonl", "offset": 10, "torn_bytes": 5,
             "sha256": "a" * 64}
    if not change:
        assert read_control(value) is True
        return
    with pytest.raises(ValueError):
        read_control({**value, **change})


@pytest.mark.parametrize("missing_day", [0, 1])
def test_missing_linked_segment_without_boundary_is_refused(tmp_path, missing_day):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    instant = iter(range(0, 10**7, 86400))
    ledger = IncidentLedger(tmp_path, 0, monotonic=lambda: next(instant))
    for day in range(3):
        ledger.append(transition(incident_id=f"inc-{day+1:016x}"), day * 86400)
    ledger.path_at(missing_day * 86400).unlink()
    e.poll()
    assert e.chain_broken
    assert len(records(e)) == missing_day


def test_missing_cursor_segment_without_boundary_is_refused(tmp_path):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0)
    ledger.append(transition(), 0)
    e.poll()
    ledger.current.unlink()
    ledger.append(transition(incident_id="inc-2222222222222222"), 86400)
    e.poll()
    assert e.chain_broken and len(records(e)) == 1


def test_explainer_privilege_at_every_runtime_policy_site(monkeypatch):
    from azazel_nexus_runtime import principal

    accounts = {name: n + 100 for n, name in enumerate(principal.DAEMON_ACCOUNTS)}
    monkeypatch.setattr(principal.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=accounts[name]))
    monkeypatch.setattr(principal.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=7))
    root = Path(daemon.__file__).parent
    sites, servers, admitted = [], [], set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text())
        resolves = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and n.func.attr == "resolve"
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "PrincipalPolicy"]
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Name) and n.func.id == "serve_forever"):
            # Every server must be covered by an actual resolve call, including
            # defaults; a new indirect/dynamic policy must extend this test.
            policy = next(k.value for k in call.keywords if k.arg == "policy")
            assert policy in resolves, (path, call.lineno)
            servers.append((path.name, policy.lineno))
        for call in resolves:
            assert not call.args and all(k.arg is not None for k in call.keywords)
            if path.stem == "auditd":
                assert ast.unparse(call) == "PrincipalPolicy.resolve(service_accounts=SERVICE_ACCOUNTS + ('azexplain',))"
            kwargs = {k.arg: (principal.SERVICE_ACCOUNTS + ("azexplain",)
                              if path.stem == "auditd" and k.arg == "service_accounts"
                              else ast.literal_eval(k.value)) for k in call.keywords}
            policy = PrincipalPolicy.resolve(**kwargs)
            uid = accounts["azexplain"]
            for gid, supplementary in ((7, ()), (8, (7,))):
                classes = policy.classify(uid, gid, 1, supplementary).classes
                expected = (frozenset({PrincipalClass.SERVICE}) if path.stem in
                            {"mio_entryd", "knowledge_lited", "auditd"} else frozenset())
                assert classes == expected, (path, call.lineno, classes)
                if classes:
                    admitted.add(path.stem)
            sites.append((path.name, call.lineno))
    assert sites and sorted(servers) == sorted(sites)
    assert admitted == {"mio_entryd", "knowledge_lited", "auditd"}


def test_first_start_seeds_end_and_missing_cursor_reseeds(tmp_path):
    e = make(tmp_path, prepare=False)
    path = append(e)
    e.prepare()
    e.poll()
    assert e.cursor["offset"] == path.stat().st_size and not records(e)
    append(e, transition(incident_id="inc-2222222222222222"))
    e.poll()
    assert len(records(e)) == 1
    (e.state / "cursor.json").unlink()
    restarted = make(tmp_path)
    restarted.poll()
    assert len(records(restarted)) == 1
    assert restarted.cursor["sequence"] == 2


def test_stale_replay_is_counted_and_pending_has_no_addresses(tmp_path):
    e = make(tmp_path)
    e.clock = lambda: 7200
    append(e)
    append(e, transition(incident_id="inc-2222222222222222", first_seen=7200, last_seen=7200,
                         attack_type="a=b; c=d 192.0.2.1", policy_reason="private host"))
    e.selection.attempts.extend([0] * 6)
    e.poll()
    assert e.refused["stale_skipped"] == 1
    checkpoint = json.loads((e.state / "cursor.json").read_bytes())
    pending = checkpoint["pending"][0][0]
    from azazel_nexus.incident_explain import PENDING_FIELDS
    # The frame's fields and the evidence pointers (digests, never content).
    assert set(pending) == PENDING_FIELDS | {"evidence"}
    assert pending["attack_type"] == "ab cd" and pending["policy_reason"] == "other"
    assert "192.0.2.1" not in json.dumps(checkpoint)
    restarted = make(tmp_path)
    restarted.monotonic = lambda: 61
    restarted.poll()
    row = records(restarted)[0]
    assert row["attack_type"] == "ab cd" and row["policy_reason"] == "other"
    assert not {"src_ip", "dst_ip"} & set(row)


def test_idle_writes_are_suppressed_and_status_is_throttled(tmp_path, monkeypatch):
    e = make(tmp_path)
    writes = []
    original = daemon.atomic_json
    def write(path, value, mode):
        writes.append(path.name)
        return original(path, value, mode)
    monkeypatch.setattr(daemon, "atomic_json", write)
    e.poll()
    assert writes == ["recent.json", "status.json"]
    writes.clear()
    e.clock = lambda: 1
    e.monotonic = lambda: 1
    e.poll()
    assert not writes
    append(e)
    e.poll()
    assert "cursor.json" in writes and "status.json" not in writes
    writes.clear()
    e.monotonic = lambda: 5
    e.poll()
    assert writes == ["recent.json", "status.json"]
    writes.clear()
    e.monotonic = lambda: 10
    e.poll()
    assert not writes


def test_gap_codes_and_recovery_hint(tmp_path):
    e = make(tmp_path)
    path = append(e)
    raw = path.read_bytes()
    path.write_bytes(raw[:-1])
    e.poll()
    assert e.snapshot()["refused"]["ledger_tail_incomplete"] == 1
    path.write_bytes(raw)
    ledger = AuditLedger(path)
    ledger.append({"event_type": "edge.incident.truncated", "at": 0,
                   "reason": "incident_segment_full"})
    e.poll()
    assert e.snapshot()["refused"]["incident_segment_full"] == 1
    with path.open("ab") as stream:
        stream.write(b"{}\n")
    e.poll()
    assert e.chain_broken
    assert e.snapshot()["recovery_hint"] == "inspect_incident_chain_then_remove_cursor_and_restart"


def test_first_start_verifies_more_than_one_poll_without_replay(tmp_path):
    e = make(tmp_path, prepare=False)
    for n in range(daemon.POLL_LINES + 2):
        append(e, transition(incident_id=f"inc-{n+1:016x}"))
    e.prepare()
    e.poll()
    assert e.cursor["sequence"] == daemon.POLL_LINES + 2
    assert not e.selection.pending and not records(e) and not e.chain_broken


def test_first_start_does_not_seed_past_corruption(tmp_path):
    e = make(tmp_path, prepare=False)
    path = append(e)
    with path.open("ab") as stream:
        stream.write(b"{}\n")
    e.prepare()
    assert e.chain_broken and not records(e)
    restarted = make(tmp_path)
    assert restarted.chain_broken
    restarted.poll()
    assert not records(restarted)


def test_resumed_pending_openings_age_out(tmp_path):
    e = make(tmp_path)
    e.selection.attempts.extend([0] * 6)
    append(e)
    e.poll()
    assert len(e.selection.pending) == 1
    resumed = make(tmp_path)
    resumed.clock = lambda: 7200
    resumed.monotonic = lambda: 61
    resumed.poll()
    assert resumed.refused["stale_skipped"] == 1
    assert not resumed.selection.pending and not records(resumed)


def test_record_and_checkpoint_refuse_unsanitized_producer_fields(tmp_path):
    e = make(tmp_path)
    append(e)
    e.poll()
    row = records(e)[0]
    for key, value in (("attack_type", "192.0.2.1 a=b;"), ("policy_reason", "internalhostname")):
        with pytest.raises(ValueError):
            read_record({**row, key: value})
    checkpoint = json.loads((e.state / "cursor.json").read_bytes())
    checkpoint["pending"] = [[transition(), 1]]
    with pytest.raises(ValueError):
        daemon.decode_checkpoint(json.dumps(checkpoint).encode())


def test_recent_closes_survives_restart_and_updates_explanation(tmp_path):
    from azazel_nexus.incident_explain import read_recent_incidents
    e = make(tmp_path)
    append(e)
    e.poll()
    row = read_recent_incidents((tmp_path / "recent.json").read_bytes())["incidents"][0]
    assert row["explanation"]["state"] == "unavailable"
    append(e, transition(event_type="closed", reason="idle"))
    e.monotonic = lambda: 5
    e.poll()
    assert e.recent[0]["state"] == "closed"
    restored = make(tmp_path)
    assert restored.recent[0]["state"] == "closed"
    assert (tmp_path / "recent.json").stat().st_mode & 0o777 == 0o644


def test_audit_selection_ignores_regular_update_and_queue_does_not_block(tmp_path):
    e = make(tmp_path)
    append(e)
    append(e, transition(3, "updated"))
    append(e, transition(1, "updated"))
    append(e, transition(1, "closed", reason="shutdown"))
    e.poll()
    events = list(e.audit_pending.queue)
    assert [v["event_type"] for v in events] == ["edge.incident." + k for k in ("opened", "escalated", "closed")]
    assert len(records(e)) == 2 and not e.storage_failed
    assert not {"attack_type", "src_ip", "technique_ids"} & set(events[0])
    assert "192.0.2.1" not in json.dumps(events)
    for i in range(300):
        e.observe_transition(transition(incident_id=f"inc-{i:016x}"))
    assert e.audit_pending.qsize() == 256
    assert e.snapshot()["audit_forward_dropped"] == 47
    assert len(e.recent) == 20


def test_audit_retry_is_independent_and_recovers(tmp_path):
    seen, failed = [], threading.Event()
    def audit(event):
        if not failed.is_set():
            failed.set()
            raise OSError("SECRET")
        seen.append(event)
        stopped.set()
    e = make(tmp_path, audit=audit)
    append(e)
    e.poll()
    stopped = threading.Event()
    worker = threading.Thread(target=e.forward_audit, args=(stopped,))
    worker.start()
    assert failed.wait(2)
    # The failed event still occupies the bounded queue; ledger polls continue.
    assert e.audit_pending.qsize() == 1
    append(e, transition(1, "updated"))
    e.poll()
    assert len(records(e)) == 2
    worker.join(3)
    assert not worker.is_alive() and len(seen) == 1
    assert not e.storage_failed and e.audit_forward_dropped == 0


def test_audit_client_uses_shared_authenticated_bounded_transport(monkeypatch):
    calls = []
    def exchange(*args, **kwargs):
        calls.append((args, kwargs))
        return {"sequence": 1, "event_hash": "a" * 64}
    monkeypatch.setattr(daemon, "_exchange", exchange)
    event = {"event_type": "edge.incident.opened", "count": 1}
    receipt = daemon.append_audit(event)
    assert receipt.sequence == 1
    assert calls == [(("audit-submit", "azaudit", "audit.append", {"event_type": "edge.incident.opened"}),
                      {"payload": {"count": 1}, "deadline_s": 2})]
    monkeypatch.setattr(daemon, "_exchange", lambda *a, **kw: {"sequence": True, "event_hash": "SECRET"})
    with pytest.raises(ValueError):
        daemon.append_audit(event)


def test_recent_summary_uses_validated_advice_and_frame_filter(tmp_path):
    from azazel_nexus.local_advisory import delivered_document, build_options
    from azazel_nexus.incident_explain import private_text, read_recent_incidents
    e = make(tmp_path)
    def mio(frame):
        options = build_options(frame)
        body = delivered_document(frame, (), options,
                                  {"option_id": "other_suspicious", "kind": "other_suspicious"},
                                  list(options), None, "deterministic")
        return {"route": "local", "outcome": "answered", "reason": "local", "ledger_seq": 1, **body}
    e.mio = mio
    append(e)
    e.poll()
    value = records(e)[0]
    row = read_recent_incidents((tmp_path / "recent.json").read_bytes())["incidents"][0]
    assert row["explanation"]["state"] == "explained"
    assert row["explanation"]["summary"] == private_text(value["mio"]["text"][:280], 280)
    assert len(row["explanation"]["summary"]) <= 280
    assert "192.0.2.1" not in json.dumps(row)


def test_legacy_i2_cursor_migrates_audit_comparison_state(tmp_path):
    e = make(tmp_path)
    append(e)
    e.poll()
    path = e.state / "cursor.json"
    value = json.loads(path.read_bytes())
    for key in ("recent", "audit_severities", "audit_forward_dropped", "audit_forward_refused"):
        del value[key]
    path.write_text(json.dumps(value))
    restored = make(tmp_path)
    append(restored, transition(1, "updated"))
    restored.poll()
    assert list(restored.audit_pending.queue)[0]["event_type"] == "edge.incident.escalated"


def test_intake_reset_closes_recent_projection_without_manufacturing_audit(tmp_path):
    e = make(tmp_path)
    append(e)
    e.poll()
    append(e, {"event_type": "edge.incident.reset", "at": 1, "reason": "intake_started"})
    e.poll()
    assert e.recent[0]["state"] == "closed"
    assert not e.audit_severities
    assert e.audit_pending.qsize() == 1


class DrainStop:
    def __init__(self, e):
        self.e, self.waits = e, []
    def is_set(self):
        return self.e.audit_pending.empty()
    def wait(self, seconds):
        self.waits.append(seconds)


def test_failed_audit_delivery_backs_off_then_drops_the_head(tmp_path):
    calls = []
    def fail(event):
        calls.append(event)
        raise ValueError("SECRET")
    e = make(tmp_path, audit=fail)
    e.observe_transition(transition())
    stop = DrainStop(e)
    e.forward_audit(stop)
    assert len(calls) == 4 and stop.waits == [0.5, 1, 2]
    assert e.audit_forward_dropped == 1 and e.audit_forward_refused == 0 and not e.storage_failed


@pytest.mark.parametrize("refusal", ["principal_denied", "argument_range", "argument_type",
                                     "undeclared_argument", "missing_argument", "unknown_verb",
                                     # auditd's rate/daily limit (#211): final, counted, not latched.
                                     "rate_limited"])
def test_audit_refusal_is_dropped_at_once_and_counted_apart(tmp_path, refusal):
    calls = []
    def refuse(event):
        calls.append(event)
        raise client.ServiceRefused(refusal)
    e = make(tmp_path, audit=refuse)
    e.observe_transition(transition())
    e.observe_transition(transition(incident_id="inc-2222222222222222"))
    stop = DrainStop(e)
    e.forward_audit(stop)
    assert len(calls) == 2 and stop.waits == []
    assert e.audit_forward_refused == 2 and e.audit_forward_dropped == 0
    status = e.snapshot()
    assert status["audit_forward_refused"] == 2
    from azazel_nexus.incident_explain import read_explainer_status
    assert read_explainer_status(json.dumps(status).encode()) == status
    e.checkpoint()
    assert make(tmp_path).audit_forward_refused == 2


def test_server_read_deadline_refusal_is_retried(tmp_path):
    calls = []
    def audit(event):
        calls.append(event)
        if len(calls) == 1:
            raise client.ServiceRefused("read_deadline")
    e = make(tmp_path, audit=audit)
    e.observe_transition(transition())
    stop = DrainStop(e)
    e.forward_audit(stop)
    assert len(calls) == 2 and stop.waits == [0.5]
    assert e.audit_forward_refused == e.audit_forward_dropped == 0


@pytest.mark.parametrize("reply,refused", [({"ok": False, "refusal": "principal_denied"}, True),
                                           ({"ok": False, "refusal": "rate_limited"}, True),
                                           ({"ok": False, "refusal": "SECRET 192.0.2.1"}, False),
                                           ({"ok": False, "refusal": "principal_denied", "x": 1}, False)])
def test_audit_client_carries_only_declared_refusal_reasons(tmp_path, monkeypatch, reply, refused):
    with tempfile.TemporaryDirectory(prefix="i3-", dir="/tmp") as directory:
        monkeypatch.setattr(runtime_paths, "ROOT", Path(directory))
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
        monkeypatch.setattr(client, "peer_credentials", lambda _: (1, os.getuid(), os.getgid()))
        path = runtime_paths.socket_path("audit-submit")
        path.parent.mkdir(parents=True, exist_ok=True)
        # BSD gives new files the directory's group, so macOS sockets in /tmp
        # are not in the caller's primary group.
        gid = path.parent.stat().st_gid
        monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=gid))
        try:
            listener = bind_socket(path, expected_gid=gid)
        except PermissionError:
            pytest.skip("sandbox denies AF_UNIX bind")
        listener.settimeout(3)
        errors = []
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    read_frame(connection)
                    send_frame(connection, reply)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with pytest.raises(ValueError) as exc:
                daemon.append_audit({"event_type": "edge.incident.opened", "count": 1})
        finally:
            thread.join(4)
            listener.close()
        assert not errors
        assert isinstance(exc.value, client.ServiceRefused) is refused
        assert str(exc.value) == "M.I.O. service refused"
        if refused:
            assert exc.value.refusal == reply["refusal"]


def test_recent_projection_failure_does_not_cost_the_audit_record(tmp_path, monkeypatch):
    e = make(tmp_path)
    def fail(*_):
        raise RuntimeError("SECRET")
    monkeypatch.setattr(daemon, "build_recent_incident", fail)
    e.observe_transition(transition())
    assert e.audit_pending.qsize() == 1 and e.refused["transition_refused"] == 1


def test_unchanged_recent_snapshot_is_rewritten_every_20_seconds(tmp_path, monkeypatch):
    e = make(tmp_path)
    append(e)
    e.poll()
    writes = []
    original = daemon.atomic_json
    monkeypatch.setattr(daemon, "atomic_json",
                        lambda path, value, mode: (writes.append(path.name), original(path, value, mode)))
    e.monotonic = lambda: 19
    e.recent_status()
    assert writes == []
    e.clock = lambda: 20
    e.monotonic = lambda: 20
    e.recent_status()
    assert writes == ["recent.json"]
    assert json.loads((tmp_path / "recent.json").read_text())["written_at"] == 20


def test_unchanged_status_is_rewritten_every_20_seconds(tmp_path, monkeypatch):
    e = make(tmp_path)
    e.poll()
    writes = []
    original = daemon.atomic_json
    monkeypatch.setattr(daemon, "atomic_json",
                        lambda path, value, mode: (writes.append(path.name), original(path, value, mode)))
    e.monotonic = lambda: 19
    e.status()
    assert "status.json" not in writes
    e.clock = lambda: 20
    e.monotonic = lambda: 20
    e.status()
    assert "status.json" in writes
    assert json.loads((tmp_path / "status.json").read_text())["written_at"] == 20


def test_severe_transition_displaces_ordinary_work_and_survives_restart(tmp_path):
    from azazel_nexus.incident_explain import MAX_PENDING
    e = make(tmp_path)
    e.selection.attempts.extend([0] * 6)
    for n in range(MAX_PENDING):
        e.selection.enqueue(transition(5, incident_id=f"inc-{n:016x}"), n + 1)
    append(e, transition(1, incident_id="inc-00000000000000aa", evidence_stored=False))
    e.poll()
    assert e.refused["queue_full"] == 1
    assert len(e.selection.pending) == MAX_PENDING
    restarted = make(tmp_path)
    restarted.monotonic = lambda: 61
    restarted.poll()
    assert records(restarted)[0]["incident_id"] == "inc-00000000000000aa"


@pytest.mark.parametrize("state", ["explained", "pending"])
def test_displacement_keeps_an_explained_row(tmp_path, state):
    from azazel_nexus.incident_explain import MAX_PENDING, build_recent_incident
    e = make(tmp_path)
    e.selection.attempts.extend([0] * 6)
    victim = "inc-00000000000000bb"
    row = build_recent_incident(transition(5, incident_id=victim))
    if state == "explained":
        row["explanation"] = {"state": "explained", "route": "local", "outcome": "answered",
                              "summary": "Inspect the incident", "knowledge_refs": [],
                              "failure_codes": []}
        e.selection.mark(transition(5, incident_id=victim))
    e.recent = [row]
    for n in range(MAX_PENDING - 1):
        e.selection.enqueue(transition(5, incident_id=f"inc-{n:016x}"), n + 1)
    queued = transition(4, "updated", incident_id=victim) if state == "explained" else transition(5, incident_id=victim)
    assert e.selection.enqueue(queued, 100) == "queued"
    append(e, transition(1, incident_id="inc-00000000000000aa", evidence_stored=False))
    e.poll()
    assert e.refused["queue_full"] == 1
    assert all(t["incident_id"] != victim for t, _ in e.selection.pending)
    shown = next(r for r in e.recent if r["incident_id"] == victim)["explanation"]
    if state == "explained":
        assert shown["state"] == "explained" and shown["summary"] == "Inspect the incident"
    else:
        assert (shown["state"], shown["failure_codes"]) == ("unavailable", ["queue_full"])
    severe = next(r for r in e.recent if r["incident_id"] == "inc-00000000000000aa")
    assert severe["evidence_stored"] is False
    # Audit stays on its declared schema: the flag is not forwarded.
    (event,) = list(e.audit_pending.queue)
    assert event["event_type"] == "edge.incident.opened" and "evidence_stored" not in event


def test_pending_order_survives_checkpoint_and_displaced_stays_gone(tmp_path):
    from azazel_nexus.incident_explain import MAX_PENDING
    from test_incident_explain import drain
    e = make(tmp_path)
    for n in range(MAX_PENDING):
        e.selection.enqueue(transition(5 if n % 3 else 3, incident_id=f"inc-{n:016x}"), n + 1)
    e.selection.enqueue(transition(1, incident_id="inc-00000000000000aa"), 100)
    displaced = e.selection.displaced
    e.selection.enqueue(transition(2, "updated", incident_id="inc-0000000000000001"), 101)
    e.checkpoint()
    restarted = make(tmp_path)
    assert list(restarted.selection.pending) == list(e.selection.pending)
    order = drain(restarted.selection)
    assert order == drain(e.selection) and order
    assert order[0][0] == "inc-00000000000000aa"
    assert [o[:2] for o in order[1:3]] == [("inc-0000000000000001", "edge.incident.opened"),
                                           ("inc-0000000000000001", "edge.incident.updated")]
    assert displaced not in {o[0] for o in order}


def test_unexplained_incident_does_not_stay_awaiting_and_severe_escalation_is_explained(tmp_path):
    from azazel_nexus.incident_explain import MAX_PENDING
    e = make(tmp_path)
    for n in range(MAX_PENDING):
        e.selection.enqueue(transition(5, incident_id=f"inc-{n:016x}"), n + 1)
    append(e, transition(5))  # its opening finds the queue full
    e.poll()
    row = next(r for r in e.recent if r["incident_id"] == transition()["incident_id"])
    assert row["explanation"]["state"] == "unavailable"
    append(e, transition(4, "updated"))  # ordinary escalation: nothing will explain it
    e.monotonic = lambda: 5
    e.poll()
    row = next(r for r in e.recent if r["incident_id"] == transition()["incident_id"])
    assert row["explanation"]["state"] == "unavailable"
    append(e, transition(1, "updated"))  # severe: explained as the first
    e.monotonic = lambda: 10
    e.poll()
    assert any(t["incident_id"] == transition()["incident_id"] and t["most_severe"] == 1
               for t, _ in e.selection.pending)


def test_closed_audit_time_is_the_intake_close_time(tmp_path):
    e = make(tmp_path)
    e.clock = lambda: 5000
    append(e, transition(last_update=100))
    append(e, transition(1, "closed", reason="idle", last_update=1000))
    e.poll()
    # Both times come from intake, so a later replay keeps them together.
    assert [v["occurred_at"] for v in e.audit_pending.queue] == [
        "1970-01-01T00:01:40Z", "1970-01-01T00:16:40Z"]


def test_explanation_store_is_held_to_monotonic_time_and_reports_future(tmp_path):
    from datetime import UTC, datetime
    jan20 = datetime(2026, 1, 20, tzinfo=UTC).timestamp()
    e = make(tmp_path)
    directory = e.store.directory
    for day in ("2026-01-10", "2099-01-01"):
        (directory / (day + ".jsonl")).write_text("")
    # The store keeps its own elapsed clock, well past boot here.
    restarted = make(tmp_path, prepare=False,
                     store_limits={"monotonic": lambda: 10**7})
    restarted.clock = lambda: jan20
    restarted.prepare()
    # The explainer's own clock only clears the restart's 60 s rate wait.
    restarted.monotonic = lambda: 61
    assert restarted.refused["segment_from_future"] == 1
    assert (directory / "2026-01-10.jsonl").exists()
    fresh = {"first_seen": jan20, "last_seen": jan20, "last_update": jan20}
    append(restarted, transition(**fresh))
    restarted.poll()
    assert (directory / "2026-01-20.jsonl").exists()
    # A forward jump during the run does not open a segment in 2098.
    leap = datetime(2098, 1, 1, tzinfo=UTC).timestamp()
    restarted.clock = lambda: leap
    append(restarted, transition(incident_id="inc-2222222222222222",
                                 **{k: leap for k in fresh}))
    restarted.poll()
    assert len(records(restarted)) == 2
    assert not (directory / "2098-01-01.jsonl").exists()
    assert (directory / "2026-01-10.jsonl").exists()


def test_a_segment_vanishing_during_seeding_is_not_a_broken_chain(tmp_path, monkeypatch):
    e = make(tmp_path, prepare=False)
    e.prepare()
    e.cursor["segment"] = "1970-01-01"

    def vanished(**_):
        raise FileNotFoundError

    monkeypatch.setattr(e, "ingest", vanished)
    e.seed()
    assert not e.chain_broken and not e.cursor["broken"]
    assert e.refused["read_failed"] == 1


def _reference_document():
    from test_incident_explain import transition as _transition

    from azazel_nexus.incident_explain import build_frame
    from azazel_nexus.local_advisory import build_options, delivered_document

    frame = build_frame(_transition(), 1)
    options = build_options(frame)
    body = delivered_document(frame, (), options,
                              {"option_id": "other_suspicious", "kind": "other_suspicious"},
                              list(options), None, "deterministic")
    return {"banner": body["advice"], **{k: v for k, v in body.items() if k != "advice"}}


@pytest.mark.parametrize("reply", [
    # The pre-handoff shape with a reference: no notice to record it with.
    lambda: {"route": "deterministic handoff", "outcome": "refused", "reason": "r",
             "ledger_seq": 1, "reference_status": "attached", "reference": _reference_document()},
    # A shape that passes nothing at all.
    lambda: {"route": "deterministic handoff", "outcome": "refused", "reason": "r",
             "ledger_seq": 1, "reference_status": "attached"},
])
def test_a_malformed_reply_never_raises_out_of_explain(tmp_path, reply):
    e = make(tmp_path)
    e.mio = lambda _: reply()
    append(e)
    e.poll()  # must not raise
    (record,) = records(e)
    assert record["mio"]["reason"] == "mio_reply_refused"
    assert record["mio"]["text"] is None and "mio_reply_refused" in record["failure_codes"]


def test_a_record_that_read_mio_reply_accepted_but_read_record_refuses_is_contained(
    tmp_path, monkeypatch,
):
    e = make(tmp_path)
    # A reader defect: an AI kind on the handoff route, which no record may hold.
    monkeypatch.setattr(daemon, "read_mio_reply", lambda reply: {
        "route": "deterministic handoff", "outcome": "refused", "reason": "x",
        "text": "free text", "content_kind": "ai_advice"})
    append(e)
    e.poll()
    (record,) = records(e)
    assert record["mio"]["route"] == "unavailable"
    assert record["failure_codes"][-1] == "mio_reply_refused"


# ---- #427: the daemon keeps its window inside RECENT_BYTES ----------------
# Windows are placed through cursor.json and restore(); increments come from the real
# poll() -> explain() -> _settle_row() path with the same Mio/Knowledge doubles as above.

from azazel_nexus.incident_explain import RECENT_BYTES as _RECENT_BYTES  # noqa: E402


def _dsize(rows, written_at=0):
    from azazel_nexus.incident_explain import RECENT_SCHEMA
    return len(json.dumps({"schema": RECENT_SCHEMA, "written_at": written_at, "incidents": rows},
                          allow_nan=False).encode())


def _scaled_row(n, fraction, bare=False):
    import math
    from test_full_node_trace import _maximal_row

    steps = [0]

    def cut(node):
        if isinstance(node, list):
            # Each list steps at its own point, so a row's size changes in small increments.
            steps[0] += 1
            phase = (steps[0] * 0.381966) % 1
            keep = min(len(node), max(1, math.ceil(len(node) * fraction + phase - 1))) if len(node) > 1 else 1
            return [cut(x) for x in node[:keep]]
        if isinstance(node, dict):
            return {k: cut(v) for k, v in node.items()}
        return node
    row = _maximal_row(n)
    row["explanation"] = cut(row["explanation"])
    row["explanation"]["summary"] = "a"
    if bare:       # rows a reset leaves alone apart from the state word (+2 bytes each)
        row.pop("full_node_trace", None)
        row["explanation"].pop("fast_assistance", None)
    return row


def _fit_rows(n, target, extra=(), bare=False):
    """n valid rows whose window with `extra` measures exactly `target` bytes (written_at 0)."""
    from azazel_nexus.incident_explain import RECENT_SCHEMA, read_recent_incidents
    extra = list(extra)
    pattern = "Inspect the launch of the interpreter and check its parent " * 6
    text = lambda k: pattern[:k][:-1] + "a" if pattern[:k].endswith(" ") else pattern[:k]
    goal = target
    for reserve in (2000, 1700, 1400, 1100, 2300, 800, 2600, 2900, 3200, 500, 3500, 3800, 4100, 1250, 1550, 1850):
        lo, hi = 0.0, 1.0
        for _ in range(30):
            mid = (lo + hi) / 2
            if _dsize([_scaled_row(i + 1, mid, bare) for i in range(n)] + extra) <= goal - n * 270:
                lo = mid
            else:
                hi = mid
        rows = [_scaled_row(i + 1, lo, bare) for i in range(n)]
        for i in range(n):
            a, b = lo, 1.0
            for _ in range(25):
                m = (a + b) / 2
                trial = rows[:i] + [_scaled_row(i + 1, m, bare)] + rows[i + 1:]
                if _dsize(trial + extra) <= goal - reserve:
                    a = m
                else:
                    b = m
            rows[i] = _scaled_row(i + 1, a, bare)
        need = goal - _dsize(rows + extra)
        if not 0 <= need <= n * 278:
            continue
        for i in range(n):
            rows[i]["explanation"]["summary"] = text(1 + need // n + (1 if i < need % n else 0))
        if _dsize(rows + extra) != goal:
            continue
        assert all(read_recent_incidents(json.dumps({
            "schema": RECENT_SCHEMA, "written_at": 1, "incidents": [r]}).encode()) for r in rows)
        return rows
    raise AssertionError("no fit")


def _loose_rows(n, target):
    """n large valid rows (the largest uniform cut that keeps the window at or under target)."""
    lo, hi = 0.0, 1.0
    for _ in range(30):
        mid = (lo + hi) / 2
        if _dsize([_scaled_row(i + 1, mid) for i in range(n)]) <= target:
            lo = mid
        else:
            hi = mid
    return [_scaled_row(i + 1, lo) for i in range(n)]


def _window(tmp_path, rows, **kwargs):
    seed = make(tmp_path)
    seed.recent = json.loads(json.dumps(rows))
    seed.checkpoint()
    return make(tmp_path, **kwargs)


def _settled_row(**kwargs):
    """The real settled row for the default transition (calibration only)."""
    with tempfile.TemporaryDirectory() as d:
        e = make(Path(d), **kwargs)
        append(e)
        e.poll()
        return json.loads(json.dumps(e.recent[0]))


SLOW_QUEUED = {"state": "queued", "usage": "unknown", "generation_id": "generation-1",
               "result_handle": "a" * 64}


def _complete_slow(receipt, *, deadline_s):
    return {**receipt, "state": "complete", "usage": "known",
            "calls": [{"usage": {"tokens_in": 1, "tokens_out": 2}, "timings": {}}],
            "assistance": {
                "schema_version": "mio.assistance.v1", "frame_id": receipt["frame_id"],
                "trace_id": receipt["trace_id"], "generation_method": "model",
                "hypotheses": [{"verification": "model_proposed_unverified",
                                "statement": "Observed symptoms may reflect a benign change."}],
                "unknowns": ["The approved change record is not present."],
                "next_checks": ["Check the authorized change record."]}}


def _slow_kwargs():
    t = transition()
    trace = f"mio-{t['incident_id'][4:]}-1"
    queued = {**SLOW_QUEUED, "frame_id": trace + ":frame", "trace_id": trace}
    return dict(mio=lambda _: {**handoff(), "slow_analysis": queued},
                mio_result=_complete_slow)


def _bound_ok(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES, read_recent_incidents
    raw = (tmp_path / "recent.json").read_bytes()
    assert len(raw) <= RECENT_BYTES
    return read_recent_incidents(raw)


def test_window_stays_within_bound_when_a_settle_overflows(tmp_path):
    from azazel_nexus.incident_explain import CODES, RECENT_BYTES
    settled = _settled_row()
    rows = _fit_rows(19, RECENT_BYTES + 1, [settled])
    e = _window(tmp_path, rows)
    before = json.loads(json.dumps(e.recent))
    append(e)
    e.poll()
    e.monotonic = lambda: 61                    # restore() holds the rate budget for 60 s
    e.poll()
    new = [r for r in e.recent if r["incident_id"] == settled["incident_id"]]
    assert len(new) == 1
    assert new[0]["explanation"]["failure_codes"] == ["status_write_failed"]
    assert new[0]["explanation"]["state"] == "unavailable"
    assert new[0].get("full_node_trace") == settled.get("full_node_trace")
    others = [r for r in e.recent if r["incident_id"] != settled["incident_id"]]
    key = lambda r: r["incident_id"]
    assert [json.dumps(r, sort_keys=True) for r in sorted(others, key=key)] == [
        json.dumps(r, sort_keys=True) for r in sorted(before, key=key)]
    assert e.refused["status_write_failed"] == 1 and not e.storage_failed
    assert set(e.refused) <= CODES
    assert len(_bound_ok(tmp_path)["incidents"]) == 20
    assert len(records(e)) == 1
    # (c) the checkpoint advanced, so a restart does not explain the same transition again
    assert e.selection.explained
    restarted = make(tmp_path)
    for k in range(1, 4):
        restarted.monotonic = lambda k=k: 100 * k
        restarted.poll()
    assert len(records(restarted)) == 1
    assert restarted.cursor["offset"] == e.cursor["offset"]


def test_window_stays_within_bound_when_a_slow_projection_overflows(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    settled = _settled_row(**_slow_kwargs())
    # The projection (degraded with its budget) is larger than the plain degraded form it is cut to.
    assert "budget" in settled["explanation"]["slow_analysis"]
    rows = _fit_rows(19, RECENT_BYTES + 1, [settled])
    e = _window(tmp_path, rows, **_slow_kwargs())
    append(e)
    e.poll()
    e.monotonic = lambda: 61
    e.poll()
    row = [r for r in e.recent if r["incident_id"] == settled["incident_id"]][0]
    assert row["explanation"]["slow_analysis"] == {"state": "degraded", "usage": "unknown"}
    rest = lambda r: {k: v for k, v in r["explanation"].items() if k != "slow_analysis"}
    assert rest(row) == rest(settled)                # the fast explanation stays
    assert e.refused["status_write_failed"] == 1 and not e.storage_failed
    assert len(_bound_ok(tmp_path)["incidents"]) == 20


def test_window_stays_within_bound_settling_incidents_one_at_a_time_with_large_rows_preloaded(tmp_path):
    """Four reader-maximal rows are preloaded; the settled rows are real (a few KB), not maximal.

    A maximal row cannot be produced by the real settle path, so this fixes the behaviour
    for the largest rows the path can make: from some n on, settled rows show as degraded.
    Only the first ten incidents are settled. The eleventh would add a pending row that no
    row in the window can give room for (a pending row becomes an unavailable row that is
    25 bytes or more longer, more with a trace); that case is covered by the section 5 tests below (settle_minimum_still_over_reduces_the_oldest).
    """
    from azazel_nexus.incident_explain import RECENT_BYTES, CODES
    maximal = _loose_rows(4, RECENT_BYTES - 16000)     # reader-bounded large rows, 30 KB left over
    e = _window(tmp_path, maximal)
    shrunk = []
    for n in range(10):
        append(e, transition(incident_id=f"inc-{0xa00 + n:016x}"))
        e.monotonic = lambda n=n: 61 * (n + 1)
        e.poll()
        e.poll()
        assert not e.storage_failed
        assert "transition_refused" not in e.refused
        _bound_ok(tmp_path)
        row = [r for r in e.recent if r["incident_id"] == f"inc-{0xa00 + n:016x}"][0]
        shrunk.append(row["explanation"].get("failure_codes") == ["status_write_failed"])
    assert not shrunk[0] and shrunk[-1]
    assert shrunk == sorted(shrunk)                  # once shrinking starts it continues
    assert e.refused["status_write_failed"] == sum(shrunk)
    assert set(e.refused) <= CODES
    assert len(records(e)) == 10
    assert len((tmp_path / "state" / "cursor.json").read_bytes()) <= RECENT_BYTES * 2


# ---- #427 section 5: a change the row cannot absorb takes room from the oldest rows ----

_Y = "inc-" + "c" * 16


def _pending_row(t):
    """The real pending row for `t` (calibration only; the formal path, in a scratch directory)."""
    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        make(base).checkpoint()
        e = make(base)
        append(e, t)
        e.poll()
        return json.loads(json.dumps([r for r in e.recent if r["incident_id"] == t["incident_id"]][0]))


def _key(r):
    return (r["last_seen"], r["first_seen"], r["incident_id"])


def _jb(r):
    return json.dumps(r, sort_keys=True)


def _old(n, **explanation):
    """A reader-valid row that sorts before every _fit_rows row (last_seen 0)."""
    from test_full_node_trace import _maximal_row
    r = _maximal_row(n)
    r["last_seen"] = 0
    r["explanation"].update(explanation)
    return r


def _small_explained(n):
    """An explained row with a short summary and nothing optional; unavailable is a little shorter."""
    r = _old(n)
    e = r["explanation"]
    for k in ("slow_analysis", "fast_assistance", "guidance", "content_kind"):
        e.pop(k, None)
    e.update(summary=("Inspect the launch of the interpreter and check its parent " * 4)[:200].strip(),
             knowledge_refs=[])
    return r


def _insert(tmp_path, d, rows=None, olds=(), settle=False, **kwargs):
    """A window `d` bytes over the bound once a new pending incident joins; then the real poll."""
    from azazel_nexus.incident_explain import RECENT_BYTES
    t = transition(incident_id=_Y)
    pending = _pending_row(t)
    if rows is None:
        rows = list(olds) + _fit_rows(19 - len(olds), RECENT_BYTES + d, [*olds, pending])
    e = _window(tmp_path, rows, **kwargs)
    before = {r["incident_id"]: _jb(r) for r in e.recent}
    append(e, t)
    e.poll()
    if settle:
        e.monotonic = lambda: 61
        e.poll()
    return e, before


def _changed(e, before):
    return sorted(r["incident_id"] for r in e.recent
                  if r["incident_id"] in before and _jb(r) != before[r["incident_id"]])


def _no_new_codes(e):
    from azazel_nexus.incident_explain import CODES
    assert set(e.refused) <= CODES
    for r in e.recent:
        assert set(r["explanation"].get("failure_codes", ())) <= CODES


GONE = {"state": "unavailable", "route": "unavailable", "outcome": "unavailable", "summary": "",
        "knowledge_refs": [], "failure_codes": ["status_write_failed"]}


def test_window_stays_within_bound_s5_under_bound_is_untouched(tmp_path):
    e, before = _insert(tmp_path, -1)
    assert any(r["incident_id"] == _Y for r in e.recent) and len(e.recent) == 20
    assert _changed(e, before) == [] and not e.refused
    _no_new_codes(e)


def test_window_stays_within_bound_s5_at_bound_is_untouched(tmp_path):
    e, before = _insert(tmp_path, 0)
    assert any(r["incident_id"] == _Y for r in e.recent) and len(e.recent) == 20
    assert _changed(e, before) == [] and not e.refused
    assert len(_bound_ok(tmp_path)["incidents"]) == 20


def test_window_stays_within_bound_s5_one_over_reduces_the_oldest(tmp_path):
    e, before = _insert(tmp_path, 1)
    assert any(r["incident_id"] == _Y for r in e.recent) and len(e.recent) == 20
    oldest = min((r for r in e.recent if r["incident_id"] != _Y), key=_key)["incident_id"]
    assert _changed(e, before) == [oldest]
    row = [r for r in e.recent if r["incident_id"] == oldest][0]
    assert row["explanation"]["slow_analysis"] == {"state": "degraded", "usage": "unknown"}
    assert e.refused["status_write_failed"] == 1 and "transition_refused" not in e.refused
    assert not e.storage_failed
    assert len(_bound_ok(tmp_path)["incidents"]) == 20
    assert (tmp_path / "state" / "cursor.json").stat().st_size > 0
    _no_new_codes(e)


def test_window_stays_within_bound_s5_a_large_oldest_row_gives_up_its_slow_first(tmp_path):
    e, before = _insert(tmp_path, 1, olds=[_old(0)])
    assert _changed(e, before) == [f"inc-{0:016x}"]
    row = [r for r in e.recent if r["incident_id"] == f"inc-{0:016x}"][0]
    assert row["explanation"]["slow_analysis"] == {"state": "degraded", "usage": "unknown"}
    rest = lambda r: {k: v for k, v in r["explanation"].items() if k != "slow_analysis"}
    assert rest(row) == rest(_old(0))
    assert row["explanation"]["state"] == "explained"
    assert e.refused["status_write_failed"] == 1


def test_window_stays_within_bound_s5_reductions_chain_from_the_oldest(tmp_path):
    olds = [_small_explained(0), _small_explained(0x100), _small_explained(0x200)]
    s1 = len(json.dumps(olds[0])) - len(json.dumps({**olds[0], "explanation": GONE}))
    assert 0 < s1 < 380
    e, before = _insert(tmp_path, s1 + 1, olds=olds)
    assert _changed(e, before) == [f"inc-{0:016x}", f"inc-{0x100:016x}"]
    for n in (0, 0x100):
        row = [r for r in e.recent if r["incident_id"] == f"inc-{n:016x}"][0]
        assert row["explanation"] == GONE
    assert e.refused["status_write_failed"] == 1       # one pass, however many rows it changed
    assert len(_bound_ok(tmp_path)["incidents"]) == 20


def test_window_stays_within_bound_s5_rows_that_would_grow_are_skipped(tmp_path):
    old = _pending_row(transition(incident_id=f"inc-{0:016x}"))
    tiny = _small_explained(0x100)          # unavailable would not be shorter than this
    tiny["explanation"].update(summary="a", failure_codes=[])
    assert len(json.dumps(GONE)) >= len(json.dumps(tiny["explanation"]))
    e, before = _insert(tmp_path, 1, olds=[old, tiny])
    skipped = {old["incident_id"], tiny["incident_id"]}
    oldest_fit = min((r for r in e.recent if r["incident_id"] not in skipped | {_Y}), key=_key)["incident_id"]
    assert _changed(e, before) == [oldest_fit]
    assert [r for r in e.recent if r["incident_id"] == old["incident_id"]][0]["explanation"]["state"] == "pending"


def test_window_stays_within_bound_s5_pending_rows_with_slow_are_untouched(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    pending = _pending_row(transition(incident_id=_Y))
    pending["last_seen"] = 0                         # the oldest row: the first one a reduction would pick
    pending["explanation"]["slow_analysis"] = {"state": "queued", "usage": "unknown"}
    assert pending["explanation"]["state"] == "pending"
    rows = [pending] + _fit_rows(19, RECENT_BYTES, [pending])
    _window(tmp_path, rows)                          # cursor.json as the reader accepts it (written_at 0)
    e = make(tmp_path, clock=lambda: 1061.0)         # "written_at": 1061.0 is 5 bytes longer: bound + 5
    e.monotonic = lambda: 100
    before = {r["incident_id"]: _jb(r) for r in e.recent}
    assert before[pending["incident_id"]] == _jb(pending)
    e.status()
    assert e.refused["status_write_failed"] == 1     # one pass, however many rows it reduced
    assert _jb([r for r in e.recent if r["incident_id"] == pending["incident_id"]][0]) == before[
        pending["incident_id"]]                      # (a) byte for byte
    others = [r for r in e.recent if r["incident_id"] != pending["incident_id"]]
    oldest = min(others, key=_key)["incident_id"]    # (b) the oldest non-pending row took the reduction
    assert _changed(e, before) == [oldest]
    assert [r for r in e.recent if r["incident_id"] == oldest][0]["explanation"]["slow_analysis"] == {
        "state": "degraded", "usage": "unknown"}
    assert len(_bound_ok(tmp_path)["incidents"]) == 20
    e.monotonic = lambda: 200
    e.poll()                                         # (c) a later pass that fits adds nothing
    assert e.refused["status_write_failed"] == 1


def test_window_stays_within_bound_s5_twenty_minimum_rows_fit_well_under_the_bound():
    """Pins a fact about the bound (design 6.4), not a daemon path: the library is called directly."""
    from azazel_nexus.incident_explain import RECENT_BYTES, build_recent_incidents
    from test_full_node_trace import _maximal_row
    rows = []
    for n in range(1, 21):
        r = _maximal_row(n)                          # non-explanation fields and the largest trace stay
        r["technique_ids"] = [f"T{1000 + i}" for i in range(8)]
        r["explanation"] = {"state": "unavailable", "route": "unavailable", "outcome": "unavailable",
                            "summary": "", "knowledge_refs": [], "failure_codes": ["status_write_failed"]}
        rows.append(r)
    value = build_recent_incidents(rows, 0)
    assert len(value["incidents"]) == 20
    size = len(json.dumps(value, allow_nan=False).encode())
    assert size < RECENT_BYTES * 0.15, size          # about 10% when written


def test_window_stays_within_bound_s5_observe_uses_one_timestamp_per_pass(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    t = transition(incident_id=_Y)
    pending = _pending_row(t)
    # Written at 0 the window measures RECENT_BYTES - 5: "1061.1" (6 chars) adds 5 bytes and just
    # fits, "1061.09" and "1061.11" (7 chars) add 6 and are one byte over.
    rows = _fit_rows(19, RECENT_BYTES - 5, [pending])
    armed = []
    values = [1061.09, 1061.1, 1061.11]
    reads = []

    def clock():
        if not armed:
            return 1061.1
        reads.append(1)
        return values[(len(reads) - 1) % 3]
    e = _window(tmp_path, rows, clock=clock)
    before = {r["incident_id"]: _jb(r) for r in e.recent}
    armed.append(1)
    e.observe_transition(t)                          # one pass, however many times it would read the clock
    assert "transition_refused" not in e.refused
    assert _Y in {r["incident_id"] for r in e.recent}
    assert len(e.recent) == 20
    oldest = min(rows, key=_key)["incident_id"]
    assert _changed(e, before) == [oldest]
    assert e.refused["status_write_failed"] == 1


def test_window_stays_within_bound_s5_restore_reduces_a_reader_valid_window_the_builder_refuses(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    pending = _pending_row(transition(incident_id=_Y))
    pending["last_seen"] = 0
    pending["explanation"]["slow_analysis"] = {"state": "queued", "usage": "unknown"}
    # A path citation ("/") is kept by the reader but withheld by the builder ("" and "withheld"
    # instead of "/" and "shown"): 2 bytes more. The file is made exactly RECENT_BYTES long.
    rows = [pending] + _fit_rows(19, RECENT_BYTES, [pending])
    _window(tmp_path, rows)
    path = tmp_path / "state" / "cursor.json"
    value = json.loads(path.read_text())
    incidents = value["recent"]["incidents"]
    victim = min((r for r in incidents if r["explanation"]["state"] != "pending"), key=_key)["incident_id"]
    for r in incidents:
        if r["incident_id"] == victim:
            r["explanation"]["knowledge_refs"][0].update(citation="/", citation_state="shown")
    measure = lambda: len(json.dumps(value["recent"], allow_nan=False).encode())
    deficit = RECENT_BYTES - measure()
    assert 0 < deficit
    for r in incidents:                              # give the freed bytes back in the other summaries
        if r["incident_id"] != victim and r["explanation"]["state"] != "pending" and deficit:
            k = len(r["explanation"]["summary"])
            room = min(deficit, 279 - k)
            text = ("Inspect the launch of the interpreter and check its parent " * 6)[:k + room]
            r["explanation"]["summary"] = text[:-1] + "a" if text.endswith(" ") else text
            deficit -= room
    assert deficit == 0
    path.write_bytes(daemon.canonical(value))        # the file as the reader and decode_checkpoint see it
    assert measure() == RECENT_BYTES
    daemon.decode_checkpoint(path.read_bytes())      # the reader's check accepts it
    e = make(tmp_path)                               # restore
    assert not e.storage_failed
    assert e.refused["status_write_failed"] == 1
    assert [r for r in e.recent if r["incident_id"] == victim][0]["explanation"]["slow_analysis"] == {
        "state": "degraded", "usage": "unknown"}
    assert [r for r in e.recent if r["incident_id"] == pending["incident_id"]][0] == pending
    assert path.stat().st_size > 0 and daemon.decode_checkpoint(path.read_bytes())
    e.monotonic = lambda: 100
    e.status()
    e.poll()
    assert not e.storage_failed
    _bound_ok(tmp_path)


def test_window_stays_within_bound_s5_ties_break_on_incident_id(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    pending = _pending_row(transition(incident_id=_Y))
    raws = []
    for k, order in enumerate((1, -1)):
        base = tmp_path / str(k)
        base.mkdir()
        a, b = _scaled_row(0, 0.3), _scaled_row(0x100, 0.3)
        a["last_seen"] = b["last_seen"] = 1            # ties with the row of incident 1 on last_seen
        a["first_seen"], b["first_seen"] = 1, 0        # a (lowest id) is later on first_seen
        rows = [a, b] + _fit_rows(17, RECENT_BYTES + 1, [a, b, pending])
        if order < 0:
            rows = rows[::-1]
        e = _window(base, rows)
        append(e, transition(incident_id=_Y))
        e.poll()
        reduced = sorted(r["incident_id"] for r in e.recent
                         if r["explanation"].get("slow_analysis") == {"state": "degraded", "usage": "unknown"})
        assert reduced == [f"inc-{1:016x}"]            # (1, 0, inc-1) < (1, 0, inc-100) < (1, 1, inc-0)
        raws.append((base / "recent.json").read_bytes())
    assert raws[0] == raws[1]


def test_window_stays_within_bound_s5_reset_closing_reduces_the_oldest(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    rows = _fit_rows(20, RECENT_BYTES, bare=True)       # closing adds 2 bytes per row
    assert all(r["state"] == "open" for r in rows)
    e = _window(tmp_path, rows)
    oldest = min(e.recent, key=_key)["incident_id"]
    append(e, {"event_type": "edge.incident.reset", "at": 1, "reason": "intake_started"})
    e.poll()
    assert not e.storage_failed and all(r["state"] == "closed" for r in e.recent)
    row = [r for r in e.recent if r["incident_id"] == oldest][0]
    assert row["explanation"]["slow_analysis"] == {"state": "degraded", "usage": "unknown"}
    assert e.refused["status_write_failed"] == 1
    assert len(_bound_ok(tmp_path)["incidents"]) == 20


def test_window_stays_within_bound_s5_unavailable_reduces_the_oldest(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    pending = _pending_row(transition(incident_id=_Y))
    # The clock prints 3601 (3 bytes longer than 0): the window with the pending row measures the bound.
    rows = _fit_rows(19, RECENT_BYTES - 3, [pending])
    e = _window(tmp_path, rows)
    e.clock = lambda: 3601
    before = {r["incident_id"]: _jb(r) for r in e.recent}
    append(e, transition(incident_id=_Y))
    e.poll()
    y = [r for r in e.recent if r["incident_id"] == _Y][0]
    assert y["explanation"]["failure_codes"] == ["stale_skipped"]
    oldest = min((r for r in e.recent if r["incident_id"] != _Y), key=_key)["incident_id"]
    assert _changed(e, before) == [oldest]
    assert e.refused["stale_skipped"] == 1 and e.refused["status_write_failed"] == 1
    assert not e.storage_failed


def test_window_stays_within_bound_s5_settle_minimum_still_over_reduces_the_oldest(tmp_path):
    maximal = _loose_rows(4, _RECENT_BYTES - 16000)
    e = _window(tmp_path, maximal)
    for n in range(11):
        append(e, transition(incident_id=f"inc-{0xa00 + n:016x}"))
        e.monotonic = lambda n=n: 61 * (n + 1)
        e.poll()
        e.poll()
        assert not e.storage_failed and "transition_refused" not in e.refused
        _bound_ok(tmp_path)
    assert len(records(e)) == 11
    assert len({r["incident_id"] for r in records(e)}) == 11
    assert e.refused["status_write_failed"] >= 1
    assert (tmp_path / "state" / "cursor.json").stat().st_size > 0
    reduced = [r for r in e.recent if r["explanation"].get("failure_codes") == ["status_write_failed"]
               or r["explanation"].get("slow_analysis") == {"state": "degraded", "usage": "unknown"}]
    assert reduced and len(e.recent) == 15
    assert min(e.recent, key=_key)["incident_id"] in {r["incident_id"] for r in reduced}  # the oldest gave way
    _no_new_codes(e)
    assert json.loads((tmp_path / "status.json").read_text())["storage_failed"] is False


def test_window_stays_within_bound_s5_restart_keeps_the_reduction(tmp_path):
    e, _ = _insert(tmp_path, 1, settle=True)
    assert e.refused["status_write_failed"] >= 1
    n = len(records(e))
    count = e.refused["status_write_failed"]
    restarted = make(tmp_path)
    assert restarted.recent == e.recent
    for k in range(1, 4):
        restarted.monotonic = lambda k=k: 100 * k
        restarted.poll()
    assert restarted.recent == e.recent
    assert len(records(restarted)) == n
    assert restarted.refused["status_write_failed"] == count


def test_window_stays_within_bound_s5_status_reduces_a_restored_window(tmp_path, monkeypatch):
    from azazel_nexus.incident_explain import RECENT_BYTES
    rows = _fit_rows(20, RECENT_BYTES)             # fits with written_at 0 (checkpoint, restore)
    seed = _window(tmp_path, rows)
    e = make(tmp_path, clock=lambda: 1061.0)       # "written_at": 1061.0 is 5 bytes longer: bound + 5
    e.monotonic = lambda: 100
    e.status()                                      # no exception
    assert e.refused["status_write_failed"] == 1
    oldest = min(e.recent, key=_key)["incident_id"]
    assert [r for r in e.recent if r["incident_id"] == oldest][0]["explanation"]["slow_analysis"] == {
        "state": "degraded", "usage": "unknown"}
    assert len(_bound_ok(tmp_path)["incidents"]) == 20
    assert json.loads((tmp_path / "status.json").read_text())["refused"]["status_write_failed"] == 1
    monkeypatch.setattr(daemon, "POLL_SECONDS", 0.02)
    calls = []
    e2 = make(tmp_path, clock=lambda: 1061.0)
    assert e2.serve(stop=lambda: calls.append(1) or len(calls) > 3) == 0
    assert not e2.storage_failed


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores directory modes")
def test_window_stays_within_bound_s5_write_failure_counts_and_keeps_recent(tmp_path):
    from azazel_nexus.incident_explain import RECENT_BYTES
    pending = _pending_row(transition(incident_id=_Y))
    e = _window(tmp_path, _fit_rows(19, RECENT_BYTES + 1, [pending]))
    e.monotonic = lambda: 100
    e.recent_status()
    kept = (tmp_path / "recent.json").read_bytes()
    append(e, transition(incident_id=_Y))
    tmp_path.chmod(0o500)
    try:
        e.monotonic = lambda: 200
        e.poll()
    finally:
        tmp_path.chmod(0o700)
    assert e.refused["status_write_failed"] == 3     # reduction, recent.json, status.json
    assert (tmp_path / "recent.json").read_bytes() == kept
    assert not list(tmp_path.glob(".snapshot-*"))


def test_window_stays_within_bound_s5_handoff_shows_the_ledger_text_of_a_reduced_row(tmp_path):
    """The recent window reduces the oldest row; root's handoff still shows the ledger, the UI's shows the row."""
    from test_handoff import example

    from azazel_nexus import runtime_paths as paths
    from azazel_nexus.handoff import build_package
    from azazel_nexus.incident_explain import RECENT_BYTES
    root = tmp_path / "root"
    root.mkdir()
    example.build_fixture(root)                    # the real Explainer explains example.INCIDENT
    x_id = example.INCIDENT
    clock = lambda: example.OPENED + 130.0         # not stale for the fixture's own history

    def make_at():
        return daemon.Explainer(
            incidents=root / "var/lib/azazel/edge-incidents", state=root / "var/lib/azazel/incident-explain",
            status_path=paths.snapshot_path("incident_explain_status", root), clock=clock,
            monotonic=lambda: 100, mio=lambda _: handoff(), knowledge=lambda _: (),
            audit=lambda event: None, guidance=lambda frame: None,
            ui_recent_path=paths.ui_copy_path("incident_recent", root),
            ui_status_path=paths.ui_copy_path("incident_explain_status", root))
    ui_dir = paths.ui_copy_path("incident_recent", root).parent
    ui_dir.mkdir(parents=True, exist_ok=True)
    paths.ui_copy_path("incident_explain_status", root).parent.mkdir(parents=True, exist_ok=True)
    seed = make_at()
    seed.prepare()
    x = json.loads(json.dumps(seed.recent[0]))
    assert x["incident_id"] == x_id and x["explanation"]["state"] == "explained"
    y = transition(incident_id=_Y, first_seen=example.OPENED + 110, last_seen=example.OPENED + 110)
    pending = _pending_row(y)
    over = len(json.dumps(clock())) - 1             # written_at prints longer than the checkpoint's 0
    rows = _fit_rows(18, RECENT_BYTES + 1 - over, [x, pending])
    shift = 0
    for i, r in enumerate(rows):                    # newer than x, so x is the oldest row
        before = len(json.dumps(r))
        r["last_seen"] = example.OPENED + 200 + i
        shift += len(json.dumps(r)) - before
    rows = _fit_rows(18, RECENT_BYTES + 1 - over - shift, [x, pending])
    for i, r in enumerate(rows):
        r["last_seen"] = example.OPENED + 200 + i
    seed.recent = [x] + rows
    seed.checkpoint()
    e = make_at()
    e.prepare()
    append(e, y, day="2026-10-29")
    e.poll()
    assert e.refused == {"status_write_failed": 1} and not e.storage_failed
    row = [r for r in e.recent if r["incident_id"] == x_id][0]
    assert row["explanation"] == GONE and any(r["incident_id"] == _Y for r in e.recent)
    root_pkg = build_package(x_id, now=example.GENERATED, principal="root", root=root)
    ai = root_pkg["ai_assessment"]
    assert ai["source"] == "explanation_ledger" and ai["explanations"][0]["text"]
    assert "status_write_failed" not in ai["explanations"][0]["failure_codes"]
    ledger = [rec for rec in records(e) if rec["incident_id"] == x_id]    # the ledger kept the record
    assert ledger and ai["explanations"][0]["text"] == ledger[0]["mio"]["text"]
    ui_pkg = build_package(x_id, now=example.GENERATED, principal="ui", root=root)
    ui_ai = ui_pkg["ai_assessment"]
    assert ui_ai["source"] == "recent_snapshot"
    assert ui_ai["explanations"][0]["failure_codes"] == ["status_write_failed"]
    assert ui_ai["explanations"][0]["text"] is None


def test_window_stays_within_bound_s5_no_new_codes(tmp_path):
    (tmp_path / "a").mkdir()
    e, _ = _insert(tmp_path / "a", 1, settle=True)
    _no_new_codes(e)


def test_codes_are_unchanged():
    from azazel_nexus.incident_explain import CODES
    assert CODES == frozenset({
        "transition_refused", "chain_broken", "queue_full", "mio_unavailable", "mio_reply_refused",
        "knowledge_unavailable", "knowledge_reply_refused", "storage_failed", "status_write_failed",
        "explanation_segment_full", "cursor_refused", "read_failed", "cursor_overtaken",
        "stale_skipped", "incident_segment_full", "ledger_tail_incomplete", "mio_gated",
        "mio_handoff", "mio_local_non_advisory", "mio_fast_unavailable", "segment_from_future"})


def test_window_stays_within_bound_and_ordinary_windows_are_untouched(tmp_path):
    settled = _settled_row()
    rows = []
    for n in range(20):
        copy_ = json.loads(json.dumps(settled))
        copy_["incident_id"] = f"inc-{0xb00 + n:016x}"
        copy_["last_seen"] = copy_["first_seen"] = n + 1
        copy_["explanation"]["guidance"]["handoff"]["incident_id"] = copy_["incident_id"]
        rows.append(copy_)
    assert 2 * 1024 < len(json.dumps(rows[0])) < 8 * 1024        # ordinary rows, 20 of them
    e = _window(tmp_path, rows)
    before = json.loads(json.dumps(e.recent))
    e._keep_window(before[0]["incident_id"])
    assert e.recent == before and not e.refused
    (tmp_path / "big").mkdir()
    big = _window(tmp_path / "big", _fit_rows(20, 200000))        # 20 rows of about 10 KB
    kept = json.loads(json.dumps(big.recent))
    big._keep_window(kept[0]["incident_id"])
    assert big.recent == kept and not big.refused
    append(e)
    e.poll()
    assert not e.refused and not e.storage_failed
    assert _bound_ok(tmp_path)["incidents"] == json.loads(json.dumps(e.recent))


OLD_SRC = os.environ.get("NEXUS_ROLLBACK_TARGET_SRC")


@pytest.mark.skipif(not OLD_SRC, reason="NEXUS_ROLLBACK_TARGET_SRC (a 74a6189 checkout) not set")
def test_window_stays_within_bound_and_74a6189_reads_the_shrunk_checkpoint(tmp_path):
    import subprocess
    import sys
    from azazel_nexus.incident_explain import RECENT_BYTES
    settled = _settled_row()
    e = _window(tmp_path, _fit_rows(19, RECENT_BYTES + 1, [settled]))
    append(e)
    e.poll()
    e.monotonic = lambda: 61
    e.poll()
    assert e.refused["status_write_failed"] == 1
    assert daemon.checkpoint_for_release_before_full_node_trace(tmp_path / "state" / "cursor.json") >= 0
    script = (
        f"import sys; sys.path[:0] = ['{OLD_SRC}/src', '{OLD_SRC}/runtime/src']\n"
        "import pathlib\n"
        "from azazel_nexus_runtime import incident_explaind as d\n"
        "from azazel_nexus.incident_explain import read_recent_incidents\n"
        "base = pathlib.Path(sys.argv[1])\n"
        "print('FILE', d.__file__)\n"
        "v = d.decode_checkpoint((base / 'state' / 'cursor.json').read_bytes())\n"
        "print('DECODED', read_recent_incidents(d.canonical(v['recent'])) is not None)\n"
        "x = d.Explainer(incidents=base / 'incidents', state=base / 'state', status_path=base / 'status2.json',\n"
        "                clock=lambda: 0, monotonic=lambda: 0, mio=lambda _: None, knowledge=lambda _: ())\n"
        "x.prepare(); print('PREPARED')\n")
    out = subprocess.run([sys.executable, "-I", "-c", script, str(tmp_path)],
                         capture_output=True, text=True)
    assert OLD_SRC in out.stdout and "DECODED True" in out.stdout and "PREPARED" in out.stdout, out
