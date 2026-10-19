"""Durable bounded consumer; optional explanations never affect intake."""
import ast
import json
import os
import tempfile
import threading
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
    e = daemon.Explainer(incidents=incidents, state=tmp_path / "state",
                            status_path=tmp_path / "status.json", clock=lambda: 0,
                            monotonic=lambda: 0, mio=lambda _: handoff(),
                            knowledge=lambda _: (), **kwargs)
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
    assert len(records(e)) == 1
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
    restarted.monotonic = lambda: 66
    restarted.poll()
    status = json.loads(restarted.status_path.read_text())
    assert status["explained"] == 2
    assert status["last_explained_at"] == 0
    assert status["mio_available"] is True
    assert status["knowledge_available"] is True
    assert not status["chain_broken"] and not status["storage_failed"]
    assert status["cursor_lag"] >= 0


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
    assert set(profile.supplementary_groups) == {"azincident-read", "azknowledge-read", "azazel-operator"}
    assert "azexplain" in DAEMON_ACCOUNTS and "azexplain" in SYSTEM_ACCOUNTS
    p = PrincipalPolicy(123, frozenset({42}), frozenset({42})).classify(42, 7, 1, (123,))
    assert p.classes == frozenset({PrincipalClass.SERVICE})
    assert render_unit(profile) == Path("packaging/systemd/" + profile.unit).read_text()
    text = Path(daemon.__file__).read_text()
    tree = ast.parse(text)
    exchanges = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_exchange"]
    assert {n.args[0].value for n in exchanges} == {"mio-entry", "audit"}
    assert len(exchanges) == 2
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
        for leaf, result in (("mio-entry", handoff()), ("knowledge-read", {"refs": [], "reason_code": "no_context"})):
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
                       "static", "knowledge_lite", 1, "verified")
    e.knowledge = lambda _: (ref,)
    append(e)
    e.poll()
    assert records(e)[0]["knowledge_state"] == "available"
    ref = KnowledgeRef("T1110", "Force", "", "T1110", "sha256:" + "a" * 64,
                       "static", "knowledge_lite", 1, "verified")
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


@pytest.mark.parametrize("missing_day", [0, 1])
def test_missing_linked_segment_without_boundary_is_refused(tmp_path, missing_day):
    from azazel_nexus_runtime.edge_intaked import IncidentLedger
    e = make(tmp_path)
    ledger = IncidentLedger(tmp_path, 0)
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
    assert set(pending) == PENDING_FIELDS
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
    assert calls == [(("audit", "azaudit", "audit.append", {"event_type": "edge.incident.opened"}),
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
                                     "undeclared_argument", "missing_argument", "unknown_verb"])
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
                                           ({"ok": False, "refusal": "SECRET 192.0.2.1"}, False),
                                           ({"ok": False, "refusal": "principal_denied", "x": 1}, False)])
def test_audit_client_carries_only_declared_refusal_reasons(tmp_path, monkeypatch, reply, refused):
    with tempfile.TemporaryDirectory(prefix="i3-", dir="/tmp") as directory:
        monkeypatch.setattr(runtime_paths, "ROOT", Path(directory))
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
        monkeypatch.setattr(client, "peer_credentials", lambda _: (1, os.getuid(), os.getgid()))
        path = runtime_paths.socket_path("audit")
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
            assert exc.value.refusal == "principal_denied"


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
