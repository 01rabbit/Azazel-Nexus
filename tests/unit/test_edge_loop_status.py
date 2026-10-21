"""I3 operator boundary, independent degradation and optional Fabric wiring."""
import builtins
import io
import json
from types import SimpleNamespace

import pytest

from azazel_nexus.capability import CapabilityState, CORE_CAPABILITIES
from azazel_nexus.edge_intake import STATUS_SCHEMA
from azazel_nexus.edge_loop_status import render_edge_loop, render_fabric_status
from azazel_nexus.incident_explain import (
    build_recent_incident, build_recent_incidents, read_recent_incidents, read_explainer_status,
)
from azazel_nexus_runtime import runtime_paths
from test_incident_explain import transition
from test_incident_explaind import make
from test_wizard_and_cli import _status


def fixtures(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    intake = {"schema": STATUS_SCHEMA, "written_at": 0, "last_accepted_at": 0,
              "accepted": 12, "processed": 12, "last_processed_at": 0,
              "refused": {"queue_full": 2}, "open_incidents": 1,
              "queue_drops": 2, "storage_failed": False}
    explain = make(tmp_path).snapshot()
    recent = build_recent_incidents([build_recent_incident(transition(edge_would="isolate"))], 0)
    recent["incidents"][0]["explanation"] = {
        "state": "explained", "route": "local", "outcome": "answered", "summary": "Inspect the incident", "failure_codes": [],
        "knowledge_refs": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter", "claim_id": "T1059"}]}
    for path, value in ((runtime_paths.edge_intake_status_path(), intake),
                        (runtime_paths.incident_explain_status_path(), explain),
                        (runtime_paths.incident_recent_path(), recent)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
    return intake, explain, recent


def render(now=0):
    out = io.StringIO()
    render_edge_loop(out, now=now)
    return out.getvalue()


def test_present_and_production_status(tmp_path, monkeypatch):
    fixtures(tmp_path, monkeypatch)
    text = render()
    assert "intake: running" in text and "explainer: running" in text
    assert "accepted: 12" in text and "queue_full=2" in text
    assert "Edge would isolate (observe-only, not executed)" in text
    assert "T1059 Command and Scripting Interpreter [claim T1059]" in text
    text = _status(tmp_path)
    assert text.index("edge loop:") > text.index("integration:")
    assert "fabric status view:" in text and "continuing regardless:" in text


def test_stale_and_chain_broken_are_independent(tmp_path, monkeypatch):
    _, explain, _ = fixtures(tmp_path, monkeypatch)
    explain.update(written_at=40, chain_broken=True,
                   recovery_hint="inspect_incident_chain_then_remove_cursor_and_restart")
    runtime_paths.incident_explain_status_path().write_text(json.dumps(explain))
    text = render(now=40)
    assert "intake: stale (snapshot expired)" in text
    assert "explainer: running" in text and "chain_broken: True" in text
    assert "inspect_incident_chain_then_remove_cursor_and_restart" in text
    assert "Edge would isolate" in text


@pytest.mark.parametrize("raw", [None, b"{}", b"[", b"x" * (256 * 1024 + 1)])
def test_recent_unavailable_does_not_hide_components(tmp_path, monkeypatch, raw):
    fixtures(tmp_path, monkeypatch)
    path = runtime_paths.incident_recent_path()
    path.unlink() if raw is None else path.write_bytes(raw)
    text = render()
    assert "recent incidents: unavailable" in text
    assert "intake: running" in text and "explainer: running" in text


@pytest.mark.parametrize("address", ["192.0.2.1", "::1", "2001:db8::1", "１９２．０．２．１"])
def test_summary_address_is_refused_wholesale(tmp_path, monkeypatch, address):
    _, _, recent = fixtures(tmp_path, monkeypatch)
    recent["incidents"][0]["explanation"]["summary"] = "inspect " + address
    raw = json.dumps(recent).encode()
    assert read_recent_incidents(raw) is None
    runtime_paths.incident_recent_path().write_bytes(raw)
    text = render()
    assert address not in text and "recent incidents: unavailable" in text


def test_components_absent_and_nonregular(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    text = _status(tmp_path)
    assert text.count("unavailable (snapshot absent or refused)") == 3
    assert "continuing regardless:" in text and "next:" in text
    path = runtime_paths.edge_intake_status_path()
    path.mkdir(parents=True)
    assert "intake: unavailable" in render()


def test_status_reader_rejects_unknown_codes_and_wrong_hint(tmp_path):
    value = make(tmp_path).snapshot()
    for mutation in ({"refused": {"192.0.2.1": 1}}, {"recovery_hint": "secret"},
                     {"mio_available": "yes"}, {"audit_forward_dropped": True},
                     {"audit_forward_refused": -1}):
        assert read_explainer_status(json.dumps({**value, **mutation}).encode()) is None
    del value["audit_forward_refused"]
    assert read_explainer_status(json.dumps(value).encode()) is None


def report():
    return SimpleNamespace(capabilities=SimpleNamespace(state=CapabilityState.CORE, available=CORE_CAPABILITIES))


def test_fabric_absent_is_safe(monkeypatch):
    real = builtins.__import__
    def unavailable(name, *args, **kw):
        if name == "azazel_fabric" or name.startswith("azazel_fabric."):
            raise ImportError("SECRET 192.0.2.1")
        return real(name, *args, **kw)
    monkeypatch.setattr(builtins, "__import__", unavailable)
    out = io.StringIO()
    render_fabric_status(report(), out)
    assert out.getvalue() == "fabric status view: not available (extra not installed)\n"


def test_fabric_present_production_projection(monkeypatch):
    pytest.importorskip("azazel_fabric")
    from azazel_nexus import fabric_boundary
    real = fabric_boundary.project_capability
    seen = []
    def project(state, available):
        seen.append((state, available))
        result = real(state, available)
        assert result.available
        assert result.view.product_view["capability_state"] == "CORE"
        return result
    monkeypatch.setattr(fabric_boundary, "project_capability", project)
    out = io.StringIO()
    render_fabric_status(report(), out)
    assert seen == [(CapabilityState.CORE, CORE_CAPABILITIES)]
    assert "projected (v" in out.getvalue()


def test_fabric_refusal_never_exposes_exception(monkeypatch):
    from azazel_nexus import fabric_boundary
    def fail(*args):
        raise ValueError("SECRET 192.0.2.1")
    monkeypatch.setattr(fabric_boundary, "project_capability", fail)
    out = io.StringIO()
    render_fabric_status(report(), out)
    assert out.getvalue() == "fabric status view: refused (projection_refused)\n"


def test_shared_runtime_snapshot_paths_respect_root(tmp_path, monkeypatch):
    from azazel_nexus import runtime_paths as shared
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    for name in ("edge_intake_status_path", "incident_explain_status_path", "incident_recent_path"):
        assert getattr(shared, name)() == getattr(runtime_paths, name)()
        assert getattr(shared, name)(tmp_path) == getattr(runtime_paths, name)()


def test_only_five_recent_rows_are_rendered(tmp_path, monkeypatch):
    fixtures(tmp_path, monkeypatch)
    value = build_recent_incidents([build_recent_incident(transition(incident_id=f"inc-{i:016x}", last_seen=i))
                                    for i in range(20)], 20)
    runtime_paths.incident_recent_path().write_text(json.dumps(value))
    text = render(now=20)
    assert text.count("Edge would") == 5
    assert "inc-0000000000000013" in text and "inc-0000000000000000" not in text


def test_internal_failure_prints_fixed_lines_and_status_continues(tmp_path, monkeypatch):
    from azazel_nexus import edge_loop_status
    fixtures(tmp_path, monkeypatch)
    def fail(*_):
        raise RuntimeError("SECRET 192.0.2.1")
    monkeypatch.setattr(edge_loop_status, "read_recent_incidents", fail)
    monkeypatch.setattr(edge_loop_status, "_render_fabric_status", fail)
    assert render() == "edge loop: unavailable (internal)\n"
    text = _status(tmp_path)
    assert "edge loop: unavailable (internal)" in text
    assert "fabric status view: unavailable (internal)" in text
    assert "SECRET" not in text and "intake:" not in text
    assert "continuing regardless:" in text and "next:" in text


def test_unparsed_time_is_an_internal_failure(tmp_path, monkeypatch):
    fixtures(tmp_path, monkeypatch)
    assert render(now=None) == "edge loop: unavailable (internal)\n"


def test_bare_number_citation_names_are_dropped(tmp_path, monkeypatch):
    _, _, recent = fixtures(tmp_path, monkeypatch)
    for name in ("Port 4444", "Interpreter ４４４４", "x_8080"):
        recent["incidents"][0]["explanation"]["knowledge_refs"][0]["name"] = name
        assert read_recent_incidents(json.dumps(recent).encode()) is None
    recent["incidents"][0]["explanation"]["knowledge_refs"][0]["name"] = "Rundll32"
    assert read_recent_incidents(json.dumps(recent).encode()) is not None


def test_pending_row_has_fixed_text_and_labels_severity_apart_from_action(tmp_path, monkeypatch):
    fixtures(tmp_path, monkeypatch)
    value = build_recent_incidents([build_recent_incident(transition(2, edge_would="throttle"))], 0)
    runtime_paths.incident_recent_path().write_text(json.dumps(value))
    text = render()
    assert "pending: awaiting explanation" in text
    assert "most severe 2 count=1; latest: Edge would throttle (observe-only, not executed)" in text
    assert "severity=" not in text


def test_intake_line_shows_processed_and_never_hides_full_evidence(tmp_path, monkeypatch):
    intake, _, _ = fixtures(tmp_path, monkeypatch)
    intake.update(last_accepted_at=0, last_processed_at=95, processed=40,
                  refused={"queue_full": 9, "read_deadline": 8, "overloaded": 7,
                           "EDGE_SHAPE": 6, "evidence_segment_full": 1,
                           "segment_from_future": 1})
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    text = render(now=100)
    assert "last processed age: 5s; processed: 40; accepted: 12;" in text
    assert "EDGE_SHAPE=6, evidence_segment_full=1, segment_from_future=1" in text
    assert text.count("evidence_segment_full") == 1


def test_intake_ledger_recovery_is_shown_only_when_it_happened(tmp_path, monkeypatch):
    intake, _, _ = fixtures(tmp_path, monkeypatch)
    # A snapshot from an intake without the field still reads, as none.
    assert "ledger_recovered" not in render()
    assert "intake: running" in render()
    intake["ledger_recovered"] = 0
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert "ledger_recovered" not in render()
    intake["ledger_recovered"] = 2
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert "        ledger_recovered: 2 (torn incident tail quarantined;" in render()
    for bad in (-1, True, "2"):
        intake["ledger_recovered"] = bad
        runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
        assert "intake: unavailable (snapshot absent or refused)" in render()


def test_row_with_unstored_evidence_is_marked(tmp_path, monkeypatch):
    fixtures(tmp_path, monkeypatch)
    value = build_recent_incidents([build_recent_incident(transition(1, evidence_stored=False))], 0)
    runtime_paths.incident_recent_path().write_text(json.dumps(value))
    assert "count=1 (evidence not stored); latest: Edge would" in render()
    value = build_recent_incidents([build_recent_incident(transition(1))], 0)
    runtime_paths.incident_recent_path().write_text(json.dumps(value))
    assert "evidence not stored" not in render()


def test_edge_forward_counts_are_shown_as_edge_reported(tmp_path, monkeypatch):
    intake, _, _ = fixtures(tmp_path, monkeypatch)
    # An intake (or Edge) without the counts: said so, nothing else hidden.
    text = render()
    assert "        Edge forward: not reported since the intake started" in text
    assert "intake: running" in text and "Edge would isolate" in text
    intake["edge_forward"] = {"dropped": 460, "failed": 7, "sent": 1200, "since": 1_790_000_000,
                              "reported_at": 90.0, "restarts": 0}
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    text = render(now=100)
    assert ("        Edge forward: dropped 460, failed 7 (as reported by Edge); sent 1200 since "
            "Edge start 2026-09-21T") in text
    assert "last report 10s ago" in text and "stale" not in text.split("Edge forward")[1].split("\n")[0]
    assert "restarted" not in text
    # Old report: kept, but marked as no longer current.
    text = render(now=90 + 901)
    assert "last report 901s ago; stale (no report for over 900s)" in text
    intake["edge_forward"]["restarts"] = 2
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert "            Edge restarted 2 time(s) since the intake started;" in render(now=100)
    # The largest start the reader admits still renders.
    intake["edge_forward"]["since"] = 2**37
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert "Edge forward: dropped 460" in render(now=100)
    intake["edge_forward"]["since"] = 2**37 + 1
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert "intake: unavailable (snapshot absent or refused)" in render(now=100)


DECOY_LABEL = ("        decoy (Deception Lite; Nexus's own observation, not Edge's; "
               "not hardware evidence): ")


def test_decoy_interactions_are_shown_as_nexus_own_not_edge(tmp_path, monkeypatch):
    intake, _, _ = fixtures(tmp_path, monkeypatch)
    intake["decoy"] = {"accepted": 3, "last_accepted_at": 88.0}
    intake["refused"] = {"queue_full": 2, "DECOY_SHAPE": 4, "decoy_rate_limited": 1,
                         "DECOY_ADDRESS": 0}
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    text = render(now=100)
    assert (DECOY_LABEL + "accepted 3; last accepted 12s ago; "
            "refused 5 (DECOY_SHAPE=4, decoy_rate_limited=1)\n") in text
    # The decoy's refusals are not Edge's: Edge's line keeps only its own.
    assert "        refusals: queue_full=2\n" in text
    assert text.count("DECOY_SHAPE") == 1 and "DECOY_ADDRESS" not in text
    # Edge's counts are untouched by the decoy's.
    assert "processed: 12; accepted: 12;" in text
    # The decoy line closes the intake's section, before the explainer.
    assert text.index("Edge forward:") < text.index("decoy (") < text.index("explainer:")
    intake["decoy"] = {"accepted": 0, "last_accepted_at": None}
    intake["refused"] = {}
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert DECOY_LABEL + "accepted 0; last accepted never; refused 0\n" in render(now=100)


def test_decoy_not_listening_is_a_fixed_line(tmp_path, monkeypatch):
    intake, _, _ = fixtures(tmp_path, monkeypatch)
    text = render()
    assert ("        decoy (Deception Lite): not listening (decoy socket not open); "
            "refused 0\n") in text
    # Why it is not listening stays visible, and only as the decoy's.
    intake["refused"] = {"decoy_listener_unavailable": 1}
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    text = render()
    assert ("not listening (decoy socket not open); "
            "refused 1 (decoy_listener_unavailable=1)\n") in text
    assert "        refusals: none\n" in text


def test_decoy_line_never_carries_an_address_or_payload(tmp_path, monkeypatch):
    intake, _, _ = fixtures(tmp_path, monkeypatch)
    # A snapshot with anything but the two fields is refused as a whole, so
    # nothing a sender chose can reach the line.
    for decoy in ({"accepted": 1, "last_accepted_at": 1.0, "peer": "192.0.2.1"},
                  {"accepted": 1, "last_accepted_at": 1.0, "payload": "SSH-2.0-x"},
                  {"accepted": "192.0.2.1", "last_accepted_at": 1.0},
                  {"accepted": 1, "last_accepted_at": "192.0.2.1"},
                  {"accepted": 1}, ["192.0.2.1"]):
        intake["decoy"] = decoy
        runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
        text = render(now=100)
        assert "intake: unavailable (snapshot absent or refused)" in text
        assert "192.0.2.1" not in text and "SSH-2.0" not in text and "decoy (" not in text
    intake["decoy"] = {"accepted": 1, "last_accepted_at": 1.0}
    intake["refused"] = {"192.0.2.1": 1}
    runtime_paths.edge_intake_status_path().write_text(json.dumps(intake))
    assert "192.0.2.1" not in render(now=100)


def test_every_reader_in_the_package_accepts_the_decoy_key(tmp_path, monkeypatch):
    """#196 P2 §11: a reader with the old closed key list took it as None.

    The writer here is the intake itself; every reader shipped with it (the
    snapshot reader, the edge loop section and the status command) reads its
    snapshot with and without `decoy`, with every decoy refusal code counted.
    """
    from azazel_nexus.edge_intake import DECOY_REFUSAL_CODES, REFUSAL_CODES, read_intake_status
    from azazel_nexus_runtime import edge_intaked as daemon
    fixtures(tmp_path, monkeypatch)
    assert DECOY_REFUSAL_CODES < REFUSAL_CODES
    assert {"DECOY_SHAPE", "decoy_peer_refused", "decoy_listener_unavailable"} <= DECOY_REFUSAL_CODES
    assert not any(c.lower().startswith("decoy") for c in REFUSAL_CODES - DECOY_REFUSAL_CODES)
    state = tmp_path / "intake-state"
    state.mkdir()
    server = daemon.IntakeServer(path=state / "unused.sock", state=state,
                                 status_path=state / "status.json", edge_uid=123)
    for listening in (False, True):
        server.decoy_listening = listening
        server.decoy_accepted = 2 if listening else 0
        server.decoy_last_accepted_at = server.clock() if listening else None
        for code in sorted(DECOY_REFUSAL_CODES):
            server.refuse(code)
        raw = daemon.canonical(server.snapshot())
        value = read_intake_status(raw)
        assert value is not None and ("decoy" in value) is listening
        assert DECOY_REFUSAL_CODES <= set(value["refused"])
        runtime_paths.edge_intake_status_path().write_bytes(raw)
        text = render(now=value["written_at"])
        assert "intake: running" in text and "explainer:" in text
        assert "        refusals: none\n" in text.split("explainer:")[0]
        if listening:
            assert DECOY_LABEL + "accepted 2; last accepted 0s ago; refused " in text
        else:
            assert "decoy (Deception Lite): not listening (decoy socket not open); refused " in text
    assert "decoy (Deception Lite; Nexus's own observation" in _status(tmp_path)
