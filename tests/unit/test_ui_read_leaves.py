"""The read-only UI's read path (ADR-0007; Codex survey S-03, S-04).

* Each snapshot writer puts a byte-identical copy of its snapshot into its own
  `run/ui-read/<leaf>`, `2750 <writer>:azui`, and nothing else changes for
  the account `azui` (no group, no socket, no write).
* `status --snapshot-reader ui` reads those copies and only those.
* The copies carry none of the terminal-only items (M22).
* The UI's four answers (`ui_model.summarize`) keep observed facts, AI
  inference, Edge's decision and the execution result apart, and never call
  an unknown, stale, absent, not-enabled or unreadable source healthy.
* The operator view's read adapter writes nothing and says *not read* for a
  store it cannot open.
"""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from azazel_nexus import runtime_paths, ui_model  # noqa: E402
from azazel_nexus.cli import main  # noqa: E402
from azazel_nexus.layout import LAYOUT  # noqa: E402
from test_noc_observe import host  # noqa: E402,F401 - the passive observation fixture

REPO = Path(__file__).resolve().parents[2]

#: Snapshot -> (writer unit, writer account), as the installer declares them.
WRITERS = {
    "audit_status": ("azazel-auditd.service", "azaudit"),
    "edge_intake_status": ("azazel-edge-intaked.service", "azintake"),
    "incident_explain_status": ("azazel-incident-explaind.service", "azexplain"),
    "incident_recent": ("azazel-incident-explaind.service", "azexplain"),
    "knowledge_status": ("azazel-knowledge-lited.service", "azknowledge"),
    "mio_status": ("azazel-mio-entryd.service", "azmioentry"),
    "units_status": ("azazel-units-observe.service", "azprobe"),
    "noc_status": ("azazel-noc-observe.service", "aznoc"),
}

#: Items only the operator's terminal shows (M22, inventory-confidentiality).
TERMINAL_ONLY_KEYS = {"bus_path", "physical_label", "interface_name", "ifname", "name_on_host",
                      "mac", "address", "addresses_list", "gateway", "nameserver",
                      "search_domain", "root", "package_root", "issuer", "revocation_sequence",
                      "floor_version", "ledger", "path", "reason_text", "health_reason",
                      "running_reason", "package_digest", "boot_id"}


# -- the layout -----------------------------------------------------------------


def test_every_ui_copy_has_its_writers_own_azui_leaf_and_nothing_else_does():
    from azazel_nexus_runtime.hardening import ALL_PROFILES

    specs = {spec.path: spec for spec in LAYOUT}
    parent = specs["/var/lib/azazel/run/ui-read"]
    assert (parent.mode, parent.owner, parent.group) == (0o711, "root", "root")
    for name, (unit, account) in WRITERS.items():
        path = runtime_paths.ui_copy_path(name, root="/")
        leaf = specs[str(path.parent)]
        assert (leaf.mode, leaf.owner, leaf.group) == (0o2750, account, "azui"), name
        # Only its writer may write there, and only as an optional path.
        holders = [p.unit for p in ALL_PROFILES
                   if str(path.parent) in p.read_write_paths + p.optional_read_write_paths]
        # The audit ledger daemon writes in either of its two lifetimes, the
        # bootstrap helper and the loop's writer, never both (ADR-0008).
        expected = ([unit, "azazel-auditd-loop.service"] if unit == "azazel-auditd.service"
                    else [unit])
        assert sorted(holders) == sorted(expected), name
        assert str(path.parent) in next(p for p in ALL_PROFILES
                                        if p.unit == unit).optional_read_write_paths
    # The UI's own unit writes none of them and joins no group.
    ui = next(p for p in ALL_PROFILES if p.unit == "azazel-ui.service")
    assert ui.supplementary_groups == ()
    assert not any(path.startswith("/var/lib/azazel/run/ui-read")
                   for path in ui.read_write_paths + ui.optional_read_write_paths)
    # azui is the group of the UI leaves and of nothing else; it owns one leaf.
    assert {spec.path for spec in LAYOUT if spec.group == "azui"} == {
        str(runtime_paths.ui_copy_path(name, root="/").parent) for name in WRITERS}
    assert [spec.path for spec in LAYOUT if spec.owner == "azui"] == ["/var/lib/azazel/run/ui-login"]


def test_the_ui_reader_and_the_operator_reader_name_different_leaves():
    for name in runtime_paths.UI_COPIES:
        operator = runtime_paths.snapshot_path(name, "/")
        ui = runtime_paths.snapshot_path(name, "/", reader="ui")
        assert operator.name == ui.name
        assert str(operator).startswith("/var/lib/azazel/run/") and "ui-read" not in str(operator)
        assert str(ui).startswith("/var/lib/azazel/run/ui-read/")
    with pytest.raises(ValueError):
        runtime_paths.snapshot_path("noc_status", "/", reader="root")


# -- the writers ------------------------------------------------------------------


def _leaves(tmp_path):
    operator, ui = tmp_path / "op" / "status.json", tmp_path / "ui" / "status.json"
    operator.parent.mkdir()
    ui.parent.mkdir()
    return operator, ui


def test_the_snapshot_writer_copies_the_same_bytes_at_0640(tmp_path):
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    operator, ui = _leaves(tmp_path)
    writer = SnapshotWriter(operator, lambda: {"schema": "x", "written_at": 1.0}, limit=1024,
                            interval_s=0, name="t", ui_path=ui)
    assert writer.write() is True
    assert ui.read_bytes() == operator.read_bytes()
    assert stat.S_IMODE(ui.stat().st_mode) == 0o640


def test_a_ui_copy_that_cannot_be_written_never_fails_the_daemon_or_its_snapshot(tmp_path):
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    operator, _ = _leaves(tmp_path)
    warned = []
    writer = SnapshotWriter(operator, lambda: {"schema": "x"}, limit=1024, interval_s=0,
                            name="t", warn=warned.append, ui_path=tmp_path / "missing" / "s.json")
    assert writer.write() is True and writer.write() is True
    assert operator.exists()
    assert len(warned) == 1 and "UI shows this snapshot as absent" in warned[0]


def test_a_snapshot_the_operator_leaf_refused_is_never_copied(tmp_path):
    """The UI's copy is never newer than, or different from, the operator's."""
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    operator, ui = _leaves(tmp_path)
    SnapshotWriter(operator, lambda: {"v": 1}, limit=1024, interval_s=0, name="t",
                   ui_path=ui).write()
    big = SnapshotWriter(operator, lambda: {"v": "x" * 4096}, limit=1024, interval_s=0,
                         name="t", warn=lambda _: None, ui_path=ui)
    assert big.write() is False
    assert json.loads(ui.read_bytes()) == {"v": 1} == json.loads(operator.read_bytes())


def test_the_explainer_copies_its_status_and_recent_list_byte_for_byte(tmp_path):
    from test_incident_explaind import make

    ui = tmp_path / "ui-copy"
    ui.mkdir()
    e = make(tmp_path, ui_status_path=ui / "status.json", ui_recent_path=ui / "recent.json")
    e.poll()
    for name in ("status.json", "recent.json"):
        assert (ui / name).read_bytes() == (tmp_path / name).read_bytes(), name
        assert stat.S_IMODE((ui / name).stat().st_mode) == 0o640


def test_auditd_and_intake_copy_what_they_wrote(tmp_path):
    from azazel_nexus_runtime.auditd import AuditService
    from azazel_nexus_runtime.edge_intaked import IntakeServer
    from azazel_nexus_runtime.status_snapshot import UiCopy

    for name in ("audit", "intake"):
        operator, ui = tmp_path / name / "op" / "status.json", tmp_path / name / "ui" / "status.json"
        operator.parent.mkdir(parents=True)
        ui.parent.mkdir(parents=True)
        if name == "audit":
            service = AuditService.__new__(AuditService)
            service.status_path, service.ui_status = operator, UiCopy(ui, name="t")
            service._status_failing, service._status_swept = False, True
            service.monotonic = lambda: 0.0
            service.status_snapshot = lambda: {"schema": "a", "written_at": 1.0}
            service.write_status()
        else:
            server = IntakeServer.__new__(IntakeServer)
            server.status_path, server.ui_status = operator, UiCopy(ui, name="t")
            server.snapshot = lambda: {"schema": "i", "written_at": 2.0}
            server._status()
        assert ui.read_bytes() == operator.read_bytes(), name
        assert stat.S_IMODE(ui.stat().st_mode) == 0o640, name


def test_each_writer_is_given_its_ui_copy_path():
    """The production composition passes each writer its own copy's path."""
    runtime = REPO / "runtime" / "src" / "azazel_nexus_runtime"
    expected = {
        "auditd.py": ['ui_copy_path("audit_status")'],
        "edge_intaked.py": ['ui_copy_path("edge_intake_status")'],
        "incident_explaind.py": ['ui_copy_path("incident_explain_status")',
                                 'ui_copy_path("incident_recent")'],
        "knowledge_lited.py": ['ui_copy_path("knowledge_status")'],
        "mio_entryd.py": ['ui_copy_path("mio_status")'],
        "units_observe.py": ['ui_copy_path("units_status")'],
        "noc_snapshot.py": ['ui_copy_path("noc_status")'],
    }
    for module, calls in expected.items():
        text = (runtime / module).read_text(encoding="utf-8")
        for call in calls:
            assert text.count(call) == 1, (module, call)


# -- M22: the copies carry no terminal-only item ---------------------------------------------


def _keys(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            _keys(item, found)
    elif isinstance(value, list):
        for item in value:
            _keys(item, found)
    return found


def test_no_copied_snapshot_shape_holds_a_terminal_only_item(tmp_path, host):  # noqa: F811
    import test_noc_status as tns
    import test_operator_snapshots as tos
    from test_status_view import NOW, _audit, _explainer, _intake, _recent

    examples = {
        "audit_status": _audit(NOW),
        "edge_intake_status": _intake(NOW, edge_forward={
            "dropped": 0, "failed": 0, "sent": 3, "since": NOW - 60, "reported_at": NOW,
            "restarts": 0}, decoy={"accepted": 1, "last_accepted_at": NOW}),
        "incident_explain_status": _explainer(tmp_path, NOW),
        "incident_recent": _recent(NOW),
        "knowledge_status": tos._knowledge(),
        "mio_status": tos._mio(),
        "units_status": tos._units(),
        "noc_status": tns._observed(host),
    }
    assert set(examples) == set(runtime_paths.UI_COPIES)
    for name, value in examples.items():
        found = _keys(value, set())
        assert not found & TERMINAL_ONLY_KEYS, (name, sorted(found & TERMINAL_ONLY_KEYS))
        text = json.dumps(value)
        for secret in ("/var/lib", "/etc/", "/opt/", "enp", "aa:bb", "192.0.2."):
            assert secret not in text, (name, secret)


def test_the_edge_probe_result_gets_no_copy():
    """It carries the package digest and free-text reasons (M22): no UI copy."""
    assert "edge_probe" not in runtime_paths.UI_COPIES
    edge_probed = (REPO / "runtime/src/azazel_nexus_runtime/edge_probed.py").read_text("utf-8")
    assert "ui_copy_path" not in edge_probed and "UiCopy" not in edge_probed


# -- the reader ---------------------------------------------------------------------------


def _status_json(tmp_path, *extra):
    from test_status_view import _argv

    run = tmp_path / f"run-{len(list(tmp_path.glob('run-*')))}"
    run.mkdir()
    out = io.StringIO()
    assert main(_argv(run, *extra, json_flag=True), out=out, err=io.StringIO()) == 0
    return json.loads(out.getvalue())


def test_the_ui_reader_reads_the_copies_and_never_the_operator_leaves(tmp_path, monkeypatch):
    from test_status_view import NOW, _absent, _audit, _intake, _write

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    _absent(tmp_path, monkeypatch)
    # Different contents in the two leaves: each reader must see its own.
    _write(runtime_paths.edge_intake_status_path(), _intake(NOW - 1, accepted=1))
    _write(runtime_paths.edge_intake_status_path(reader="ui"), _intake(NOW - 1, accepted=2))
    _write(runtime_paths.audit_status_path(reader="ui"), _audit(NOW - 1))
    operator = _status_json(tmp_path)
    ui = _status_json(tmp_path, "--snapshot-reader", "ui")
    assert operator["snapshot_reader"] == "operator" and ui["snapshot_reader"] == "ui"
    intake = lambda view: view["sections"]["edge_loop"]["intake"]["snapshot"]["accepted"]  # noqa: E731
    assert (intake(operator), intake(ui)) == (1, 2)
    audit = lambda view: [h for h in view["sections"]["health"] if h["subject"] == "audit"][0]  # noqa: E731
    assert audit(operator)["source"]["freshness"] == "unavailable"
    assert audit(ui)["source"]["freshness"] == "fresh"
    for name in ("knowledge_status", "mio_status", "services", "noc"):
        assert ui["sections"][name]["source"]["leaf"] == "ui"
        assert operator["sections"][name]["source"]["leaf"] == "operator"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file; the uid-1001 run checks it")
def test_an_unreadable_operator_leaf_does_not_stop_the_ui_reader(tmp_path, monkeypatch):
    """As on a node: the operator leaf is closed to this account, the copy open."""
    from test_status_view import NOW, _absent, _intake, _write

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    _absent(tmp_path, monkeypatch)
    _write(runtime_paths.edge_intake_status_path(), _intake(NOW - 1))
    _write(runtime_paths.edge_intake_status_path(reader="ui"), _intake(NOW - 1))
    closed = runtime_paths.edge_intake_status_path().parent
    closed.chmod(0o000)
    try:
        ui = _status_json(tmp_path, "--snapshot-reader", "ui")
        operator = _status_json(tmp_path)
    finally:
        closed.chmod(0o755)
    assert ui["sections"]["edge_loop"]["intake"]["status"] == "running"
    assert operator["sections"]["edge_loop"]["intake"]["status"] == "unavailable"


# -- the four answers --------------------------------------------------------------------


def _model(sections=None, access=None, observers=None, setup=None, schema=True):
    view = {"schema": "azazel-nexus/status-view/1", "sections": sections or {},
            "as_of": "2026-09-21T04:01:00Z"} if schema else None
    return ui_model.project(view, origin={"kind": "live"}, served_at="t", access=access or {},
                            observers=observers or {}, setup=setup)


def _noc(families, *, freshness="fresh", snapshot=True):
    def family(state):
        if state is None:
            return {"state": "unknown", "reason": "x", "value": None, "age_s": 0}
        routes, down = {"usable": (1, False), "down": (1, True), "none": (0, False)}[state]
        return {"state": "observed", "reason": None, "age_s": 0, "value": {
            "table_main": {"default_routes": routes, "egress_ifindex": [2] if routes else [],
                           "via_gateway": bool(routes), "linkdown": down, "dead": False},
            "other_tables": {}, "policy_rules_evaluated": False}}
    snap = {"collection": "observed", "observed_at": 1.0, "uplink": {
        "ipv4": family(families[0]), "ipv6": family(families[1]),
        "reachability": {"state": "unknown", "reason": "active_check_not_performed"}}}
    return {"status": "observed", "reason_code": None, "freshness": freshness,
            "source": {"freshness": freshness, "reason_code": None if freshness == "fresh"
                       else "snapshot_expired"},
            "snapshot": snap if snapshot else None}


@pytest.mark.parametrize("families, word", [
    (("usable", "none"), "path_observed"),
    (("down", "none"), "path_down_observed"),
    (("none", "none"), "no_default_route_observed"),
    ((None, None), "unknown"),
])
def test_communication_says_what_the_passive_observation_saw_and_never_ok(families, word):
    answer = _model({"noc": _noc(families)})["summary"]["communication"]
    assert answer["status"] == word
    labels = json.loads((REPO / "runtime/src/azazel_nexus_runtime/ui_static/labels.json")
                        .read_text("utf-8"))
    assert labels["words"][word][1] != "ok"
    codes = [b["code"] for b in answer["basis"]]
    assert "reachability_not_measured" in codes
    assert all(b["kind"] == "observed" for b in answer["basis"])


@pytest.mark.parametrize("noc, access, observers, word, reason", [
    (None, {}, {}, "not_collected", "section_absent_from_read_model"),
    ({"status": "unavailable", "reason_code": "snapshot_absent_or_refused", "snapshot": None,
      "source": {}}, {"noc_status": "permission_denied"}, {"noc": "not_enabled"},
     "permission_denied", "access_permission_denied"),
    ({"status": "unavailable", "reason_code": "snapshot_absent_or_refused", "snapshot": None,
      "source": {}}, {"noc_status": "absent"}, {"noc": "not_enabled"},
     "observer_not_enabled", "observer_timer_not_enabled"),
    ({"status": "unavailable", "reason_code": "snapshot_absent_or_refused", "snapshot": None,
      "source": {}}, {"noc_status": "absent"}, {"noc": "enabled"},
     "unknown", "snapshot_absent_or_refused"),
    ("stale", {}, {}, "stale", "snapshot_expired"),
])
def test_an_unusable_noc_source_is_said_as_such(noc, access, observers, word, reason):
    if noc == "stale":
        noc = _noc(("usable", "usable"), freshness="stale")
    sections = {"noc": noc} if noc is not None else {}
    answer = _model(sections, access, observers)["summary"]["communication"]
    assert (answer["status"], answer["reason_code"]) == (word, reason)


def _loop(rows, *, intake="running", recent_fresh=True, open_total=None, explainer=None):
    def part(status, snapshot, fresh=True):
        return {"status": status, "reason_code": None, "snapshot": snapshot,
                "source": {"freshness": "fresh" if fresh else "stale",
                           "reason_code": None if fresh else "snapshot_expired"}}
    if open_total is None:
        open_total = sum(1 for row in rows if row.get("state") == "open")
    return {"status": "read", "intake": part(intake, {"accepted": 1, "open_incidents": open_total}),
            "explainer": part("running", explainer or {}),
            "recent": part("read", {"incidents": rows}, fresh=recent_fresh)}


def _row(state="open", action="throttle", kind="ai_advice", severity=3):
    return {"incident_id": "inc-0000000000000001", "state": state, "last_seen": 5.0,
            "most_severe": severity, "explanation": {"content_kind": kind},
            "edge_decision": {"kind": "would", "action": action, "executed": False}}


def test_events_and_response_keep_facts_inference_decision_and_result_apart():
    model = _model({"edge_loop": _loop([_row(), _row(action="notify", kind="none"),
                                        _row(state="closed")])})
    events, response = model["summary"]["events"], model["summary"]["response"]
    assert events["status"] == "open_incidents" and events["count"] == 2
    codes = {b["code"]: b for b in events["basis"]}
    assert codes["open_incidents_total"]["count"] == 2 and codes["open_incidents_listed"]["count"] == 2
    assert codes["ai_explanations"]["kind"] == "ai_inference" and codes["ai_explanations"]["count"] == 1
    assert response["status"] == "observe_only_no_execution"
    decision = [b for b in response["basis"] if b["kind"] == "edge_decision"][0]
    assert decision == {"kind": "edge_decision", "code": "would_not_executed",
                        "actions": {"notify": 1, "throttle": 1}}
    result = [b for b in response["basis"] if b["kind"] == "execution_result"][0]
    assert result["code"] == "none_accepted"
    # Nothing on the page says a `would` was carried out.
    assert "executed" not in json.dumps(model["summary"]).replace("would_not_executed", "")


@pytest.mark.parametrize("intake, word", [("running", "no_open_incidents"),
                                          ("stale", "unknown"), ("unavailable", "unknown")])
def test_no_open_incident_is_news_only_while_the_intake_is_running(intake, word):
    loop = _loop([_row(state="closed")], intake=intake)
    if intake == "stale":
        loop["intake"]["source"] = {"freshness": "stale", "reason_code": "snapshot_expired"}
        word = "stale"
    answer = _model({"edge_loop": loop})["summary"]["events"]
    assert answer["status"] == word


def test_the_next_steps_name_the_screen_or_the_command_and_never_act():
    setup = {"schema": "azazel-nexus/setup/1", "steps": [
        {"name": "installed-files", "status": "done", "reason": "r", "next_command": "x"},
        {"name": "operator-observers", "status": "needed", "reason": "r",
         "next_command": "sudo systemctl enable --now azazel-noc-observe.timer"}]}
    model = _model({"edge_loop": _loop([_row()]), "noc": _noc(("none", "none"))},
                   observers={"noc": "not_enabled", "units": "enabled"}, setup=setup)
    items = model["summary"]["next"]["items"]
    codes = [item["code"] for item in items]
    assert codes == ["check_uplink", "review_incidents_and_hand_off", "enable_observers",
                     "continue_setup"]
    assert codes == sorted(codes, key=ui_model.NEXT_CODES.index)
    assert items[2]["command"] == "sudo systemctl enable --now azazel-noc-observe.timer"
    assert model["summary"]["next"]["status"] == "action_needed"
    quiet = _model({"edge_loop": _loop([]), "noc": _noc(("usable", "none"))},
                   observers={"noc": "enabled", "units": "enabled"})
    assert [i["code"] for i in quiet["summary"]["next"]["items"]] == ["keep_monitoring"]
    assert quiet["summary"]["next"]["status"] == "monitoring_only"


def test_an_unreadable_read_model_is_said_in_every_answer():
    model = _model(schema=False)
    summary = model["summary"]
    assert summary["communication"]["status"] == "not_collected"
    assert summary["events"]["status"] == "not_collected"
    assert summary["next"]["items"][0]["code"] == "read_model_unavailable"


def test_every_summary_word_and_code_has_a_label_and_none_is_healthy():
    labels = json.loads((REPO / "runtime/src/azazel_nexus_runtime/ui_static/labels.json")
                        .read_text("utf-8"))
    for word in ui_model.SUMMARY_WORDS:
        assert word in labels["words"], word
        assert labels["words"][word][1] != "ok", word
    assert set(ui_model.NEXT_CODES) == set(labels["summary"]["next"])
    for code in ("observer_timer_not_enabled", "default_route_link_down", "no_default_route",
                 "uplink_not_observed", "intake_not_evidenced_running"):
        assert code in labels["reasons"], code
    from azazel_nexus.operator_view import PROVIDER_REASON_CODES
    assert sorted(PROVIDER_REASON_CODES - set(labels["reasons"])) == []


def test_the_page_renders_the_four_answers_first_and_the_details_on_their_own_screen():
    script = (REPO / "runtime/src/azazel_nexus_runtime/ui_static/app.js").read_text("utf-8")
    page = (REPO / "runtime/src/azazel_nexus_runtime/ui_static/index.html").read_text("utf-8")
    for question in ("通信は維持されているか", "何が起きているか", "何を自動対処しているか",
                     "担当者が次にすること"):
        assert question in script, question
    for kind in ui_model.BASIS_KINDS:
        assert kind + ":" in script, kind
    assert 'id="tab-detail"' in page and 'id="panel-detail"' in page
    assert page.index('id="tab-overview"') < page.index('id="tab-detail"')
    assert "operatorViewCard(section(\"operator_view\"))" in script


def test_incident_ui_labels_async_slow_result_as_unverified_and_separate():
    script = (REPO / "runtime/src/azazel_nexus_runtime/ui_static/app.js").read_text("utf-8")
    assert 'var slow = ex.slow_analysis' in script
    assert 'M.I.O. 非同期モデル提案（未検証・助言のみ）' in script
    assert 'slow.state === "complete" && slow.verification === "model_proposed_unverified"' in script
    assert "事実・判断・実行指示として扱わない" in script


# -- the operator view's read adapter -----------------------------------------------------


def _tree(root):
    return sorted((str(p.relative_to(root)), p.stat().st_mtime_ns, p.stat().st_mode)
                  for p in root.rglob("*"))


def test_the_adapter_writes_nothing_and_says_absent_only_for_a_node_without_models(tmp_path):
    from azazel_nexus.operator_view_source import read_section

    before = _tree(tmp_path)
    section = read_section(usable_mib=8000, root=tmp_path)
    assert _tree(tmp_path) == before
    assert section["schema"] == "azazel-nexus/status-view/operator-view/1"
    assert section["inputs"]["model_store"] == "readable"
    catalog = section["sections"][2]["rows"][0]
    assert catalog == {"axis": "catalog_state", "value": "absent",
                       "reason": "no catalog has been presented; the node was told nothing"}
    assert section["provider"]["state"] == "not admitted"
    assert "admission_switched_off_in_build" in section["provider"]["reason_codes"]
    assert section["source"]["writes"] == "none"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file; the uid-1001 run checks it")
def test_a_model_store_this_account_cannot_open_is_not_read_never_absent(tmp_path):
    from azazel_nexus.operator_view_source import read_section

    models = tmp_path / "var/lib/azazel/models"
    models.mkdir(parents=True)
    models.chmod(0o000)
    try:
        section = read_section(usable_mib=8000, root=tmp_path)
    finally:
        models.chmod(0o755)
    assert section["status"] == "partial" and "model_store" in section["unread_inputs"]
    assert section["inputs"]["model_store"] == "permission_denied"
    rows = {sec["key"]: sec["rows"] for sec in section["sections"]}
    assert rows["catalog"][0]["reason_code"] == "catalog_permission_denied"
    assert rows["catalog"][0]["value"] is None
    assert all(row["value"] is None for row in rows["import"])


def test_the_adapter_reads_the_admission_record_from_entryds_snapshot():
    from azazel_nexus.operator_view_source import read_section

    section = {"freshness": "fresh", "snapshot": {
        "recorded": True, "record_uncertain": False, "ceiling": "LITE",
        "reasons": {"health": {"local": "not_admitted", "remote": "unavailable"}}}}
    view = read_section(usable_mib=8000, mio_status_section=section, root="/nonexistent")
    assert view["inputs"]["mio_entry_record"] == "readable"
    assert "local_not_admitted" in view["provider"]["reason_codes"]
    cognition = {r["axis"]: r for r in view["sections"][0]["rows"]}
    assert cognition["mio_profile"]["value"] == "local-only"
    stale = read_section(usable_mib=8000, root="/nonexistent",
                         mio_status_section={**section, "freshness": "stale"})
    assert stale["inputs"]["mio_entry_record"] == "stale"
    assert "admission_record_unread" in stale["provider"]["reason_codes"]
    # The words entryd records (mio_status.HEALTH_REASONS), each read as written.
    from azazel_nexus.mio_status import HEALTH_REASONS
    for word in HEALTH_REASONS:
        reasons = {"health": {"local": word, "remote": "unavailable"}}
        view = read_section(usable_mib=8000, root="/nonexistent", mio_status_section={
            **section, "snapshot": {**section["snapshot"], "reasons": reasons}})
        expected = "local_observation_invalid" if word == "invalid_observation" else "local_" + word
        assert expected in view["provider"]["reason_codes"], word


# -- Codex review R389 ------------------------------------------------------------


#: Citations that name a path, with whatever comes before it (R389b-01). Each
#: carries a marker the checks look for as a plain substring, so they do not
#: depend on the rule the product uses to recognise a path.
PATH_CITATIONS = (
    ("see /srv/private/MARKA", "MARKA"), ("docs/private/MARKB.md", "MARKB"),
    ("(./relative/MARKC)", "MARKC"), ("source=/srv/private/MARKD", "MARKD"),
    ("source:./private/MARKE", "MARKE"), ("source\uff1a\uff0fsrv\uff0fMARKF", "MARKF"),
    ("C:\\private\\MARKG", "MARKG"), ("path\u2215srv\u2215MARKH", "MARKH"),
)
MARKERS = tuple(marker for _, marker in PATH_CITATIONS)


def _rows_with_path_citations(chunk):
    """A row holds at most eight citations; four per run, two runs."""
    from test_status_view import DISPLAY_REF, NOW, _recent

    rows = _recent(NOW)["incidents"]
    for citation, _ in PATH_CITATIONS[chunk * 4:chunk * 4 + 4]:
        rows[0]["explanation"]["knowledge_refs"].append({**DISPLAY_REF, "citation": citation})
    return rows


def _no_marker(text, where):
    for marker in MARKERS:
        assert marker not in text, (where, marker)


@pytest.mark.parametrize("chunk", [0, 1])
def test_r389_01_a_citation_naming_a_path_never_reaches_either_raw_file(tmp_path, monkeypatch,
                                                                        chunk):
    """New writes and a restored older checkpoint alike: the operator snapshot,
    the UI's raw copy and the browser's JSON hold none of the markers."""
    from azazel_nexus.incident_explain import build_recent_incidents
    from test_incident_explaind import make
    from test_status_view import NOW

    rows = _rows_with_path_citations(chunk)
    built = build_recent_incidents(rows, NOW)
    _no_marker(json.dumps(built, ensure_ascii=False), "builder")
    refs = built["incidents"][0]["explanation"]["knowledge_refs"]
    assert sum(r.get("citation_state") == "withheld" for r in refs) == 4
    # The new-write path: the explainer's own writer.
    ui = tmp_path / "ui"
    ui.mkdir()
    e = make(tmp_path, ui_status_path=ui / "status.json", ui_recent_path=ui / "recent.json")
    e.recent = rows
    e.monotonic = lambda: 100
    e.recent_status()
    raw = (ui / "recent.json").read_text("utf-8")
    assert raw == (tmp_path / "recent.json").read_text("utf-8")
    _no_marker(raw, "new write, UI copy")
    # The restore path: a checkpoint an older release wrote with the citations.
    e.checkpoint()
    cursor = tmp_path / "state" / "cursor.json"
    checkpoint = json.loads(cursor.read_text("utf-8"))
    checkpoint["recent"]["incidents"] = rows
    cursor.write_text(json.dumps(checkpoint), "utf-8")
    (ui / "recent.json").unlink()
    restored = make(tmp_path, ui_status_path=ui / "status.json", ui_recent_path=ui / "recent.json")
    # Restored as the older release wrote it, markers and all.
    assert any(MARKERS[chunk * 4] in json.dumps(r) for r in restored.recent)
    restored.monotonic = lambda: 200
    restored.recent_status()
    _no_marker((ui / "recent.json").read_text("utf-8"), "restored, UI copy")
    _no_marker((tmp_path / "recent.json").read_text("utf-8"), "restored, operator snapshot")
    # The browser's JSON, built from the raw UI copy (even one an older
    # writer left with the citations in it).
    from azazel_nexus import runtime_paths
    from test_status_view import _absent, _write
    node = tmp_path / "node"
    node.mkdir()
    monkeypatch.setenv("AZAZEL_ROOT", str(node))
    _absent(node, monkeypatch)
    legacy = {"schema": built["schema"], "written_at": NOW - 1, "incidents": rows}
    _write(runtime_paths.incident_recent_path(reader="ui"), legacy)
    view = _status_json(node, "--snapshot-reader", "ui")
    assert view["sections"]["edge_loop"]["recent"]["snapshot"] is not None
    document = ui_model.browser_json(ui_model.project(view, origin={"kind": "live"}, served_at="t"))
    _no_marker(document.decode("utf-8"), "browser JSON")


def test_r389_02_the_intakes_count_is_the_total_and_none_is_never_guessed():
    # The intake reports one open incident; the list shows none open.
    lagging = _model({"edge_loop": _loop([_row(state="closed")], open_total=1)})
    answer = lagging["summary"]["events"]
    assert (answer["status"], answer["count"], answer["reason_code"]) == (
        "open_incidents", 1, "incident_list_incomplete")
    # And the other way (R389b-02): the list still shows one open, the intake
    # none -- said as a list ahead of the intake, never as a list that misses.
    ahead = _model({"edge_loop": _loop([_row()], open_total=0)})["summary"]["events"]
    assert (ahead["status"], ahead["count"], ahead["reason_code"]) == (
        "open_incidents", 1, "incident_list_ahead_of_intake")
    differs = [b for b in ahead["basis"] if b["code"] == "list_differs_from_intake"][0]
    assert (differs["count"], differs["listed"]) == (0, 1)
    labels = json.loads((REPO / "runtime/src/azazel_nexus_runtime/ui_static/labels.json")
                        .read_text("utf-8"))
    assert "少ない" in labels["reasons"]["incident_list_incomplete"]
    assert "多い" in labels["reasons"]["incident_list_ahead_of_intake"]
    assert "list_differs_from_intake" in [b["code"] for b in answer["basis"]]
    assert lagging["summary"]["next"]["items"][0]["code"] == "review_incidents_and_hand_off"
    # An old open incident pushed out of the twenty newest closed rows.
    crowded = _model({"edge_loop": _loop([_row(state="closed")] * 20, open_total=1)})
    assert crowded["summary"]["events"]["status"] == "open_incidents"
    # The explainer's own trouble is said beside the count.
    for flags, code in (({"chain_broken": True}, "explainer_chain_broken"),
                        ({"storage_failed": True}, "explainer_storage_failed"),
                        ({"cursor_lag": 4}, "explainer_behind")):
        model = _model({"edge_loop": _loop([], open_total=2, explainer=flags)})
        assert model["summary"]["events"]["status"] == "open_incidents"
        assert code in [b["code"] for b in model["summary"]["events"]["basis"]], code
    # A degraded intake (storage failed) with zero: completeness unknown.
    degraded = _model({"edge_loop": _loop([], intake="degraded", open_total=0)})
    assert degraded["summary"]["events"]["status"] == "unknown"
    # A count that is not a number: not "none".
    loop = _loop([])
    loop["intake"]["snapshot"]["open_incidents"] = "x"
    assert _model({"edge_loop": loop})["summary"]["events"]["status"] == "unknown"
    # Only a running intake reporting zero, and a list with none open, is "none".
    assert _model({"edge_loop": _loop([])})["summary"]["events"]["status"] == "no_open_incidents"


def test_r389_03_the_most_severe_is_the_smallest_number():
    rows = [_row(severity=3), _row(severity=1), _row(severity=4)]
    listed = [b for b in _model({"edge_loop": _loop(rows)})["summary"]["events"]["basis"]
              if b["code"] == "open_incidents_listed"][0]
    assert listed["most_severe"] == 1
    script = (REPO / "runtime/src/azazel_nexus_runtime/ui_static/app.js").read_text("utf-8")
    assert "数値が小さいほど重大" in script


def test_r389_05_only_the_operator_view_version_this_page_knows_is_shown():
    from azazel_nexus.operator_view_source import SCHEMA

    good = {"schema": SCHEMA, "status": "read", "reason_code": None, "inputs": {
        "model_store": "readable", "smuggled": "x"}, "unread_inputs": [], "provider": {
        "state": "not admitted", "reason_codes": ["core_reserve_unmeasured"], "extra": 1},
        "sections": [{"key": "catalog", "title": "Catalog", "rows": [
            {"axis": "catalog_state", "value": "absent", "reason": "r", "secret": "SECRET"}]}],
        "operations": [{"confirmation": "profile", "available": True, "reason": "r",
                        "transition": "t", "secret": "SECRET"}], "unknown_field": "SECRET"}
    model = _model({"operator_view": good})
    shown = model["sections"]["operator_view"]
    assert "SECRET" not in json.dumps(shown) and "smuggled" not in json.dumps(shown)
    assert shown["sections"][0]["rows"][0] == {"axis": "catalog_state", "value": "absent",
                                               "reason": "r"}
    for other in ({**good, "schema": "azazel-nexus/status-view/operator-view/2"},
                  {k: v for k, v in good.items() if k != "schema"}, "not a section"):
        model = _model({"operator_view": other})
        assert "operator_view" not in model["sections"]
        assert model["pending"]["operator_view"] == "section_version_unsupported"


def test_r389_section_3_a_failed_ui_copy_is_removed_not_left_fresh(tmp_path, monkeypatch):
    from azazel_nexus_runtime import status_snapshot
    from azazel_nexus_runtime.status_snapshot import UiCopy

    path = tmp_path / "status.json"
    copy = UiCopy(path, name="t", warn=lambda _: None)
    assert copy.write(b'{"written_at": 1}\n') and path.exists()

    def full(*args):
        raise OSError(28, "no space")
    monkeypatch.setattr(status_snapshot, "_replace", full)
    assert copy.write(b'{"written_at": 2}\n') is False
    assert not path.exists()


# -- R389-04, R389-06: the operator view's model store ------------------------------


def _store(tmp_path, *, catalog="valid", entries=None, installed=None, mode=None):
    """A model store at `<root>/var/lib/azazel/models` in one of the states."""
    import test_operator_view as tov
    from azazel_nexus.model_catalog import CATALOG_DOMAIN, CATALOG_FILENAME, catalog_payload

    models = tmp_path / "var/lib/azazel/models"
    (models / "inbox").mkdir(parents=True)
    if catalog == "unset":
        return models
    (models / "trust").mkdir()
    (models / "trust/trust.json").write_text(json.dumps({
        "commissioning_digest": tov.COMMISSIONING,
        "catalog_keys": {"catalog-key": bytes(tov._key().verify_key).hex()}}), "utf-8")
    entries = [tov.an_entry()] if entries is None else entries
    body = catalog_payload(version=1, commissioning_digest=tov.COMMISSIONING, entries=entries)
    if catalog == "corrupt":
        body = b"{not json"
    signature = bytes(tov._key().sign(CATALOG_DOMAIN + body).signature)
    if catalog == "unsigned":
        signature = bytes(64)
    (models / "trust" / CATALOG_FILENAME).write_bytes(signature + body)
    if installed is not None:
        from azazel_nexus.model_import import MANIFEST_SCHEMA
        (models / "state/generations").mkdir(parents=True)
        (models / "state/generations/1.json").write_text(json.dumps(
            {"schema": MANIFEST_SCHEMA, "generation_id": "g1", "installed": installed}), "utf-8")
        (models / "state/current").write_text("1", "utf-8")
        (models / "store").mkdir()
        artifact = models / "store" / "small-advisor.gguf"
        artifact.write_bytes(tov.WEIGHTS)
        artifact.chmod(0o000)
    if mode is not None:
        models.chmod(mode)
    return models


def _catalog_row(section):
    rows = {sec["key"]: sec["rows"] for sec in section["sections"]}
    return rows["catalog"][0]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file; the uid-1001 run checks it")
@pytest.mark.parametrize("state, value, code", [
    ("unset", "absent", None),
    ("unsigned", None, "catalog_unsigned"),
    ("corrupt", None, "catalog_invalid"),
    ("denied", None, "catalog_permission_denied"),
    ("empty", "empty", None),
])
def test_r389_06_five_catalog_states_stay_five(tmp_path, state, value, code):
    from azazel_nexus.operator_view_source import read_section

    models = _store(tmp_path, catalog={"denied": "valid", "empty": "valid"}.get(state, state),
                    entries=[] if state == "empty" else None,
                    mode=0o000 if state == "denied" else None)
    try:
        section = read_section(usable_mib=8000, root=tmp_path)
    finally:
        models.chmod(0o755)
    row = _catalog_row(section)
    assert row["value"] == value, state
    assert row.get("reason_code") == code, state
    if code is not None:
        assert "model_store" in section["unread_inputs"]
        assert "not presented" not in row["reason"] and "told nothing" not in row["reason"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file; the uid-1001 run checks it")
def test_r389_04_status_never_opens_or_hashes_an_installed_artifact(tmp_path, monkeypatch):
    """The artifact is unreadable (0000) and `ModelImport.reading_for` (which
    re-hashes) raises: the screen still describes the installed model -- as
    recorded at promotion, not re-verified, never `present`."""
    import test_operator_view as tov
    from azazel_nexus import model_catalog
    from azazel_nexus.model_import import ModelImport
    from azazel_nexus.operator_view_source import read_section

    def forbidden(*args, **kwargs):
        raise AssertionError("an artifact was opened or hashed")
    monkeypatch.setattr(ModelImport, "reading_for", forbidden)
    monkeypatch.setattr(model_catalog, "verify_artifact", forbidden)
    models = _store(tmp_path, installed={"small-advisor": tov.an_entry().digest})
    try:
        section = read_section(usable_mib=8000, root=tmp_path)
    finally:
        (models / "store/small-advisor.gguf").chmod(0o644)
    rows = {sec["key"]: sec["rows"] for sec in section["sections"]}
    model = [r for r in rows["catalog"] if r["axis"] == "model"][0]
    assert model["value"] == "declared" and model["refused_by"] is None
    assert "not re-verified" in model["reason"]
    assert "present" not in json.dumps(rows["catalog"]).replace("presented", "")
    # A generation record that names another digest is not passed off either.
    other = tmp_path / "other"
    _store(other, installed={"small-advisor": "sha256:" + "0" * 64})
    try:
        mismatch = read_section(usable_mib=8000, root=other)
    finally:
        (other / "var/lib/azazel/models/store/small-advisor.gguf").chmod(0o644)
    row = [r for r in {s["key"]: s["rows"] for s in mismatch["sections"]}["catalog"]
           if r["axis"] == "model"][0]
    assert row["refused_by"] == model_catalog.Refusal.DIGEST_MISMATCH.value


def test_r389b_concurrent_ui_copy_writes_and_removals_never_interleave(tmp_path, monkeypatch):
    """The intake can write its status from the worker and from shutdown at
    once; a failing call's removal must not interleave with a replace."""
    import threading
    import time as clock
    from azazel_nexus_runtime import status_snapshot
    from azazel_nexus_runtime.status_snapshot import UiCopy

    inside, overlaps = [], []
    original = status_snapshot._replace

    def slow(path, body, mode):
        if inside:
            overlaps.append(body)
        inside.append(body)
        clock.sleep(0.05)
        try:
            if body.startswith(b"fail"):
                raise OSError(28, "no space")
            original(path, body, mode)
        finally:
            inside.pop()
    monkeypatch.setattr(status_snapshot, "_replace", slow)
    copy = UiCopy(tmp_path / "status.json", name="t", warn=lambda _: None)
    threads = [threading.Thread(target=copy.write, args=(body,))
               for body in (b"ok-1\n", b"fail\n", b"ok-2\n", b"fail\n")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert overlaps == []


def test_slow_ui_renders_dispatch_and_fence_fields():
    script = (REPO / "runtime/src/azazel_nexus_runtime/ui_static/app.js").read_text()
    assert 'budget.dispatch.forEach' in script
    assert 'budget.fence_state' in script
    assert '送信済み' in script and '未送信' in script
