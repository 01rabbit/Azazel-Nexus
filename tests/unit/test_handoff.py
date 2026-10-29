"""The expert handoff package (goal 2 F, S-19): `azazel-nexus handoff export`.

Mock evidence: every source is a file in a fixture `AZAZEL_ROOT` tree, built
by `tools/build_handoff_example.py` (the incident chain written with
`AuditLedger`, explained by the real `Explainer` with fixed replies instead
of sockets). No process, socket, systemd unit or VM is involved.
"""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus import handoff
from azazel_nexus.audit import AuditLedger
from azazel_nexus.handoff import HandoffRefused, build_package, encode_files, write_package
from test_noc_observe import host  # noqa: F401 - the fake netlink host fixture

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("build_handoff_example",
                                               REPO / "tools" / "build_handoff_example.py")
example = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(example)

INCIDENT = example.INCIDENT
NOW = example.GENERATED
SECRET_FORMS = ("192.0.2.10", "192.0.2.55", "2001:db8::7", "aa:bb:cc:dd:ee:ff", "/etc/shadow",
                "hunter2xyz", "2010937", "3306", "ET SCAN", "operator-a", "eth0",
                "-----BEGIN OPENSSH PRIVATE KEY-----", "https://")


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "root"
    path.mkdir()
    example.build_fixture(path)
    return path


@pytest.fixture
def out(tmp_path):
    path = tmp_path / "out"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def package(root, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("principal", "root")
    return build_package(INCIDENT, root=root, **kw)


def text_of(files):
    return b"".join(files.values()).decode("utf-8")


def explanations_dir(root):
    return root / "var/lib/azazel/incident-explain/explanations"


def write_record(root, mio, *, refs=(), state="skipped", codes=()):
    from azazel_nexus.incident_explain import read_record

    record = read_record({
        "incident_id": INCIDENT, "explained_at": example.OPENED + 200, "transition": "updated",
        "edge_would": "isolate", "policy_reason": "severity_critical_contains_immediately",
        "attack_type": "absent", "technique_ids": ["T1046"], "mio": mio,
        "knowledge_refs": list(refs), "knowledge_state": state, "failure_codes": list(codes)})
    for old in explanations_dir(root).glob("*.jsonl"):
        old.unlink()
    (explanations_dir(root) / "2026-10-29.jsonl").write_text(json.dumps(record) + "\n")


# -- the documented example ------------------------------------------------------


def test_the_documented_example_is_what_the_fixture_generates(tmp_path):
    files = example.generate(tmp_path)
    for name, raw in files.items():
        stored = (example.EXAMPLE / name).read_bytes()
        assert stored == raw, f"{name} is stale: run tools/build_handoff_example.py"
    markdown = files["handoff.ja.md"].decode()
    assert "試験用 fixture から生成した例" in markdown.splitlines()[2]
    assert json.loads(files["handoff.json"])["provenance"] == "fixture"


def test_the_manifest_lists_each_file_with_its_digest(root):
    files = encode_files(package(root))
    manifest = json.loads(files["manifest.json"])
    assert manifest["schema"] == handoff.MANIFEST_SCHEMA
    assert manifest["upload"] == "none"
    assert {f["name"] for f in manifest["files"]} == {"handoff.json", "handoff.ja.md"}
    for entry in manifest["files"]:
        raw = files[entry["name"]]
        assert entry["sha256"] == hashlib.sha256(raw).hexdigest() and entry["bytes"] == len(raw)
    assert json.loads(files["handoff.json"])["schema"] == "azazel-nexus/handoff-package/1"


# -- the sections ---------------------------------------------------------------


def test_every_required_section_is_present_and_kept_apart(root):
    p = package(root)
    for key in ("time", "observed_facts", "edge_decision", "execution", "ai_assessment",
                "business_impact", "evidence_refs", "knowledge", "operator_actions",
                "unconfirmed", "confidentiality", "sources"):
        assert key in p
    assert p["observed_facts"]["authority"] == "edge_observation"
    assert p["edge_decision"]["authority"] == "edge_deterministic_rules"
    assert p["execution"]["authority"] == "execution_result"
    assert p["ai_assessment"]["authority"] == "advisory_only_not_fact"
    assert p["time"]["occurred_at"] == "2026-10-29T03:14:00Z"
    assert [t["event_type"] for t in p["observed_facts"]["transitions"]] == ["opened", "updated"]
    assert p["knowledge"]["citations"][0]["generation"] == 7
    assert p["knowledge"]["citations"][0]["superseded"] is True  # Lite is at 8 now
    assert p["operator_actions"]["node_actions"][0]["actor"] == "withheld"
    assert [e["event_type"] for e in p["operator_actions"]["incident_audit"]] == [
        "edge.incident.opened", "edge.incident.escalated"]


@pytest.mark.parametrize("would", ["throttle", "redirect", "isolate", "notify"])
def test_a_would_is_never_reported_as_executed(root, would):
    ledger = root / "var/lib/azazel/edge-incidents/2026-10-29.jsonl"
    AuditLedger(ledger).append(example.transition(
        "updated", example.OPENED + 90, 20, 1, would, "severity_critical_contains_immediately",
        example.DIGESTS[0], example.DIGESTS[2]))
    p = package(root)
    execution = p["execution"]
    assert execution["status"] == "not_executed" and execution["executed_count"] == 0
    assert execution["automatic_actions"]
    for action in execution["automatic_actions"]:
        assert action["executed"] is False and action["state"] == "would"
        assert action["expires_at"] is None
        assert action["lease"]["status"] == action["release"]["status"] == "not_applicable"
    assert all(d["executed"] is False and d["kind"] == "would"
               for d in p["edge_decision"]["decisions"])
    markdown = handoff.render_markdown(p)
    assert "**実行されていない**" in markdown and "実行なし" in markdown
    assert "実行済" not in markdown and "executed\": true" not in json.dumps(p)


def test_no_ai_and_no_explanation_is_unavailable_not_a_default(root):
    for old in explanations_dir(root).glob("*.jsonl"):
        old.unlink()
    recent = root / "var/lib/azazel/run/incident-explain-status/recent.json"
    recent.unlink()
    p = package(root)
    ai = p["ai_assessment"]
    assert ai["status"] == "unavailable" and ai["reason_code"] == "no_explanation_recorded"
    assert ai["explanations"] == []
    assert "no_ai_answer" in [u["code"] for u in p["unconfirmed"]]
    assert p["knowledge"]["status"] == "unavailable"


def test_an_unreachable_mio_is_recorded_as_not_ai(root):
    write_record(root, {"route": "unavailable", "outcome": "unavailable",
                        "reason": "mio_unavailable", "text": None},
                 codes=("mio_unavailable",))
    item = package(root)["ai_assessment"]["explanations"][0]
    assert item["labelled_ai_output"] is False and item["local_route_answered"] is False
    assert item["failure_codes"] == ["mio_unavailable"]


def test_a_deterministic_handoff_notice_is_not_ai(root):
    from azazel_nexus.local_advisory import HANDOFF_NOTICE

    write_record(root, {"route": "deterministic handoff", "outcome": "answered",
                        "reason": "mio_handoff:no_reference", "text": None,
                        "content_kind": "deterministic_notice", "notice": HANDOFF_NOTICE["ja"]},
                 codes=("mio_handoff",))
    p = package(root)
    item = p["ai_assessment"]["explanations"][0]
    assert (item["labelled_ai_output"], item["content_kind"]) == (False, "deterministic_notice")
    assert "AI の出力ではない" in handoff.render_markdown(p)


def test_connectivity_is_counted_from_the_noc_snapshot_without_identity(root, host):
    from test_noc_status import _observed

    snapshot = _observed(host)
    snapshot["written_at"] = NOW - 30
    leaf = root / "var/lib/azazel/run/noc-status"
    leaf.mkdir()
    (leaf / "status.json").write_text(json.dumps(snapshot))
    p = package(root)
    seen = p["business_impact"]["connectivity_observed"]
    assert seen["status"] == "observed" and seen["snapshot_age_s"] == 30
    interfaces = [i for i in snapshot["interfaces"]["value"]
                  if not (i["loopback"]["state"] == "observed" and i["loopback"]["value"])]
    assert seen["interfaces"] == len(interfaces)
    assert seen["interfaces"] > 0
    assert seen["carrier_up"] + seen["carrier_down"] <= len(interfaces)
    assert seen["reachability"]["status"] == "not_measured"
    assert p["business_impact"]["assessment"]["status"] == "unavailable"
    assert "ifindex" not in json.dumps(seen)


# -- evidence ---------------------------------------------------------------------


def test_evidence_is_digests_only_and_missing_evidence_is_counted(root):
    p = package(root)
    evidence = p["evidence_refs"]
    assert evidence["status"] == "partial" and evidence["reason_code"] == "evidence_not_stored"
    assert evidence["transitions_with_evidence_not_stored"] == 1
    assert {r["digest"] for r in evidence["refs"]} == set(example.DIGESTS[:2])
    assert all(r["content_included"] is False for r in evidence["refs"])
    assert evidence["raw_payload_included"] is False
    assert "evidence_not_stored" in [u["code"] for u in p["unconfirmed"]]


def test_a_broken_incident_chain_is_said_and_not_trusted(root):
    ledger = root / "var/lib/azazel/edge-incidents/2026-10-29.jsonl"
    lines = ledger.read_bytes().splitlines(keepends=True)
    ledger.write_bytes(lines[0] + lines[0])  # replayed line: sequence does not continue
    p = package(root)
    assert p["observed_facts"]["ledger"]["chain"] == "broken"
    assert p["observed_facts"]["status"] == "partial"
    sources = {s["source"]: s for s in p["sources"]}
    assert sources["incident_ledger"]["reason_code"] == "chain_broken"


def test_an_absent_incident_ledger_falls_back_to_the_snapshot_and_says_so(root):
    for path in (root / "var/lib/azazel/edge-incidents").glob("*.jsonl"):
        path.unlink()
    p = package(root)
    assert p["observed_facts"]["source"] == "recent_snapshot"
    assert p["observed_facts"]["status"] == "partial"
    assert p["evidence_refs"]["status"] == "unavailable" and p["evidence_refs"]["refs"] == []
    assert "incident_ledger_unavailable" in [u["code"] for u in p["unconfirmed"]]
    assert p["time"]["occurred_at_source"] == "recent_snapshot.first_seen"


def test_an_unknown_incident_writes_nothing(root):
    with pytest.raises(HandoffRefused) as refused:
        build_package("inc-0000000000000000", now=NOW, principal="root", root=root)
    assert refused.value.code == "incident_not_found"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_operator_gets_the_snapshots_and_each_ledger_says_why_not(root):
    for leaf in ("var/lib/azazel/edge-incidents", "var/lib/azazel/incident-explain",
                 "var/lib/azazel/state/audit", "var/lib/azazel/state/knowledge"):
        os.chmod(root / leaf, 0)
    try:
        p = package(root, principal="operator")
    finally:
        for leaf in ("var/lib/azazel/edge-incidents", "var/lib/azazel/incident-explain",
                     "var/lib/azazel/state/audit", "var/lib/azazel/state/knowledge"):
            os.chmod(root / leaf, 0o700)
    sources = {s["source"]: s for s in p["sources"]}
    for name in ("incident_ledger", "explanation_ledger", "audit_chain", "knowledge_clock_floor"):
        assert sources[name]["reason_code"] == "not_readable_by_principal", name
    assert p["generator"]["principal_class"] == "operator"
    assert p["ai_assessment"]["source"] == "recent_snapshot"
    assert p["operator_actions"]["status"] == "unavailable"
    codes = [u["code"] for u in p["unconfirmed"]]
    assert {"incident_ledger_unavailable", "explanation_ledger_unavailable",
            "audit_unavailable"} <= set(codes)


# -- the clock ----------------------------------------------------------------------


def test_a_synchronized_clock_is_only_said_as_synchronized_this_boot(root):
    clock = package(root)["time"]["clock"]
    assert clock["status"] == "synchronized_this_boot" and clock["signals"] == []
    assert "not that it is still synchronized" in clock["synchronized_this_boot"]["means"]


def test_no_timesync_marker_is_unverified(root):
    (root / "run/systemd/timesync/synchronized").unlink()
    p = package(root)
    assert p["time"]["clock"]["status"] == "unverified"
    assert "clock_unverified" in [u["code"] for u in p["unconfirmed"]]


def test_a_writable_timesync_marker_is_not_evidence(root):
    os.chmod(root / "run/systemd/timesync/synchronized", 0o666)
    assert package(root)["time"]["clock"]["synchronized_this_boot"]["status"] == "refused"


def test_a_clock_behind_the_knowledge_floor_is_untrusted(root):
    # The floor says 05:00 was already seen; generate "at" 04:00.
    p = package(root, now=NOW - 4800)
    clock = p["time"]["clock"]
    assert clock["status"] == "untrusted"
    assert "wall_clock_behind_knowledge_floor" in clock["signals"]
    assert clock["knowledge_floor"]["now_behind_floor"] is True
    assert "clock_untrusted" in [u["code"] for u in p["unconfirmed"]]


def test_records_dated_after_generation_make_the_clock_untrusted(root):
    (root / "var/lib/azazel/state/knowledge/clock-floor.json").unlink()
    p = package(root, now=example.OPENED + 30)  # the escalation is 30 s later
    clock = p["time"]["clock"]
    assert clock["status"] == "untrusted"
    assert "records_dated_after_generation" in clock["signals"]
    assert "incident_ledger" in clock["future_dated_sources"]


def test_an_implausible_wall_clock_is_untrusted_even_with_a_marker(root):
    (root / "var/lib/azazel/state/knowledge/clock-floor.json").unlink()
    p = package(root, now=978307200.0)  # 2001-01-01: an RTC reset
    assert p["time"]["clock"]["status"] == "untrusted"
    assert "wall_clock_implausible" in p["time"]["clock"]["signals"]


def test_a_tampered_floor_is_unavailable_not_trusted(root):
    floor = root / "var/lib/azazel/state/knowledge/clock-floor.json"
    floor.write_text('{"schema": "azazel-nexus/knowledge-clock-floor/v1", "floor_utc": "2026-10-29T05:00:00Z"}\n')
    clock = package(root)["time"]["clock"]
    assert clock["knowledge_floor"] == {"status": "unavailable", "reason_code": "refused",
                                        "floor_utc": None}


def test_the_floor_reader_agrees_with_the_floor_writer(root, tmp_path):
    runtime = pytest.importorskip("azazel_nexus_runtime.knowledge_clock_floor")
    from datetime import datetime, timezone

    floor = root / "var/lib/azazel/state/knowledge/clock-floor.json"
    floor.write_bytes(runtime.encode_floor(datetime(2026, 10, 29, 6, tzinfo=timezone.utc)))
    clock = package(root)["time"]["clock"]
    assert clock["knowledge_floor"]["floor_utc"] == "2026-10-29T06:00:00Z"
    assert clock["status"] == "untrusted"


# -- confidentiality ---------------------------------------------------------------


def test_addresses_ids_ports_signature_text_and_actors_are_not_copied(root):
    files = encode_files(package(root))
    text = text_of(files)
    for form in ("192.0.2.10", "2010937", "3306", "ET SCAN", "operator-a"):
        assert form not in text, form
    suppressed = json.loads(files["handoff.json"])["confidentiality"]["suppressed"]
    assert suppressed["network_address"] == 2 and suppressed["rule_identifier"] == 2
    assert suppressed["service_port"] == 2 and suppressed["producer_free_text"] == 2
    assert suppressed["operator_identity"] == 1


def test_secrets_and_identifiers_in_free_text_are_replaced_and_counted(root):
    write_record(root, {
        "route": "local", "outcome": "answered", "reason": "local", "content_kind": "ai_advice",
        "text": ("Check 192.0.2.55 and 2001:db8::7 on eth0 (aa:bb:cc:dd:ee:ff), read /etc/shadow, "
                 "see https://intranet.example/x, password=hunter2xyz "
                 "-----BEGIN OPENSSH PRIVATE KEY----- AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDhZ "
                 "admin@corp.example")},
        refs=[{"technique_id": "T1046", "name": "Network Service Discovery",
               "summary": "Seen from 192.0.2.55 via gw.corp.example:8443", "claim_id": "T1046",
               "bundle_digest": example.BUNDLE, "freshness": "current",
               "source_kind": "knowledge_lite", "generation": 7, "trust_check": "verified",
               "as_of": "2026-10-29T03:14:30Z", "citation": "internal wiki at 10.1.2.3"}],
        state="available")
    files = encode_files(package(root))
    text = text_of(files)
    for form in SECRET_FORMS + ("10.1.2.3", "gw.corp.example:8443", "admin@corp.example"):
        assert form not in text, form
    p = json.loads(files["handoff.json"])
    counts = p["confidentiality"]["suppressed"]
    for category in ("network_address", "mac_address", "path", "url", "secret_like",
                     "interface_name", "host_port", "email", "citation_text"):
        assert counts[category] >= 1, category
    assert p["knowledge"]["citations"][0]["citation_state"] == "withheld"
    assert "[伏字:network_address]" in p["ai_assessment"]["explanations"][0]["text"]


def test_the_final_scan_refuses_a_package_whose_suppression_failed(root, monkeypatch):
    write_record(root, {"route": "local", "outcome": "answered", "reason": "local",
                        "content_kind": "ai_advice", "text": "Block 192.0.2.55 now"})
    monkeypatch.setattr(handoff.Suppressor, "text", lambda self, value, limit=4096: value)
    with pytest.raises(HandoffRefused) as refused:
        encode_files(package(root))
    assert refused.value.code == "suppression_incomplete:network_address"


def test_timestamps_and_digests_are_not_mistaken_for_addresses():
    assert handoff.scan_for_leaks(b'"2026-10-29T03:14:00Z" "sha256:' + b"ab" * 32 + b'"') == []
    assert handoff.scan_for_leaks(b"fe80::1") == ["network_address"]


# -- offline ----------------------------------------------------------------------


def test_generation_and_writing_use_no_network(root, out, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network used")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    files = encode_files(package(root))
    path = write_package(out, handoff.package_name(json.loads(files["handoff.json"])), files)
    assert sorted(os.listdir(path)) == ["handoff.ja.md", "handoff.json", "manifest.json"]


def test_the_module_has_no_transport():
    import ast

    for name in ("handoff.py", "handoff_cli.py"):
        tree = ast.parse((REPO / "src/azazel_nexus" / name).read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                    if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in getattr(node, "names", [])}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module and node.level == 0}
        assert not imported & {"socket", "ssl", "http", "urllib", "subprocess", "smtplib",
                               "ftplib", "requests", "httpx"}, name


# -- writing ------------------------------------------------------------------------


def files_and_name(root):
    files = encode_files(package(root))
    return files, handoff.package_name(json.loads(files["handoff.json"]))


def test_written_atomically_into_a_new_private_directory(root, out):
    files, name = files_and_name(root)
    path = write_package(out, name, files)
    assert path == out / name and os.listdir(out) == [name]
    assert os.stat(path).st_mode & 0o777 == 0o700
    for file_name, raw in files.items():
        assert (path / file_name).read_bytes() == raw
        assert os.stat(path / file_name).st_mode & 0o777 == 0o600


def test_an_existing_package_is_never_overwritten(root, out):
    files, name = files_and_name(root)
    (out / name).mkdir()
    (out / name / "handoff.json").write_text("operator's own file")
    writes = []
    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, write=lambda fd, data: writes.append(fd))
    assert refused.value.code == "output_exists"
    assert writes == [], "refused only after writing"
    assert (out / name / "handoff.json").read_text() == "operator's own file"
    assert sorted(os.listdir(out)) == [name]


@pytest.mark.parametrize("empty", [False, True])
def test_a_name_that_appears_while_writing_is_not_replaced(root, out, empty):
    files, name = files_and_name(root)

    def write(fd, data):
        if not (out / name).exists():
            (out / name).mkdir()
            if not empty:
                (out / name / "theirs").write_text("kept")
        return os.write(fd, data)

    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, write=write)
    assert refused.value.code == "output_exists"
    assert sorted(os.listdir(out)) == [name]
    assert sorted(os.listdir(out / name)) == ([] if empty else ["theirs"])


def test_an_existing_symlink_at_the_name_is_refused(root, out, tmp_path):
    files, name = files_and_name(root)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (out / name).symlink_to(target)
    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files)
    assert refused.value.code == "output_exists"
    assert os.listdir(target) == []


@pytest.mark.parametrize("where", ["leaf", "component"])
def test_a_symlinked_output_path_is_refused(root, out, tmp_path, where):
    files, name = files_and_name(root)
    if where == "leaf":
        link = tmp_path / "link"
        link.symlink_to(out)
    else:
        (tmp_path / "linkparent").symlink_to(tmp_path)
        link = tmp_path / "linkparent" / "out"
    with pytest.raises(HandoffRefused) as refused:
        write_package(link, name, files)
    assert refused.value.code == "output_path_refused"
    assert os.listdir(out) == []


@pytest.mark.parametrize("path, code", [
    ("relative/dir", "output_path_not_absolute"),
    ("/var/lib/azazel/run", "output_in_product_state"),
    ("/etc/azazel", "output_in_product_state"),
    ("/proc/self", "output_in_product_state"),
])
def test_unsafe_output_locations_are_refused(root, path, code):
    files, name = files_and_name(root)
    with pytest.raises(HandoffRefused) as refused:
        write_package(Path(path), name, files)
    assert refused.value.code == code


def test_a_dot_dot_path_is_refused(root, out):
    files, name = files_and_name(root)
    with pytest.raises(HandoffRefused) as refused:
        write_package(Path(str(out) + "/../out"), name, files)
    assert refused.value.code == "output_path_refused"


def test_a_shared_writable_output_directory_is_refused(root, out):
    files, name = files_and_name(root)
    os.chmod(out, 0o777)
    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files)
    assert refused.value.code == "output_dir_shared_writable"
    assert os.listdir(out) == []


def test_too_little_space_is_refused_before_anything_is_written(root, out):
    files, name = files_and_name(root)
    need = sum(len(raw) for raw in files.values()) + handoff.SPACE_HEADROOM_BYTES
    small = lambda fd: SimpleNamespace(f_bavail=need // 4096, f_frsize=4096)  # noqa: E731
    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, statvfs=small)
    assert refused.value.code == "insufficient_space"
    assert os.listdir(out) == []


@pytest.mark.parametrize("failing", [1, 2, 3])
def test_a_disk_that_fills_part_way_leaves_nothing(root, out, failing):
    files, name = files_and_name(root)
    calls = []

    def write(fd, data):
        calls.append(fd)
        if len(calls) == failing:
            # Half the bytes land, then the device is full.
            os.write(fd, bytes(data[: max(1, len(data) // 2)]))
            raise OSError(errno.ENOSPC, "No space left on device")
        return os.write(fd, data)

    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, write=write)
    assert refused.value.code == "insufficient_space"
    assert os.listdir(out) == [], "a partial package or temporary directory was left"


# -- the command ----------------------------------------------------------------------


def run_cli(argv, *, principal="root", root=None, now="2026-10-29T05:14:00Z"):
    import argparse

    from azazel_nexus import handoff_cli

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    handoff_cli.add_parser(sub)
    args = parser.parse_args(["handoff", *argv])
    stream = io.StringIO()
    code = handoff_cli.run(args, now=now, out=stream, principal=principal, root=root)
    return code, stream.getvalue()


def test_the_command_writes_the_package_and_prints_the_manifest_digest(root, out):
    code, text = run_cli(["export", "--incident", "latest", "--output-dir", str(out)], root=root)
    assert code == 0, text
    (name,) = os.listdir(out)
    manifest = (out / name / "manifest.json").read_bytes()
    assert f"manifest sha256: {hashlib.sha256(manifest).hexdigest()}" in text
    assert "uploaded: no" in text
    assert INCIDENT in name


def test_the_command_refuses_a_principal_outside_root_and_operator(root, out):
    code, text = run_cli(["export", "--incident", INCIDENT, "--output-dir", str(out)],
                         principal="nobody", root=root)
    assert code == 2 and "principal_refused" in text
    assert os.listdir(out) == []


def test_the_command_says_a_fixed_code_and_nothing_from_below(root, out):
    code, text = run_cli(["export", "--incident", "inc-zz", "--output-dir", str(out)], root=root)
    assert code == 1 and "incident_id_refused" in text
    code, text = run_cli(["export", "--incident", INCIDENT, "--output-dir", "rel"], root=root)
    assert code == 1 and "output_path_not_absolute" in text


def test_the_cli_entry_point_lists_handoff():
    from azazel_nexus.cli import main

    stream = io.StringIO()
    with pytest.raises(SystemExit):
        import contextlib

        with contextlib.redirect_stdout(stream):
            main(["handoff", "export", "--help"])
    assert "--output-dir" in stream.getvalue()
