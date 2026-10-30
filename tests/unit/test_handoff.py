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
    assert seen["status"] == "observed" and seen["snapshot"]["age_s"] == 30
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
    clock = package(root)["time"]["generation_clock"]
    assert clock["status"] == "synchronized_this_boot" and clock["signals"] == []
    assert "not that it is still synchronized" in clock["synchronized_this_boot"]["means"]


def test_no_timesync_marker_is_unverified(root):
    (root / "run/systemd/timesync/synchronized").unlink()
    p = package(root)
    assert p["time"]["generation_clock"]["status"] == "unverified"
    assert "clock_unverified" in [u["code"] for u in p["unconfirmed"]]


def test_a_writable_timesync_marker_is_not_evidence(root):
    os.chmod(root / "run/systemd/timesync/synchronized", 0o666)
    assert package(root)["time"]["generation_clock"]["synchronized_this_boot"]["status"] == "refused"


def test_a_clock_behind_the_knowledge_floor_is_untrusted(root):
    # The floor says 05:00 was already seen; generate "at" 04:00.
    p = package(root, now=NOW - 4800)
    clock = p["time"]["generation_clock"]
    assert clock["status"] == "untrusted"
    assert "wall_clock_behind_knowledge_floor" in clock["signals"]
    assert clock["knowledge_floor"]["now_behind_floor"] is True
    assert "clock_untrusted" in [u["code"] for u in p["unconfirmed"]]


def test_records_dated_after_generation_make_the_clock_untrusted(root):
    (root / "var/lib/azazel/state/knowledge/clock-floor.json").unlink()
    p = package(root, now=example.OPENED + 30)  # the escalation is 30 s later
    clock = p["time"]["generation_clock"]
    assert clock["status"] == "untrusted"
    assert "records_dated_after_generation" in clock["signals"]
    assert "incident_ledger" in clock["future_dated_sources"]


def test_an_implausible_wall_clock_is_untrusted_even_with_a_marker(root):
    (root / "var/lib/azazel/state/knowledge/clock-floor.json").unlink()
    p = package(root, now=978307200.0)  # 2001-01-01: an RTC reset
    assert p["time"]["generation_clock"]["status"] == "untrusted"
    assert "wall_clock_implausible" in p["time"]["generation_clock"]["signals"]


def test_a_tampered_floor_is_unavailable_not_trusted(root):
    floor = root / "var/lib/azazel/state/knowledge/clock-floor.json"
    floor.write_text('{"schema": "azazel-nexus/knowledge-clock-floor/v1", "floor_utc": "2026-10-29T05:00:00Z"}\n')
    clock = package(root)["time"]["generation_clock"]
    assert clock["knowledge_floor"] == {"status": "unavailable", "reason_code": "refused",
                                        "floor_utc": None}


def test_the_floor_reader_agrees_with_the_floor_writer(root, tmp_path):
    runtime = pytest.importorskip("azazel_nexus_runtime.knowledge_clock_floor")
    from datetime import datetime, timezone

    floor = root / "var/lib/azazel/state/knowledge/clock-floor.json"
    floor.write_bytes(runtime.encode_floor(datetime(2026, 10, 29, 6, tzinfo=timezone.utc)))
    clock = package(root)["time"]["generation_clock"]
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


#: (text, the token that must not reach the package)
LEAKY_FORMS = {
    "network_address": ("Block 192.0.2.55 now", "192.0.2.55"),
    "network_address_v6": ("Block 2001:db8::7 now", "2001:db8::7"),
    "mac_address": ("Station aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
    "url": ("See https://intranet", "https://intranet"),
    "email": ("Ask admin@corp.example", "admin@corp.example"),
    "windows_path": ("Open C:\\Users\\ops\\notes", "Users"),
    "unix_path": ("Read /etc/shadow", "/etc/shadow"),
    "host_port": ("Try gateway:8443", "gateway:8443"),
    "host_name": ("Host db01.corp.local is affected", "db01.corp.local"),
    "interface_name": ("Link eth0 is down", "eth0"),
    "percent_encoded": ("Value pass%3Dword", "pass%3Dword"),
    "hex_value": ("Key " + "cd" * 32, "cd" * 32),
    "base64_value": ("Blob cGFzc3dvcmQ9aHVudGVy", "cGFzc3dvcmQ9aHVudGVy"),
    "secret_like": ("password=hunter2xyz", "hunter2xyz"),
}


@pytest.mark.parametrize("category", sorted(LEAKY_FORMS))
def test_unrecognised_free_text_is_withheld_and_counted(root, category):
    from azazel_nexus.lite_import import read_knowledge_refs

    text, token = LEAKY_FORMS[category]
    mio = {"route": "local", "outcome": "answered", "reason": "local",
           "content_kind": "ai_advice", "text": text}
    ref = {"technique_id": "T1046", "name": "Network Service Discovery", "summary": text,
           "claim_id": "T1046", "bundle_digest": example.BUNDLE, "freshness": "current",
           "source_kind": "knowledge_lite", "generation": 7, "trust_check": "verified",
           "as_of": "2026-10-29T03:14:30Z", "citation": text[:160]}
    try:
        read_knowledge_refs([ref])
        refs = [ref]
    except ValueError:
        refs = []  # Knowledge's own reader refuses it before it is ever stored
    write_record(root, mio, refs=refs, state="available" if refs else "skipped")
    files = encode_files(package(root))
    assert token not in text_of(files), category
    p = json.loads(files["handoff.json"])
    item = p["ai_assessment"]["explanations"][0]
    assert (item["text"], item["text_state"]) == (None, "withheld")
    suppressed = p["confidentiality"]["suppressed"]
    assert suppressed["ai_free_text"] == 1
    if refs:
        citation = p["knowledge"]["citations"][0]
        assert citation["summary"] is None and citation["summary_state"] == "withheld"
        assert citation["citation"] is None and citation["citation_state"] == "withheld"
        assert suppressed["knowledge_free_text"] == 2
    assert "free_text_withheld" in [u["code"] for u in p["unconfirmed"]]


def test_fixed_banners_and_plain_phrases_are_shown_with_their_method(root):
    p = package(root)
    item = p["ai_assessment"]["explanations"][0]
    assert item["text_state"] == "shown"
    assert item["generation_method"] == "deterministic_keyword_matching"
    citation = p["knowledge"]["citations"][0]
    assert citation["name"] == "Network Service Discovery"
    assert citation["summary_state"] == "shown" and citation["citation_state"] == "shown"
    assert p["confidentiality"]["suppressed"]["ai_free_text"] == 0


DETECTED = {
    "network_address": "Block 192.0.2.55 now",
    "mac_address": "Station aa:bb:cc:dd:ee:ff",
    "url": "See https://intranet",
    "email": "Ask admin@corp.example",
    "windows_path": "Open C:\\Users\\ops",
    "unix_path": "Read /etc/shadow",
    "host_port": "Try gateway:8443",
    "host_name": "Host db01.corp.local",
    "interface_name": "Link eth0 down",
    "percent_encoded": "pass%3Dword",
    "hex_value": "Key " + "ab" * 32,
    "base64_value": "Blob cGFzc3dvcmQ9aHVudGVy",
    "secret_like": "password=hunter2xyz",
}


@pytest.mark.parametrize("category", sorted(DETECTED))
def test_the_final_scan_refuses_each_form_when_suppression_is_disabled(root, monkeypatch,
                                                                         category):
    """The allowlist switched off: the scan alone must still refuse to write."""
    text = DETECTED[category]
    write_record(root, {"route": "local", "outcome": "answered", "reason": "local",
                        "content_kind": "ai_advice", "text": text})
    monkeypatch.setattr(handoff, "_text_of", lambda value, fixed, hide: (value, "disabled")
                        if value else (None, "none"))
    with pytest.raises(HandoffRefused) as refused:
        encode_files(package(root))
    assert refused.value.code.startswith("suppression_incomplete:")
    assert category in refused.value.code.split(":", 1)[1].split(","), refused.value.code


@pytest.mark.parametrize("field", ["name", "summary", "citation"])
def test_the_final_scan_covers_knowledge_text_when_the_allowlist_is_disabled(root, monkeypatch,
                                                                             field):
    ref = {"technique_id": "T1046", "name": "Network Service Discovery", "summary": "",
           "claim_id": "T1046", "bundle_digest": example.BUNDLE, "freshness": "current",
           "source_kind": "knowledge_lite", "generation": 7, "trust_check": "verified",
           "as_of": "2026-10-29T03:14:30Z", "citation": ""}
    ref[field] = "Host db01.corp.local"
    write_record(root, {"route": "unavailable", "outcome": "unavailable",
                        "reason": "mio_unavailable", "text": None}, refs=[ref],
                 state="available", codes=("mio_unavailable",))
    monkeypatch.setattr(handoff, "plain_words", lambda text, limit: text)
    with pytest.raises(HandoffRefused) as refused:
        encode_files(package(root))
    assert "host_name" in refused.value.code


def test_the_final_scan_covers_audit_values(root, monkeypatch):
    import re

    chain = root / "var/lib/azazel/state/audit/2026-10-29.jsonl"
    AuditLedger(chain).append({"event_type": "knowledge.lite.import_refused",
                               "code": "see /etc/shadow", "occurred_at": "2026-10-29T03:20:00Z"})
    p = package(root)
    assert p["operator_actions"]["node_actions"][-1]["code"] == "withheld"
    assert p["confidentiality"]["suppressed"]["audit_value"] == 1
    monkeypatch.setattr(handoff, "_AUDIT_WORD", re.compile(r".*", re.DOTALL))
    with pytest.raises(HandoffRefused) as refused:
        encode_files(package(root))
    assert "unix_path" in refused.value.code


def test_codes_timestamps_and_digests_are_not_mistaken_for_identifiers(root):
    assert handoff.scan_package(package(root)) == []
    assert handoff.scan_package({"digest": "sha256:" + "ab" * 32}) == []
    assert handoff.scan_package({"note": "sha256:" + "ab" * 32}) == ["hex_value"]
    assert handoff.scan_package({"note": "abcdef" * 8}) == ["hex_value"]
    assert handoff.detect("fe80::1") == ["network_address"]
    assert handoff.detect("12:30:45 and 2026-10-29T03:14:00Z") == []


# -- offline ----------------------------------------------------------------------


def test_generation_and_writing_use_no_network(root, out, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network used")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    files = encode_files(package(root))
    path = write_package(out, handoff.package_name(json.loads(files["handoff.json"])), files).path
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
    result = write_package(out, name, files)
    path = result.path
    assert result.durable and path == out / name and os.listdir(out) == [name]
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


@pytest.mark.parametrize("kind", ["empty_dir", "full_dir", "file", "symlink"])
def test_a_name_that_appears_just_before_creation_is_kept(root, out, tmp_path, kind):
    """The race R388-06 names: after the last check, before the directory is made."""
    files, name = files_and_name(root)
    target = out / name
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    def racing_mkdir(path, mode, *, dir_fd):
        if kind == "empty_dir":
            target.mkdir()
        elif kind == "full_dir":
            target.mkdir()
            (target / "theirs").write_text("kept")
        elif kind == "file":
            target.write_text("kept")
        else:
            target.symlink_to(elsewhere)
        return os.mkdir(path, mode, dir_fd=dir_fd)

    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, mkdir=racing_mkdir)
    assert refused.value.code == "output_exists" and refused.value.remnant is None
    assert os.listdir(out) == [name]
    if kind == "empty_dir":
        assert os.listdir(target) == []
    elif kind == "full_dir":
        assert (target / "theirs").read_text() == "kept"
    elif kind == "file":
        assert target.read_text() == "kept"
    else:
        assert target.is_symlink() and os.listdir(elsewhere) == []


def test_a_file_planted_inside_the_new_directory_is_not_overwritten(root, out):
    files, name = files_and_name(root)

    def write(fd, data):
        planted = out / name / "manifest.json"
        if not planted.exists():
            planted.write_text("theirs")
        return os.write(fd, data)

    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, write=write)
    assert refused.value.code == "write_failed"
    assert (out / name / "manifest.json").read_text() == "theirs"
    assert os.listdir(out / name) == ["manifest.json"]
    assert refused.value.remnant == out / name


def test_a_file_sync_failure_before_the_manifest_leaves_nothing(root, out):
    files, name = files_and_name(root)
    calls = []

    def fsync(fd):
        calls.append(fd)
        if len(calls) == 2:
            raise OSError(errno.EIO, "I/O error")
        return os.fsync(fd)

    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, fsync=fsync)
    assert refused.value.code == "write_failed" and refused.value.remnant is None
    assert os.listdir(out) == []


def test_a_directory_sync_failure_after_publishing_is_reported_not_hidden(root, out):
    files, name = files_and_name(root)
    calls = []

    def fsync(fd):
        calls.append(fd)
        if len(calls) > len(files):
            raise OSError(errno.EIO, "I/O error")
        return os.fsync(fd)

    result = write_package(out, name, files, fsync=fsync)
    assert result.durable is False and result.path == out / name
    for file_name, raw in files.items():
        assert (out / name / file_name).read_bytes() == raw


def test_a_failed_cleanup_names_the_directory_left_behind(root, out, monkeypatch):
    files, name = files_and_name(root)

    def write(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    def no_rmdir(*args, **kwargs):
        raise OSError(errno.EBUSY, "busy")

    monkeypatch.setattr(handoff.os, "rmdir", no_rmdir)
    with pytest.raises(HandoffRefused) as refused:
        write_package(out, name, files, write=write)
    assert refused.value.code == "insufficient_space"
    assert refused.value.remnant == out / name
    assert os.listdir(out / name) == []


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


# -- R388-02: every transition counts, only the display is bounded -------------------


def test_transitions_beyond_the_display_bound_still_decide_the_state(root):
    ledger = AuditLedger(root / "var/lib/azazel/edge-incidents/2026-10-29.jsonl")
    for i in range(300):
        ledger.append(example.transition(
            "updated", example.OPENED + 120 + i, 20 + i, 3, "throttle",
            "severity_elevated_throttle_reversible", example.DIGESTS[0],
            "sha256:%064x" % (1000 + i)))
    # After the display bound: severity rises, the decision changes, evidence
    # is lost, and the incident closes.
    ledger.append(example.transition(
        "updated", example.OPENED + 500, 400, 1, "isolate",
        "severity_critical_contains_immediately", example.DIGESTS[0], example.DIGESTS[2],
        evidence_stored=False))
    ledger.append(example.transition(
        "closed", example.OPENED + 600, 400, 1, "isolate",
        "severity_critical_contains_immediately", example.DIGESTS[0], example.DIGESTS[2],
        reason="idle"))
    p = package(root)
    observed = p["observed_facts"]
    assert observed["summary"]["most_severe"] == 1 and observed["summary"]["count"] == 400
    assert observed["summary"]["latest_transition"] == "closed"
    assert observed["summary"]["transitions_with_evidence_not_stored"] == 2
    display = observed["transitions_display"]
    assert (display["total"], display["shown"], display["omitted"]) == (304, 256, 48)
    assert display["omitted_range"]["from"] == "2026-10-29T03:14:00Z"
    assert observed["transitions"][-1]["event_type"] == "closed"
    assert p["edge_decision"]["latest"]["action"] == "isolate"
    assert "isolate" in [a["action"] for a in p["execution"]["automatic_actions"]]
    assert p["incident"]["state"] == "closed"
    assert p["evidence_refs"]["refs_display"]["omitted"] > 0
    assert p["evidence_refs"]["transitions_with_evidence_not_stored"] == 2
    assert "display_truncated" in [u["code"] for u in p["unconfirmed"]]
    assert "古い 48 件を省略" in handoff.render_markdown(p)


# -- R388-03: the chain is anchored ---------------------------------------------------


def _segment(root, day="2026-10-29"):
    return root / "var/lib/azazel/edge-incidents" / f"{day}.jsonl"


def test_a_removed_first_line_is_a_broken_chain(root):
    path = _segment(root)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[1:]))
    p = package(root)
    sources = {s["source"]: s for s in p["sources"]}
    assert sources["incident_ledger"]["reason_code"] == "chain_broken"
    assert sources["incident_ledger"]["verified"]["anchor"] == "genesis"
    assert p["observed_facts"]["status"] == "partial"


def test_a_removed_first_segment_is_a_broken_chain(root):
    first = _segment(root)
    second = _segment(root, "2026-10-30")
    AuditLedger(second).append(example.transition(
        "updated", example.OPENED + 86400, 30, 2, "redirect", "severity_high_redirect_to_decoy",
        example.DIGESTS[0], example.DIGESTS[1]), chain_from=AuditLedger(first).head())
    assert package(root)["observed_facts"]["status"] == "available"
    first.unlink()
    p = package(root)
    sources = {s["source"]: s for s in p["sources"]}
    assert sources["incident_ledger"]["reason_code"] == "chain_broken"


def _retire_first_day(root):
    """What `IncidentLedger.before_delete` writes, then the unlink."""
    first, second = _segment(root), _segment(root, "2026-10-30")
    sequence, digest = AuditLedger(first).head()
    AuditLedger(second).append(example.transition(
        "updated", example.OPENED + 86400, 30, 2, "redirect", "severity_high_redirect_to_decoy",
        example.DIGESTS[0], example.DIGESTS[1]), chain_from=(sequence, digest))
    boundary = first.parent / "retained-boundary.json"
    boundary.write_text(json.dumps({"oldest": second.name, "sequence": sequence, "hash": digest,
                                    "deleted": first.name}, sort_keys=True,
                                   separators=(",", ":")) + "\n")
    return first, boundary


def test_a_lawful_retention_is_read_from_its_boundary(root):
    first, _ = _retire_first_day(root)
    # The crash window: the boundary is durable, the unlink has not happened.
    p = package(root)
    sources = {s["source"]: s for s in p["sources"]}
    assert sources["incident_ledger"]["status"] == "read"
    assert sources["incident_ledger"]["verified"]["anchor"] == "retention_boundary"
    first.unlink()
    p = package(root)
    sources = {s["source"]: s for s in p["sources"]}
    assert sources["incident_ledger"]["status"] == "read"
    assert [t["event_type"] for t in p["observed_facts"]["transitions"]] == ["updated"]


@pytest.mark.parametrize("damage", ["hash", "sequence", "oldest", "shape"])
def test_a_retention_boundary_that_does_not_match_is_refused(root, damage):
    first, boundary = _retire_first_day(root)
    first.unlink()
    value = json.loads(boundary.read_text())
    if damage == "hash":
        value["hash"] = "f" * 64
    elif damage == "sequence":
        value["sequence"] += 1
    elif damage == "oldest":
        value["oldest"] = "2026-10-31.jsonl"
    else:
        value["extra"] = 1
    boundary.write_text(json.dumps(value))
    sources = {s["source"]: s for s in package(root)["sources"]}
    assert sources["incident_ledger"]["status"] == "unavailable"
    assert sources["incident_ledger"]["reason_code"] in {
        "chain_broken", "retention_boundary_mismatch", "retention_boundary_refused"}


def test_the_reader_accepts_what_the_intake_ledger_retires(tmp_path):
    """The real writer's retention, not a copy of it, read by this reader."""
    runtime = pytest.importorskip("azazel_nexus_runtime.edge_intaked")
    base = tmp_path / "base"
    base.mkdir()
    day1 = example.OPENED
    ledger = runtime.IncidentLedger(base, day1, max_bytes=1, monotonic=lambda: 0)
    ledger.append(example.transition("opened", day1, 1, 3, "throttle",
                                     "severity_elevated_throttle_reversible",
                                     example.DIGESTS[0], example.DIGESTS[0]), day1)
    ledger.append(example.transition("updated", day1 + 86400, 2, 3, "throttle",
                                     "severity_elevated_throttle_reversible",
                                     example.DIGESTS[0], example.DIGESTS[1]), day1 + 86400)
    directory = base / "incidents"
    assert (directory / "retained-boundary.json").exists()
    chain = handoff._read_incident_chain(directory, lambda e: True)
    assert (chain.status, chain.anchor) == ("read", "retention_boundary")


def test_an_audit_range_read_says_it_is_not_anchored(root):
    older = root / "var/lib/azazel/state/audit/2026-10-01.jsonl"
    older.write_text("")
    p = package(root)
    audit = {s["source"]: s for s in p["sources"]}["audit_chain"]
    assert audit["status"] == "read" and audit["verified"]["anchored"] is False
    assert "audit_unanchored" in [u["code"] for u in p["unconfirmed"]]
    older.unlink()
    audit = {s["source"]: s for s in package(root)["sources"]}["audit_chain"]
    assert audit["verified"]["anchored"] is True


# -- R388-04: an expired snapshot is the last record, not the current state -----------


def _age_snapshot(root, leaf, seconds):
    path = root / "var/lib/azazel/run" / leaf / "status.json"
    value = json.loads(path.read_text())
    value["written_at"] = NOW - seconds
    path.write_text(json.dumps(value))


@pytest.mark.parametrize("age, fresh", [(150, True), (151, False), (-6, False)])
def test_knowledge_beyond_its_freshness_bound_is_not_current(root, age, fresh):
    _age_snapshot(root, "knowledge-status", age)
    p = package(root)
    now_k = p["knowledge"]["lite_now"]
    citation = p["knowledge"]["citations"][0]
    markdown = handoff.render_markdown(p)
    if fresh:
        assert now_k["status"] == "read" and citation["superseded"] is True
    else:
        assert now_k["status"] == "stale_last_recorded"
        assert now_k["reason_code"] in {"snapshot_expired", "snapshot_dated_in_future"}
        assert citation["superseded"] is None and citation["generation_now"] is None
        assert "最終記録のみ（現在は未確認）" in markdown
        assert "現在の世代は未確認" in markdown
        codes = [u["code"] for u in p["unconfirmed"]]
        assert "stale_snapshot" in codes and "knowledge_current_unknown" in codes


def test_an_expired_loop_snapshot_is_marked_in_json_and_markdown(root):
    _age_snapshot(root, "edge-intake-status", 31)
    p = package(root)
    assert p["loop_health"]["intake"]["status"] == "stale_last_recorded"
    sources = {s["source"]: s for s in p["sources"]}
    assert sources["intake_status_snapshot"]["freshness"] == "stale"
    assert "| stale |" in handoff.render_markdown(p)


# -- R388-05: the time of the incident, apart from the time of generation -------------


def test_an_impossible_occurrence_time_is_untrusted_with_a_good_clock(root):
    ledger = AuditLedger(_segment(root))
    ledger.append(example.transition("updated", 946684800.0, 15, 2, "redirect",
                                     "severity_high_redirect_to_decoy", example.DIGESTS[0],
                                     example.DIGESTS[1], first_seen=946684800.0))
    p = package(root)
    assert p["time"]["generation_clock"]["status"] == "synchronized_this_boot"
    occurrence = p["time"]["occurrence"]
    assert occurrence["status"] == "untrusted"
    assert "occurred_before_plausible_date" in occurrence["signals"]
    assert "transitions_out_of_order" in occurrence["signals"]
    assert "occurrence_time_untrusted" in [u["code"] for u in p["unconfirmed"]]


def test_last_seen_before_first_seen_is_named(root):
    AuditLedger(_segment(root)).append(example.transition(
        "updated", example.OPENED + 90, 15, 2, "redirect", "severity_high_redirect_to_decoy",
        example.DIGESTS[0], example.DIGESTS[1], last_seen=example.OPENED - 60))
    assert "last_seen_before_first_seen" in package(root)["time"]["occurrence"]["signals"]


def test_a_knowledge_lookup_dated_after_generation_is_named(root):
    write_record(root, {"route": "unavailable", "outcome": "unavailable",
                        "reason": "mio_unavailable", "text": None},
                 refs=[{"technique_id": "T1046", "name": "Network Service Discovery",
                        "summary": "", "claim_id": "T1046", "bundle_digest": example.BUNDLE,
                        "freshness": "current", "source_kind": "knowledge_lite",
                        "generation": 7, "trust_check": "verified",
                        "as_of": "2026-10-30T00:00:00Z", "citation": ""}],
                 state="available", codes=("mio_unavailable",))
    p = package(root)
    assert "knowledge_citation" in p["time"]["generation_clock"]["future_dated_sources"]
    assert "records_dated_after_generation" in p["time"]["occurrence"]["signals"]


def test_without_a_bad_sign_the_occurrence_is_still_only_unverified(root):
    occurrence = package(root)["time"]["occurrence"]
    assert (occurrence["status"], occurrence["signals"]) == ("unverified", [])
    assert occurrence["reason_code"] == "no_synchronization_evidence_at_occurrence"


# -- R388-07: the command tells what is on the media ----------------------------------


def test_the_command_reports_an_unconfirmed_sync_with_the_package_path(root, out,
                                                                      monkeypatch):
    real = handoff.write_package

    def write(parent, name, files):
        calls = []

        def fsync(fd):
            calls.append(fd)
            if len(calls) > len(files):
                raise OSError(errno.EIO, "I/O error")
            return os.fsync(fd)
        return real(parent, name, files, fsync=fsync)

    from azazel_nexus import handoff_cli

    monkeypatch.setattr(handoff_cli, "write_package", write)
    code, text = run_cli(["export", "--incident", INCIDENT, "--output-dir", str(out)], root=root)
    assert code == 3 and "durability_unconfirmed" in text
    (name,) = os.listdir(out)
    assert f"handoff: written {out / name}" in text and "nothing was written" not in text


def test_the_command_names_a_directory_it_could_not_remove(root, out, monkeypatch):
    real = handoff.write_package

    def write(parent, name, files):
        def full(fd, data):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(parent, name, files, write=full)

    def no_rmdir(*args, **kwargs):
        raise OSError(errno.EBUSY, "busy")

    from azazel_nexus import handoff_cli

    monkeypatch.setattr(handoff_cli, "write_package", write)
    monkeypatch.setattr(handoff.os, "rmdir", no_rmdir)
    code, text = run_cli(["export", "--incident", INCIDENT, "--output-dir", str(out)], root=root)
    assert code == 1 and "nothing was written" not in text
    (name,) = os.listdir(out)
    assert f"left at {out / name}" in text
