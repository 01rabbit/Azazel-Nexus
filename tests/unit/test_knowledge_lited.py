"""The daemon reads the tar store, with separate commissioned trust only."""

import json
import os
import socket
import sys
import threading
from pathlib import Path

import pytest
from azazel_nexus_runtime import knowledge_lited as daemon
from azazel_nexus_runtime.principal import PrincipalClass, PrincipalPolicy
from azazel_nexus_runtime.protocol import RequestRefused
from nacl.signing import SigningKey
from test_lite_bundle import KEY_ID, SEED, _manifest, _signed

from azazel_nexus.edge_package import inspect as inspect_edge
from azazel_nexus.lite_import import CommissionedLite, LiteImport
from azazel_nexus.lite_trust import TrustStore
from azazel_nexus.revocation import RevocationList
from azazel_nexus.revocation_policy import (
    REVOCATION_SIGNING,
    RevocationPolicy,
    commission_policy,
)

NOW = "2026-10-18T00:00:00Z"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    root = tmp_path / "var/lib/azazel/knowledge"
    trust = tmp_path / "var/lib/azazel/lite-trust"
    (root / "inbox").mkdir(parents=True)
    (root / "trust").mkdir()
    (trust / "trust").mkdir(parents=True)
    key = SigningKey(SEED).verify_key.encode()
    anchors = f'threshold = 1\n[keys]\n"{KEY_ID}" = "{key.hex()}"\n'
    (root / "trust/anchors.toml").write_text(anchors)
    (trust / "trust/anchors.toml").write_text(anchors)
    TrustStore(trust).pin([key.hex()], commissioning_digest=DIGEST,
                         pinned_at=NOW, actor="test")
    revoker = SigningKey.generate()
    policy = RevocationPolicy(keys={"r": revoker.verify_key.encode()},
                              key_roles={"r": REVOCATION_SIGNING}, threshold=1, generation=1)
    commission_policy(trust, policy, commissioning_digest=DIGEST,
                      anchors_key_roles={}, anchors_keys={})
    service = daemon.KnowledgeLiteService(root=root, trust_root=trust, now=lambda: NOW)
    return service, root, trust, revoker


def admit(node, expiry="2027-01-01T00:00:00Z"):
    _, root, _, _ = node
    (root / "inbox/bundle.tar.gz").write_bytes(_signed(
        _manifest(bundle_version=5),
        {"tables/a.jsonl": json.dumps({"agg_next_expiry": expiry}).encode() + b"\n"},
    ))
    importer = LiteImport(CommissionedLite(root))
    assert importer.import_entry(importer.list_inbox()[0].entry_id, now=NOW).admitted


def snapshot(*roots):
    return {str(path): (path.read_bytes(), path.stat().st_mtime_ns)
            for root in roots for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize("state", ["unavailable", "available", "stale", "quarantined", "unverified"])
def test_states_are_bounded_read_only_and_leave_edge_unchanged(node, state):
    service, root, trust, _ = node
    if state in {"available", "stale", "unverified"}:
        admit(node, "2020-01-01T00:00:00Z" if state == "stale" else "2027-01-01T00:00:00Z")
    elif state == "quarantined":
        (root / "quarantine").mkdir()
        (root / "quarantine/held").write_bytes(b"not opened")
    if state == "unverified":
        (trust / "revocations.signed").write_bytes(b"invalid")
    before = snapshot(root, trust)
    edge = inspect_edge(root / "edge").as_event()
    for _ in range(2):
        result = service.handle(None)
        assert set(result) == {"state", "reason_code", "generation", "freshness"}
        assert result["state"] == ("unavailable" if state == "unverified" else state)
        assert result["reason_code"] == ("no_bundle" if state == "unavailable" else state)
        assert result["generation"] == (5 if state in {"available", "stale"} else None)
        assert result["freshness"] == ({"available": "current", "stale": "stale"}.get(state, "absent"))
    assert snapshot(root, trust) == before
    assert inspect_edge(root / "edge").as_event() == edge


def test_revoked_generation_is_quarantined(node):
    service, _, trust, revoker = node
    admit(node)
    statement = RevocationList(sequence=1, issued_at=NOW, revoked_generations=frozenset({5}))
    (trust / "revocations.signed").write_bytes(
        revoker.sign(statement.signature_target()).signature + statement.as_payload())
    assert service.handle(None) == {"state": "quarantined", "reason_code": "revoked",
                                    "generation": 5, "freshness": "absent"}


def test_corrupt_admitted_bundle_is_quarantined(node):
    service, root, _, _ = node
    admit(node)
    (root / "admitted/current.tar.gz").write_bytes(b"broken")
    assert service.handle(None)["reason_code"] == "bundle_refused"


@pytest.mark.parametrize("which", ["trust", "store"])
def test_unreadable_storage_still_answers(node, monkeypatch, which):
    service, root, trust, _ = node
    admit(node)
    original = os.open
    target = trust / "trust.json" if which == "trust" else root / "admitted/current.tar.gz"

    def denied(path, *args, **kwargs):
        if Path(path) == target:
            raise PermissionError("must not leak this path")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", denied)
    assert service.handle(None) == {"state": "unavailable", "reason_code": f"{which}_unreadable",
                                    "generation": None, "freshness": "absent"}


def test_store_anchors_do_not_override_commissioned_trust(node):
    service, root, trust, _ = node
    admit(node)
    (root / "trust/anchors.toml").write_text("hostile")
    assert service.handle(None)["state"] == "available"
    (trust / "trust.json").unlink()
    assert service.handle(None)["reason_code"] == "trust_unreadable"


def test_verb_contract():
    assert daemon.STATUS_VERB.admits == frozenset({PrincipalClass.OPERATOR, PrincipalClass.SERVICE})
    policy = PrincipalPolicy(operator_gid=100, service_uids=frozenset({200}))
    for uid, gid in [(101, 100), (200, 300)]:
        daemon.REGISTRY.resolve("knowledge.status", policy.classify(uid, gid, 1))
    with pytest.raises(RequestRefused):
        daemon.REGISTRY.resolve("knowledge.import", policy.classify(101, 100, 1))
    with pytest.raises(RequestRefused):
        daemon.STATUS_VERB.bind({"path": "/secret"})
    with pytest.raises(RequestRefused):
        daemon.REGISTRY.resolve("knowledge.status", policy.classify(301, 300, 1))


def test_main_wiring_and_no_arguments(node, monkeypatch):
    from azazel_nexus_runtime import runtime_paths, serve

    _, root, trust, _ = node
    captured = {}
    monkeypatch.setattr(runtime_paths, "ROOT", root.parents[3])
    monkeypatch.setattr(runtime_paths, "lite_trust_root", lambda: trust)
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda name: ("sink", name))
    from types import SimpleNamespace
    monkeypatch.setattr(daemon.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=123))
    monkeypatch.setattr(serve, "serve_forever", lambda **kwargs: captured.update(kwargs) or 0)
    resolved = []
    monkeypatch.setattr(daemon.PrincipalPolicy, "resolve", lambda **kw: resolved.append(kw) or "policy")
    assert daemon.main([], ready=lambda: None) == 0
    assert captured["path"] == root.parent / "run/knowledge/knowledge.sock"
    assert captured["additional_sockets"] == ((root.parent / "run/knowledge-read/knowledge-read.sock", 123, daemon.READ_REGISTRY),)
    assert captured["audit"] == ("sink", "knowledge")
    assert captured["handler"].__self__.root == root
    assert resolved == [{"service_accounts": ("azmioentry", "azarbiter", "azmio")}]
    monkeypatch.setattr(sys, "argv", ["az-knowledge-lited", "--path"])
    with pytest.raises(SystemExit, match="takes no arguments"):
        daemon.main()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_PEERCRED contract")
def test_socket_round_trip_and_refusals(node):
    from azazel_nexus_runtime.serve import serve_forever
    from azazel_nexus_runtime.transport import read_frame, send_frame

    service, root, _, _ = node
    path = root.parent / "run/knowledge/knowledge.sock"
    path.parent.mkdir(parents=True)
    ready = threading.Event()
    stop = threading.Event()
    events = []
    failures = []

    def run():
        try:
            serve_forever(path=path, registry=daemon.REGISTRY,
                          policy=PrincipalPolicy(os.getgid(), frozenset()),
                          audit=events.append, handler=service.handle,
                          ready=ready.set, stop=stop.is_set)
        except OSError as exc:
            failures.append(exc)
            ready.set()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert ready.wait(3)
        if failures:
            raise failures[0]
        for arguments in ({}, {"path": "/secret"}):
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(3)
                connection.connect(str(path))
                send_frame(connection, {"verb": "knowledge.status", "arguments": arguments})
                # read_frame requires EOF after the body to reject trailing bytes.
                connection.shutdown(socket.SHUT_WR)
                reply = json.loads(read_frame(connection))
            assert reply["ok"] is (not arguments)
        assert events[0]["event_type"] == "runtime.request_refused"
        assert "/secret" not in repr(events)
    finally:
        stop.set()
        thread.join(3)
    assert not thread.is_alive()
    assert not path.exists()


@pytest.mark.parametrize("value", [None, "T1110", {}, ["T1110"] * 9,
                                   ["TA0001"], ["T1110\n"], [1], ["T１１１０"]])
def test_lookup_argument_refusals(value):
    with pytest.raises(RequestRefused):
        daemon.LOOKUP_VERB.bind({"technique_ids": value})


def test_lookup_service_only_and_no_payload():
    from azazel_nexus_runtime.transport import SocketServer

    policy = PrincipalPolicy(operator_gid=100, service_uids=frozenset({200}))
    operator = policy.classify(101, 100, 1)
    service = policy.classify(200, 300, 1)
    with pytest.raises(RequestRefused):
        daemon.REGISTRY.resolve("knowledge.lookup", operator)
    assert daemon.REGISTRY.resolve("knowledge.lookup", service) is daemon.LOOKUP_VERB
    engine = SocketServer(registry=daemon.REGISTRY, policy=policy, audit=lambda e: None)
    for arguments, payload in [({}, {}), ({"technique_ids": [], "path": "/secret"}, {}),
                               ({"technique_ids": []}, {"text": "secret"})]:
        with pytest.raises(RequestRefused):
            engine._parse(json.dumps({"verb": "knowledge.lookup", "arguments": arguments,
                                      "event": payload}).encode(), service)


def test_lookup_response_and_audit(node):
    from types import SimpleNamespace

    from test_knowledge_lookup import admit_rows

    service, root, trust, _ = node
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force",
                       "description": "Private context"}])
    events = []
    service.audit = events.append
    request = SimpleNamespace(verb=daemon.LOOKUP_VERB,
                              arguments={"technique_ids": ["T1110"]}, payload={})
    before = snapshot(root, trust)
    result = service.handle(request)
    assert result["refs"][0]["claim_id"] == "T1110"
    assert result["reason_code"] == "available"
    assert events == [{"event_type": "knowledge.lookup", "technique_ids": ["T1110"], "count": 1}]
    assert "Private context" not in repr(events)
    assert snapshot(root, trust) == before
    (trust / "trust.json").unlink()
    assert service.handle(request) == {"refs": [], "reason_code": "trust_unreadable"}


def test_lookup_json_escape_bound(node):
    from types import SimpleNamespace

    from test_knowledge_lookup import admit_rows

    service = node[0]
    admit_rows(node, [{"technique_id": "T1110", "name": "😀" * 120,
                       "description": "😀" * 240}] * 16)
    events = []
    service.audit = events.append
    request = SimpleNamespace(verb=daemon.LOOKUP_VERB,
                              arguments={"technique_ids": ["T1110"]}, payload={})
    result = service.handle(request)
    assert 0 < len(result["refs"]) < 16
    assert len(json.dumps({"ok": True, "result": result}).encode()) <= 60 * 1024
    assert events[0]["count"] == len(result["refs"])


def test_read_listener_only_registers_lookup():
    policy = PrincipalPolicy(100, frozenset({201}))
    principal = policy.classify(201, 200, 1)
    assert daemon.READ_REGISTRY.resolve("knowledge.lookup", principal) == daemon.LOOKUP_VERB
    with pytest.raises(RequestRefused):
        daemon.READ_REGISTRY.resolve("knowledge.status", principal)


@pytest.mark.parametrize("watermark", ["6", None, "abc", "-1", "9" * 100, "directory", "symlink"])
def test_status_refuses_untrusted_watermark(node, watermark):
    service, root, _, _ = node
    admit(node)
    path = root / "state/watermark"
    path.unlink()
    if watermark == "directory":
        path.mkdir()
    elif watermark == "symlink":
        path.symlink_to(root / "inbox/bundle.tar.gz")
    elif watermark is not None:
        path.write_text(watermark)
    assert service.handle(None) == {"state": "quarantined", "reason_code": "state_untrusted",
                                    "generation": None, "freshness": "absent"}


@pytest.mark.parametrize("floor", ["4", "5"])
def test_status_serves_equal_or_newer_than_watermark(node, floor):
    service, root, _, _ = node
    admit(node)
    (root / "state/watermark").write_text(floor)
    assert service.handle(None)["state"] == "available"


def test_status_reports_unreadable_watermark_as_unreadable(node, monkeypatch):
    import azazel_nexus.lite_import as lite_import

    service, _, _, _ = node
    admit(node)

    def denied(path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(lite_import, "_read_watermark", denied)
    assert service.handle(None) == {"state": "unavailable", "reason_code": "store_unreadable",
                                    "generation": None, "freshness": "absent"}
