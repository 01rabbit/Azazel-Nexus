"""The daemon reads the tar store, with separate commissioned trust only."""

import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path

import pytest
from azazel_nexus import model_paths
from azazel_nexus_runtime import knowledge_clock_floor
from azazel_nexus_runtime import knowledge_lited as daemon
from azazel_nexus_runtime.knowledge_clock_floor import ClockFloor
from azazel_nexus_runtime.principal import PrincipalClass, PrincipalPolicy
from azazel_nexus_runtime.protocol import RequestRefused
from nacl.signing import SigningKey
from test_lite_bundle import KEY_ID, SEED, _manifest, _signed

from azazel_nexus.edge_package import inspect as inspect_edge
from azazel_nexus.lite_import import STATUS_KEYS, CommissionedLite, LiteImport, status_refused
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
    service = daemon.KnowledgeLiteService(root=root, trust_root=trust,
                                          clock_floor=ClockFloor(floor_dir(tmp_path)),
                                          now=lambda: NOW)
    return service, root, trust, revoker


def floor_dir(tmp_path):
    state = tmp_path / "var/lib/azazel/state/knowledge"
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o700)
    return state


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
        assert tuple(result) == STATUS_KEYS
        assert result["state"] == ("unavailable" if state == "unverified" else state)
        assert result["reason_code"] == ("no_bundle" if state == "unavailable" else state)
        assert result["generation"] == (5 if state in {"available", "stale"} else None)
        assert result["freshness"] == ({"available": "current", "stale": "stale"}.get(state, "absent"))
        if state in {"available", "stale"}:
            assert result["bundle_digest_short"].startswith("sha256:")
            assert len(result["bundle_digest_short"]) == len("sha256:") + 12
            assert result["signer_key_ids"] == [KEY_ID]
            assert result["static_count"] == 0
            assert result["current_count"] == (1 if state == "available" else 0)
            assert result["next_expiry"] == ("2027-01-01T00:00:00Z" if state == "available" else None)
        else:
            assert all(result[key] is None for key in STATUS_KEYS[4:])
    assert snapshot(root, trust) == before
    assert inspect_edge(root / "edge").as_event() == edge


def test_revoked_generation_is_quarantined(node):
    service, _, trust, revoker = node
    admit(node)
    statement = RevocationList(sequence=1, issued_at=NOW, revoked_generations=frozenset({5}))
    (trust / "revocations.signed").write_bytes(
        revoker.sign(statement.signature_target()).signature + statement.as_payload())
    assert service.handle(None) == status_refused("quarantined", "revoked", 5, "absent")


def test_corrupt_admitted_bundle_is_quarantined(node):
    service, root, _, _ = node
    admit(node)
    (root / "admitted/current.tar.gz").write_bytes(b"broken")
    assert service.handle(None)["reason_code"] == "bundle_refused"


@pytest.mark.parametrize("which", ["trust", "store"])
def test_unreadable_storage_still_answers(node, monkeypatch, which, private_os):
    private_os(model_paths)
    service, root, trust, _ = node
    admit(node)
    original = os.open
    target = trust / "trust.json" if which == "trust" else root / "admitted/current.tar.gz"

    def denied(path, *args, **kwargs):
        if Path(path) == target:
            raise PermissionError("must not leak this path")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(model_paths.os, "open", denied)
    assert service.handle(None) == status_refused("unavailable", f"{which}_unreadable", None, "absent")


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
    floor = captured["handler"].__self__.clock_floor
    assert type(floor) is ClockFloor
    assert floor.directory == root.parents[3] / "var/lib/azazel/state/knowledge"
    assert resolved == [{"service_accounts": ("azmioentry", "azarbiter", "azmio", "azexplain")}]
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
    assert events == [{"event_type": "knowledge.clock_floor_created", "cause": "initial"},
                      {"event_type": "knowledge.lookup", "technique_ids": ["T1110"], "count": 1}]
    assert "Private context" not in repr(events)
    assert snapshot(root, trust) == before
    (trust / "trust.json").unlink()
    assert service.handle(request) == {"refs": [], "reason_code": "trust_unreadable"}


def test_lookup_json_escape_bound(node):
    from types import SimpleNamespace

    from test_knowledge_lookup import admit_rows

    service = node[0]
    admit_rows(node, [{"technique_id": "T1110", "name": "😀" * 120,
                       "description": "😀" * 240}] * 16,
               profile={"provenance": {"attack_technique": {"dataset": {"citation": "😀" * 160}}}})
    events = []
    service.audit = events.append
    request = SimpleNamespace(verb=daemon.LOOKUP_VERB,
                              arguments={"technique_ids": ["T1110"]}, payload={})
    result = service.handle(request)
    assert 0 < len(result["refs"]) < 16
    # The trim only ever removes references beyond the eight a display shows.
    assert len(result["refs"]) >= 8
    assert result["refs"][0]["citation"] == "😀" * 160
    assert len(json.dumps({"ok": True, "result": result}).encode()) <= 60 * 1024
    lookups = [e for e in events if e["event_type"] == "knowledge.lookup"]
    assert lookups[0]["count"] == len(result["refs"])


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
    assert service.handle(None) == status_refused("quarantined", "state_untrusted", None, "absent")


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
    assert service.handle(None) == status_refused("unavailable", "store_unreadable", None, "absent")


# -- the persisted wall-clock floor (P3) ------------------------------------

def _lookup(service):
    from types import SimpleNamespace

    return service.handle(SimpleNamespace(verb=daemon.LOOKUP_VERB,
                                          arguments={"technique_ids": ["T1110"]}, payload={}))


def _clocked(node, tmp_path, instants, events=None):
    """A fresh service (a restart) on the same floor, reading `instants` in order."""
    _, root, trust, _ = node
    clock = iter(instants)
    return daemon.KnowledgeLiteService(
        root=root, trust_root=trust, clock_floor=ClockFloor(floor_dir(tmp_path)),
        now=lambda: next(clock), audit=(events.append if events is not None else lambda e: None))


UNTRUSTED_STATUS = status_refused("unavailable", "state_untrusted", None, "absent")
UNTRUSTED_LOOKUP = {"refs": [], "reason_code": "state_untrusted"}
EXPIRY = "2026-10-19T00:00:00Z"
BEFORE_EXPIRY = "2026-10-18T12:00:00Z"
AFTER_EXPIRY = "2026-10-20T00:00:00Z"


def test_clock_regression_does_not_redeliver_expired_rows(node, tmp_path):
    from test_knowledge_lookup import admit_rows

    admit_rows(node, [{"technique_id": "T1110", "name": "dated", "agg_next_expiry": EXPIRY}])
    # Control: on a clock before the expiry the dated row is served.
    fresh = tmp_path / "control"
    fresh.mkdir(mode=0o700)
    control = daemon.KnowledgeLiteService(root=node[1], trust_root=node[2],
                                          clock_floor=ClockFloor(fresh),
                                          now=lambda: BEFORE_EXPIRY)
    assert _lookup(control)["refs"][0]["freshness"] == "current"

    events = []
    service = _clocked(node, tmp_path, [AFTER_EXPIRY, AFTER_EXPIRY, BEFORE_EXPIRY,
                                        BEFORE_EXPIRY, BEFORE_EXPIRY], events)
    assert _lookup(service) == {"refs": [], "reason_code": "no_context"}
    assert service.handle(None)["freshness"] == "stale"
    # The wall clock is moved back before the expiry: the row stays withheld.
    assert _lookup(service) == UNTRUSTED_LOOKUP
    assert service.handle(None) == UNTRUSTED_STATUS
    assert _lookup(service) == UNTRUSTED_LOOKUP
    # One audit record for the transition, a fixed cause, no instant or path.
    clock_events = [e for e in events if e["event_type"] == "knowledge.clock_untrusted"]
    assert clock_events == [{"event_type": "knowledge.clock_untrusted", "cause": "regressed"}]
    assert BEFORE_EXPIRY not in repr(events) and str(tmp_path) not in repr(events)

    # A restart does not forget the floor: the persisted copy still refuses.
    restarted = _clocked(node, tmp_path, [BEFORE_EXPIRY, BEFORE_EXPIRY])
    assert _lookup(restarted) == UNTRUSTED_LOOKUP
    assert restarted.handle(None) == UNTRUSTED_STATUS

    # The clock catching up past the floor serves again; still no expired row.
    caught_up = _clocked(node, tmp_path, ["2026-10-20T00:00:01Z"])
    assert _lookup(caught_up) == {"refs": [], "reason_code": "no_context"}


def test_clock_regression_hides_static_reference_too(node, tmp_path):
    from test_knowledge_lookup import admit_rows

    admit_rows(node, [{"technique_id": "T1110", "name": "static"}])
    service = _clocked(node, tmp_path, [AFTER_EXPIRY, BEFORE_EXPIRY])
    assert _lookup(service)["reason_code"] == "available"
    assert _lookup(service) == UNTRUSTED_LOOKUP


def test_clock_untrusted_reply_reaches_client_as_unavailable(node, tmp_path, monkeypatch):
    from azazel_nexus_runtime import knowledge_client

    monkeypatch.setattr(knowledge_client, "_exchange", lambda *a, **k: dict(UNTRUSTED_LOOKUP))
    with pytest.raises(knowledge_client.KnowledgeUnavailable) as caught:
        knowledge_client.lookup_context(("T1110",))
    assert caught.value.code == "knowledge_unavailable"


@pytest.mark.parametrize("damage", [
    "garbage", "empty", "other_schema", "extra_key", "not_canonical", "naive_instant",
    "oversized", "directory", "symlink", "group_writable", "hardlink", "missing_directory",
    "directory_group_writable",
])
def test_unreadable_floor_fails_closed(node, tmp_path, damage):
    from test_knowledge_lookup import admit_rows

    admit_rows(node, [{"technique_id": "T1110", "name": "static"}])
    state = floor_dir(tmp_path)
    path = state / knowledge_clock_floor.FILENAME
    good = knowledge_clock_floor.encode_floor(
        knowledge_clock_floor._instant("2026-10-17T00:00:00Z"))
    records = {
        "garbage": b"not json",
        "empty": b"",
        "other_schema": good.replace(b"clock-floor/v1", b"clock-floor/v2"),
        "extra_key": b'{"extra":1,"floor_utc":"2026-10-17T00:00:00Z","schema":"'
                     + knowledge_clock_floor.SCHEMA.encode() + b'"}\n',
        "not_canonical": good.rstrip(b"\n"),
        "naive_instant": good.replace(b"00:00Z", b"00:00"),
        "oversized": good + b" " * 300,
    }
    events = []
    service = _clocked(node, tmp_path, [NOW, NOW], events)
    if damage in records:
        path.write_bytes(records[damage])
        path.chmod(0o600)
    elif damage == "directory":
        path.mkdir()
    elif damage == "symlink":
        target = tmp_path / "elsewhere"
        target.write_bytes(good)
        path.symlink_to(target)
    elif damage == "group_writable":
        path.write_bytes(good)
        path.chmod(0o620)
    elif damage == "hardlink":
        path.write_bytes(good)
        os.link(path, tmp_path / "second-name")
    elif damage == "missing_directory":
        state.rmdir()
    elif damage == "directory_group_writable":
        state.chmod(0o770)
    assert _lookup(service) == UNTRUSTED_LOOKUP
    assert service.handle(None) == UNTRUSTED_STATUS
    assert [e for e in events if e["event_type"] == "knowledge.clock_untrusted"] == [
        {"event_type": "knowledge.clock_untrusted", "cause": "floor_unavailable"}]


def test_floor_that_cannot_be_kept_fails_closed(node, tmp_path, private_os):
    from test_knowledge_lookup import admit_rows

    admit_rows(node, [{"technique_id": "T1110", "name": "static"}])
    fake = private_os(knowledge_clock_floor)

    def refused(*args, **kwargs):
        raise OSError(28, "no space")

    fake.rename = refused
    service = _clocked(node, tmp_path, [NOW, NOW])
    assert _lookup(service) == UNTRUSTED_LOOKUP
    assert service.handle(None) == UNTRUSTED_STATUS
    assert not (floor_dir(tmp_path) / knowledge_clock_floor.FILENAME).exists()


def test_floor_unreadable_by_permission_fails_closed(node, tmp_path, private_os):
    fake = private_os(knowledge_clock_floor)
    original = os.open

    def denied(path, *args, **kwargs):
        if path == knowledge_clock_floor.FILENAME:
            raise PermissionError(13, "denied")
        return original(path, *args, **kwargs)

    floor_dir(tmp_path)
    service = _clocked(node, tmp_path, [NOW, NOW])
    service.handle(None)  # first write succeeds and is read back
    fake.open = denied
    assert service.handle(None) == UNTRUSTED_STATUS


def test_floor_is_raise_only_and_writes_are_bounded(node, tmp_path):
    state = floor_dir(tmp_path)
    path = state / knowledge_clock_floor.FILENAME
    floor = ClockFloor(state)
    assert floor.admit("2026-10-18T00:00:00.900000Z") is True
    # Truncated to seconds: the persisted floor never exceeds an observed instant.
    assert knowledge_clock_floor.decode_floor(path.read_bytes()) == \
        knowledge_clock_floor._instant("2026-10-18T00:00:00Z")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    first = path.read_bytes()
    before = path.stat().st_mtime_ns
    assert floor.admit("2026-10-18T00:00:00.950000Z") is True
    # Within the same whole second: no write.
    assert path.read_bytes() == first and path.stat().st_mtime_ns == before
    # The in-process floor is exact even within that second.
    assert floor.admit("2026-10-18T00:00:00.920000Z") is False
    # A later whole second is persisted before the answer.
    assert floor.admit("2026-10-18T00:00:01.100000Z") is True
    assert b"2026-10-18T00:00:01Z" in path.read_bytes()
    assert ClockFloor(state).admit("2026-10-18T00:00:00.999999Z") is False
    assert not (state / ".clock-floor.json.partial").exists()


def test_restart_between_observations_still_detects_regression(node, tmp_path):
    """T0 and T0+59s answered, then a crash: T0+1s must not revive a T0+30s row."""
    from test_knowledge_lookup import admit_rows

    t0, t30, t59, t1 = ("2026-10-18T00:00:00Z", "2026-10-18T00:00:30Z",
                        "2026-10-18T00:00:59Z", "2026-10-18T00:00:01Z")
    admit_rows(node, [{"technique_id": "T1110", "name": "dated", "agg_next_expiry": t30}])
    first = _clocked(node, tmp_path, [t0, t59])
    assert _lookup(first)["refs"]
    assert _lookup(first) == {"refs": [], "reason_code": "no_context"}
    # No orderly shutdown: a new process on the same floor.
    restarted = _clocked(node, tmp_path, [t1, t1])
    assert _lookup(restarted) == UNTRUSTED_LOOKUP
    assert restarted.handle(None) == UNTRUSTED_STATUS
    floor = ClockFloor(floor_dir(tmp_path))
    assert floor.admit(t30) is False and floor.admit(t59) is True


def test_floor_owned_by_another_uid_is_refused(node, tmp_path):
    state = floor_dir(tmp_path)
    ClockFloor(state).admit(NOW)
    other = os.geteuid() + 1
    with pytest.raises(knowledge_clock_floor.FloorUnavailable):
        ClockFloor(state, owner=other).admit(NOW)
    service = daemon.KnowledgeLiteService(root=node[1], trust_root=node[2],
                                          clock_floor=ClockFloor(state, owner=other),
                                          now=lambda: NOW)
    assert service.handle(None) == UNTRUSTED_STATUS


def test_file_owned_by_another_uid_is_refused(node, tmp_path, private_os):
    """The leaf is ours, the record is not: the file check alone refuses."""
    state = floor_dir(tmp_path)
    ClockFloor(state).admit(NOW)
    fake = private_os(knowledge_clock_floor)
    real = os.fstat

    def fstat(fd):
        info = real(fd)
        if not stat.S_ISREG(info.st_mode):
            return info
        values = list(info)
        values[stat.ST_UID] = os.geteuid() + 1
        return os.stat_result(values)

    fake.fstat = fstat
    with pytest.raises(knowledge_clock_floor.FloorUnavailable):
        ClockFloor(state).admit(NOW)


def test_recovery_after_a_forward_jump_by_removing_the_floor(node, tmp_path):
    from test_knowledge_lookup import admit_rows

    admit_rows(node, [{"technique_id": "T1110", "name": "static"}])
    ahead = _clocked(node, tmp_path, ["2031-01-01T00:00:00Z"])
    assert _lookup(ahead)["reason_code"] == "available"
    corrected = _clocked(node, tmp_path, [NOW, NOW])
    assert _lookup(corrected) == UNTRUSTED_LOOKUP
    # The documented recovery: correct the clock, remove the file, restart.
    (floor_dir(tmp_path) / knowledge_clock_floor.FILENAME).unlink()
    recovered = _clocked(node, tmp_path, [NOW, NOW])
    assert _lookup(recovered)["reason_code"] == "available"
    assert recovered.handle(None)["state"] == "available"


def test_service_requires_a_clock_floor(node):
    _, root, trust, _ = node
    with pytest.raises(TypeError):
        daemon.KnowledgeLiteService(root=root, trust_root=trust, now=lambda: NOW)
    with pytest.raises(TypeError):
        daemon.KnowledgeLiteService(root=root, trust_root=trust, clock_floor=None,
                                    now=lambda: NOW)


# -- knowledge.status display facts (P2) --------------------------------------

def test_status_display_counts_nearest_expiry_and_no_secrets(node):
    from test_knowledge_lookup import admit_rows

    service, root, trust, _ = node
    admit_rows(node, [
        {"technique_id": "T1110", "name": "static one"},
        {"technique_id": "T1046", "name": "static two"},
        {"technique_id": "T1110.001", "name": "later", "agg_next_expiry": "2027-03-01T00:00:00Z"},
        {"technique_id": "T1110.002", "name": "sooner", "agg_next_expiry": "2026-11-01T12:30:45.999Z"},
        {"technique_id": "T1110.003", "name": "expired", "agg_next_expiry": "2020-01-01T00:00:00Z"},
    ])
    result = service.handle(None)
    assert result["state"] == "available"
    assert (result["static_count"], result["current_count"]) == (2, 2)
    # Truncated to seconds: never later than the row's own expiry.
    assert result["next_expiry"] == "2026-11-01T12:30:45Z"
    assert result["signer_key_ids"] == [KEY_ID]
    full = CommissionedLite(root)
    digest = "sha256:" + __import__("hashlib").sha256(
        (root / "admitted/current.tar.gz").read_bytes()).hexdigest()
    assert result["bundle_digest_short"] == digest[:19]
    text = json.dumps(result)
    assert digest not in text and str(root) not in text and str(trust) not in text
    assert full.admitted.name not in text


def test_signer_key_ids_are_sorted_and_capped_at_eight(node):
    import hashlib

    from signing_oracle import sign_detached
    from test_lite_bundle import _tar

    service, root, trust, _ = node
    seeds = {f"signer-{i:02d}": bytes([i + 1]) * 32 for i in range(10)}
    keys = {name: SigningKey(seed).verify_key.encode() for name, seed in seeds.items()}
    anchors = "threshold = 10\n[keys]\n" + "".join(
        f'"{name}" = "{key.hex()}"\n' for name, key in keys.items())
    (root / "trust/anchors.toml").write_text(anchors)
    (trust / "trust/anchors.toml").write_text(anchors)
    TrustStore(trust).path.unlink()
    TrustStore(trust).pin([key.hex() for key in keys.values()], commissioning_digest=DIGEST,
                         pinned_at=NOW, actor="test")
    table = json.dumps({"technique_id": "T1110", "name": "static"}).encode() + b"\n"
    manifest = json.dumps({"bundle_format_version": 1, "bundle_version": 5, "kind": "full",
                           "files": {"tables/attack_technique.jsonl": hashlib.sha256(table).hexdigest()}},
                          indent=2, sort_keys=True).encode()
    signatures = "".join(f"{name}:{sign_detached(seed=seed, message=manifest).hex()}\n"
                         for name, seed in reversed(list(seeds.items())))
    (root / "inbox/bundle.tar.gz").write_bytes(_tar({
        "manifest.json": manifest, "manifest.sig": signatures.encode(),
        "tables/attack_technique.jsonl": table}))
    importer = LiteImport(CommissionedLite(root))
    assert importer.import_entry(importer.list_inbox()[0].entry_id, now=NOW).admitted
    result = service.handle(None)
    assert result["state"] == "available"
    assert result["signer_key_ids"] == [f"signer-{i:02d}" for i in range(8)]
