"""#196 P2: a decoy reach becomes Nexus evidence, never an input to Edge.

`docs/deception-redirect-prerequisites.md` §6 (P2), §7 Q8, §8 and §11. The
event is a closed Fabric `EnvironmentEvent` (`interaction`): bytes received,
truncated and responder, and nothing that could carry what was sent or who
sent it. The intake receives it on a socket of its own, from the azdecoy uid
only, at a bounded rate, stores it in its own evidence leaf labelled as not
Edge's, and never lets it reach the incident tracker.

Every address in this file is from a documentation range (RFC 5737, RFC 3849,
RFC 7042) and every identifier is a placeholder.
"""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
from test_edge_intake import edge_event

from azazel_nexus.decoy_interaction import (
    DECOY_REFUSAL_CODES,
    MAX_BYTES_RECEIVED,
    MAX_INTERACTION_LINE,
    RECORD_KIND,
    RESPONDER_NAMES,
    DecoyEventRefused,
    DecoyInteractionRecord,
    build_interaction,
    incidents_near,
    parse_interaction,
)
from azazel_nexus.edge_intake import REFUSAL_CODES, read_intake_status
from azazel_nexus_runtime import decoy_report
from azazel_nexus_runtime import edge_intaked as daemon
from azazel_nexus_runtime.decoy_loopback import MAX_READ_BYTES, RESPONDERS, Observation
from azazel_nexus_runtime.refusal_log import REFUSAL_EVENT, BoundedRefusalLog

GENERATION = "sha256:" + "ab" * 32
EVENT_ID = "evt-" + "0" * 32
EDGE_UID, DECOY_UID = 123, 456


def fields(**overrides):
    value = dict(
        event_id=EVENT_ID,
        decoy_name="ssh-decoy",
        generation_digest=GENERATION,
        node_id="node-placeholder",
        observed_at="2026-10-21T00:00:00Z",
        bytes_received=12,
        truncated=False,
        responder="ssh-banner",
    )
    value.update(overrides)
    return value


def event(**overrides):
    return build_interaction(**fields(**overrides)).as_dict()


def refused_code(value) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    with pytest.raises(DecoyEventRefused) as caught:
        parse_interaction(raw)
    return caught.value.code


# -- the closed shape ------------------------------------------------------


def test_the_event_is_a_closed_interaction_with_three_metadata_keys():
    value = event()
    assert value == {
        "schema_version": "environment-event/v0.1",
        "event_id": EVENT_ID,
        "environment_id": "ssh-decoy",
        "package_id": GENERATION,
        "node_id": "node-placeholder",
        "event_type": "interaction",
        "observed_at": "2026-10-21T00:00:00Z",
        "evidence_refs": [],
        "metadata": {"bytes_received": 12, "truncated": False, "responder": "ssh-banner"},
    }
    interaction = parse_interaction(json.dumps(value).encode())
    assert interaction.as_dict() == value
    assert interaction.line.endswith(b"\n") and interaction.line.count(b"\n") == 1
    assert len(interaction.encoded) < MAX_INTERACTION_LINE
    assert interaction.digest.startswith("sha256:")


def test_the_library_bounds_equal_the_decoy_runtime():
    assert RESPONDER_NAMES == set(RESPONDERS)
    assert MAX_BYTES_RECEIVED == MAX_READ_BYTES


def test_every_decoy_refusal_code_is_one_the_status_reader_accepts():
    assert DECOY_REFUSAL_CODES <= REFUSAL_CODES


@pytest.mark.parametrize("extra", ["payload", "data", "peer", "src_ip", "peer_address",
                                   "credentials", "decision"])
def test_an_extra_top_level_field_is_refused(extra):
    value = event()
    value[extra] = "x"
    assert refused_code(value) == "DECOY_SHAPE"


@pytest.mark.parametrize("extra", ["payload", "password", "username", "src_ip", "peer_port",
                                   "first_bytes"])
def test_an_extra_metadata_key_is_refused(extra):
    value = event()
    value["metadata"][extra] = "x"
    assert refused_code(value) == "DECOY_SHAPE"


@pytest.mark.parametrize("missing", ["event_id", "metadata", "evidence_refs", "node_id"])
def test_a_missing_field_is_refused(missing):
    value = event()
    del value[missing]
    assert refused_code(value) == "DECOY_SHAPE"


@pytest.mark.parametrize(("field", "value"), [
    ("environment_id", "192.0.2.10"),
    ("environment_id", "198-51-100-7"),
    ("environment_id", "ssh-203-0-113-9"),
    ("node_id", "2001:db8::1"),
    ("node_id", "02-00-5e-00-53-01"),
    ("event_id", "fe80::1%eth0"),
])
def test_an_identifier_that_looks_like_an_address_is_refused_as_one(field, value):
    with pytest.raises(DecoyEventRefused) as caught:
        build_interaction(**fields(**{
            {"environment_id": "decoy_name"}.get(field, field): value}))
    assert caught.value.code == "DECOY_ADDRESS"
    raw = event()
    raw[field] = value
    assert refused_code(raw) == "DECOY_ADDRESS"


def test_an_address_as_the_responder_is_refused_as_one():
    raw = event()
    raw["metadata"]["responder"] = "192.0.2.10"
    assert refused_code(raw) == "DECOY_ADDRESS"


@pytest.mark.parametrize("responder", [
    "SSH-2.0-OpenSSH_8.4p1 Debian-5",  # a banner is a payload, not a name
    "root:placeholder",
    "unknown-banner",
    "",
])
def test_a_responder_outside_the_table_is_refused(responder):
    raw = event()
    raw["metadata"]["responder"] = responder
    assert refused_code(raw) == "DECOY_RANGE"


@pytest.mark.parametrize(("key", "value", "code"), [
    ("bytes_received", MAX_BYTES_RECEIVED + 1, "DECOY_RANGE"),
    ("bytes_received", -1, "DECOY_RANGE"),
    ("bytes_received", True, "DECOY_TYPE"),
    ("bytes_received", 1.5, "DECOY_TYPE"),
    ("bytes_received", "12", "DECOY_TYPE"),
    ("truncated", 1, "DECOY_TYPE"),
    ("truncated", "false", "DECOY_TYPE"),
    ("responder", ["ssh-banner"], "DECOY_TYPE"),
])
def test_metadata_values_are_typed_and_bounded(key, value, code):
    raw = event()
    raw["metadata"][key] = value
    assert refused_code(raw) == code


def test_truncated_only_at_the_read_ceiling():
    assert event(bytes_received=MAX_BYTES_RECEIVED, truncated=True)["metadata"]["truncated"]
    raw = event()
    raw["metadata"]["truncated"] = True
    assert refused_code(raw) == "DECOY_RANGE"


@pytest.mark.parametrize(("field", "value", "code"), [
    ("schema_version", "environment-event/v0.2", "DECOY_RANGE"),
    ("event_type", "activated", "DECOY_RANGE"),
    ("evidence_refs", ["sha256:" + "cd" * 32], "DECOY_RANGE"),
    ("evidence_refs", "none", "DECOY_TYPE"),
    ("observed_at", "2026-10-21T00:00:00+09:00", "DECOY_RANGE"),
    ("observed_at", 1, "DECOY_TYPE"),
    ("package_id", "deception-lite", "DECOY_RANGE"),
    ("event_id", "evt-" + "0" * 31, "DECOY_RANGE"),
    ("environment_id", "Decoy.One", "DECOY_RANGE"),
    ("node_id", "x" * 200, "DECOY_RANGE"),
    ("metadata", [], "DECOY_TYPE"),
])
def test_fixed_and_pattern_bound_fields(field, value, code):
    raw = event()
    raw[field] = value
    assert refused_code(raw) == code


@pytest.mark.parametrize(("raw", "code"), [
    (b"{", "DECOY_JSON"),
    (b"\xff", "DECOY_JSON"),
    (b'{"a": NaN}', "DECOY_JSON"),
    (b'{"event_id": "a", "event_id": "b"}', "DECOY_JSON"),
    (b"[]", "DECOY_SHAPE"),
    (b" " * (MAX_INTERACTION_LINE + 1), "DECOY_TOO_LARGE"),
])
def test_the_line_itself_is_bounded(raw, code):
    assert refused_code(raw) == code


def test_a_refusal_never_carries_the_input():
    raw = event()
    raw["metadata"]["payload"] = "placeholder-secret"
    with pytest.raises(DecoyEventRefused) as caught:
        parse_interaction(json.dumps(raw).encode())
    assert "placeholder-secret" not in str(caught.value)
    assert str(caught.value) == "DECOY_SHAPE"


def test_the_shape_is_a_valid_fabric_environment_event():
    fabric = pytest.importorskip("azazel_fabric")
    from azazel_nexus.fabric_boundary import FABRIC_PIN

    if fabric.__version__ != FABRIC_PIN.lstrip("v"):
        pytest.skip("pinned Fabric required")
    from azazel_fabric.deception_contracts.models import EnvironmentEvent

    model = EnvironmentEvent.model_validate(event())
    assert model.event_type == "interaction"
    assert model.metadata == {"bytes_received": 12, "truncated": False,
                              "responder": "ssh-banner"}


# -- from the decoy's observation ------------------------------------------


def observation(**overrides):
    value = dict(decoy_name="ssh-decoy", at="2026-10-21T00:00:00Z",
                 generation_digest=GENERATION, bytes_received=40,
                 responder="ssh-banner", truncated=False)
    value.update(overrides)
    return Observation(**value)


def test_the_decoy_builds_its_event_from_its_observation():
    interaction = decoy_report.interaction_from_observation(
        observation(), node_id="node-placeholder", event_id=lambda: EVENT_ID)
    value = interaction.as_dict()
    assert value["environment_id"] == "ssh-decoy"
    assert value["package_id"] == GENERATION
    assert value["metadata"] == {"bytes_received": 40, "truncated": False,
                                 "responder": "ssh-banner"}
    fresh = decoy_report.interaction_from_observation(observation(), node_id="node-placeholder")
    assert parse_interaction(fresh.encoded).as_dict()["event_id"].startswith("evt-")


def test_the_observation_has_no_field_that_could_reach_the_event():
    assert set(Observation.__dataclass_fields__) == {
        "decoy_name", "at", "generation_digest", "bytes_received", "responder", "truncated"}


@pytest.mark.parametrize("bad", [
    {"responder": "unknown-banner"},
    {"bytes_received": MAX_READ_BYTES + 1},
    {"decoy_name": "192.0.2.10"},
])
def test_the_decoy_cannot_report_outside_the_shape(bad):
    with pytest.raises(DecoyEventRefused):
        decoy_report.interaction_from_observation(observation(**bad), node_id="node-placeholder")


def test_only_an_observation_is_reported():
    with pytest.raises(DecoyEventRefused):
        decoy_report.interaction_from_observation(
            observation().as_event(), node_id="node-placeholder")


# -- the stored record and its incident ------------------------------------


def stored(at=1000.0, name="ssh-decoy"):
    return DecoyInteractionRecord.receive(
        build_interaction(**fields(decoy_name=name)), lambda: at).as_dict()


def test_the_record_is_labelled_as_not_edge():
    value = stored()
    assert value["kind"] == RECORD_KIND
    assert value["edge_observation"] is False
    assert value["observer"] == "azazel-nexus"
    # An Edge evidence record is {"event", "digest", "received_at"}.
    assert "event" not in value
    assert value["environment_event"]["event_type"] == "interaction"


def incident(ident, port, first, last):
    return {"incident_id": ident, "target_port": port, "first_seen": first,
            "last_seen": last, "src_ip": "192.0.2.50"}


def test_an_interaction_joins_an_incident_by_decoy_port_and_time_only():
    incidents = [
        incident("inc-near", 2222, 900.0, 950.0),
        incident("inc-later", 2222, 1200.0, 1300.0),
        incident("inc-other-port", 8080, 990.0, 1010.0),
        incident("inc-old", 2222, 0.0, 100.0),
    ]
    ports = {"ssh-decoy": 2222}
    assert incidents_near(stored(), incidents, decoy_ports=ports) == ["inc-later", "inc-near"]
    assert incidents_near(stored(), incidents, decoy_ports=ports, window_s=60) == ["inc-near"]
    assert incidents_near(stored(name="web-decoy"), incidents, decoy_ports=ports) == []


def test_an_edge_record_is_never_joined_as_an_interaction():
    edge_record = {"event": edge_event(), "digest": "sha256:" + "0" * 64, "received_at": 1000.0}
    assert incidents_near(edge_record, [incident("inc-a", 2222, 900.0, 1100.0)],
                          decoy_ports={"ssh-decoy": 2222}) == []
    forged = dict(stored(), edge_observation=True)
    assert incidents_near(forged, [incident("inc-a", 2222, 900.0, 1100.0)],
                          decoy_ports={"ssh-decoy": 2222}) == []


# -- the intake's decoy socket ---------------------------------------------


def wait_for(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


class Refusals:
    def __init__(self):
        self.events = []

    def __call__(self, event):
        self.events.append(event)


def peer_by_socket(connection):
    """The test seam for SO_PEERCRED: which socket was reached decides the uid."""
    return DECOY_UID if str(connection.getsockname()).endswith("decoy.sock") else EDGE_UID


@pytest.fixture
def running():
    servers = []
    with tempfile.TemporaryDirectory(prefix="p2-", dir="/tmp") as directory:
        root = Path(directory)

        def start(*, decoy=True, decoy_path=None, **kwargs):
            leaf = root / str(len(servers))
            leaf.mkdir()
            state = leaf / "state"
            state.mkdir()
            kwargs.setdefault("decoy_refusals", Refusals())
            server = daemon.IntakeServer(
                path=leaf / "in.sock",
                state=state,
                status_path=leaf / "status.json",
                edge_uid=EDGE_UID,
                peer_uid=peer_by_socket,
                decoy_path=(decoy_path or leaf / "decoy.sock") if decoy else None,
                decoy_uid=DECOY_UID if decoy else None,
                **kwargs,
            )
            stop, ready = threading.Event(), threading.Event()
            errors = []

            def run():
                try:
                    server.serve(stop=stop.is_set, ready=ready.set)
                except BaseException as exc:  # noqa: BLE001 - relay to pytest
                    errors.append(exc)
                    ready.set()

            thread = threading.Thread(target=run)
            servers.append((server, stop, thread, errors))
            thread.start()
            assert ready.wait(3)
            assert not errors
            return server

        yield start
        for server, stop, thread, errors in servers:
            stop.set()
            thread.join(4)
            assert not thread.is_alive()
            assert not errors
            assert not server.path.exists()
            if server.decoy_path is not None:
                assert not server.decoy_path.exists()


def send(path, data):
    """Send one line and close the write half; return whatever came back."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        try:
            client.sendall(data)
            client.shutdown(socket.SHUT_WR)
            return client.recv(64)
        except OSError:  # a refused peer may be closed before it finishes
            return None


def interaction_line(**overrides):
    return build_interaction(**fields(**overrides)).line


def ledger_types(server):
    lines = []
    for path in sorted((server.state / "incidents").glob("*.jsonl")):
        lines += [json.loads(line)["event"]["event_type"] for line in path.read_text().splitlines()]
    return lines


def test_an_interaction_is_stored_as_nexus_evidence_and_not_as_edge(running):
    server = running()
    assert send(server.decoy_path, interaction_line()) == b""  # nothing is answered
    wait_for(lambda: server.decoy_accepted == 1)
    (path,) = (server.state / "decoy-evidence").glob("*.jsonl")
    record = json.loads(path.read_text())
    assert record["kind"] == RECORD_KIND and record["edge_observation"] is False
    assert record["environment_event"]["metadata"]["responder"] == "ssh-banner"
    assert path.stat().st_mode & 0o777 == 0o640
    # Edge's evidence, counters, tracker and incident ledger are untouched.
    assert list((server.state / "evidence").glob("*.jsonl")) == []
    assert (server.accepted, server.processed, server.tracker.incidents) == (0, 0, {})
    assert ledger_types(server) == ["edge.incident.reset"]
    assert server.decoy_path.stat().st_mode & 0o777 == 0o660
    server._status()
    status = read_intake_status(server.status_path.read_bytes())
    assert status["decoy"]["accepted"] == 1
    assert status["accepted"] == 0 and not any(status["refused"].values())


def test_edge_and_decoy_records_stay_apart(running):
    server = running()
    send(server.path, json.dumps(edge_event()).encode() + b"\n")
    send(server.decoy_path, interaction_line())
    wait_for(lambda: server.accepted == 1 and server.decoy_accepted == 1)
    (edge,) = (server.state / "evidence").glob("*.jsonl")
    (decoy,) = (server.state / "decoy-evidence").glob("*.jsonl")
    assert set(json.loads(edge.read_text())) == {"event", "digest", "received_at"}
    assert json.loads(decoy.read_text())["kind"] == RECORD_KIND
    assert ledger_types(server) == ["edge.incident.reset", "edge.incident.opened"]


def test_a_decoy_line_on_edges_socket_and_an_edge_line_on_the_decoys_are_refused(running):
    server = running()
    send(server.path, interaction_line())
    send(server.decoy_path, json.dumps(edge_event()).encode() + b"\n")
    stats = {"schema": "azazel-edge/forward-stats/v1", "dropped": 0, "failed": 0,
             "sent": 1, "since": 1}
    send(server.decoy_path, json.dumps(stats).encode() + b"\n")
    wait_for(lambda: server.refused["EDGE_SHAPE"] == 1 and server.refused["DECOY_SHAPE"] == 1
             and server.refused["DECOY_TOO_LARGE"] == 1)
    assert server.edge_forward is None
    assert server.accepted == server.decoy_accepted == 0


def test_only_the_decoy_uid_may_send(running):
    server = running()
    server.peer_uid = lambda _: EDGE_UID  # Edge's uid is not the decoy's
    send(server.decoy_path, interaction_line())
    wait_for(lambda: server.refused["decoy_peer_refused"] == 1)
    assert server.decoy_refusals.events == [
        {"event_type": REFUSAL_EVENT, "uid": EDGE_UID, "reason": "decoy_peer_refused"}]

    def unknown(_):
        raise OSError("placeholder")

    server.peer_uid = unknown
    send(server.decoy_path, interaction_line())
    wait_for(lambda: server.refused["decoy_peer_refused"] == 2)
    assert server.decoy_refusals.events[-1]["uid"] is None
    assert server.decoy_accepted == 0
    assert not (server.state / "decoy-evidence").exists() or not list(
        (server.state / "decoy-evidence").glob("*.jsonl"))


def test_an_address_or_a_payload_is_refused_and_logged_without_the_value(running):
    server = running()
    raw = event()
    raw["environment_id"] = "192.0.2.10"
    send(server.decoy_path, json.dumps(raw).encode() + b"\n")
    raw = event()
    raw["metadata"]["payload"] = "placeholder-secret"
    send(server.decoy_path, json.dumps(raw).encode() + b"\n")
    send(server.decoy_path, b"x" * (MAX_INTERACTION_LINE + 10) + b"\n")
    wait_for(lambda: len(server.decoy_refusals.events) == 3)
    assert [e["reason"] for e in server.decoy_refusals.events] == [
        "DECOY_ADDRESS", "DECOY_SHAPE", "DECOY_TOO_LARGE"]
    assert all(e["uid"] == DECOY_UID for e in server.decoy_refusals.events)
    assert "192.0.2.10" not in json.dumps(server.decoy_refusals.events)
    assert "placeholder-secret" not in json.dumps(server.decoy_refusals.events)
    assert server.decoy_accepted == 0


def test_the_decoy_rate_is_bounded(running):
    server = running(decoy_per_minute=2)
    for _ in range(4):
        send(server.decoy_path, interaction_line())
    wait_for(lambda: server.decoy_accepted == 2 and server.refused["decoy_rate_limited"] == 2)
    (path,) = (server.state / "decoy-evidence").glob("*.jsonl")
    assert len(path.read_text().splitlines()) == 2


def test_a_full_decoy_day_does_not_touch_edge_evidence(running, monkeypatch):
    monkeypatch.setattr(daemon, "DECOY_SEGMENT_BYTES", 1000)
    server = running()
    send(server.decoy_path, interaction_line())
    send(server.decoy_path, interaction_line())
    wait_for(lambda: server.refused["decoy_evidence_segment_full"] == 1)
    send(server.path, json.dumps(edge_event()).encode() + b"\n")
    wait_for(lambda: server.accepted == 1)
    assert server.decoy_accepted == 1
    assert not server.storage_failed


def test_decoy_readers_never_take_edges_slots(running):
    server = running(read_deadline=0.3)
    held = []
    try:
        for _ in range(daemon.DECOY_MAX_CONNECTIONS + 2):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            held.append(client)
            client.connect(str(server.decoy_path))
            client.sendall(b"{")
        wait_for(lambda: server.refused["decoy_overloaded"] == 2)
        send(server.path, json.dumps(edge_event()).encode() + b"\n")
        wait_for(lambda: server.accepted == 1)
        wait_for(lambda: server.refused["decoy_read_deadline"] == daemon.DECOY_MAX_CONNECTIONS)
        assert server.refused["overloaded"] == 0
    finally:
        for client in held:
            client.close()


def test_without_the_decoy_account_the_intake_serves_edge_as_before(running):
    server = running(decoy=False)
    assert server.decoy_path is None
    send(server.path, json.dumps(edge_event()).encode() + b"\n")
    wait_for(lambda: server.accepted == 1)
    assert not (server.state / "decoy-evidence").exists()
    server._status()
    status = read_intake_status(server.status_path.read_bytes())
    assert "decoy" not in status and not any(status["refused"].values())


def test_a_missing_decoy_leaf_leaves_edges_intake_running(running):
    server = running(decoy_path=Path("/tmp/p2-missing-leaf-placeholder/decoy.sock"))
    assert server.refused["decoy_listener_unavailable"] == 1
    assert not server.decoy_listening
    send(server.path, json.dumps(edge_event()).encode() + b"\n")
    wait_for(lambda: server.accepted == 1)
    server._status()
    assert "decoy" not in read_intake_status(server.status_path.read_bytes())


def test_the_refusal_log_is_bounded_per_uid_and_reason(running, tmp_path):
    log = BoundedRefusalLog(tmp_path / "decoy-refusals.jsonl")
    server = running(decoy_refusals=log)
    for _ in range(5):
        send(server.decoy_path, b"{}\n")
    wait_for(lambda: server.refused["DECOY_SHAPE"] == 5)
    lines = (tmp_path / "decoy-refusals.jsonl").read_text().splitlines()
    assert [json.loads(line) for line in lines] == [
        {"event_type": REFUSAL_EVENT, "uid": DECOY_UID, "reason": "DECOY_SHAPE"}]
    assert log.suppressed == 4


def test_the_default_refusal_log_lives_in_the_intakes_private_state(tmp_path):
    server = daemon.IntakeServer(path=tmp_path / "in.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=EDGE_UID)
    assert isinstance(server.decoy_refusals, BoundedRefusalLog)
    assert server.decoy_refusals.path == tmp_path / "decoy-refusals.jsonl"
    assert not server.decoy_enabled


def test_main_opens_the_decoy_socket_only_with_the_decoy_account(monkeypatch):
    import grp
    import pwd

    captured = {}

    class Server:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def serve(self, **_):
            return 0

    class Entry:
        def __init__(self, ident):
            self.pw_uid = self.gr_gid = ident

    def lookup(name):
        if name == "azdecoy" and captured.get("no_decoy"):
            raise KeyError(name)
        return Entry({"azedge": EDGE_UID, "azdecoy": DECOY_UID}[name])

    monkeypatch.setattr(daemon, "IntakeServer", Server)
    monkeypatch.setattr(pwd, "getpwnam", lookup)
    monkeypatch.setattr(grp, "getgrnam", lookup)
    assert daemon.main([]) == 0
    assert captured["decoy_uid"] == captured["decoy_gid"] == DECOY_UID
    assert str(captured["decoy_path"]).endswith("/var/lib/azazel/run/decoy-intake/decoy-intake.sock")
    captured.clear()
    captured["no_decoy"] = True
    assert daemon.main([]) == 0
    assert captured["decoy_path"] is None and captured["decoy_uid"] is None
    assert captured["edge_uid"] == EDGE_UID
