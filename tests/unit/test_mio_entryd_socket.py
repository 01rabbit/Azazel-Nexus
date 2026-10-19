"""Linux SO_PEERCRED round trips, using short AZAZEL_ROOT contract paths."""

import json
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.transport import bind_socket, read_frame, send_frame

from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_PEERCRED required")


@pytest.fixture
def root(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="azmio-", dir="/tmp") as directory:
        base = Path(directory)
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(runtime_paths, "ROOT", base)

        path = runtime_paths.socket_path

        for leaf in ("mio-entry", "mio-advise", "mio", "remote"):
            path(leaf).parent.mkdir(parents=True)
        runtime_paths.mio_state_dir().mkdir(parents=True)
        monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
        monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
        policy = PrincipalPolicy(os.getgid(), frozenset())
        monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: policy)
        yield path


def test_main_real_round_trip_records_handoff(root):
    ready = threading.Event()
    stop = threading.Event()
    errors = []

    def run():
        try:
            entry.main([], ready=ready.set, stop=stop.is_set)
        except (OSError, ValueError, RuntimeError) as error:
            errors.append(error)
            ready.set()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert ready.wait(5)
        if errors:
            raise errors[0]
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(root("mio-entry")))
            send_frame(connection, {"verb": "mio.route", "arguments": {
                "privacy_class": PrivacyClass.P0_PUBLIC.value, "deadline_ms": 1000,
            }})
            connection.shutdown(socket.SHUT_WR)
            response = json.loads(read_frame(connection))
        assert response["ok"] is True
        assert response["result"]["route"] == Route.DETERMINISTIC_HANDOFF.value
        ledger = RouteChain(runtime_paths.mio_state_dir() / "route")
        ledger.verify()
        events = [item.event for item in ledger]
        assert response["result"]["ledger_seq"] == len(events)
        availability = next(e for e in events if e["event_type"] == "mio.entry.availability")
        assert availability["local"] == "local_unavailable"
        assert availability["remote"] == "remote_unavailable"
        assert response["result"]["reason"]
        # The explainer's listener registers mio.advise alone: routing is not a verb there.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(root("mio-advise")))
            send_frame(connection, {"verb": "mio.route", "arguments": {
                "privacy_class": PrivacyClass.P0_PUBLIC.value, "deadline_ms": 1000,
            }})
            connection.shutdown(socket.SHUT_WR)
            refused = json.loads(read_frame(connection))
        assert refused == {"ok": False, "refusal": "unknown_verb"}
    finally:
        stop.set()
        thread.join(5)
    assert not thread.is_alive()
    assert not root("mio-entry").exists()
    assert not root("mio-advise").exists()


def test_per_uid_rate_limit_spans_both_listeners(root):
    # One kernel-reported uid has one bucket, whichever listener it reaches:
    # the explainer's mio-advise listener cannot be used to bypass the limit
    # on the operator listener, nor the other way round (#211 S4, #213 O1).
    ready = threading.Event()
    stop = threading.Event()
    errors = []

    def run():
        try:
            entry.main([], ready=ready.set, stop=stop.is_set)
        except (OSError, ValueError, RuntimeError) as error:
            errors.append(error)
            ready.set()

    def exchange(leaf, document):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(root(leaf)))
            send_frame(connection, document)
            connection.shutdown(socket.SHUT_WR)
            return json.loads(read_frame(connection))

    route = {"verb": "mio.route", "arguments": {
        "privacy_class": PrivacyClass.P0_PUBLIC.value, "deadline_ms": 1000}}
    # Spends a token, then is refused as a malformed situation frame.
    advise = {"verb": "mio.advise", "arguments": {"deadline_ms": 500}, "event": {"x": 1}}
    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert ready.wait(5)
        if errors:
            raise errors[0]
        for _ in range(entry.RATE_BURST):
            assert exchange("mio-advise", advise) == {"ok": False, "refusal": "malformed_frame"}
        assert exchange("mio-entry", route) == {"ok": False, "refusal": "rate_limited"}
        assert exchange("mio-advise", advise) == {"ok": False, "refusal": "rate_limited"}
        refusals = [item.event for item in RouteChain(runtime_paths.mio_state_dir() / "route")
                    if item.event["event_type"] == "runtime.request_refused"]
        # Aggregated per uid: the first refusal is recorded, the rest counted.
        assert len(refusals) == 1 and refusals[0]["uid"] == os.getuid()
    finally:
        stop.set()
        thread.join(5)
    assert not thread.is_alive()


def test_fake_locald_not_admitted_is_recorded(root):
    listener = bind_socket(root("mio"), expected_gid=os.getgid())
    listener.settimeout(2)
    errors = []
    requests = []

    def serve():
        # One probe: the request reuses the capability sample it triggered.
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                requests.append(json.loads(read_frame(connection)))
                send_frame(connection, {"ok": True, "result": {
                    "readiness": "refused", "reason": "not admitted",
                }})
        except (OSError, ValueError, RuntimeError) as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        service = entry.MioEntryService()
        reply = service.handle(SimpleNamespace(arguments={
            "privacy_class": PrivacyClass.P0_PUBLIC.value, "deadline_ms": 1000,
        }))
        assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
        ledger = RouteChain(service.router.ledger.directory)
        ledger.verify()
        events = [item.event for item in ledger]
        transition = next(e for e in events if e["event_type"] == "mio.capability.transition")
        assert transition["reasons"]["health"]["local"] == "not_admitted"
        availability = next(e for e in events if e["event_type"] == "mio.entry.availability")
        assert availability["local"] == "local_not_admitted"
    finally:
        thread.join(5)
        listener.close()
    assert not errors
    assert not thread.is_alive()
    assert requests == [{"verb": "model.activate", "arguments": {
        "model_id": "uncommissioned", "runtime_id": "uncommissioned",
    }}]
