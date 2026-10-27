"""Real processes: entry and reference daemons over SO_PEERCRED sockets.

No model host runs, no model is installed or admitted, and local model
admission stays closed. The reference daemon starts through its own `main()`
and reads a test-signed, really activated Mission Pack through the same
holder and verification as production; only the root-owned config read is
replaced by the test's context, as in `test_playbook_selection.py`. The
activation library decides which units such a node may run through its
normal grant path. None of this is systemd, hardware or HG-05 evidence.
"""

import json
import os
import socket
import sys
import tempfile
import threading
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_playbooks
from azazel_nexus_runtime import mio_referenced as referenced
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.transport import read_frame, send_frame
from test_mission_pack import NOW
from test_playbook_selection import activate

from azazel_nexus import model_admission
from azazel_nexus.activation import LOCAL_MODEL_PROVIDER
from azazel_nexus.local_advisory import HANDOFF_NOTICE, read_reference
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.routing import Route

pytest_plugins = ["test_mission_pack", "test_playbook_selection"]
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_PEERCRED required")

FRAME = {"request_id": "core-reference", "privacy_class": "P2-mission",
         "question": "SSH host-1 T1110.003",
         "context": [{"kind": "auth_log", "text": "Password spray against host-1"}]}


@pytest.fixture
def root(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="azref-", dir="/tmp") as directory:
        base = Path(directory)
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(runtime_paths, "ROOT", base)
        for leaf in ("mio-entry", "mio-advise", "mio", "remote", "mio-reference"):
            runtime_paths.socket_path(leaf).parent.mkdir(parents=True)
        runtime_paths.mio_state_dir().mkdir(parents=True)
        runtime_paths.mio_reference_state_dir().mkdir(parents=True)
        real_getpwnam = client.pwd.getpwnam

        def getpwnam(name):
            # Only the socket owners the client verifies; the explainer and
            # arbiter accounts stay absent, so this caller is neither.
            if name in {"azmioref", "azmio", "azremote", "azmioentry"}:
                return SimpleNamespace(pw_uid=os.getuid())
            if name in {"azexplain", "azarbiter"}:
                raise KeyError(name)
            return real_getpwnam(name)

        monkeypatch.setattr(client.pwd, "getpwnam", getpwnam)
        monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
        # The test's own uid stands in for azmioentry: the reference verb
        # admits a SERVICE principal only, so it is classified as one.
        policy = PrincipalPolicy(os.getgid(), frozenset({os.getuid()}))
        monkeypatch.setattr(PrincipalPolicy, "resolve", lambda **kw: policy)
        # Pack validity is judged at the fixture's time, not the wall clock.
        monkeypatch.setattr(referenced, "PlaybookSelectionHolder",
                            partial(mio_playbooks.PlaybookSelectionHolder, clock=lambda: NOW))
        yield base


class Daemon:
    def __init__(self, main):
        self.ready, self.stop, self.errors = threading.Event(), threading.Event(), []
        self.thread = threading.Thread(target=self._run, args=(main,))

    def _run(self, main):
        try:
            main([], ready=self.ready.set, stop=self.stop.is_set)
        except BaseException as error:  # noqa: BLE001 - surfaced to the test
            self.errors.append(error)
            self.ready.set()

    def __enter__(self):
        self.thread.start()
        assert self.ready.wait(10)
        if self.errors:
            raise self.errors[0]
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(10)
        assert not self.thread.is_alive()


def advise(frame=FRAME, deadline_ms=2000):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(runtime_paths.socket_path("mio-entry")))
        send_frame(connection, {"verb": "mio.advise", "arguments": {"deadline_ms": deadline_ms},
                                "event": frame})
        connection.shutdown(socket.SHUT_WR)
        response = json.loads(read_frame(connection))
    assert response["ok"] is True, response
    return response["result"]


def route_events():
    chain = RouteChain(runtime_paths.mio_state_dir() / "route")
    chain.verify()
    return [item.event for item in chain]


def test_no_model_admission_on_this_node():
    """The precondition, read from the code, not assumed."""
    from azazel_nexus_runtime.activated import wired_capabilities

    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    assert LOCAL_MODEL_PROVIDER not in wired_capabilities()


def test_verified_playbook_reference_with_no_model(root, selection_node, monkeypatch):
    ctx = activate(selection_node)
    monkeypatch.setattr(mio_playbooks, "selection_context", lambda config, pack_root: ctx)
    monkeypatch.setattr(referenced, "mission_pack_root", lambda: ctx.root)
    with Daemon(referenced.main), Daemon(entry.main):
        assert not runtime_paths.socket_path("mio").exists(), "no model host runs"
        reply = advise()
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["reference_status"] == "attached"
    assert reply["handoff"]["kind"] == "deterministic_reference"
    assert reply["handoff"]["ai_attempts"] == 0
    assert "advice" not in reply and "fields" not in reply
    document = read_reference(reply["reference"])
    assert document["provenance"] == {**document["provenance"], "source": "keyword",
                                      "model_id": "deterministic"}
    recorded = route_events()
    assert [e["event_type"] for e in recorded if e["event_type"].startswith("mio.route.")][-2:] == [
        "mio.route.handoff", "mio.route.terminal"]
    handoff = next(e for e in recorded if e["event_type"] == "mio.entry.handoff")
    assert handoff["reference_status"] == "attached" and handoff["reference_reason"] is None
    ledger = (runtime_paths.mio_reference_state_dir() / "reference.jsonl").read_text()
    assert "mio.local.playbook_selection" in ledger and '"active"' in ledger
    # Nothing of the situation is written by the reference daemon.
    assert "Password spray" not in ledger and "host-1" not in ledger


def test_no_pack_gives_the_fixed_notice_and_reason(root):
    with Daemon(referenced.main), Daemon(entry.main):
        reply = advise()
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["reference_status"] == "unavailable"
    assert reply["reference_reason"] == "no_pack"
    assert reply["handoff"] == {"kind": "deterministic_notice", "notice": HANDOFF_NOTICE["en"],
                                "ai_attempts": 0, "failures": []}
    assert "reference" not in reply and "advice" not in reply


def test_reference_daemon_down_still_ends_in_the_handoff(root):
    with Daemon(entry.main):
        reply = advise()
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["reference_reason"] == "reference_service_unavailable"
    assert reply["handoff"]["kind"] == "deterministic_notice"


def test_the_reference_daemon_refuses_everyone_but_a_service(root, monkeypatch):
    monkeypatch.setattr(PrincipalPolicy, "resolve",
                        lambda **kw: PrincipalPolicy(os.getgid(), frozenset()))
    with Daemon(referenced.main):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(runtime_paths.socket_path("mio-reference")))
            send_frame(connection, {"verb": "mio.reference", "arguments": {"deadline_ms": 500},
                                    "event": FRAME})
            connection.shutdown(socket.SHUT_WR)
            response = json.loads(read_frame(connection))
    assert response == {"ok": False, "refusal": "principal_denied"}


def test_the_activation_library_grants_the_reference_without_model_wiring(tmp_path):
    """The normal grant path: nothing wired, so the model host stays masked."""
    from test_activation import ACTOR, NOW as ACTIVATION_NOW, _controller, _lease

    from azazel_nexus.activation import UnitState

    controller, units, _, _ = _controller(tmp_path)
    outcome = controller.activate(now=ACTIVATION_NOW, actor=ACTOR, lease=_lease(), wired=())
    assert "azazel-mio-referenced.service" in outcome.granted
    assert "azazel-mio-entryd.service" in outcome.granted
    assert "azazel-mio-locald.service" in outcome.withheld
    assert units.state("azazel-mio-locald.service") is UnitState.MASKED
    verdict = next(v for v in outcome.verdicts if v.unit == "azazel-mio-locald.service")
    assert verdict.reason.startswith("wiring_absent") and LOCAL_MODEL_PROVIDER in verdict.reason


def test_a_remote_daemon_that_never_answers_cannot_hold_the_request(root):
    """Real socket: accepts, reads, never replies. The attempt's share of the
    one deadline is the socket timeout, not the 0.5 s probe default."""
    import time

    from azazel_nexus_runtime.transport import bind_socket

    listener = bind_socket(runtime_paths.socket_path("remote"), expected_gid=os.getgid())
    held = []
    stop = threading.Event()

    def accept():
        listener.settimeout(0.05)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                continue
            held.append(connection)  # never answered, never closed

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        began = time.monotonic()
        reply = client.RemoteSocketClient().handle(None, deadline_ms=120)
        elapsed = time.monotonic() - began
    finally:
        stop.set()
        thread.join(5)
        for connection in held:
            connection.close()
        listener.close()
    assert reply == {"outcome": "unavailable", "refusal": "remote_unavailable"}
    assert held, "the daemon accepted the connection"
    assert 0.1 <= elapsed < 0.4
