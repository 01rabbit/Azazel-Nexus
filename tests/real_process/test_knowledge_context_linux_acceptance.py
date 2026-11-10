"""Linux isolated acceptance for the Knowledge Context broker boundary (unit 29).

Runs only in the isolated root container runner (`run-docker.sh`), beside the
existing `test_knowledge_context_process_interop.py`, and reuses its helpers.
Everything here is real processes and a real Linux kernel: SO_PEERCRED /
SO_PEERGROUPS on real AF_UNIX sockets, distinct uids, a real Knowledge mTLS
producer process, a real Nexus broker process, restarts by signal.

What is NOT real here (documented in docs/knowledge-context-consumer.md): systemd
itself. Area B uses a `setpriv` process-attribute approximation, labelled as
such; it is not systemd acceptance.

Test-only seams (all outside product code): the broker harness can record the
real producer envelope and, while a control file exists, offer an earlier
envelope at the *network edge* (`KnowledgeClient._post_path`), so replay is
tested through the product's real signature / TTL / request-binding code.
"""

from __future__ import annotations

import errno
import grp
import json
import os
import pwd
import secrets
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from test_knowledge_context_process_interop import (
    ROOT, _PREREQUISITE_ERROR, _drop_to, _normal_entry_advisory, _pki, _ready,
    _wait_socket, pytestmark,  # noqa: F401  (pytestmark re-exported for skip gating)
)
from azazel_nexus.knowledge_context_adapter import (
    KnowledgeContextRefused, read_signed_response,
)
from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRefused, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass
from azazel_nexus.spki import spki_pin

MAX_TTL = 30  # test value; the product has no default (commissioning decision)
QUESTION = "synthetic public context"

CLIENT_SNIPPET = r'''
import errno, json, os, socket, struct, sys, time
spec = json.loads(sys.argv[1])
path = os.path.join(os.environ["AZAZEL_ROOT"],
                    "var/lib/azazel/run/knowledge-context/knowledge-context.sock")
doc = spec["doc"]
args = doc.get("arguments", {})
mono = args.get("deadline_monotonic_ns")
if isinstance(mono, str) and mono.startswith("MONO"):
    args["deadline_monotonic_ns"] = time.monotonic_ns() + int(mono[4:]) * 1_000_000
payload = json.dumps(doc, separators=(",", ":")).encode()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(spec.get("timeout", 12))
try:
    s.connect(path)
except OSError as exc:
    print(json.dumps({"connect": errno.errorcode.get(exc.errno, str(exc.errno))}))
    sys.exit(0)
s.sendall(struct.pack("!I", len(payload)) + payload)
s.shutdown(socket.SHUT_WR)
def rd(n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out
head = rd(4)
if len(head) < 4:
    print(json.dumps({"connect": "ok", "reply": None}))
    sys.exit(0)
body = rd(struct.unpack("!I", head)[0])
print(json.dumps({"connect": "ok", "reply": json.loads(body)}))
'''

BOUNDARY_CLIENT = r'''
import json, sys
from azazel_nexus_runtime.knowledge_context_socket import (
    KnowledgeContextUnavailable, request_context)
try:
    request_context({"privacy_class": "P0-public", "question": "x"}, deadline_s=3)
    print(json.dumps({"outcome": "response"}))
except KnowledgeContextUnavailable as exc:
    print(json.dumps({"outcome": "unavailable", "detail": str(exc),
                      "cause": type(exc.__cause__).__name__ if exc.__cause__ else None}))
'''

IMPOSTOR = r'''
import json, os, socket, stat, sys, time
path = sys.argv[1]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
os.chmod(path, 0o660)
server.listen(4)
print(json.dumps({"ready": True, "uid": os.getuid()}), flush=True)
server.settimeout(8)
accepted = 0
received = 0
try:
    conn, _ = server.accept()
    accepted = 1
    conn.settimeout(1.0)
    try:
        received = len(conn.recv(4096))
    except socket.timeout:
        received = 0
    conn.close()
except socket.timeout:
    pass
print(json.dumps({"accepted": accepted, "received": received}), flush=True)
'''


def _set_socket(path, uid, gid, mode):
    os.chown(path, 0, 0)  # the runner has no CAP_FOWNER: chmod needs root ownership
    os.chmod(path, mode)
    os.chown(path, uid, gid)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _doc(question=QUESTION, *, mono="MONO+8000", deadline_ms=8000, args=None, top=None,
         frame=None):
    arguments = {"deadline_ms": deadline_ms, "deadline_monotonic_ns": mono}
    arguments.update(args or {})
    document = {"verb": "knowledge.context", "arguments": arguments,
                "event": {"frame": frame or {"privacy_class": "P0-public",
                                             "question": question}}}
    document.update(top or {})
    return document


class Stack:
    """Producer + broker (+ optional locald/entryd) in the isolated container."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.pki = _pki(tmp / "pki")
        self.seed = secrets.token_hex(32)  # test-only key, never printed or stored in evidence
        self.port = _free_port()
        self.service_root = tmp / "service-root"
        self.producer: subprocess.Popen | None = None
        self.broker: subprocess.Popen | None = None
        self.locald: subprocess.Popen | None = None
        self.entryd: subprocess.Popen | None = None
        self.egress = pwd.getpwnam("azknowledgeegress")
        self.mio = pwd.getpwnam("azmio")
        self.entry = pwd.getpwnam("azmioentry")
        self.operator = pwd.getpwnam("azoperator")
        self.ctx_gid = grp.getgrnam("azknowledge-context-client").gr_gid
        self.operator_gid = grp.getgrnam("azazel-operator").gr_gid
        self.server_der = ssl.PEM_cert_to_DER_cert((self.pki / "server.pem").read_text())
        self.knowledge = Path(os.environ["KNOWLEDGE_TEST_SRC"]).resolve()
        self.public_hex = ""
        self._layout()
        self.exchange = self.service_root / "var/lib/azazel/state/knowledge-context/exchange"
        self.audit = self.service_root / "var/lib/azazel/state/knowledge-context/audit.jsonl"
        self.replay = self.tmp / "replay.envelope"  # lives outside the egress-only state dir
        self.exchange.mkdir()
        self.exchange.chmod(0o700)  # before chown: the runner has no CAP_FOWNER
        os.chown(self.exchange, self.egress.pw_uid, 0)
        self.env = {**os.environ, "AZAZEL_ROOT": str(self.service_root)}

    def _layout(self) -> None:
        advise_gid = grp.getgrnam("azmio-advise").gr_gid
        sr = self.service_root
        for leaf in ("knowledge-context", "mio", "mio-entry", "mio-advise", "mio-status",
                     "ui-read/mio"):
            (sr / "var/lib/azazel/run" / leaf).mkdir(parents=True)
        (sr / "var/lib/azazel/state/mio").mkdir(parents=True)
        (sr / "var/lib/azazel/state/knowledge-context").mkdir(parents=True)
        e, m, n = self.egress, self.mio, self.entry
        for directory, owner, group, mode in (
            (sr, 0, 0, 0o755), (sr / "var", 0, 0, 0o755), (sr / "var/lib", 0, 0, 0o755),
            (sr / "var/lib/azazel", 0, 0, 0o711), (sr / "var/lib/azazel/run", 0, 0, 0o711),
            (sr / "var/lib/azazel/run/knowledge-context", e.pw_uid, self.ctx_gid, 0o2710),
            (sr / "var/lib/azazel/run/mio", m.pw_uid, self.operator_gid, 0o2710),
            (sr / "var/lib/azazel/run/mio-entry", n.pw_uid, self.operator_gid, 0o2710),
            (sr / "var/lib/azazel/run/mio-advise", n.pw_uid, advise_gid, 0o2710),
            (sr / "var/lib/azazel/run/mio-status", n.pw_uid, self.operator_gid, 0o2750),
            (sr / "var/lib/azazel/run/ui-read", 0, 0, 0o711),
            (sr / "var/lib/azazel/run/ui-read/mio", n.pw_uid, 0, 0o2750),
            (sr / "var/lib/azazel/state/knowledge-context", e.pw_uid, 0, 0o700),
            (sr / "var/lib/azazel/state/mio", n.pw_uid, 0, 0o700),
        ):
            directory.chmod(mode)
            os.chown(directory, owner, group)
        os.chmod(self.pki, 0o750)
        os.chown(self.pki, 0, e.pw_gid)
        for name in ("ca.pem", "nexus.pem", "nexus.key"):
            path = self.pki / name
            path.chmod(0o640 if name.endswith(".key") else 0o644)
            os.chown(path, 0, e.pw_gid)

    # -- producer ---------------------------------------------------------
    def start_producer(self, seed: str | None = None) -> dict:
        wrapper = ROOT / "tests/real_process/_knowledge_context_producer_process.py"
        pythonpath = os.pathsep.join([
            str(self.knowledge / "src"), str(self.knowledge / "tests/unit"),
            os.environ.get("PYTHONPATH", "")])
        deadline = time.monotonic() + 15
        last = ""
        self.starts = getattr(self, "starts", 0) + 1
        while time.monotonic() < deadline:
            process = subprocess.Popen(
                [sys.executable, str(wrapper), str(self.tmp / f"knowledge-root-{self.starts}-{time.monotonic_ns()}"),
                 str(self.pki), seed or self.seed, str(self.port)],
                cwd=self.knowledge / "tests/unit",
                env={**os.environ, "PYTHONPATH": pythonpath}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready = _ready(process)
            except AssertionError as exc:  # port still in TIME_WAIT after a restart
                last = str(exc)[-300:]
                process.kill(); process.wait(timeout=5)
                time.sleep(0.5)
                continue
            self.producer = process
            return ready
        raise AssertionError(f"producer did not start: {last}")

    def stop_producer(self, sig=signal.SIGTERM) -> None:
        process, self.producer = self.producer, None
        if process is not None and process.poll() is None:
            process.send_signal(sig)
            process.wait(timeout=10)
        for stream in (process.stdout, process.stderr) if process else ():
            stream.close()

    # -- broker -----------------------------------------------------------
    def start_broker(self, *, replay: bool = False) -> None:
        env = {**self.env, "U29_EXCHANGE_DIR": str(self.exchange),
               "U29_AUDIT_FILE": str(self.audit)}
        if replay:
            env["U29_REPLAY_FILE"] = str(self.replay)
        self.broker = subprocess.Popen(
            [sys.executable, str(ROOT / "tests/real_process/_knowledge_context_broker_process.py"),
             str(self.service_root), str(self.pki), str(self.port), self.public_hex,
             spki_pin(self.server_der)],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, preexec_fn=self.credentials(self.egress))
        assert _ready(self.broker)["ready"] is True

    def stop_broker(self, sig=signal.SIGTERM) -> int:
        process, self.broker = self.broker, None
        if process is None:
            return 0
        if process.poll() is None:
            process.send_signal(sig)
            process.wait(timeout=10)
        for stream in (process.stdout, process.stderr):
            stream.close()
        return process.returncode

    def credentials(self, account, supplementary=()):
        def apply():
            os.setgroups(list(supplementary))
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        return apply

    # -- client -----------------------------------------------------------
    def call(self, account, supplementary, document, *, root=None, timeout=15) -> dict:
        env = {**self.env, "AZAZEL_ROOT": str(root or self.service_root)}
        result = subprocess.run(
            [sys.executable, "-B", "-c", CLIENT_SNIPPET,
             json.dumps({"doc": document, "timeout": 12})],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout,
            preexec_fn=self.credentials(account, supplementary))
        assert result.returncode == 0, result.stderr[-800:]
        return json.loads(result.stdout)

    def as_service(self, document=None) -> dict:
        return self.call(self.mio, (self.ctx_gid,), document or _doc())

    # -- evidence ---------------------------------------------------------
    def audit_events(self) -> list[dict]:
        if not self.audit.exists():
            return []
        return [json.loads(line) for line in self.audit.read_text().splitlines() if line]

    def exchanges(self) -> list[tuple[str, str, bytes, bytes]]:
        """[(stamp, kind, request_body, envelope)] ordered by time."""
        rows = []
        for path in sorted(self.exchange.glob("*.request")):
            stamp, kind = path.name.rsplit(".", 2)[0], path.name.split(".")[-2]
            rows.append((stamp, kind, path.read_bytes(),
                         path.with_suffix(".envelope").read_bytes()))
        rows.sort(key=lambda r: int(r[0].split("-")[1]))
        return rows

    def registry(self, now: datetime) -> tuple[KnowledgeRegistry, str]:
        endpoint = ProviderRecord(
            provider_id="azazel-knowledge", host="knowledge.test", port=self.port,
            path_template="/knowledge/{model}", certificate_pin=spki_pin(self.server_der),
            client_identity="nexus-process-test", model_id="knowledge-v1",
            max_request_bytes=4096, max_response_bytes=8192, deadline_seconds=8,
            allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,))
        peer = KnowledgePeer(endpoint, ("127.0.0.1",), bytes.fromhex(self.public_hex), 1)
        iso = lambda value: value.isoformat().replace("+00:00", "Z")  # noqa: E731
        return KnowledgeRegistry("sha256:" + "a" * 64, {endpoint.provider_id: peer},
                                 iso(now - timedelta(days=1)), iso(now + timedelta(days=1)), 1
                                 ), endpoint.provider_id

    def shutdown(self) -> None:
        for name in ("entryd", "locald"):
            process = getattr(self, name)
            if process is not None and process.poll() is None:
                process.terminate(); process.wait(timeout=10)
        self.stop_broker()
        self.stop_producer()


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    import tempfile
    import shutil
    base = Path(tempfile.mkdtemp(prefix="u29-", dir="/tmp"))
    base.chmod(0o755)
    state = Stack(base)
    try:
        ready = state.start_producer()
        state.public_hex = ready["public_key"]
        state.start_broker()
        yield state
    finally:
        state.shutdown()
        shutil.rmtree(base, ignore_errors=True)


def _request_ids(stack: Stack) -> list[str]:
    return [json.loads(row[2])["request_id"] for row in stack.exchanges()]


def _ok_response(reply: dict) -> dict:
    assert reply["connect"] == "ok" and reply["reply"]["ok"] is True, reply
    return reply["reply"]["result"]["response"]


def _refused(reply: dict) -> str:
    assert reply["connect"] == "ok", reply
    body = reply["reply"]
    if body.get("ok") is True:
        return body["result"]["refusal"]
    return body["refusal"]


# ---------------------------------------------------------------------------
# Area A: Linux AF_UNIX peer authentication on a real kernel
# ---------------------------------------------------------------------------

def test_a1_a5_allowed_peer_denied_peers_and_socket_attributes(stack: Stack):
    """Allowed service peer is served; denied peers are refused *inside the broker*.

    Segments: client uid -> AF_UNIX (SO_PEERCRED/SO_PEERGROUPS) -> broker policy.
    The denied peers are placed in the socket's group on purpose so the
    filesystem boundary passes and the refusal can only come from the peer
    check; the broker's own audit record carries the kernel-reported uid.
    """
    sock_dir = stack.service_root / "var/lib/azazel/run/knowledge-context"
    sock = sock_dir / "knowledge-context.sock"
    info = sock.lstat()
    assert stat.S_ISSOCK(info.st_mode)
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
        stack.egress.pw_uid, stack.ctx_gid, 0o660)
    assert (sock_dir.stat().st_uid, sock_dir.stat().st_gid,
            stat.S_IMODE(sock_dir.stat().st_mode)) == (
        stack.egress.pw_uid, stack.ctx_gid, 0o2710)
    for ancestor in ("var/lib/azazel", "var/lib/azazel/run"):
        assert stat.S_IMODE((stack.service_root / ancestor).stat().st_mode) == 0o711

    # A1 allowed peer (azmio + client group)
    before = len(stack.exchanges())
    response = _ok_response(stack.as_service())
    assert response["authority"] == "advisory_only"
    assert len(stack.exchanges()) == before + 1  # the real producer was queried

    # A2 non-service uids with filesystem access: refused by the broker policy.
    for account in (stack.operator, stack.entry):
        marks = (len(stack.audit_events()), len(stack.exchanges()))
        reply = stack.call(account, (stack.ctx_gid,), _doc())
        assert _refused(reply) == "principal_denied", reply
        events = stack.audit_events()[marks[0]:]
        refusals = [e for e in events if e.get("event_type") == "runtime.request_refused"]
        assert len(refusals) == 1, events
        assert refusals[0]["uid"] == account.pw_uid          # kernel-derived, not claimed
        assert refusals[0]["reason"] == "principal_denied"
        assert refusals[0]["verb"] == "knowledge.context"
        assert refusals[0]["classes"] == (["operator"] if account is stack.operator else [])
        assert not [e for e in events if e.get("event_type") == "knowledge.context.requested"]
        assert len(stack.exchanges()) == marks[1]            # handler and egress not reached

    # root (this process' uid) is not a service principal for this verb either.
    marks = len(stack.audit_events())
    root_reply = stack.call_as_root(_doc())
    assert _refused(root_reply) == "principal_denied", root_reply
    root_refusal = stack.audit_events()[marks:][-1]
    assert root_refusal["uid"] == 0 and root_refusal["reason"] == "principal_denied"

    # A3 outside the group: kernel EACCES at connect (service uid alone is not enough).
    assert stack.call(stack.mio, (), _doc())["connect"] == "EACCES"
    assert stack.call(stack.operator, (), _doc())["connect"] == "EACCES"

    # The request body can name any identity; the kernel value is what counts.
    marks = len(stack.audit_events())
    claim = _doc(top={"uid": stack.mio.pw_uid, "principal": "azmio"})
    assert _refused(stack.call(stack.operator, (stack.ctx_gid,), claim)) == "principal_denied"
    claim_in_args = _doc(args={"uid": stack.mio.pw_uid})
    reply = stack.call(stack.mio, (stack.ctx_gid,), claim_in_args)
    assert _refused(reply) == "client_asserted_principal", reply
    kinds = [e["reason"] for e in stack.audit_events()[marks:]
             if e.get("event_type") == "runtime.request_refused"]
    assert kinds == ["principal_denied", "client_asserted_principal"], kinds
    # ... and the allowed peer still works afterwards (the refusals did not break it).
    assert _ok_response(stack.as_service())["authority"] == "advisory_only"


def _call_as_root(self: Stack, document: dict) -> dict:
    result = subprocess.run(
        [sys.executable, "-B", "-c", CLIENT_SNIPPET, json.dumps({"doc": document})],
        cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


Stack.call_as_root = _call_as_root  # type: ignore[attr-defined]


def test_a4_peer_information_missing_is_fail_closed(stack: Stack):
    """A socket that carries no AF_UNIX credentials never becomes a principal."""
    from azazel_nexus_runtime.knowledge_contextd import REGISTRY
    from azazel_nexus_runtime.principal import PrincipalPolicy, peer_credentials
    from azazel_nexus_runtime.transport import SocketServer

    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
    client = socket.create_connection(listener.getsockname())
    server_side, _ = listener.accept()
    # Real kernel answer for a non-AF_UNIX peer: no usable credentials.
    pid, uid, gid = peer_credentials(server_side)
    assert (pid, uid, gid) == (0, -1, -1), (pid, uid, gid)  # observed kernel answer
    reached = []
    events: list[dict] = []
    engine = SocketServer(
        registry=REGISTRY,
        policy=PrincipalPolicy.resolve(operator_group="azknowledge-context-client",
                                       service_accounts=("azmio",)),
        audit=events.append)
    client.sendall(struct.pack("!I", 2) + b"{}")
    client.shutdown(socket.SHUT_WR)
    try:
        engine.serve_connection(server_side, lambda request: reached.append(request) or {})
        outcome = "returned"
    except Exception as exc:  # fail-closed by exception is acceptable; record which
        outcome = type(exc).__name__
    finally:
        for sock in (client, server_side, listener):
            sock.close()
    assert not reached, "handler must not be reached without a kernel-attested principal"
    print("U29-OBS a4", json.dumps(
        {"peer_credentials": [pid, uid, gid], "outcome": outcome,
         "audit_reasons": [e.get("reason") for e in events]}))


def test_a4b_client_refuses_impostor_broker_sockets(stack: Stack):
    """The caller checks the socket owner/mode/group before connecting, and the
    peer uid after connecting; an impostor is refused without being trusted."""
    sr2 = stack.tmp / "service-root-impostor"
    run = sr2 / "var/lib/azazel/run/knowledge-context"
    run.mkdir(parents=True)
    for directory, mode in ((sr2, 0o755), (sr2 / "var", 0o755), (sr2 / "var/lib", 0o755),
                            (sr2 / "var/lib/azazel", 0o711),
                            (sr2 / "var/lib/azazel/run", 0o711)):
        directory.chmod(mode)
    run.chmod(0o2710)
    os.chown(run, stack.operator.pw_uid, stack.ctx_gid)
    path = run / "knowledge-context.sock"

    def client_outcome() -> dict:
        result = subprocess.run(
            [sys.executable, "-B", "-c", BOUNDARY_CLIENT], cwd=ROOT,
            env={**stack.env, "AZAZEL_ROOT": str(sr2)}, capture_output=True, text=True,
            timeout=15, preexec_fn=stack.credentials(stack.mio, (stack.ctx_gid,)))
        assert result.returncode == 0, result.stderr[-800:]
        return json.loads(result.stdout)

    # (1) wrong owner: a root-created listener chowned to the operator uid.
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path)); listener.listen(4); listener.settimeout(0.7)
    _set_socket(path, stack.operator.pw_uid, stack.ctx_gid, 0o660)
    outcome = client_outcome()
    assert outcome["outcome"] == "unavailable" and outcome["detail"] == "broker unavailable"
    assert outcome["cause"] == "SocketMisconfigured", outcome   # owner check, before connect
    with pytest.raises(socket.timeout):
        listener.accept()                                       # nothing ever connected
    # (2) wrong mode (0666) with the right owner.
    _set_socket(path, stack.egress.pw_uid, stack.ctx_gid, 0o666)
    outcome = client_outcome()
    assert outcome["cause"] == "SocketMisconfigured", outcome
    with pytest.raises(socket.timeout):
        listener.accept()
    # (3) wrong group.
    _set_socket(path, stack.egress.pw_uid, stack.operator_gid, 0o660)
    outcome = client_outcome()
    assert outcome["cause"] == "SocketMisconfigured", outcome
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close(); path.unlink()

    # (4) file attributes forged to be correct, but the process behind the socket
    # is the operator uid: the kernel's SO_PEERCRED on the connected socket decides.
    impostor = subprocess.Popen(
        [sys.executable, "-B", "-c", IMPOSTOR, str(path)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, preexec_fn=stack.credentials(stack.operator))
    try:
        ready = json.loads(impostor.stdout.readline())
        assert ready["uid"] == stack.operator.pw_uid
        os.chown(path, stack.egress.pw_uid, stack.ctx_gid)      # root fixes up the file attributes
        outcome = client_outcome()
        assert outcome == {"outcome": "unavailable", "detail": "peer identity", "cause": None}, outcome
        accepted = json.loads(impostor.stdout.readline())
        assert accepted == {"accepted": 1, "received": 0}      # reached the peer check; no request bytes were sent
    finally:
        impostor.kill(); impostor.wait(timeout=5)
        impostor.stdout.close(); impostor.stderr.close()


def test_a6_restart_and_socket_regeneration_keep_the_boundary(stack: Stack):
    sock = stack.service_root / "var/lib/azazel/run/knowledge-context/knowledge-context.sock"

    def attributes():
        info = sock.lstat()
        return stat.S_ISSOCK(info.st_mode), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)

    expected = (True, stack.egress.pw_uid, stack.ctx_gid, 0o660)

    def exercise():
        marks = len(stack.audit_events())
        assert attributes() == expected
        assert _ok_response(stack.as_service())["authority"] == "advisory_only"
        assert _refused(stack.call(stack.operator, (stack.ctx_gid,), _doc())) == "principal_denied"
        assert stack.call(stack.mio, (), _doc())["connect"] == "EACCES"
        reasons = [e.get("reason") for e in stack.audit_events()[marks:]
                   if e.get("event_type") == "runtime.request_refused"]
        assert reasons == ["principal_denied"]

    exercise()
    # Orderly stop: the socket is removed, a client fails closed.
    assert stack.stop_broker(signal.SIGTERM) == 0
    assert not sock.exists()
    assert stack.call(stack.mio, (stack.ctx_gid,), _doc())["connect"] in ("ENOENT",)
    stack.start_broker(); exercise()
    # Crash: a stale socket file remains; clients are refused (no listener), then
    # the restart replaces it with the same owner/group/mode.
    assert stack.stop_broker(signal.SIGKILL) == -signal.SIGKILL
    assert stat.S_ISSOCK(sock.lstat().st_mode)
    assert stack.call(stack.mio, (stack.ctx_gid,), _doc())["connect"] == "ECONNREFUSED"
    stack.start_broker(); exercise()


# ---------------------------------------------------------------------------
# Area C: replay across restarts (no persisted replay state; request binding)
# ---------------------------------------------------------------------------

def _envelope_times(envelope: bytes) -> tuple[datetime, datetime]:
    doc = json.loads(envelope[64:])
    parse = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00"))  # noqa: E731
    return parse(doc["issued_at"]), parse(doc["expires_at"])


def _fresh_capture(stack: Stack) -> tuple[str, bytes, bytes]:
    """One live exchange through the real chain; returns (request_id, request, envelope)."""
    before = len(stack.exchanges())
    response = _ok_response(stack.as_service())
    rows = stack.exchanges()
    assert len(rows) == before + 1 and rows[-1][1] == "live"
    request_id = json.loads(rows[-1][2])["request_id"]
    assert response["request_id"] == request_id
    return request_id, rows[-1][2], rows[-1][3]


def _restart_broker_with_replay(stack: Stack, envelope: bytes, sig) -> None:
    stack.stop_broker(sig)
    stack.replay.write_bytes(envelope)
    stack.start_broker(replay=True)


def _end_replay(stack: Stack) -> None:
    stack.replay.unlink()
    stack.stop_broker()
    stack.start_broker()


def _binding_control(stack: Stack, request_body: bytes, envelope: bytes, other_body: bytes) -> None:
    """Same envelope, direct product call: accepted for its own request, refused
    for a different request. This is the evidence that refusal is by binding and
    not by expiry, key or signature."""
    from azazel_nexus.fabric_boundary import validate_knowledge_context_request
    issued, expires = _envelope_times(envelope)
    now = issued + (expires - issued) / 2
    registry, peer_id = stack.registry(now)
    own = validate_knowledge_context_request(json.loads(request_body))
    other = validate_knowledge_context_request(json.loads(other_body))
    iso = now.isoformat().replace("+00:00", "Z")
    read_signed_response(envelope, request=own, registry=registry, peer_id=peer_id,
                         now=iso, max_ttl_seconds=MAX_TTL)
    with pytest.raises(KnowledgeContextRefused):
        read_signed_response(envelope, request=other, registry=registry, peer_id=peer_id,
                             now=iso, max_ttl_seconds=MAX_TTL)


@pytest.mark.parametrize("restart_signal", [signal.SIGTERM, signal.SIGKILL])
def test_c1_old_envelope_is_not_adopted_after_broker_restart(stack: Stack, restart_signal):
    rid1, req1, envelope1 = _fresh_capture(stack)
    _issued, expires = _envelope_times(envelope1)
    _restart_broker_with_replay(stack, envelope1, restart_signal)
    try:
        # S1 is still inside its signed lifetime: expiry cannot be the reason for refusal.
        assert datetime.now(UTC) < expires
        reply = stack.as_service()
        assert _refused(reply) == "unavailable", reply
        replayed = [r for r in stack.exchanges() if r[1] == "replayed"]
        assert replayed, "the replay hook was not exercised"
        stamp, kind, req2, offered = replayed[-1]
        assert offered == envelope1
        rid2 = json.loads(req2)["request_id"]
        assert rid2 != rid1                                  # a new request was made after restart
        _binding_control(stack, req1, envelope1, req2)       # refusal is by request binding
        events = stack.audit_events()
        assert events[-1]["event_type"] == "knowledge.context.completed"
        assert events[-1]["outcome"] == "unavailable"
        assert not any(e.get("outcome") == "verified_advisory" for e in events[-1:])
    finally:
        _end_replay(stack)
    # A legitimate new request is not refused forever.
    rid3, req3, envelope3 = _fresh_capture(stack)
    assert rid3 not in (rid1,) and envelope3 != envelope1


def test_c2_producer_restart_same_key_and_changed_key(stack: Stack):
    rid1, req1, envelope1 = _fresh_capture(stack)
    # (a) producer restarts with the same signing key and the same endpoint.
    stack.stop_producer()
    assert stack.as_service() is not None and _refused(stack.as_service()) == "unavailable"
    ready = stack.start_producer()
    assert ready["public_key"] == stack.public_hex
    rid2, req2, envelope2 = _fresh_capture(stack)           # broker was NOT restarted
    assert rid2 != rid1
    # the earlier producer's envelope is still refused for a new request
    _restart_broker_with_replay(stack, envelope2, signal.SIGTERM)
    try:
        assert _refused(stack.as_service()) == "unavailable"
    finally:
        _end_replay(stack)
    # (b) producer restarts with a different key (the Knowledge fixture's default
    # behaviour): nothing is adopted, and recovery needs the registry key update
    # that is an operator commissioning step (the broker was not restarted and keeps the old key pinned).
    stack.stop_producer()
    stack.start_producer(secrets.token_hex(32))
    marks = len(stack.exchanges())
    try:
        assert _refused(stack.as_service()) == "unavailable"
        assert len(stack.exchanges()) == marks + 1 and stack.exchanges()[-1][1] == "live"
    finally:
        stack.stop_producer()
        stack.start_producer()                               # original key again
    _fresh_capture(stack)                                    # no permanent refusal


def test_c3_concurrent_requests_are_not_cross_adopted(stack: Stack):
    marks = len(stack.exchanges())
    results: list[dict] = []
    lock = threading.Lock()

    def worker():
        reply = stack.as_service()
        with lock:
            results.append(reply)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert len(results) == 6
    served = [r["reply"]["result"]["response"] for r in results
              if r["connect"] == "ok" and r["reply"]["ok"] is True
              and "response" in r["reply"]["result"]]
    refused = [r["reply"]["result"]["refusal"] for r in results
               if r["connect"] == "ok" and r["reply"]["ok"] is True
               and "refusal" in r["reply"]["result"]]
    assert served and len(served) + len(refused) == 6, results
    assert set(refused) <= {"timeout", "unavailable"}
    live_ids = [json.loads(row[2])["request_id"] for row in stack.exchanges()[marks:]
                if row[1] == "live"]
    served_ids = [r["request_id"] for r in served]
    assert len(set(served_ids)) == len(served_ids)           # no response served twice
    assert set(served_ids) <= set(live_ids)                  # each belongs to a real request
    # each served response matches the envelope recorded for that same request
    envelopes = {json.loads(row[2])["request_id"]: row[3] for row in stack.exchanges()[marks:]}
    for response in served:
        payload = json.loads(envelopes[response["request_id"]][64:])["payload"]
        assert payload["request_id"] == response["request_id"]


def test_c4_audit_ledger_state_fail_closed():
    """Corrupt / torn / missing durable state stops the real daemon before it serves."""
    import shutil
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="u29c4-", dir="/tmp"))
    base.chmod(0o755)
    try:
        s = Stack.__new__(Stack)
        s.tmp = base
        s.egress = pwd.getpwnam("azknowledgeegress")
        s.mio = pwd.getpwnam("azmio")
        s.entry = pwd.getpwnam("azmioentry")
        s.operator = pwd.getpwnam("azoperator")
        s.ctx_gid = grp.getgrnam("azknowledge-context-client").gr_gid
        s.operator_gid = grp.getgrnam("azazel-operator").gr_gid
        s.pki = base / "pki"; s.pki.mkdir()
        for name in ("ca.pem", "nexus.pem", "nexus.key"):
            (s.pki / name).write_text("x")
        s.service_root = base / "service-root"
        s._layout()
        state = s.service_root / "var/lib/azazel/state/knowledge-context"
        ledger = state / "context.jsonl"
        results = {}
        for label, content in (("garbage", b"not a ledger line\n"),
                               ("torn_tail", None), ("empty", b"")):
            for item in state.iterdir():
                item.unlink()
            if label == "torn_tail":
                # one valid record, then a record cut off mid-write
                good = subprocess.run(
                    [sys.executable, "-B", "-c",
                     "from azazel_nexus.audit import AuditLedger; import sys;"
                     "l=AuditLedger(__import__('pathlib').Path(sys.argv[1]));"
                     "l.append({'event_type':'x'})", str(ledger)],
                    capture_output=True, text=True)
                assert good.returncode == 0, good.stderr[-400:]
                content = ledger.read_bytes() + b'{"sequence":2,"event'
            ledger.write_bytes(content)
            ledger.chmod(0o600); os.chown(ledger, s.egress.pw_uid, 0)
            process = subprocess.Popen(
                [sys.executable, "-B", "-c",
                 "from azazel_nexus_runtime.knowledge_contextd import main; raise SystemExit(main())"],
                cwd=ROOT, env={**os.environ, "AZAZEL_ROOT": str(s.service_root)},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, preexec_fn=s.credentials(s.egress))
            try:
                code = process.wait(timeout=6)
                served = False
            except subprocess.TimeoutExpired:
                code, served = None, True
                process.kill(); process.wait(timeout=5)
            for stream in (process.stdout, process.stderr):
                stream.close()
            sock = s.service_root / "var/lib/azazel/run/knowledge-context/knowledge-context.sock"
            results[label] = {"exit": code, "served": served, "socket": sock.exists()}
            if sock.exists():
                sock.unlink()
        print("U29-OBS c4", json.dumps(results, sort_keys=True))
        assert results["garbage"]["served"] is False and results["garbage"]["exit"] not in (0, None)
        assert results["torn_tail"]["served"] is False and results["torn_tail"]["exit"] not in (0, None)
        assert results["empty"]["served"] is True  # an empty ledger is a fresh start
    finally:
        shutil.rmtree(base, ignore_errors=True)


# ---------------------------------------------------------------------------
# Area D: clocks (wall clock for validity, monotonic clock for budgets)
# ---------------------------------------------------------------------------

def _window(envelope: bytes) -> tuple[datetime, datetime, dict]:
    doc = json.loads(envelope[64:])
    parse = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00"))  # noqa: E731
    issued, expires = parse(doc["issued_at"]), parse(doc["expires_at"])
    gen, sem_exp = parse(doc["payload"]["generated_at"]), parse(doc["payload"]["expires_at"])
    return max(issued, gen), min(expires, sem_exp), doc


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def test_d1_d2_nexus_signature_window_boundaries_and_unknown_clock(stack: Stack):
    """Direct product call (`read_signed_response`) on a real signed envelope.

    No grace period exists or is added: validity is [max(issued, generated),
    min(expires, semantic expires)). Also records, as an observation and not a
    guarantee, that the Context path keeps no wall-clock floor.
    """
    from azazel_nexus.fabric_boundary import validate_knowledge_context_request
    _rid, request_body, envelope = _fresh_capture(stack)
    low, high, doc = _window(envelope)
    assert high > low and (high - low).total_seconds() <= MAX_TTL
    request = validate_knowledge_context_request(json.loads(request_body))
    registry, peer_id = stack.registry(low)
    micro = timedelta(microseconds=1)

    def verdict(now) -> bool:
        try:
            read_signed_response(envelope, request=request, registry=registry,
                                 peer_id=peer_id, now=now, max_ttl_seconds=MAX_TTL)
            return True
        except KnowledgeContextRefused:
            return False

    assert verdict(_iso(low - micro)) is False       # not yet issued/generated
    assert verdict(_iso(low)) is True                # boundary: inclusive start
    assert verdict(_iso(low + (high - low) / 2)) is True
    assert verdict(_iso(high - micro)) is True
    assert verdict(_iso(high)) is False              # boundary: exclusive end, no grace
    assert verdict(_iso(high + timedelta(seconds=1))) is False
    assert verdict(_iso(high + timedelta(hours=1))) is False
    # TTL bound is the caller's: the same envelope under a shorter maximum is refused.
    lifetime = (datetime.fromisoformat(doc["expires_at"].replace("Z", "+00:00"))
                - datetime.fromisoformat(doc["issued_at"].replace("Z", "+00:00"))).total_seconds()
    shorter = int(lifetime) - 1
    if shorter >= 1:
        with pytest.raises(KnowledgeContextRefused):
            read_signed_response(envelope, request=request, registry=registry, peer_id=peer_id,
                                 now=_iso(low), max_ttl_seconds=shorter)
    # D2: unknown / unusable clock values are refused, never treated as "now ok".
    for bad in ("", "garbage", "2026-11-10T00:00:00", "0000-00-00T00:00:00Z", None, 12345):
        with pytest.raises((KnowledgeContextRefused, ValueError, TypeError, AttributeError)):
            read_signed_response(envelope, request=request, registry=registry, peer_id=peer_id,
                                 now=bad, max_ttl_seconds=MAX_TTL)
    # Observation: no wall-clock floor in this path. After the window has passed,
    # moving the injected clock backwards makes the same (request, envelope) valid
    # again. The consumer's request is consumed within the call, and a different
    # request_id is refused (see C1), so the exposure is limited to a caller that
    # still holds both. Recorded in docs; not claimed as a protection.
    assert verdict(_iso(high + timedelta(seconds=5))) is False
    assert verdict(_iso(low + micro)) is True
    # The commissioning registry is on the same wall clock: before its own
    # issued_at it is refused; inside its window it is accepted.
    narrow = KnowledgeRegistry(registry.commissioning_digest, registry.peers,
                               _iso(low - timedelta(seconds=1)), _iso(high + timedelta(seconds=5)), 1)
    with pytest.raises((KnowledgeContextRefused, ValueError, KnowledgeRefused)):
        narrow.resolve(peer_id, now=_iso(low - timedelta(seconds=2)))
    assert narrow.resolve(peer_id, now=_iso(low)).endpoint.provider_id == peer_id


def test_d3_mio_expiry_uses_its_own_wall_clock_without_grace(stack: Stack, monkeypatch):
    """Nexus accepted the answer; MIO re-checks it against its own `now`.

    In production both read the host's CLOCK_REALTIME in different processes at
    different instants (MIO's is later). Here only the MIO side is injected, a
    deliberate test-only mismatch; inter-host clock difference is not tested.
    """
    from azazel_nexus_runtime import mio_fast_assistance

    response = _ok_response(stack.as_service())
    gen = datetime.fromisoformat(response["generated_at"].replace("Z", "+00:00"))
    exp = datetime.fromisoformat(response["expires_at"].replace("Z", "+00:00"))

    class Clock(datetime):
        fixed: datetime = gen

        @classmethod
        def now(cls, tz=None):
            return cls.fixed.astimezone(tz) if tz else cls.fixed

    monkeypatch.setattr(mio_fast_assistance, "datetime", Clock)
    source = {"request_id": "u29-clock", "privacy_class": "P0-public",
              "question": QUESTION, "context": []}
    seen = {}

    def project(now: datetime):
        Clock.fixed = now
        result = mio_fast_assistance.fast_assistance(
            source, deadline_s=2.0, fabric_knowledge_context_response=response)
        advisory = result.get("fabric_knowledge_context_advisory")
        seen[_iso(now)] = {"advisory": advisory is not None,
                           "unknowns": sorted(u for u in result.get("unknowns", [])
                                              if "KNOWLEDGE" in u)}
        return advisory

    micro = timedelta(microseconds=1)
    assert project(gen - timedelta(seconds=1)) is None        # MIO clock behind: future-dated
    assert project(gen) is not None
    assert project(exp - micro) is not None
    assert project(exp) is None                               # MIO clock at/after expiry
    assert project(exp + timedelta(seconds=30)) is None
    expired = seen[_iso(exp)]
    assert "KNOWLEDGE_CONTEXT_PARTIAL" not in expired["unknowns"] or not expired["advisory"]
    print("U29-OBS d3", json.dumps(seen, sort_keys=True))


def test_d4_budget_uses_monotonic_clock_over_the_real_socket(stack: Stack):
    marks = len(stack.exchanges())
    # An absolute monotonic deadline already in the past: refused before any egress.
    reply = stack.as_service(_doc(mono="MONO-1000"))
    assert _refused(reply) == "timeout", reply
    assert len(stack.exchanges()) == marks
    # A 1 ms budget: whatever happens, no response is adopted.
    reply = stack.as_service(_doc(mono="MONO+8000", deadline_ms=1))
    assert _refused(reply) in ("timeout", "unavailable"), reply
    # The monotonic value cannot extend deadline_ms (the shorter one governs).
    reply = stack.as_service(_doc(mono="MONO+600000", deadline_ms=1))
    assert _refused(reply) in ("timeout", "unavailable"), reply
    # Both honest: served.
    assert _ok_response(stack.as_service())["authority"] == "advisory_only"


# ---------------------------------------------------------------------------
# Integration: producer -> mTLS -> broker -> AF_UNIX -> locald -> entryd
# ---------------------------------------------------------------------------

def _start_chain(stack: Stack) -> None:
    stack.locald = subprocess.Popen(
        [sys.executable, str(ROOT / "tests/real_process/_mio_locald_context_process.py")],
        cwd=ROOT, env=stack.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
        preexec_fn=stack.credentials(stack.mio, (stack.ctx_gid,)))
    assert _ready(stack.locald)["ready"] is True
    stack.entryd = subprocess.Popen(
        [sys.executable, "-B", "-c",
         "from azazel_nexus_runtime.mio_entryd import main; raise SystemExit(main())"],
        cwd=ROOT, env=stack.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
        preexec_fn=stack.credentials(stack.entry, (stack.operator_gid,)))
    _wait_socket(stack.service_root / "var/lib/azazel/run/mio-advise/mio-advise.sock", stack.entryd)


def _assert_advisory_only(entry: dict) -> None:
    assert entry["full_node_context_status"] == "received", entry
    assert entry["advisory_authority"] == "advisory_only", entry
    assert entry["advisory_claim_status"] == "source_reported_unverified", entry
    assert entry["advisory_trust"] == "unverified_advisory_only", entry
    assert entry["snapshot_state"] == "partial" and entry["partial_warning"] is True, entry
    assert entry["lite_claim_count"] == 0 and entry["observation_count"] == 0, entry
    assert entry["handoff_action"] is None, entry            # OBSERVE-only; nothing executable


def test_e_normal_path_replay_degradation_and_recovery(stack: Stack):
    """Whole chain: success; replayed answer after a broker restart degrades with
    no advisory and no lingering context; recovery is automatic."""
    _start_chain(stack)
    _assert_advisory_only(_normal_entry_advisory(stack.service_root))
    _rid, _req, envelope = _fresh_capture(stack)
    _restart_broker_with_replay(stack, envelope, signal.SIGKILL)
    try:
        degraded = _normal_entry_advisory(stack.service_root)
        assert degraded["advisory_authority"] is None, degraded
        assert degraded["full_node_context_status"] == "unavailable", degraded
        assert degraded["knowledge_status"] == "unavailable", degraded
        assert degraded["lite_claim_count"] == 0 and degraded["observation_count"] == 0
        assert degraded["handoff_action"] is None
    finally:
        _end_replay(stack)
    _assert_advisory_only(_normal_entry_advisory(stack.service_root))
    # producer restarted (same key, same endpoint): the chain keeps working
    stack.stop_producer()
    stack.start_producer()
    _assert_advisory_only(_normal_entry_advisory(stack.service_root))


# ---------------------------------------------------------------------------
# Area B (approximation, NOT systemd): the real daemon under setpriv attributes
# ---------------------------------------------------------------------------

def _status_field(pid: int, name: str) -> str:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(name)


def test_b2_real_daemon_under_setpriv_attributes_is_an_approximation(stack: Stack):
    """The shipped (uncommissioned) `az-knowledge-contextd` main, started with a
    non-root uid, no-new-privs and umask 0027. This is NOT systemd acceptance:
    ProtectSystem/ReadWritePaths/PrivateTmp/seccomp/MemoryDenyWriteExecute/
    IPAddressDeny/Condition/Type=notify are not applied here (see docs). Paths are
    AZAZEL_ROOT-relocated, not the real /var/lib/azazel."""
    import shutil
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="u29b2-", dir="/tmp"))
    base.chmod(0o755)
    try:
        s = Stack.__new__(Stack)
        s.tmp, s.egress = base, stack.egress
        s.mio, s.entry, s.operator = stack.mio, stack.entry, stack.operator
        s.ctx_gid, s.operator_gid = stack.ctx_gid, stack.operator_gid
        s.pki = base / "pki"; s.pki.mkdir()
        for name in ("ca.pem", "nexus.pem", "nexus.key"):
            (s.pki / name).write_text("x")
        s.service_root = base / "service-root"
        s._layout()
        s.env = {**os.environ, "AZAZEL_ROOT": str(s.service_root)}
        egress = s.egress
        command = [
            "setpriv", f"--reuid={egress.pw_uid}", f"--regid={egress.pw_gid}", "--clear-groups",
            "--no-new-privs", "--inh-caps=-all", "sh", "-c",
            "umask 0027; exec " + sys.executable + " -B -c "
            "'from azazel_nexus_runtime.knowledge_contextd import main; raise SystemExit(main())'"]
        daemon = subprocess.Popen(command, cwd=ROOT, env=s.env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        sock = s.service_root / "var/lib/azazel/run/knowledge-context/knowledge-context.sock"
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not sock.exists():
                assert daemon.poll() is None, daemon.stderr.read()[-800:]
                time.sleep(0.05)
            assert stat.S_ISSOCK(sock.lstat().st_mode)
            pid = daemon.pid
            # attributes of the *daemon process itself*
            assert _status_field(pid, "NoNewPrivs") == "1"
            assert _status_field(pid, "CapEff") == "0000000000000000"
            assert _status_field(pid, "CapPrm") == "0000000000000000"
            assert _status_field(pid, "CapInh") == "0000000000000000"
            assert _status_field(pid, "Uid").split()[0] == str(egress.pw_uid)
            assert _status_field(pid, "Umask") == "0027"
            bounding = _status_field(pid, "CapBnd")
            info = sock.lstat()
            assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
                egress.pw_uid, s.ctx_gid, 0o660)
            ledger = s.service_root / "var/lib/azazel/state/knowledge-context/context.jsonl"
            assert ledger.exists() and stat.S_IMODE(ledger.stat().st_mode) == 0o640
            # allowed service peer: the shipped factory is uncommissioned -> fixed refusal
            reply = s.call(s.mio, (s.ctx_gid,), _doc())
            assert _refused(reply) == "unavailable", reply
            # denied operator peer: refused by policy; the daemon's own ledger shows it
            assert _refused(s.call(s.operator, (s.ctx_gid,), _doc())) == "principal_denied"
            assert s.call(s.mio, (), _doc())["connect"] == "EACCES"
            records = [json.loads(line) for line in ledger.read_text().splitlines() if line]
            refusals = [r for r in records if r["event"].get("reason") == "principal_denied"] \
                if records and "event" in records[0] else \
                [r for r in records if r.get("reason") == "principal_denied"]
            assert refusals, records[:3]
            # forbidden operations under the same attributes
            probe = subprocess.run(
                ["setpriv", f"--reuid={egress.pw_uid}", f"--regid={egress.pw_gid}",
                 "--clear-groups", "--no-new-privs", "--inh-caps=-all", sys.executable, "-B", "-c",
                 "import os, json\nout={}\n"
                 "def t(name, fn):\n"
                 "    try: fn(); out[name]='allowed'\n"
                 "    except OSError as e: out[name]=e.errno\n"
                 "t('setuid_root', lambda: os.setuid(0))\n"
                 "t('chown', lambda: os.chown('/tmp', 0, 0))\n"
                 "t('write_usr', lambda: open('/usr/u29-probe','w'))\n"
                 "print(json.dumps(out))"],
                capture_output=True, text=True, timeout=10)
            outcomes = json.loads(probe.stdout)
            assert outcomes["setuid_root"] == errno.EPERM
            assert outcomes["chown"] == errno.EPERM
            assert outcomes["write_usr"] == errno.EACCES   # ordinary DAC, not ProtectSystem
            print("U29-OBS b2", json.dumps({"CapBnd": bounding, "probe": outcomes}))
        finally:
            # The shipped main installs no SIGTERM handler: the default action ends
            # the process without the orderly unlink, so a stale socket remains.
            daemon.terminate(); daemon.wait(timeout=5)
            daemon.stdout.close(); daemon.stderr.close()
        assert daemon.returncode == -signal.SIGTERM and stat.S_ISSOCK(sock.lstat().st_mode)
        again = subprocess.Popen(command, cwd=ROOT, env=s.env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                reply = s.call(s.mio, (s.ctx_gid,), _doc())
                if reply["connect"] == "ok":
                    break
                time.sleep(0.1)
            assert _refused(reply) == "unavailable"         # restart replaced the stale socket
            info = sock.lstat()
            assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
                egress.pw_uid, s.ctx_gid, 0o660)
        finally:
            again.kill(); again.wait(timeout=5)
            again.stdout.close(); again.stderr.close()
        # Fail-closed when the state area is not writable: no socket is ever bound.
        state = s.service_root / "var/lib/azazel/state/knowledge-context"
        for item in state.iterdir():
            item.unlink()
        os.chown(state, 0, 0)
        state.chmod(0o500)  # root-owned, not writable by the service uid
        if sock.exists():
            sock.unlink()
        blocked = subprocess.run(
            ["setpriv", f"--reuid={egress.pw_uid}", f"--regid={egress.pw_gid}", "--clear-groups",
             "--no-new-privs", "--inh-caps=-all", sys.executable, "-B", "-c",
             "from azazel_nexus_runtime.knowledge_contextd import main; raise SystemExit(main())"],
            cwd=ROOT, env=s.env, capture_output=True, text=True, timeout=10)
        assert blocked.returncode != 0 and not sock.exists()
        state.chmod(0o700)
    finally:
        shutil.rmtree(base, ignore_errors=True)
