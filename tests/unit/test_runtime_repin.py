"""Repin admission, byte binding, single use, and safe failure with fake library."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime.commissiond import REGISTRY, REPIN_VERBS, CommissionService
from azazel_nexus_runtime.principal import PrincipalClass, PrincipalPolicy
from azazel_nexus_runtime.protocol import RequestRefused
from azazel_nexus_runtime.repin_confirmation import ANCHOR_FILENAME, MAX_ANCHOR_BYTES
from azazel_nexus_runtime.transport import Request, SocketServer
from nacl.signing import SigningKey

POLICY = PrincipalPolicy(operator_gid=123, service_uids=frozenset({456}))
ROOT = POLICY.classify(0, 0, 42)
SENTINEL = "SENTINEL-KEY-MATERIAL-NO-OUTPUT"


def request(name, arguments, principal=ROOT):
    verb = REGISTRY.resolve("trust.repin." + name, principal)
    return Request(verb, verb.bind(arguments), principal)


@pytest.fixture
def setup(tmp_path):
    anchor = tmp_path / ANCHOR_FILENAME
    key = bytes(SigningKey.generate().verify_key).hex()
    content = json.dumps({"keys": [key], "sentinel": SENTINEL}).encode()
    anchor.write_bytes(content)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    calls = []
    tick = [100.0]

    def repin(req, confirmation):
        calls.append((req, confirmation, req.new_anchor_path.read_bytes()))
        return SimpleNamespace(promoted=True, generation=2, reason_code=SENTINEL,
                               new_fingerprint=SENTINEL, old_fingerprint=SENTINEL)

    audit = []
    service = CommissionService(commissioning_dir=tmp_path, snapshot_dir=snapshots,
                                repin=repin, clock=lambda: tick[0],
                                now=lambda: "2026-10-17T01:00:00Z", append=audit.append)
    return SimpleNamespace(service=service, anchor=anchor, snapshots=snapshots,
                           calls=calls, tick=tick, content=content, key=key, audit=audit)


def challenge(env, principal=ROOT, reason="rotation"):
    return env.service.handle(request("challenge", {
        "reason": reason, "new_anchor_file": ANCHOR_FILENAME,
    }, principal))


def confirm(env, result, principal=ROOT, **overrides):
    args = {"nonce": result["nonce"], "echo": result["confirmation_words"], **overrides}
    return env.service.handle(request("confirm", args, principal))


def test_success_binds_reason_principal_digest_and_immutable_snapshot(setup):
    result = challenge(setup)
    assert result["new_fingerprint"] == "sha256:" + hashlib.sha256(setup.content).hexdigest()
    assert result["reason"] == "rotation"
    assert result["expires_in"] == 60
    assert confirm(setup, result) == {"promoted": True, "generation": 2, "state": "complete", "audit_complete": True}
    req, confirmation, data = setup.calls[0]
    assert req.reason == "rotation" and req.principal == "root"
    assert req.new_anchor_path != setup.anchor and data == setup.content
    assert confirmation.nonce == result["nonce"]
    assert confirmation.confirmed_at == "2026-10-17T01:00:00Z"
    assert not req.new_anchor_path.exists()
    with pytest.raises(RequestRefused):
        confirm(setup, result)
    assert len(setup.calls) == 1


@pytest.mark.parametrize("principal", [POLICY.classify(1000, 123, 42),
                                       POLICY.classify(456, 123, 42),
                                       POLICY.classify(1000, 1000, 42)])
@pytest.mark.parametrize("verb", ["challenge", "confirm"])
def test_only_root_is_admitted(principal, verb):
    with pytest.raises(RequestRefused):
        REGISTRY.resolve("trust.repin." + verb, principal)
    assert all(item.admits == frozenset({PrincipalClass.ROOT}) for item in REPIN_VERBS)


@pytest.mark.parametrize("principal", [None, False, SimpleNamespace(uid=0),
                                       POLICY.classify(1000, 123, 42)])
def test_not_checked_or_nonroot_cannot_bypass_registry(setup, principal):
    verb = REPIN_VERBS[0]
    untrusted = Request(verb, {"reason": "rotation", "new_anchor_file": ANCHOR_FILENAME}, principal)
    with pytest.raises(RequestRefused):
        setup.service.handle(untrusted)
    assert not setup.calls


@pytest.mark.parametrize("change", ["echo", "nonce", "uid", "gid", "pid", "expired", "digest"])
def test_mismatch_expiry_or_replay_never_calls_library(setup, change):
    result = challenge(setup)
    principal = ROOT
    overrides = {}
    if change == "echo":
        overrides["echo"] = "WRONG"
    elif change == "nonce":
        overrides["nonce"] = "sha256:" + "0" * 64
    elif change in {"uid", "gid", "pid"}:
        principal = replace(ROOT, **{change: 17})
    elif change == "expired":
        setup.tick[0] += 60
    elif change == "digest":
        setup.anchor.write_bytes(setup.content + b" ")
    with pytest.raises(RequestRefused):
        confirm(setup, result, principal, **overrides)
    if change not in {"uid", "nonce"}:
        # A failed confirmation attempt also consumes the challenge.
        with pytest.raises(RequestRefused):
            confirm(setup, result)
    assert not setup.calls


@pytest.mark.parametrize("name", ["/etc/passwd", "../repin-anchor.json", "other.json"])
def test_arbitrary_paths_are_not_protocol_values(name):
    with pytest.raises(RequestRefused):
        request("challenge", {"reason": "rotation", "new_anchor_file": name})


@pytest.mark.parametrize("change", ["missing", "symlink", "directory", "large", "empty"])
def test_anchor_refusals_are_bounded(setup, change):
    setup.anchor.unlink()
    if change == "symlink":
        target = setup.anchor.with_name("secret")
        target.write_text(SENTINEL)
        setup.anchor.symlink_to(target)
    elif change == "directory":
        setup.anchor.mkdir()
    elif change == "large":
        setup.anchor.write_bytes(b"x" * (MAX_ANCHOR_BYTES + 1))
    elif change == "empty":
        setup.anchor.touch()
    with pytest.raises(RequestRefused) as error:
        challenge(setup)
    assert SENTINEL not in str(error.value)
    assert not setup.calls


def test_challenges_are_random_short_lived_and_bounded(setup):
    results = [challenge(setup) for _ in range(32)]
    assert len({item["nonce"] for item in results}) == 32
    with pytest.raises(RequestRefused):
        challenge(setup)
    setup.tick[0] += 60
    assert challenge(setup)


def test_fixed_input_changed_inside_operation_cannot_change_snapshot(setup):
    def operation(req, confirmation):
        setup.anchor.write_text(SENTINEL)
        assert req.new_anchor_path.read_bytes() == setup.content
        return SimpleNamespace(promoted=True, generation=3)
    setup.service.repin_confirmation.repin = operation
    assert confirm(setup, challenge(setup))["generation"] == 3


def test_snapshot_directory_must_not_allow_other_writers(setup):
    setup.snapshots.chmod(0o777)
    with pytest.raises(RequestRefused):
        confirm(setup, challenge(setup))
    assert not setup.calls


class FakeConnection:
    """Exercise the actual transport and refusal sink without binding sockets."""
    def __init__(self, frame):
        import struct
        self.data = struct.pack("!I", len(frame)) + frame
        self.sent = b""

    def settimeout(self, timeout):
        pass

    def recv(self, size):
        result, self.data = self.data[:size], self.data[size:]
        return result

    def sendall(self, data):
        self.sent += data


def test_key_material_never_reaches_reply_refusal_sink_or_journal(setup, monkeypatch, capsys):
    from azazel_nexus_runtime import transport

    monkeypatch.setattr(transport, "peer_credentials", lambda connection: (42, 0, 0))
    monkeypatch.setattr(transport, "peer_supplementary_groups", lambda connection: ())
    events = []
    engine = SocketServer(registry=REGISTRY, policy=POLICY, audit=events.append)
    connections = []

    def exchange(verb, arguments):
        raw = json.dumps({"verb": "trust.repin." + verb, "arguments": arguments}).encode()
        connection = FakeConnection(raw)
        connections.append(connection)
        engine.serve_connection(connection, setup.service.handle)
        return json.loads(connection.sent[4:])

    result = exchange("challenge", {"reason": "recovery", "new_anchor_file": ANCHOR_FILENAME})["result"]
    exchange("confirm", {"nonce": result["nonce"], "echo": "WRONG"})
    result = challenge(setup)

    def fail(req, confirmation):
        raise RuntimeError(SENTINEL + setup.key)
    setup.service.repin_confirmation.repin = fail
    exchange("confirm", {"nonce": result["nonce"], "echo": result["confirmation_words"]})
    output = capsys.readouterr()
    recorded = repr(events) + repr([conn.sent for conn in connections]) + output.out + output.err
    assert SENTINEL not in recorded and setup.key not in recorded
    assert len(events) == 2
    # The commissioning lock (`lite_trust_ops.trust_lock`) is the one file
    # left there; no snapshot of the anchor is.
    assert [path.name for path in setup.snapshots.iterdir()] in ([], ["trust.lock"])


@pytest.mark.parametrize("error", [OSError("unreadable"), AttributeError("SO_PEERCRED")])
def test_unreadable_peer_credentials_never_dispatch(setup, monkeypatch, error):
    from azazel_nexus_runtime import transport

    def unavailable(connection):
        raise error
    monkeypatch.setattr(transport, "peer_credentials", unavailable)
    engine = SocketServer(registry=REGISTRY, policy=POLICY, audit=lambda event: None)
    with pytest.raises(type(error)):
        engine.serve_connection(FakeConnection(b'{}'), lambda req: pytest.fail("dispatched"))
    assert not setup.calls


def test_default_production_operation_refuses_without_commissioned_store(setup, monkeypatch):
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.repin_confirmation import production_repin

    monkeypatch.setattr(runtime_paths, "ROOT", setup.snapshots)
    setup.service.repin_confirmation.repin = production_repin
    with pytest.raises(RequestRefused):
        confirm(setup, challenge(setup))
    assert not setup.calls


@pytest.mark.skipif(not hasattr(__import__("socket"), "SO_PEERCRED"),
                    reason="kernel SO_PEERCRED requires Linux")
def test_real_unix_peer_policy_and_root_round_trip(setup, tmp_path):
    import os
    import socket
    import threading

    from azazel_nexus_runtime.transport import bind_socket, read_frame, send_frame

    path = tmp_path / "repin.sock"
    listener = bind_socket(path)
    events = []
    engine = SocketServer(registry=REGISTRY, policy=POLICY, audit=events.append)
    failures = []

    def exchange(verb, args):
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    engine.serve_connection(connection, setup.service.handle)
            except (OSError, RequestRefused) as error:
                failures.append(error)
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(str(path))
                send_frame(client, {"verb": "trust.repin." + verb, "arguments": args})
                client.shutdown(socket.SHUT_WR)
                return json.loads(read_frame(client))
        finally:
            worker.join(timeout=3)
            assert not worker.is_alive()
            assert not failures

    try:
        response = exchange("challenge", {"reason": "rotation", "new_anchor_file": ANCHOR_FILENAME})
        if os.getuid() != 0:
            assert response == {"ok": False, "refusal": "principal_denied"}
            assert not setup.calls
        else:
            result = response["result"]
            answer = exchange("confirm", {"nonce": result["nonce"],
                                          "echo": result["confirmation_words"]})
            assert answer == {"ok": True, "result": {"promoted": True, "generation": 2, "state": "complete", "audit_complete": True}}
            assert len(setup.calls) == 1
    finally:
        listener.close()
        path.unlink(missing_ok=True)


def test_root_socket_caller_can_confirm_without_cli_or_tty(setup, monkeypatch):
    """Residual threat: ROOT can echo the reply without any human presence.

    Exercise the socket transport with injected ROOT peer credentials and no
    bind, so this protocol claim also runs on sandboxed/non-Linux hosts.
    The real AF_UNIX peer-credential round trip is covered separately above.
    """
    from azazel_nexus_runtime import transport

    monkeypatch.setattr(transport, "peer_credentials", lambda connection: (42, 0, 0))
    monkeypatch.setattr(transport, "peer_supplementary_groups", lambda connection: ())
    engine = SocketServer(registry=REGISTRY, policy=POLICY, audit=lambda event: None)

    def exchange(verb, arguments):
        connection = FakeConnection(json.dumps({
            "verb": "trust.repin." + verb, "arguments": arguments,
        }).encode())
        engine.serve_connection(connection, setup.service.handle)
        return json.loads(connection.sent[4:])

    response = exchange("challenge", {"reason": "rotation", "new_anchor_file": ANCHOR_FILENAME})
    assert response["ok"] is True
    result = response["result"]
    assert exchange("confirm", {"nonce": result["nonce"], "echo": result["confirmation_words"]}) == {
        "ok": True, "result": {"promoted": True, "generation": 2, "state": "complete", "audit_complete": True},
    }
    assert len(setup.calls) == 1


def test_cleanup_failure_preserves_committed_promotion(setup, monkeypatch):
    from pathlib import Path

    result = challenge(setup)

    def fail_unlink(path, **kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(Path, "unlink", fail_unlink)
    assert confirm(setup, result) == {
        "promoted": True, "generation": 2, "state": "complete", "audit_complete": True, "cleanup_failed": True,
    }
    assert len(setup.calls) == 1
    assert setup.calls[0][0].new_anchor_path.exists()
    with pytest.raises(RequestRefused):
        confirm(setup, result)


@pytest.mark.parametrize("error", [RuntimeError("operation failed"), KeyboardInterrupt()])
def test_cleanup_failure_does_not_mask_in_flight_exception(setup, monkeypatch, error):
    from pathlib import Path

    def operation(req, confirmation):
        raise error

    def fail_unlink(path, **kwargs):
        raise OSError(SENTINEL)

    setup.service.repin_confirmation.repin = operation
    monkeypatch.setattr(Path, "unlink", fail_unlink)
    expected = RequestRefused if isinstance(error, Exception) else type(error)
    with pytest.raises(expected) as caught:
        confirm(setup, challenge(setup))
    if isinstance(error, Exception):
        assert caught.value.__cause__ is error
        assert SENTINEL not in str(caught.value)
    else:
        assert caught.value is error
