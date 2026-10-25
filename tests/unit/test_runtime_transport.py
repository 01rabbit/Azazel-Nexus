"""The socket, the frame, and who the server decides is calling (#37).

Every test here uses a **real** `AF_UNIX` socket. A transport tested against a
mock is a transport whose framing has never met a stream, and framing bugs are
exactly what a stream socket produces: short reads, split headers, bytes that
arrive after the message.

Nothing here waits. Deadlines are set to a small finite value and the peer
that triggers them is a socket nobody writes to, so the test finishes when the
deadline does. No test sleeps.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time

import pytest

from azazel_nexus_runtime.principal import (
    Principal,
    PrincipalClass,
    PrincipalPolicy,
    SocketMisconfigured,
    peer_supplementary_groups,
    verify_socket,
)
from azazel_nexus_runtime.protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
    fingerprint,
)
from azazel_nexus_runtime.transport import (
    MAX_FRAME_BYTES,
    SocketServer,
    bind_socket,
    send_frame,
)

HEADER = struct.Struct("!I")

PING = Verb("node.ping", admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR}))
PICK = Verb(
    "node.pick",
    arguments=(
        Argument("ordinal", ArgumentKind.ORDINAL, maximum=7),
        Argument("snapshot", ArgumentKind.DIGEST),
        Argument("dry_run", ArgumentKind.FLAG),
        Argument("unit", ArgumentKind.ENUM, choices=("auditd", "watchdog")),
    ),
    admits=frozenset({PrincipalClass.ROOT}),
)
#: Admits a class this test process can never hold: the policy below
#: resolves no service uids, so this verb is denied whatever uid CI runs
#: as. Without it the denial test would pass for one reason as root and
#: another otherwise, which is two tests neither of which was written.
SERVICE_ONLY = Verb("node.service_only", admits=frozenset({PrincipalClass.SERVICE}))

REGISTRY = VerbRegistry([PING, PICK, SERVICE_ONLY])
DIGEST = "sha256:" + "ab" * 32


def _policy(**kwargs) -> PrincipalPolicy:
    """A policy that classes this test process as root, so verbs are reachable.

    The tests run as whatever uid CI provides. Classing that uid explicitly is
    the honest way to exercise the admitted path without weakening the check
    being tested -- `classify` still derives everything from the credentials
    the kernel reports.
    """

    kwargs.setdefault("operator_gid", None)
    kwargs.setdefault("service_uids", frozenset())
    return PrincipalPolicy(**kwargs)


def _root_policy() -> PrincipalPolicy:
    """A policy under which `node.ping` is admitted whatever uid CI runs as.

    `PING` admits ROOT or OPERATOR; this grants OPERATOR to the test
    process's own gid. So the served path is reachable deterministically,
    and `node.service_only` is deterministically denied, because no service
    uid is resolved. Neither outcome depends on whether the suite happens to
    run as root.
    """

    return _policy(operator_gid=os.getgid())


@pytest.fixture
def server(tmp_path):
    recorded: list[dict] = []
    listener = bind_socket(tmp_path / "test.sock")
    engine = SocketServer(
        registry=REGISTRY,
        policy=_root_policy(),
        audit=recorded.append,
        deadline=0.5,
    )
    yield listener, engine, recorded, tmp_path / "test.sock"
    listener.close()


def _exchange(server, payload, *, raw: bytes | None = None, handler=None):
    """Send one request and return `(reply, recorded events)`."""

    listener, engine, recorded, path = server
    handler = handler or (lambda request: {"verb": request.verb.name})

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2.0)
    client.connect(str(path))

    def serve():
        connection, _ = listener.accept()
        with connection:
            engine.serve_connection(connection, handler)

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        if raw is not None:
            client.sendall(raw)
        else:
            send_frame(client, payload)
        client.shutdown(socket.SHUT_WR)
        reply = client.recv(MAX_FRAME_BYTES)
    finally:
        worker.join(timeout=5)
        assert not worker.is_alive(), "the server did not finish within the deadline"
        client.close()
    body = json.loads(reply[HEADER.size :]) if reply else None
    return body, recorded


# -- the socket itself ---------------------------------------------------


def test_a_socket_is_bound_with_the_declared_mode(tmp_path):
    path = tmp_path / "declared.sock"
    listener = bind_socket(path)
    try:
        verify_socket(path)
        assert path.stat().st_mode & 0o777 == 0o660
    finally:
        listener.close()


def test_a_socket_must_match_the_reviewed_group_before_it_is_served(tmp_path):
    path = tmp_path / "operator.sock"
    expected_gid = tmp_path.stat().st_gid
    listener = bind_socket(path, expected_gid=expected_gid)
    try:
        verify_socket(path, expected_gid=expected_gid)
        with pytest.raises(SocketMisconfigured, match="reviewed operator group"):
            verify_socket(path, expected_gid=expected_gid + 1)
    finally:
        listener.close()


def test_the_umask_does_not_decide_the_socket_mode(tmp_path):
    """`bind` respects the umask; the `chmod` after it is what overrides that.

    A daemon started under an unexpected umask would otherwise create a
    socket whose permissions differ from its packaging, and nothing would
    notice until someone reached it.
    """

    previous = os.umask(0o077)
    try:
        path = tmp_path / "umask.sock"
        listener = bind_socket(path)
        try:
            assert path.stat().st_mode & 0o777 == 0o660
        finally:
            listener.close()
    finally:
        os.umask(previous)


def test_a_socket_path_too_long_to_bind_is_refused_before_binding(tmp_path):
    """`AF_UNIX path too long` from a subprocess at boot is a puzzle.

    The integration harness hit it from a scratch directory whose name was
    long, and the kernel's message names neither the limit nor the path's
    length. Refused here, with the arithmetic.
    """

    from azazel_nexus_runtime.transport import MAX_SOCKET_PATH_BYTES

    deep = tmp_path
    while len(str(deep / "x.sock")) <= MAX_SOCKET_PATH_BYTES:
        deep = deep / "dddddddddd"
    deep.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SocketMisconfigured) as refused:
        bind_socket(deep / "x.sock")
    assert str(MAX_SOCKET_PATH_BYTES) in str(refused.value)


def test_a_world_writable_socket_is_refused(tmp_path):
    path = tmp_path / "loose.sock"
    listener = bind_socket(path)
    try:
        path.chmod(0o666)
        with pytest.raises(SocketMisconfigured):
            verify_socket(path)
    finally:
        listener.close()


def test_binding_closes_the_listener_when_verification_fails(tmp_path, monkeypatch):
    """A daemon that raises while holding a bound socket occupies the path.

    The next start then finds something at the address and has to decide
    whether removing it is safe -- which is a decision nobody should be
    making at boot.
    """

    import azazel_nexus_runtime.transport as transport_module

    created: list[socket.socket] = []
    real_socket = socket.socket

    def recording_socket(*args, **kwargs):
        made = real_socket(*args, **kwargs)
        created.append(made)
        return made

    def refuse(path, **kwargs):
        raise SocketMisconfigured("something replaced the socket")

    monkeypatch.setattr(transport_module, "verify_socket", refuse)
    monkeypatch.setattr(transport_module.socket, "socket", recording_socket)

    with pytest.raises(SocketMisconfigured):
        bind_socket(tmp_path / "doomed.sock")

    # Asserted on the object itself, not inferred from being able to rebind:
    # CPython would close it by refcount as soon as the frame unwound, so a
    # rebind test passes whether the close is there or not.
    assert created, "no socket was created"
    assert created[0].fileno() == -1, (
        "the listener was left open; a daemon that raises while holding a "
        "bound socket occupies the path for its next start"
    )


def test_something_that_is_not_a_socket_is_refused(tmp_path):
    ordinary = tmp_path / "not-a-socket"
    ordinary.write_text("")
    ordinary.chmod(0o660)
    with pytest.raises(SocketMisconfigured):
        verify_socket(ordinary)


# -- the principal is the server's to decide -----------------------------


def test_the_principal_comes_from_the_kernel_not_the_request(server):
    """A request carrying a role is refused, and refused as that.

    Not as a typo. An attempt to supply a principal should be visible in the
    ledger as an attempt to supply a principal.
    """

    reply, recorded = _exchange(
        server, {"verb": "node.ping", "arguments": {"role": "root"}}
    )
    assert reply == {"ok": False, "refusal": "client_asserted_principal"}
    assert recorded[0]["reason"] == "client_asserted_principal"


@pytest.mark.parametrize("key", ["principal", "uid", "as_user", "sudo", "authority"])
def test_every_reserved_principal_key_is_refused(server, key):
    reply, _ = _exchange(server, {"verb": "node.ping", "arguments": {key: "x"}})
    assert reply["refusal"] == "client_asserted_principal"


def test_no_verb_may_declare_an_argument_that_names_a_principal():
    for name in ("principal", "role", "uid", "sudo"):
        with pytest.raises(ValueError):
            Argument(name, ArgumentKind.FLAG)


def test_a_verb_that_admits_nobody_cannot_be_built():
    """Default deny as a property of the type, not a branch somebody writes."""

    with pytest.raises(ValueError):
        Verb("node.orphan")


def test_a_caller_outside_the_admitted_classes_is_denied_and_recorded(server):
    """Denied before the arguments are looked at, and recorded with the verb.

    The verb name is safe to record here precisely because it is one this
    daemon declared -- unlike an unknown verb's name, which is the caller's.
    """

    reply, recorded = _exchange(server, {"verb": "node.service_only", "arguments": {}})
    assert reply == {"ok": False, "refusal": "principal_denied"}
    assert recorded[0]["verb"] == "node.service_only"
    assert recorded[0]["uid"] == os.getuid()
    assert recorded[0]["pid"] == os.getpid()


def test_the_server_classifies_exactly_what_the_kernel_reported(server):
    """The wiring, checked without depending on which uid the suite runs as.

    A mutation replacing the reported credentials with a constant survived
    the first time, because this container runs the suite as root and the
    constant happened to be root. A guard that only fires under some uids is
    a guard that is absent under the others.
    """

    import azazel_nexus_runtime.transport as transport_module

    listener, engine, recorded, path = server
    seen: list[tuple[int, int, int]] = []
    # Values this process could not hold, so the assertion cannot be
    # satisfied by coincidence. The first version compared against
    # `os.getuid()`, which is 0 in this container -- and the mutation that
    # replaced the credentials with a constant 0 passed it.
    REPORTED = (4444, 4242, 4343)  # (pid, uid, gid), as SO_PEERCRED orders them

    class Spy(PrincipalPolicy):
        def classify(self, uid, gid, pid, supplementary_groups=()):
            seen.append((uid, gid, pid))
            return super().classify(uid, gid, pid, supplementary_groups)

    engine.policy = Spy(operator_gid=4343, service_uids=frozenset())
    original = transport_module.peer_credentials
    original_groups = transport_module.peer_supplementary_groups
    transport_module.peer_credentials = lambda connection: REPORTED
    transport_module.peer_supplementary_groups = lambda connection: ()
    try:
        reply, _ = _exchange(server, {"verb": "node.ping", "arguments": {}})
    finally:
        transport_module.peer_credentials = original
        transport_module.peer_supplementary_groups = original_groups

    assert seen == [(4242, 4343, 4444)], (
        "the server did not pass on what the credential read returned; it "
        "used something else to decide who was calling"
    )
    assert reply["ok"] is True


def test_reaching_the_socket_is_not_itself_a_permission(server):
    """The connection succeeded. That decided nothing.

    The socket's mode answers who can connect; peer credentials answer who
    did. Neither substitutes for the other, and this is the second.
    """

    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset())
    principal = policy.classify(uid=12345, gid=12345, pid=1)
    assert principal.classes == frozenset()
    assert not principal.admits(PING.admits)


def test_supplementary_operator_group_grants_operator_but_never_elevates_a_service():
    operator_gid = 9001
    service_uid = 9002
    policy = PrincipalPolicy(
        operator_gid=operator_gid,
        service_uids=frozenset({service_uid}),
    )

    operator = policy.classify(1000, 1000, 1, (operator_gid,))
    service = policy.classify(service_uid, 1001, 2, (operator_gid,))

    assert operator.classes == frozenset({PrincipalClass.OPERATOR})
    assert service.classes == frozenset({PrincipalClass.SERVICE})


def test_linux_peer_supplementary_groups_are_kernel_reported():
    import socket as socket_module

    # Not `hasattr(socket, "SO_PEERGROUPS")`: CPython never exports it, so
    # that guard skipped this test everywhere and hid that no Linux peer
    # ever had supplementary groups.
    if sys.platform != "linux":
        pytest.skip("SO_PEERGROUPS is Linux-specific")
    left, right = socket_module.socketpair(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    try:
        assert set(peer_supplementary_groups(left)) == set(os.getgroups())
    finally:
        left.close()
        right.close()


def test_a_daemon_account_carrying_the_operator_group_is_never_an_operator():
    """entryd's unit grants it `azazel-operator` to reach provider sockets.

    Once supplementary groups are actually read, that must not turn azmioentry
    into an operator at a daemon that does not list it as a service.
    """

    operator_gid = 9001
    entry_uid = 9003
    policy = PrincipalPolicy(
        operator_gid=operator_gid, service_uids=frozenset(), daemon_uids=frozenset({entry_uid}),
    )
    assert policy.classify(entry_uid, entry_uid, 3, (operator_gid,)).classes == frozenset()
    assert policy.classify(entry_uid, operator_gid, 3).classes == frozenset()
    # An ordinary operator user is unaffected.
    assert policy.classify(1000, 1000, 1, (operator_gid,)).classes == frozenset(
        {PrincipalClass.OPERATOR})


def test_every_installed_daemon_account_is_a_daemon_account():
    from azazel_nexus_runtime.hardening import SYSTEM_ACCOUNTS
    from azazel_nexus_runtime.principal import DAEMON_ACCOUNTS, SERVICE_ACCOUNTS

    assert set(SYSTEM_ACCOUNTS) <= set(DAEMON_ACCOUNTS)
    assert set(SERVICE_ACCOUNTS) <= set(DAEMON_ACCOUNTS)


def test_every_unit_account_is_a_daemon_account():
    """A new unit account cannot be forgotten: it would become an operator elsewhere."""
    import re
    from pathlib import Path

    from azazel_nexus_runtime import hardening
    from azazel_nexus_runtime.principal import DAEMON_ACCOUNTS

    root = Path(__file__).resolve().parents[2]
    unit_users = set()
    for unit in sorted((root / "packaging/systemd").glob("*.service")):
        unit_users |= set(re.findall(r"^User=(\S+)$", unit.read_text(encoding="utf-8"), re.MULTILINE))
    profiles = hardening.PROFILES.values() if isinstance(hardening.PROFILES, dict) else hardening.PROFILES
    profile_users = {profile.account for profile in profiles}
    assert unit_users and profile_users
    assert (unit_users | profile_users) - {"root"} <= set(DAEMON_ACCOUNTS)


def test_root_supplementary_operator_group_never_makes_root_an_operator():
    operator_gid = 4242
    policy = PrincipalPolicy(operator_gid=operator_gid, service_uids=frozenset())
    assert policy.classify(0, 0, 1, (operator_gid,)).classes == frozenset({PrincipalClass.ROOT})
    # A root whose primary group is the operator group keeps the earlier behaviour.
    assert PrincipalClass.OPERATOR in policy.classify(0, operator_gid, 1).classes


def test_unavailable_peer_groups_are_reported_and_grant_nothing(capsys):
    import errno

    from azazel_nexus_runtime import principal

    class Refusing:
        def getsockopt(self, *args):
            raise OSError(errno.ERANGE, "too many groups")
    if principal._peergroups_option(__import__("socket")) is None:
        pytest.skip("no SO_PEERGROUPS option on this platform")
    assert principal.peer_supplementary_groups(Refusing()) == ()
    assert "peer supplementary groups unavailable: ERANGE" in capsys.readouterr().err


def test_resolve_marks_daemon_accounts_that_exist(monkeypatch):
    import types

    from azazel_nexus_runtime import principal as principal_module

    table = {"azmioentry": 9003, "azarbiter": 9004, "azfetch": 9005}

    def getpwnam(name):
        if name not in table:
            raise KeyError(name)
        return types.SimpleNamespace(pw_uid=table[name])

    monkeypatch.setattr(principal_module.pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(principal_module.grp, "getgrnam",
                        lambda name: types.SimpleNamespace(gr_gid=9001))
    policy = PrincipalPolicy.resolve(service_accounts=("azarbiter",))
    assert policy.service_uids == frozenset({9004})
    assert policy.daemon_uids == frozenset({9003, 9004, 9005})
    assert policy.classify(9003, 9003, 1, (9001,)).classes == frozenset()


class _GroupsConnection:
    """Records the getsockopt request; answers with fixed kernel bytes."""

    def __init__(self, groups=(), error=None):
        self.calls = []
        self._raw = b"".join(struct.pack("=I", group) for group in groups)
        self._error = error

    def getsockopt(self, level, option, buflen):
        self.calls.append((level, option, buflen))
        if self._error is not None:
            raise self._error
        return self._raw


def test_peergroups_option_uses_the_linux_generic_value_cpython_does_not_export(monkeypatch):
    import types

    from azazel_nexus_runtime import principal as principal_module

    bare = types.SimpleNamespace()  # a socket module without SO_PEERGROUPS, like CPython's
    monkeypatch.setattr(sys, "platform", "linux")
    for machine, expected in (("x86_64", 59), ("aarch64", 59), ("sparc64", None),
                              ("parisc", None), ("alpha", None), ("mips", None)):
        monkeypatch.setattr(principal_module.os, "uname",
                            lambda machine=machine: types.SimpleNamespace(machine=machine))
        assert principal_module._peergroups_option(bare) == expected, machine
    # A module that does export it wins over the table.
    assert principal_module._peergroups_option(types.SimpleNamespace(SO_PEERGROUPS=1234)) == 1234
    monkeypatch.setattr(sys, "platform", "darwin")
    assert principal_module._peergroups_option(bare) is None


def test_peer_groups_buffer_fits_cpythons_getsockopt_limit(monkeypatch):
    import socket as socket_module

    from azazel_nexus_runtime import principal as principal_module

    monkeypatch.setattr(principal_module, "_peergroups_option", lambda module: 59)
    connection = _GroupsConnection((985, 984))
    assert peer_supplementary_groups(connection) == (985, 984)
    # CPython raises "getsockopt buflen out of range" above 1024; the old
    # 4 * 65536 request was swallowed as OSError and returned no groups.
    assert connection.calls == [(socket_module.SOL_SOCKET, 59, 1024)]
    # A refusal (for example ERANGE for more than 256 groups) stays fail-closed.
    assert peer_supplementary_groups(_GroupsConnection(error=OSError(34, "ERANGE"))) == ()
    odd = _GroupsConnection()
    odd._raw = b"\x01\x02\x03"
    with pytest.raises(SocketMisconfigured):
        peer_supplementary_groups(odd)


def test_linux_supplementary_operator_can_reach_and_use_its_socket(tmp_path):
    if sys.platform != "linux":
        pytest.skip("SO_PEERGROUPS is Linux-specific")
    operator_gid = next(
        (group for group in os.getgroups() if group != os.getgid()), None
    )
    if operator_gid is None:
        pytest.skip("test process has no supplementary group to exercise")

    leaf = tmp_path / "audit"
    leaf.mkdir()
    os.chown(leaf, os.getuid(), operator_gid)
    os.chmod(leaf, 0o2710)
    path = leaf / "audit.sock"
    listener = bind_socket(path, expected_gid=operator_gid)
    registry = VerbRegistry([
        Verb("node.operator_only", admits=frozenset({PrincipalClass.OPERATOR}))
    ])
    engine = SocketServer(
        registry=registry,
        policy=PrincipalPolicy(operator_gid=operator_gid, service_uids=frozenset()),
        audit=lambda _event: None,
    )
    try:
        reply, _ = _exchange((listener, engine, [], path), {"verb": "node.operator_only"})
        assert reply == {"ok": True, "result": {"verb": "node.operator_only"}}
    finally:
        listener.close()


def test_a_principals_audit_fields_carry_nothing_a_caller_chose(server):
    principal = Principal(uid=1, gid=2, pid=3, classes=frozenset({PrincipalClass.ROOT}))
    fields = principal.as_audit_fields()
    assert set(fields) == {"uid", "gid", "pid", "classes"}
    assert all(isinstance(v, (int, list)) for v in fields.values())


# -- the frame -----------------------------------------------------------


def test_a_well_formed_request_is_served(server):
    reply, recorded = _exchange(server, {"verb": "node.ping", "arguments": {}})
    assert reply == {"ok": True, "result": {"verb": "node.ping"}}
    assert recorded == [], "a served request is not a refusal"


def test_a_frame_larger_than_the_ceiling_is_refused_without_reading_the_body(server):
    """The ceiling is enforced on the declared length, not after the fact.

    A limit checked after reading everything has already spent the memory it
    exists to protect.
    """

    listener, engine, recorded, path = server
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2.0)
    client.connect(str(path))

    def serve():
        connection, _ = listener.accept()
        with connection:
            engine.serve_connection(connection, lambda request: {})

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        # A header claiming far more than the ceiling, and **no body at all**.
        # If the server read before checking, it would block here until its
        # deadline and report a different refusal.
        client.sendall(HEADER.pack(MAX_FRAME_BYTES + 1))
        reply = client.recv(4096)
    finally:
        worker.join(timeout=5)
        assert not worker.is_alive()
        client.close()

    body = json.loads(reply[HEADER.size :])
    assert body["refusal"] == "frame_too_large"
    assert recorded[0]["reason"] == "frame_too_large"


def test_a_truncated_frame_is_refused_as_truncated(server):
    reply, recorded = _exchange(server, None, raw=HEADER.pack(64) + b"{}")
    assert reply["refusal"] == "truncated_frame"


def test_the_three_malformed_frames_are_recorded_as_three_different_things(server):
    """A zero length, a missing header, and bytes that are not JSON.

    All three are malformed frames and all three are different events at a
    socket. Recording one word for the lot would make a peer that never
    sends a header indistinguishable from one that sends garbage -- and the
    detail is safe to record here because all three strings are literals in
    this daemon, not the caller's.
    """

    _, zero = _exchange(server, None, raw=HEADER.pack(0))
    assert zero[-1]["reason"] == "malformed_frame"
    assert zero[-1]["argument"] == "zero length"

    _, no_header = _exchange(server, None, raw=b"\x00\x00")
    assert no_header[-1]["argument"] == "no length header"

    _, not_json = _exchange(server, None, raw=HEADER.pack(3) + b"\xff\xfe\xfd")
    assert not_json[-1]["argument"] == "not json"


def test_a_zero_length_frame_is_malformed(server):
    reply, _ = _exchange(server, None, raw=HEADER.pack(0))
    assert reply["refusal"] == "malformed_frame"


def test_a_header_that_never_arrives_is_malformed(server):
    reply, _ = _exchange(server, None, raw=b"\x00\x00")
    assert reply["refusal"] == "malformed_frame"


def test_bytes_after_the_frame_are_refused(server):
    """One request per connection, and the protocol says so.

    Ignoring the extra bytes would mean a caller could append a second request
    that is neither served nor reported.
    """

    body = json.dumps({"verb": "node.ping", "arguments": {}}).encode()
    reply, _ = _exchange(
        server, None, raw=HEADER.pack(len(body)) + body + b"extra"
    )
    assert reply["refusal"] == "trailing_bytes"


def test_a_frame_that_is_not_json_is_malformed(server):
    reply, _ = _exchange(server, None, raw=HEADER.pack(3) + b"\xff\xfe\xfd")
    assert reply["refusal"] == "malformed_frame"


def test_valid_json_that_is_not_an_object_is_refused_as_that(server):
    body = json.dumps([1, 2, 3]).encode()
    reply, _ = _exchange(server, None, raw=HEADER.pack(len(body)) + body)
    assert reply["refusal"] == "not_an_object"


def test_a_peer_that_stops_sending_hits_the_deadline_and_does_not_hang(server):
    """The cheapest denial of service there is, refused in finite time."""

    listener, engine, recorded, path = server
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(path))
    started = time.monotonic()

    def serve():
        connection, _ = listener.accept()
        with connection:
            engine.serve_connection(connection, lambda request: {})

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        client.sendall(HEADER.pack(32))  # promises 32 bytes, sends none
        worker.join(timeout=5)
        assert not worker.is_alive(), "the server waited past its deadline"
    finally:
        client.close()
    assert time.monotonic() - started < 4
    assert recorded[0]["reason"] == "read_deadline"


def test_a_split_header_is_still_read_as_one_frame(server):
    """A stream socket has no message boundaries.

    A reader that assumed one `recv` returns a whole header would work on
    every test and fail on a loaded machine.
    """

    listener, engine, recorded, path = server
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2.0)
    client.connect(str(path))
    body = json.dumps({"verb": "node.ping", "arguments": {}}).encode()
    header = HEADER.pack(len(body))

    def serve():
        connection, _ = listener.accept()
        with connection:
            engine.serve_connection(connection, lambda request: {"served": True})

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        for byte in header:
            client.sendall(bytes([byte]))
        for index in range(0, len(body), 3):
            client.sendall(body[index : index + 3])
        client.shutdown(socket.SHUT_WR)
        reply = client.recv(4096)
    finally:
        worker.join(timeout=5)
        assert not worker.is_alive()
        client.close()
    body_out = json.loads(reply[HEADER.size :])
    assert body_out == {"ok": True, "result": {"served": True}}


# -- the verb allowlist --------------------------------------------------


def test_an_unknown_verb_is_refused(server):
    reply, _ = _exchange(server, {"verb": "node.definitely_not", "arguments": {}})
    assert reply["refusal"] == "unknown_verb"


def test_an_unknown_verbs_name_is_never_written_to_the_ledger(server):
    """A rejected frame is attacker-supplied by definition.

    Recording its contents would make the audit chain a place anyone who can
    reach the socket may write text into. The fingerprint is what correlates
    repeats.
    """

    marker = "verb_" + "z" * 200
    reply, recorded = _exchange(server, {"verb": marker, "arguments": {}})
    assert reply["refusal"] == "unknown_verb"
    serialized = json.dumps(recorded[0])
    assert marker not in serialized
    assert "verb" not in recorded[0]
    assert len(recorded[0]["request_fingerprint"]) == 16


def test_an_undeclared_arguments_name_is_never_written_to_the_ledger(server):
    """Its key was chosen by the caller, so it is the caller's text.

    This is the case the first version of the recorder got wrong: the
    declared-argument names are ours and safe to record, and this one is not,
    and they were being treated alike.
    """

    marker = "key_" + "q" * 200
    reply, recorded = _exchange(
        server, {"verb": "node.ping", "arguments": {marker: 1}}
    )
    assert reply["refusal"] == "undeclared_argument"
    assert marker not in json.dumps(recorded[0])
    assert "argument" not in recorded[0], (
        "the recorder kept a key the caller chose; declared argument names "
        "are ours to record and this one is not"
    )


def test_the_same_rejected_frame_fingerprints_the_same_way(server):
    """So an operator can see one unknown verb arriving four hundred times."""

    _exchange(server, {"verb": "nope", "arguments": {}})
    _, recorded = _exchange(server, {"verb": "nope", "arguments": {}})
    assert len(recorded) == 2
    assert recorded[0]["request_fingerprint"] == recorded[1]["request_fingerprint"]


def test_two_different_frames_fingerprint_differently():
    assert fingerprint(b"a") != fingerprint(b"b")
    assert len(fingerprint(b"a")) == 16


# -- arguments have no free-text kind ------------------------------------


def test_no_argument_kind_carries_unbounded_text():
    """The whole type system, and every kind in it is bounded.

    `ENUM` is a choice from a set the verb declares. `DIGEST` and `TIMESTAMP`
    are fixed grammars, compared and never dereferenced. `IDENTIFIER` is the
    one kind carrying text a caller chose, and it is bounded on both axes --
    64 characters from an alphabet with no whitespace, no control characters
    and no shell metacharacters.

    None of them would let a caller name a path, a unit or a command. This
    test is pinned to the exact set so that adding a kind is a decision
    somebody makes here rather than one that arrives with a feature.
    """

    assert {kind.value for kind in ArgumentKind} == {
        "ordinal",
        "flag",
        "enum",
        "digest",
        "timestamp",
        "identifier",
    }


def test_an_identifier_is_bounded_in_length_and_alphabet():
    argument = Argument("actor", ArgumentKind.IDENTIFIER)
    assert argument.coerce("operator@console") == "operator@console"
    for rejected in (
        "a" * 65,
        "has space",
        "semi;colon",
        "new\nline",
        "",
        "../../etc/passwd",
        "$(whoami)",
    ):
        with pytest.raises(RequestRefused):
            argument.coerce(rejected)


def test_a_timestamp_must_be_an_rfc3339_instant_in_utc():
    argument = Argument("occurred_at", ArgumentKind.TIMESTAMP)
    assert argument.coerce("2026-09-20T12:00:00Z") == "2026-09-20T12:00:00Z"
    for rejected in (
        "2026-09-20 12:00:00Z",
        "2026-09-20T12:00:00+09:00",
        "2026-09-20",
        "yesterday",
    ):
        with pytest.raises(RequestRefused):
            argument.coerce(rejected)


def test_a_payload_is_refused_by_a_verb_that_does_not_declare_one(server):
    """An object nothing validates is an object that reaches the daemon unchecked."""

    reply, _ = _exchange(
        server, {"verb": "node.ping", "arguments": {}, "event": {"anything": 1}}
    )
    assert reply["refusal"] == "undeclared_argument"


def test_an_ordinal_is_bounded_at_declaration():
    with pytest.raises(ValueError):
        Argument("index", ArgumentKind.ORDINAL)


def test_an_enum_that_enumerates_nothing_is_refused():
    with pytest.raises(ValueError):
        Argument("unit", ArgumentKind.ENUM)


def test_a_boolean_is_not_an_ordinal():
    """`bool` is an `int` in Python, and `True` would address element one."""

    argument = Argument("ordinal", ArgumentKind.ORDINAL, maximum=7)
    with pytest.raises(RequestRefused) as refused:
        argument.coerce(True)
    assert refused.value.refusal is Refusal.ARGUMENT_TYPE


def test_an_ordinal_out_of_range_is_refused_rather_than_clamped():
    argument = Argument("ordinal", ArgumentKind.ORDINAL, maximum=7)
    with pytest.raises(RequestRefused) as refused:
        argument.coerce(8)
    assert refused.value.refusal is Refusal.ARGUMENT_RANGE


def test_a_digest_must_match_the_grammar_exactly():
    argument = Argument("snapshot", ArgumentKind.DIGEST)
    assert argument.coerce(DIGEST) == DIGEST
    for bad in ("sha256:xyz", "../etc/passwd", DIGEST.upper(), DIGEST + "a"):
        with pytest.raises(RequestRefused):
            argument.coerce(bad)


def test_an_enum_value_outside_the_declared_set_is_refused():
    argument = Argument("unit", ArgumentKind.ENUM, choices=("auditd", "watchdog"))
    assert argument.coerce("auditd") == "auditd"
    with pytest.raises(RequestRefused):
        argument.coerce("azazel-enforced.service")


def test_a_missing_argument_is_refused_separately_from_an_undeclared_one():
    principal = Principal(uid=0, gid=0, pid=1, classes=frozenset({PrincipalClass.ROOT}))
    verb = REGISTRY.resolve("node.pick", principal)
    with pytest.raises(RequestRefused) as missing:
        verb.bind({"ordinal": 1})
    assert missing.value.refusal is Refusal.MISSING_ARGUMENT

    with pytest.raises(RequestRefused) as undeclared:
        verb.bind(
            {
                "ordinal": 1,
                "snapshot": DIGEST,
                "dry_run": False,
                "unit": "auditd",
                "surprise": 1,
            }
        )
    assert undeclared.value.refusal is Refusal.UNDECLARED_ARGUMENT


def test_a_complete_request_binds():
    principal = Principal(uid=0, gid=0, pid=1, classes=frozenset({PrincipalClass.ROOT}))
    verb = REGISTRY.resolve("node.pick", principal)
    bound = verb.bind(
        {"ordinal": 7, "snapshot": DIGEST, "dry_run": True, "unit": "watchdog"}
    )
    assert bound == {
        "ordinal": 7,
        "snapshot": DIGEST,
        "dry_run": True,
        "unit": "watchdog",
    }


def test_a_registry_refuses_a_duplicate_verb():
    with pytest.raises(ValueError):
        VerbRegistry([PING, PING])


#: A trailing line ending, blank or NUL after a valid value. `$` matches before
#: a final `\n`, so a grammar closed with `$` and used with `match` admitted
#: the first of these (Azazel-Fabric#65). Each must be refused.
TRAILING = ("\n", "\r\n", " ", "\x00")


@pytest.mark.parametrize(
    "kind, valid",
    [
        (ArgumentKind.DIGEST, DIGEST),
        (ArgumentKind.TIMESTAMP, "2026-09-20T12:00:00Z"),
        (ArgumentKind.IDENTIFIER, "operator@console"),
    ],
)
@pytest.mark.parametrize("suffix", TRAILING)
def test_an_argument_with_a_trailing_line_ending_is_refused(kind, valid, suffix):
    argument = Argument("value", kind)
    assert argument.coerce(valid) == valid
    with pytest.raises(RequestRefused) as refused:
        argument.coerce(valid + suffix)
    assert refused.value.refusal is Refusal.ARGUMENT_RANGE
