"""Contract tests for the fixed systemd readiness notification."""

import socket
import tempfile
from pathlib import Path

import pytest

from azazel_nexus_runtime import systemd_notify
from azazel_nexus_runtime.units import UnitOperationFailed


VALID_INVOCATION_ID = "a" * 32
NOTIFY_SOCKET = "/run/systemd/notify"


@pytest.fixture
def valid_environment(monkeypatch):
    monkeypatch.setattr(systemd_notify, "ROOT", Path("/"))
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda path: str(path) == "/run/systemd/system",
    )
    monkeypatch.setenv("INVOCATION_ID", VALID_INVOCATION_ID)
    monkeypatch.setenv("NOTIFY_SOCKET", NOTIFY_SOCKET)


@pytest.mark.parametrize(
    ("root", "systemd_present", "invocation_id", "notify_socket"),
    [
        (Path("/tmp/image"), True, VALID_INVOCATION_ID, NOTIFY_SOCKET),
        (Path("/"), False, VALID_INVOCATION_ID, NOTIFY_SOCKET),
        (Path("/"), True, "", NOTIFY_SOCKET),
        (Path("/"), True, "g" * 32, NOTIFY_SOCKET),
        (Path("/"), True, "a" * 31, NOTIFY_SOCKET),
        (Path("/"), True, "a" * 33, NOTIFY_SOCKET),
        (Path("/"), True, VALID_INVOCATION_ID, ""),
        (Path("/"), True, VALID_INVOCATION_ID, "/tmp/notify"),
    ],
)
def test_invalid_environment_is_rejected_before_socket_creation(
    monkeypatch, root, systemd_present, invocation_id, notify_socket
):
    monkeypatch.setattr(systemd_notify, "ROOT", root)
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda path: systemd_present and str(path) == "/run/systemd/system",
    )
    monkeypatch.setenv("INVOCATION_ID", invocation_id)
    monkeypatch.setenv("NOTIFY_SOCKET", notify_socket)

    def forbidden_socket(*_args, **_kwargs):
        pytest.fail("socket created before environment validation")

    monkeypatch.setattr(systemd_notify.socket, "socket", forbidden_socket)
    with pytest.raises(UnitOperationFailed):
        systemd_notify.notify_ready()


def test_public_api_has_no_address_or_message_overrides():
    import inspect

    assert tuple(inspect.signature(systemd_notify.notify_ready).parameters) == ()
    assert tuple(inspect.signature(systemd_notify.notify_watchdog).parameters) == ()


class FakeSocket:
    def __init__(self, *, send_result=None, send_error=None):
        self.send_result = send_result
        self.send_error = send_error
        self.timeout = None
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, payload, address):
        self.sent.append((payload, address))
        if self.send_error is not None:
            raise self.send_error
        return len(payload) if self.send_result is None else self.send_result

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def install_fake_socket(monkeypatch, fake):
    created = []

    def create(family, kind):
        created.append((family, kind))
        return fake

    monkeypatch.setattr(systemd_notify.socket, "socket", create)
    return created


def test_ready_sends_exact_payload_to_fixed_socket_with_finite_timeout(
    valid_environment, monkeypatch
):
    fake = FakeSocket()
    created = install_fake_socket(monkeypatch, fake)

    systemd_notify.notify_ready()

    assert created == [(socket.AF_UNIX, socket.SOCK_DGRAM)]
    assert fake.timeout == 1.0
    assert fake.sent == [(b"READY=1", NOTIFY_SOCKET)]
    assert fake.closed


def test_watchdog_sends_exact_payload_to_fixed_socket_with_finite_timeout(
    valid_environment, monkeypatch
):
    fake = FakeSocket()
    created = install_fake_socket(monkeypatch, fake)

    systemd_notify.notify_watchdog()

    assert created == [(socket.AF_UNIX, socket.SOCK_DGRAM)]
    assert fake.timeout == 1.0
    assert fake.sent == [(b"WATCHDOG=1", NOTIFY_SOCKET)]
    assert fake.closed


def test_short_send_is_a_redacted_operation_failure(valid_environment, monkeypatch):
    fake = FakeSocket(send_result=2)
    install_fake_socket(monkeypatch, fake)

    with pytest.raises(UnitOperationFailed) as error:
        systemd_notify.notify_ready()

    assert fake.closed
    assert "2" not in str(error.value)


@pytest.mark.parametrize(
    "failure", [TimeoutError("private timeout detail"), OSError("private socket detail")]
)
def test_send_failure_is_redacted_and_socket_is_closed(
    valid_environment, monkeypatch, failure
):
    fake = FakeSocket(send_error=failure)
    install_fake_socket(monkeypatch, fake)

    with pytest.raises(UnitOperationFailed) as error:
        systemd_notify.notify_ready()

    assert fake.closed
    assert "private" not in str(error.value)


def test_socket_creation_failure_is_redacted(valid_environment, monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("private creation detail")

    monkeypatch.setattr(systemd_notify.socket, "socket", fail)

    with pytest.raises(UnitOperationFailed) as error:
        systemd_notify.notify_ready()

    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    ("root", "systemd_present", "invocation_id", "notify_socket"),
    [
        (Path("/tmp/image"), True, VALID_INVOCATION_ID, NOTIFY_SOCKET),
        (Path("/"), False, VALID_INVOCATION_ID, NOTIFY_SOCKET),
        (Path("/"), True, "", NOTIFY_SOCKET),
        (Path("/"), True, VALID_INVOCATION_ID, "/tmp/notify"),
    ],
)
def test_watchdog_invalid_context_is_rejected_before_socket_creation(
    monkeypatch, root, systemd_present, invocation_id, notify_socket
):
    monkeypatch.setattr(systemd_notify, "ROOT", root)
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda path: systemd_present and str(path) == "/run/systemd/system",
    )
    monkeypatch.setenv("INVOCATION_ID", invocation_id)
    monkeypatch.setenv("NOTIFY_SOCKET", notify_socket)

    def forbidden_socket(*_args, **_kwargs):
        pytest.fail("socket created before watchdog context validation")

    monkeypatch.setattr(systemd_notify.socket, "socket", forbidden_socket)
    with pytest.raises(UnitOperationFailed):
        systemd_notify.notify_watchdog()


@pytest.mark.parametrize("send_result", [0, 3])
def test_watchdog_noncomplete_send_is_refused_and_socket_closed(
    valid_environment, monkeypatch, send_result
):
    fake = FakeSocket(send_result=send_result)
    install_fake_socket(monkeypatch, fake)

    with pytest.raises(UnitOperationFailed):
        systemd_notify.notify_watchdog()

    assert fake.sent == [(b"WATCHDOG=1", NOTIFY_SOCKET)]
    assert fake.closed


def test_watchdog_failed_send_is_redacted_and_socket_closed(valid_environment, monkeypatch):
    fake = FakeSocket(send_error=OSError("private watchdog socket detail"))
    install_fake_socket(monkeypatch, fake)

    with pytest.raises(UnitOperationFailed) as error:
        systemd_notify.notify_watchdog()

    assert fake.closed
    assert "private" not in str(error.value)


def test_private_sender_accepts_only_address_and_still_sends_fixed_message(
    valid_environment, monkeypatch
):
    import inspect

    fake = FakeSocket()
    install_fake_socket(monkeypatch, fake)

    assert tuple(inspect.signature(systemd_notify._send_ready).parameters) == (
        "address",
    )
    systemd_notify._send_ready(NOTIFY_SOCKET)

    assert fake.sent == [(b"READY=1", NOTIFY_SOCKET)]
    assert fake.closed


def test_private_sender_delivers_to_temporary_unix_datagram_socket():
    with tempfile.TemporaryDirectory(prefix="n-", dir="/tmp") as short_dir:
        address = str(Path(short_dir) / "s")
        receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            receiver.bind(address)
            receiver.settimeout(1.0)
            systemd_notify._send_ready(address)
            assert receiver.recv(64) == b"READY=1"
        finally:
            receiver.close()


def test_runtime_ready_callback_is_enabled_only_for_host_root(monkeypatch):
    monkeypatch.setattr(systemd_notify, "ROOT", Path("/"))
    assert systemd_notify.runtime_ready_callback() is systemd_notify.notify_ready

    monkeypatch.setattr(systemd_notify, "ROOT", Path("/tmp/relocated"))
    assert systemd_notify.runtime_ready_callback() is None


def _short_socket_path():
    directory = tempfile.mkdtemp(prefix="azn-", dir="/tmp")
    return directory, directory + "/n"


def test_barrier_waits_until_the_receiver_has_closed_the_passed_descriptor():
    import array
    import os
    import threading

    directory, address = _short_socket_path()
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(address)
    seen = []

    def manager():
        fds = array.array("i")
        message, ancillary, _flags, _addr = receiver.recvmsg(64, socket.CMSG_LEN(fds.itemsize))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data[:fds.itemsize])
        seen.append((message, len(fds)))
        for fd in fds:
            os.close(fd)  # "processed": the barrier's read end now sees EOF

    thread = threading.Thread(target=manager)
    thread.start()
    try:
        systemd_notify._barrier(address, 5.0)
    finally:
        thread.join(5)
        receiver.close()
        os.unlink(address)
        os.rmdir(directory)
    assert seen == [(b"BARRIER=1", 1)]


def test_barrier_times_out_when_the_descriptor_is_kept():
    import os

    directory, address = _short_socket_path()
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(address)
    try:
        # Nobody receives: the descriptor stays queued, so no EOF arrives.
        with pytest.raises(UnitOperationFailed, match="timed out"):
            systemd_notify._barrier(address, 0.2)
    finally:
        receiver.close()
        os.unlink(address)
        os.rmdir(directory)


def test_barrier_requires_the_fixed_context(monkeypatch):
    monkeypatch.setattr(systemd_notify, "ROOT", Path("/tmp/image"))
    monkeypatch.setattr(systemd_notify, "_barrier",
                        lambda *_args: pytest.fail("barrier sent outside systemd"))
    with pytest.raises(UnitOperationFailed):
        systemd_notify.notify_barrier()
