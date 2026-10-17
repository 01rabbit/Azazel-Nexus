from __future__ import annotations

import socket
import errno
import asyncio
import tempfile
from importlib.metadata import PackageNotFoundError

import pytest

from azazel_nexus_runtime import systemd_socket
from azazel_nexus_runtime.systemd_socket import FixedSystemBusSocket
from azazel_nexus_runtime.units import UnitOperationFailed


class _FakeSocket:
    def __init__(self, events, *, connect_error=None):
        self.events = events
        self.connect_error = connect_error
        self.closed = False

    def settimeout(self, value):
        self.events.append(("timeout", value))

    def connect(self, address):
        self.events.append(("connect", address))
        if self.connect_error:
            raise self.connect_error

    def setblocking(self, value):
        self.events.append(("blocking", value))

    def makefile(self, mode):
        self.events.append(("makefile", mode))
        return object()

    def fileno(self):
        return 23

    def close(self):
        self.closed = True
        self.events.append(("close",))


class _SocketHarness(FixedSystemBusSocket):
    def __init__(self, bus_address, *, parent_error=None):
        self._bus_address = bus_address
        self.parent_error = parent_error
        self._sock = None
        self._stream = None
        super().__init__()

    def _setup_socket(self):
        return super()._setup_socket()


class _Parent:
    def __init__(self, *, parent_error=None):
        if parent_error:
            raise parent_error


def _address(path=None):
    return [("unix", {"path": path or systemd_socket.SYSTEM_BUS_SOCKET})]


def test_supported_dbus_next_version_is_exactly_023(monkeypatch):
    monkeypatch.setattr(systemd_socket, "version", lambda distribution: "0.2.3")
    systemd_socket.require_supported_dbus_next()


@pytest.mark.parametrize("installed_version", ["0.2.2", "0.2.4", "1.0.0"])
def test_unreviewed_dbus_next_versions_are_rejected(monkeypatch, installed_version):
    monkeypatch.setattr(systemd_socket, "version", lambda distribution: installed_version)
    with pytest.raises(UnitOperationFailed, match="unreviewed system bus client version"):
        systemd_socket.require_supported_dbus_next()


def test_missing_dbus_next_distribution_is_rejected_without_metadata_details(monkeypatch):
    def missing(_distribution):
        raise PackageNotFoundError("dbus-next", "private metadata detail")

    monkeypatch.setattr(systemd_socket, "version", missing)
    with pytest.raises(UnitOperationFailed, match="pinned system bus client unavailable") as error:
        systemd_socket.require_supported_dbus_next()
    assert "private" not in str(error.value)


def test_fixed_socket_sets_own_timeout_then_connects_then_sets_nonblocking(monkeypatch):
    events = []
    fake = _FakeSocket(events)
    monkeypatch.setattr(systemd_socket.socket, "socket", lambda *args: fake)

    bus = _SocketHarness(_address())
    bus._setup_socket()

    assert events == [
        ("timeout", systemd_socket._SOCKET_TIMEOUT_SECONDS),
        ("connect", systemd_socket.SYSTEM_BUS_SOCKET),
        ("blocking", False),
        ("makefile", "rwb"),
    ]
    assert bus._sock is fake
    assert bus._stream is not None
    assert bus._fd == 23
    assert not fake.closed


@pytest.mark.parametrize(
    "address",
    [
        [("tcp", {"host": "127.0.0.1", "port": 1234})],
        [("unix", {"abstract": "system-bus"})],
        [("unix", {"path": systemd_socket.SYSTEM_BUS_SOCKET}),
         ("tcp", {"host": "127.0.0.1", "port": 1234})],
        [("unix", {"path": "/tmp/other-system-bus"})],
    ],
)
def test_socket_rejects_nonfixed_or_multiple_addresses_before_open(address, monkeypatch):
    opened = []
    monkeypatch.setattr(systemd_socket.socket, "socket", lambda *args: opened.append(args))
    bus = _SocketHarness(address)

    with pytest.raises(UnitOperationFailed, match="fixed system bus socket"):
        bus._setup_socket()
    assert opened == []


def test_socket_closes_when_unix_connect_fails(monkeypatch):
    events = []
    fake = _FakeSocket(events, connect_error=TimeoutError("private connect detail"))
    monkeypatch.setattr(systemd_socket.socket, "socket", lambda *args: fake)

    with pytest.raises(TimeoutError, match="private connect detail"):
        _SocketHarness(_address())._setup_socket()
    assert fake.closed
    assert events[-1] == ("close",)
    assert ("blocking", False) not in events


def test_parent_constructor_failure_closes_socket_and_stream():
    class Stream:
        closed = False

        def close(self):
            self.closed = True

    resources = {}

    class FailingBus(FixedSystemBusSocket, _Parent):
        def __init__(self):
            self._sock = _FakeSocket([])
            self._stream = Stream()
            resources["socket"] = self._sock
            resources["stream"] = self._stream
            super().__init__(parent_error=RuntimeError("private parent detail"))

    with pytest.raises(RuntimeError, match="private parent detail"):
        FailingBus()
    assert resources["socket"].closed
    assert resources["stream"].closed


def test_real_unix_connect_refuses_when_listen_queue_is_full(monkeypatch):
    temporary_directory = tempfile.TemporaryDirectory(prefix="azbus-", dir="/tmp")
    socket_path = temporary_directory.name + "/bus.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    clients = []
    try:
        listener.bind(socket_path)
        listener.listen(1)
        listener.settimeout(0.02)

        # Fill the finite accept queue without accepting. The connect timeout
        # is short so this remains a local socket test, never a D-Bus service.
        queue_full = False
        for _ in range(32):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(0.02)
            try:
                client.connect(socket_path)
            except TimeoutError:
                client.close()
                queue_full = True
                break
            except ConnectionRefusedError:
                client.close()
                # Some Unix implementations refuse immediately once the
                # listen queue is full; others leave connect blocked to timeout.
                queue_full = True
                break
            except BlockingIOError as error:
                client.close()
                if error.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise
                queue_full = True
                break
            clients.append(client)
        if not queue_full:
            pytest.fail("bounded client attempts did not fill the Unix listen queue")

        monkeypatch.setattr(systemd_socket, "SYSTEM_BUS_SOCKET", socket_path)
        monkeypatch.setattr(systemd_socket, "_SOCKET_TIMEOUT_SECONDS", 0.03)
        # Independent test ceiling keeps a missing production timeout from
        # hanging the suite. The adapter must replace this with its own bound.
        real_socket = socket.socket
        created = []

        def bounded_test_socket(*args):
            result = real_socket(*args)
            result.settimeout(0.5)
            created.append(result)
            return result

        monkeypatch.setattr(systemd_socket.socket, "socket", bounded_test_socket)
        bus = _SocketHarness(_address(socket_path))
        with pytest.raises((TimeoutError, ConnectionRefusedError, BlockingIOError)) as refused:
            bus._setup_socket()
        if isinstance(refused.value, BlockingIOError):
            assert refused.value.errno in {errno.EAGAIN, errno.EWOULDBLOCK}
        assert bus._sock is None
        assert len(created) == 1
        assert created[0].gettimeout() == 0.03
        assert created[0].fileno() == -1
    finally:
        for client in clients:
            client.close()
        listener.close()
        temporary_directory.cleanup()


def test_session_close_releases_fixed_socket_resources_after_loop_close():
    from types import SimpleNamespace
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession

    loop = asyncio.new_event_loop()
    events = []

    class Resource:
        def close(self):
            assert loop.is_closed()
            events.append("resource-close")

    class Bus(FixedSystemBusSocket):
        def __init__(self):
            self._sock = Resource()
            self._stream = Resource()

        def disconnect(self):
            events.append("disconnect")

    session = SystemdBusSession(bus=Bus(), loop=loop, previous_loop=None,
                                message_type=SimpleNamespace(), message_factory=object)
    session.close()
    assert events == ["disconnect", "resource-close", "resource-close"]
