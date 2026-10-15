"""Bound transport waits with synthetic buses, never a system service bus."""

import asyncio
import sys
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import systemd_bus as transport
from azazel_nexus_runtime.units import DbusUnitManager, UnitOperationFailed


@pytest.mark.parametrize("disconnect_fails", [False, True])
@pytest.mark.parametrize(
    "failure",
    ["connect", "owner_timeout", "pid_timeout", "uid_timeout", "bad_pid", "bad_uid", "credential_error"],
)
def test_connect_failure_disconnects_closes_and_restores(monkeypatch, disconnect_fails, failure):
    monkeypatch.setattr(transport, "require_supported_dbus_next", lambda: None)
    observed = {}
    previous = asyncio.new_event_loop()
    asyncio.set_event_loop(previous)

    class Bus:
        def __init__(self, *, bus_address):
            observed["loop"] = asyncio.get_event_loop()
            observed["bus_address"] = bus_address

        async def connect(self):
            if failure == "connect":
                try:
                    await asyncio.Event().wait()
                finally:
                    observed["cancelled"] = True

        async def call(self, message):
            if failure == "owner_timeout" and message.member == "GetNameOwner":
                try:
                    await asyncio.Event().wait()
                finally:
                    observed["cancelled"] = True
            if failure == "pid_timeout" and message.member == "GetConnectionUnixProcessID":
                try:
                    await asyncio.Event().wait()
                finally:
                    observed["cancelled"] = True
            if failure == "uid_timeout" and message.member == "GetConnectionUnixUser":
                try:
                    await asyncio.Event().wait()
                finally:
                    observed["cancelled"] = True
            if failure == "credential_error" and message.member == "GetConnectionUnixUser":
                raise RuntimeError("private credential transport detail")
            if message.member == "GetNameOwner":
                return SimpleNamespace(
                    message_type=1, signature="s", body=[":1.42"],
                    sender="org.freedesktop.DBus",
                )
            value = 2 if failure == "bad_pid" and message.member == "GetConnectionUnixProcessID" else 1
            if failure == "bad_uid" and message.member == "GetConnectionUnixUser":
                value = 1000
            return SimpleNamespace(
                message_type=1, signature="u", body=[value], sender="org.freedesktop.DBus"
            )

        def disconnect(self):
            observed["disconnected"] = True
            if disconnect_fails:
                raise RuntimeError("private connection detail")

    monkeypatch.setitem(
        sys.modules,
        "dbus_next",
        SimpleNamespace(
            Message=lambda **kwargs: SimpleNamespace(**kwargs),
            MessageType=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        ),
    )
    monkeypatch.setitem(sys.modules, "dbus_next.aio", SimpleNamespace(MessageBus=Bus))
    monkeypatch.setattr(transport, "_BUS_TIMEOUT_SECONDS", 0.01)
    try:
        with pytest.raises(UnitOperationFailed, match="could not connect") as error:
            transport.SystemdBusSession.connect()
        assert "private" not in str(error.value)
        assert observed["disconnected"]
        if failure in {"connect", "owner_timeout", "pid_timeout", "uid_timeout"}:
            assert observed["cancelled"]
        assert asyncio.all_tasks(observed["loop"]) == set()
        assert observed["bus_address"] == "unix:path=/run/dbus/system_bus_socket"
        assert observed["loop"].is_closed()
        assert asyncio.get_event_loop() is previous
    finally:
        previous.close()
        asyncio.set_event_loop(None)


def test_mask_timeout_never_observes_or_claims_success(monkeypatch):
    class Bus:
        def __init__(self):
            self.calls = []
            self.cancelled = False
            self.disconnected = False

        async def call(self, message):
            self.calls.append(message)
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True

        def disconnect(self):
            self.disconnected = True

    bus = Bus()
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(transport, "_BUS_TIMEOUT_SECONDS", 0.01)
    session = transport.SystemdBusSession(
        bus=bus,
        loop=loop,
        previous_loop=None,
        message_type=SimpleNamespace(ERROR="error", METHOD_RETURN="return"),
        message_factory=lambda **kwargs: SimpleNamespace(**kwargs),
    )
    try:
        with pytest.raises(UnitOperationFailed, match="did not complete"):
            DbusUnitManager(session).mask("azazel-auditd.service")
        assert [call.member for call in bus.calls] == ["MaskUnitFiles"]
        assert bus.cancelled
    finally:
        session.close()
    assert loop.is_closed() and bus.disconnected
