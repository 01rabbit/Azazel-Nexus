"""The fixed systemd Manager calls used by Nexus activation.

This module does not accept D-Bus destinations, interfaces, object paths,
signatures, or unit names from callers. It maps the runtime's narrow semantic
verbs onto the systemd system-bus API and validates every reply. In
particular, it never exposes ``StartUnit``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Sequence

from .units import UNIT_NAMES, UnitOperationFailed

__all__ = ["SystemdBusSession", "SystemdUnitCalls"]

DESTINATION = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
UNIT_INTERFACE = "org.freedesktop.systemd1.Unit"

_UNITS = frozenset(UNIT_NAMES.values())
_ACTIVE_STATES = frozenset(
    {
        "active",
        "reloading",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "maintenance",
        "refreshing",
    }
)
_UNIT_FILE_STATES = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "linked",
        "linked-runtime",
        "alias",
        "masked",
        "masked-runtime",
        "static",
        "indirect",
        "disabled",
        "generated",
        "transient",
        "invalid",
    }
)


@dataclass(frozen=True)
class _Reply:
    signature: str
    body: list


class SystemdUnitCalls:
    """Translate the adapter's fixed method/unit pair to typed D-Bus calls."""

    def __init__(
        self,
        exchange: Callable[..., _Reply],
    ) -> None:
        self._exchange = exchange

    def __call__(self, method: str, unit: str) -> object:
        if unit not in _UNITS:
            raise UnitOperationFailed(
                "the systemd client refused a unit outside the fixed allowlist"
            )

        if method == "GetUnitFileState":
            reply = self._exchange(MANAGER_INTERFACE, "GetUnitFileState", "s", [unit])
            value = self._one(reply, "s", "GetUnitFileState")
            if not isinstance(value, str) or value not in _UNIT_FILE_STATES:
                raise UnitOperationFailed("systemd returned an unknown unit-file state")
            return value

        if method == "GetActiveState":
            unit_reply = self._exchange(MANAGER_INTERFACE, "GetUnit", "s", [unit])
            object_path = self._one(unit_reply, "o", "GetUnit")
            expected_path = _unit_object_path(unit)
            if object_path != expected_path:
                raise UnitOperationFailed("systemd returned an invalid unit object")
            property_reply = self._exchange(
                PROPERTIES_INTERFACE,
                "Get",
                "ss",
                [UNIT_INTERFACE, "ActiveState"],
                path=expected_path,
            )
            variant = self._one(property_reply, "v", "Properties.Get")
            value = getattr(variant, "value", None)
            if not isinstance(value, str) or value not in _ACTIVE_STATES:
                raise UnitOperationFailed("systemd returned an invalid active state")
            return value == "active"

        signatures = {
            "MaskUnitFiles": ("asbb", "a(sss)"),
            "UnmaskUnitFiles": ("asb", "a(sss)"),
            "EnableUnitFiles": ("asbb", "ba(sss)"),
        }
        contract = signatures.get(method)
        if contract is None:
            raise UnitOperationFailed(
                "the systemd client refused an undeclared manager operation"
            )

        signature, expected_reply = contract
        body: list[object]
        if method == "UnmaskUnitFiles":
            body = [[unit], False]
        else:
            body = [[unit], False, False]
        reply = self._exchange(MANAGER_INTERFACE, method, signature, body)
        if reply.signature != expected_reply:
            raise UnitOperationFailed(
                f"systemd returned an invalid {method} reply signature"
            )
        if method == "EnableUnitFiles":
            if (
                len(reply.body) != 2
                or not isinstance(reply.body[0], bool)
                or not isinstance(reply.body[1], list)
            ):
                raise UnitOperationFailed("systemd returned an invalid enable reply")
        elif len(reply.body) != 1 or not isinstance(reply.body[0], list):
            raise UnitOperationFailed(f"systemd returned an invalid {method} reply")
        return reply.body

    @staticmethod
    def _one(reply: _Reply, signature: str, operation: str) -> object:
        if reply.signature != signature or len(reply.body) != 1:
            raise UnitOperationFailed(f"systemd returned an invalid {operation} reply")
        return reply.body[0]


def _unit_object_path(unit: str) -> str:
    """Encode a known ASCII unit name as systemd's D-Bus object path."""

    encoded = "".join(
        character
        if character.isalnum() or character == "_"
        else f"_{ord(character):02x}"
        for character in unit
    )
    return f"/org/freedesktop/systemd1/unit/{encoded}"


class SystemdBusSession:
    """Synchronous, one-shot facade over a connected system D-Bus session."""

    def __init__(
        self,
        *,
        bus: object,
        loop: asyncio.AbstractEventLoop,
        previous_loop: asyncio.AbstractEventLoop | None,
        message_type,
        message_factory,
    ):
        self._bus = bus
        self._loop = loop
        self._previous_loop = previous_loop
        self._message_type = message_type
        self._message_factory = message_factory
        self.calls = SystemdUnitCalls(self._exchange)

    @classmethod
    def connect(cls) -> "SystemdBusSession":
        """Connect only to the system bus; fail if the pinned client is absent."""

        try:
            from dbus_next import Message, MessageType
            from dbus_next.aio import MessageBus
            from dbus_next.constants import BusType
        except ImportError as exc:  # pragma: no cover - exercised on target
            raise UnitOperationFailed(
                "the pinned dbus-next runtime dependency is not installed"
            ) from exc

        try:
            previous_loop = asyncio.get_event_loop()
        except RuntimeError:
            previous_loop = None
        if previous_loop is not None and previous_loop.is_running():
            raise UnitOperationFailed(
                "could not connect to the system D-Bus service manager"
            )

        loop = asyncio.new_event_loop()
        try:
            # dbus-next 0.2.3 binds its asyncio transport to the current loop
            # while constructing MessageBus. Keep that loop current for both
            # construction and connection, then restore the caller's context.
            asyncio.set_event_loop(loop)
            bus = MessageBus(bus_type=BusType.SYSTEM)
            loop.run_until_complete(bus.connect())
        except Exception as exc:  # noqa: BLE001 - translated at the trust boundary
            loop.close()
            asyncio.set_event_loop(previous_loop)
            raise UnitOperationFailed(
                "could not connect to the system D-Bus service manager"
            ) from exc
        return cls(
            bus=bus,
            loop=loop,
            previous_loop=previous_loop,
            message_type=MessageType,
            message_factory=Message,
        )

    def _exchange(
        self,
        interface: str,
        member: str,
        signature: str,
        body: Sequence[object],
        *,
        path: str = MANAGER_PATH,
    ) -> _Reply:
        if interface not in {MANAGER_INTERFACE, PROPERTIES_INTERFACE}:
            raise UnitOperationFailed("the systemd client refused an interface")
        if interface == MANAGER_INTERFACE:
            allowed = {
                "GetUnitFileState": "s",
                "GetUnit": "s",
                "MaskUnitFiles": "asbb",
                "UnmaskUnitFiles": "asb",
                "EnableUnitFiles": "asbb",
            }
            if allowed.get(member) != signature or path != MANAGER_PATH:
                raise UnitOperationFailed("the systemd client refused a call shape")
        elif (
            member != "Get"
            or signature != "ss"
            or path not in {_unit_object_path(unit) for unit in _UNITS}
            or list(body) != [UNIT_INTERFACE, "ActiveState"]
        ):
            raise UnitOperationFailed("the systemd client refused a property path")

        message = self._message_factory(
            destination=DESTINATION,
            path=path,
            interface=interface,
            member=member,
            signature=signature,
            body=list(body),
        )
        try:
            reply = self._loop.run_until_complete(self._bus.call(message))
        except Exception as exc:  # noqa: BLE001 - translated at the trust boundary
            raise UnitOperationFailed(
                f"systemd D-Bus call {member} did not complete"
            ) from exc
        if reply.message_type == self._message_type.ERROR:
            raise UnitOperationFailed(f"systemd D-Bus call {member} returned an error")
        if reply.message_type != self._message_type.METHOD_RETURN:
            raise UnitOperationFailed(
                f"systemd D-Bus call {member} returned an invalid message type"
            )
        return _Reply(reply.signature, reply.body)

    def __call__(self, method: str, unit: str) -> object:
        return self.calls(method, unit)

    def close(self) -> None:
        try:
            self._bus.disconnect()
        finally:
            if not self._loop.is_closed():
                self._loop.close()
            asyncio.set_event_loop(self._previous_loop)

    def __enter__(self) -> "SystemdBusSession":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
