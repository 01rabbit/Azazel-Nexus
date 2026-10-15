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

from .bootstrap_systemd_profile import observe_bootstrap_systemd_profile
from .systemd_socket import FixedSystemBusSocket, SYSTEM_BUS_ADDRESS, require_supported_dbus_next
from .units import UNIT_NAMES, UnitOperationFailed

__all__ = ["SystemdBusSession", "SystemdUnitCalls"]

DESTINATION = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
UNIT_INTERFACE = "org.freedesktop.systemd1.Unit"

# Transport bounds, not node-health measurements or bootstrap lease duration.
# An unanswered D-Bus call must not keep the refusing controller stuck forever.
# A timeout is uncertainty: callers must not infer completion or retry widening.
_BUS_TIMEOUT_SECONDS = 10.0
_SYSTEM_BUS_ADDRESS = SYSTEM_BUS_ADDRESS

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
    #: True only for an opted-in call that got exactly systemd's NoSuchUnit.
    no_such_unit: bool = False


_NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"


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

        if method in {"GetActiveState", "GetInactiveState"}:
            unit_reply = self._exchange(
                MANAGER_INTERFACE, "GetUnit", "s", [unit], allow_no_such_unit=True
            )
            if getattr(unit_reply, "no_such_unit", False) is True:
                # GetUnit never loads a unit, so NoSuchUnit means systemd holds
                # no unit object: it has no ActiveState to report and is not
                # active, activating, deactivating or holding a job. That is
                # read as "inactive" -- the same claim the loaded path makes
                # from ActiveState alone, not proof that no process exists --
                # and only with fresh masked file state (every governed unit
                # must be masked) and a re-read confirming it is still not
                # loaded. Anything else is refused.
                state_reply = self._exchange(
                    MANAGER_INTERFACE, "GetUnitFileState", "s", [unit]
                )
                if self._one(state_reply, "s", "GetUnitFileState") != "masked":
                    raise UnitOperationFailed(
                        "systemd reported an unloaded unit that is not masked"
                    )
                recheck = self._exchange(
                    MANAGER_INTERFACE, "GetUnit", "s", [unit], allow_no_such_unit=True
                )
                if getattr(recheck, "no_such_unit", False) is not True:
                    raise UnitOperationFailed("governed unit was loaded during observation")
                return method == "GetInactiveState"
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
            return value == ("inactive" if method == "GetInactiveState" else "active")

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

    def bootstrap_profile(self):
        """Observe fixed Manager properties and classify the reviewed profile.

        This is read-only. A matching profile is compatibility evidence only;
        it does not authorize publishing files or changing systemd state.
        """
        version = self._manager_property("Version", "s")
        unit_path = self._manager_property("UnitPath", "as")
        return observe_bootstrap_systemd_profile(version=version, unit_path=unit_path)

    def _manager_property(self, name: str, signature: str):
        reply = self._exchange(
            PROPERTIES_INTERFACE, "Get", "ss", [MANAGER_INTERFACE, name],
            path=MANAGER_PATH,
        )
        variant = self._one(reply, "v", f"Manager.{name}")
        value = getattr(variant, "value", None)
        if (getattr(variant, "signature", None) != signature
                or (signature == "s" and type(value) is not str)
                or (signature == "as" and type(value) is not list)):
            raise UnitOperationFailed("systemd manager profile property refused")
        return value

    @staticmethod
    def _one(reply: _Reply, signature: str, operation: str) -> object:
        if reply.signature != signature or len(reply.body) != 1:
            raise UnitOperationFailed(f"systemd returned an invalid {operation} reply")
        return reply.body[0]


def _unit_object_path(unit: str) -> str:
    """Encode systemd's byte-wise bus label (not unit-name validation)."""

    encoded = "".join(
        chr(byte)
        if 65 <= byte <= 90 or 97 <= byte <= 122 or (index > 0 and 48 <= byte <= 57)
        else f"_{byte:02x}"
        for index, byte in enumerate(unit.encode("utf-8"))
    ) or "_"
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
        self._admitted_owner = getattr(bus, "_azazel_systemd_owner", None)
        self.calls = SystemdUnitCalls(self._exchange)

    @classmethod
    def connect(cls) -> "SystemdBusSession":
        """Connect only to the system bus; fail if the pinned client is absent."""

        try:
            from dbus_next import Message, MessageType
            from dbus_next.aio import MessageBus
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
        bus = None
        try:
            # dbus-next 0.2.3 binds its asyncio transport to the current loop
            # while constructing MessageBus. Keep that loop current for both
            # construction and connection, then restore the caller's context.
            asyncio.set_event_loop(loop)
            require_supported_dbus_next()
            # Do not let DBUS_SYSTEM_BUS_ADDRESS redirect privileged control.
            class FixedBus(FixedSystemBusSocket, MessageBus):
                pass

            bus = FixedBus(bus_address=_SYSTEM_BUS_ADDRESS)
            loop.run_until_complete(
                asyncio.wait_for(bus.connect(), _BUS_TIMEOUT_SECONDS)
            )
            from .bootstrap_manager_identity import inspect_bootstrap_manager_identity

            identity = loop.run_until_complete(inspect_bootstrap_manager_identity(
                bus=bus, message_factory=Message, message_type=MessageType,
                timeout_seconds=_BUS_TIMEOUT_SECONDS,
            ))
            bus._azazel_systemd_owner = identity.owner
        except BaseException as exc:
            try:
                if bus is not None:
                    try:
                        bus.disconnect()
                    except Exception:
                        pass  # Connection failure remains a redacted refusal.
            finally:
                try:
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.wait(pending, timeout=_BUS_TIMEOUT_SECONDS))
                finally:
                    try:
                        loop.close()
                    finally:
                        try:
                            if isinstance(bus, FixedSystemBusSocket):
                                bus._close_fixed_socket()
                        finally:
                            asyncio.set_event_loop(previous_loop)
            if not isinstance(exc, Exception):
                raise
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
        allow_no_such_unit: bool = False,
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
        elif member != "Get" or signature != "ss":
            raise UnitOperationFailed("the systemd client refused a property call")
        elif path == MANAGER_PATH:
            if (len(body) != 2 or body[0] != MANAGER_INTERFACE
                    or type(body[1]) is not str
                    or body[1] not in {"Version", "UnitPath"}):
                raise UnitOperationFailed("the systemd client refused a manager property")
        elif (path not in {_unit_object_path(unit) for unit in _UNITS}
                or list(body) != [UNIT_INTERFACE, "ActiveState"]):
            raise UnitOperationFailed("the systemd client refused a property path")

        message = self._message_factory(
            destination=self._admitted_owner or DESTINATION,
            path=path,
            interface=interface,
            member=member,
            signature=signature,
            body=list(body),
        )
        try:
            reply = self._loop.run_until_complete(
                asyncio.wait_for(self._bus.call(message), _BUS_TIMEOUT_SECONDS)
            )
        except Exception as exc:  # noqa: BLE001 - translated at the trust boundary
            raise UnitOperationFailed(
                f"systemd D-Bus call {member} did not complete"
            ) from exc
        if reply.message_type == self._message_type.ERROR:
            name = getattr(reply, "error_name", None)
            if (allow_no_such_unit and member == "GetUnit"
                    and type(name) is str and name == _NO_SUCH_UNIT):
                if (self._admitted_owner is not None
                        and getattr(reply, "sender", None) != self._admitted_owner):
                    raise UnitOperationFailed("systemd D-Bus reply owner refused")
                return _Reply("", [], no_such_unit=True)
            raise UnitOperationFailed(f"systemd D-Bus call {member} returned an error")
        if reply.message_type != self._message_type.METHOD_RETURN:
            raise UnitOperationFailed(
                f"systemd D-Bus call {member} returned an invalid message type"
            )
        if self._admitted_owner is not None and getattr(reply, "sender", None) != self._admitted_owner:
            raise UnitOperationFailed("systemd D-Bus reply owner refused")
        return _Reply(reply.signature, reply.body)

    def __call__(self, method: str, unit: str) -> object:
        return self.calls(method, unit)

    def bootstrap_profile(self):
        """Read manager compatibility facts; performs no control operation."""
        return self.calls.bootstrap_profile()

    def close(self) -> None:
        try:
            self._bus.disconnect()
        finally:
            try:
                if not self._loop.is_closed():
                    self._loop.close()
            finally:
                try:
                    if isinstance(self._bus, FixedSystemBusSocket):
                        self._bus._close_fixed_socket()
                finally:
                    asyncio.set_event_loop(self._previous_loop)

    def __enter__(self) -> "SystemdBusSession":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
