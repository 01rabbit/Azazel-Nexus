"""The fixed systemd Manager calls used by Nexus activation.

This module does not accept D-Bus destinations, interfaces, object paths,
signatures, or unit names from callers. It maps the runtime's narrow semantic
verbs onto the systemd system-bus API and validates every reply. In
particular, it never exposes ``StartUnit``. The one ``StopUnit`` it can send
has the Knowledge Context broker and mode ``replace`` as constants.

``EdgeUnitStateReader`` is the narrower, read-only view handed to
``az-edge-probed``: one verb, one unit, three properties, and no route to the
mask/unmask/enable calls the controller uses.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.edge_package import EDGE_UNIT as _EDGE_UNIT
from azazel_nexus.operator_snapshots import OBSERVED_UNITS

from .activation_markers import (
    MARKER_GUARDED_UNITS,
    NON_GRANTABLE_MARKER_UNITS,
)
from .bootstrap_systemd_profile import observe_bootstrap_systemd_profile
from .systemd_socket import FixedSystemBusSocket, SYSTEM_BUS_ADDRESS, require_supported_dbus_next
from .units import CONTEXTD_UNIT, UNIT_NAMES, UnitOperationFailed

__all__ = ["EdgeUnitStateReader", "SystemdBusSession", "SystemdUnitCalls", "UnitStatesReader"]

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
_CORE_UNIT_NAMES = frozenset(definition.name for definition in CORE_UNITS)
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


#: The only unit-object properties beyond ActiveState that may be read, and
#: only on the Edge unit's object, for ``EdgeUnitStateReader``.
_EDGE_UNIT_PROPERTIES = ("LoadState", "ActiveState", "SubState")
#: The units whose three state properties may be read: the Edge unit (for
#: ``EdgeUnitStateReader``) and the packaged services the unit-state
#: observer reports (``UnitStatesReader``, U2). Read-only either way.
_STATE_READ_UNITS = frozenset({_EDGE_UNIT, *OBSERVED_UNITS})
_LOAD_STATES = frozenset(
    {"stub", "loaded", "not-found", "bad-setting", "error", "merged", "masked"}
)
#: SubState values differ per unit type; this bounds their shape, not the set.
_SUB_STATE = re.compile(r"[a-z][a-z-]{0,31}")
#: The loaded definition of a grantable unit, read by the pass before any
#: grant (#251 H-1): property name and D-Bus signature. Read-only.
_LOADED_UNIT_PROPERTIES = (
    ("Id", "s"),
    ("LoadState", "s"),
    ("FragmentPath", "s"),
    ("DropInPaths", "as"),
    ("Conditions", "a(sbbsi)"),
    ("Asserts", "a(sbbsi)"),
    ("Requires", "as"),
    ("After", "as"),
)
_CONDITION_TYPES = (str, bool, bool, str, int)
#: The cgroup IP filter of a service, read from the `Service` interface (not
#: `Unit`) and only for the Knowledge Context broker (U49): name, signature.
SERVICE_INTERFACE = "org.freedesktop.systemd1.Service"
_IP_FILTER_PROPERTIES = (("IPAddressAllow", "a(iayu)"), ("IPAddressDeny", "a(iayu)"))
_IP_FILTER_LIMIT = 64
_IP_FAMILY_BYTES = {2: 4, 10: 16}
_PROPERTY_LIMIT = 256
#: Bound on the `GetAll` reply of the Unit interface (the bootstrap's bound).
_ALL_PROPERTIES_LIMIT = 2048
_TEXT_LIMIT = 4096


@dataclass(frozen=True)
class _Reply:
    signature: str
    body: list
    #: True only for an opted-in call that got exactly systemd's NoSuchUnit.
    no_such_unit: bool = False


_NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"

#: The one body StopUnit is ever sent with. A constant, not an argument: the
#: stop authority is for the Knowledge Context broker and for nothing else.
_STOP_CONTEXTD_BODY = (CONTEXTD_UNIT, "replace")
_JOB_PATH = re.compile(r"/org/freedesktop/systemd1/job/([1-9][0-9]{0,18})")


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

        # NON_GRANTABLE_MARKER_UNITS is empty at present (contextd is
        # grantable since A1). The branch stays for a future unit that is
        # marker-guarded but must never be unmasked or enabled by the pass.
        if method == "MaskUnitFiles" and unit not in _CORE_UNIT_NAMES:
            raise UnitOperationFailed("the systemd client refused a non-core mask")
        if (method in {"UnmaskUnitFiles", "EnableUnitFiles"}
                and unit in NON_GRANTABLE_MARKER_UNITS):
            raise UnitOperationFailed("the systemd client refused a non-grantable unit")

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

    def reload(self) -> None:
        """Manager.Reload: no argument, and the reply must be empty.

        Fixed: there is no unit, path or option to pass. Reloading makes the
        manager re-read the unit files that mask, unmask and enable changed.
        """
        reply = self._exchange(MANAGER_INTERFACE, "Reload", "", [])
        if reply.signature != "" or list(reply.body) != []:
            raise UnitOperationFailed("systemd returned an invalid Reload reply")

    def stop_contextd(self) -> str:
        """Manager.StopUnit for the Knowledge Context broker, mode `replace`.

        No argument: the unit and the mode are the constants above. The reply
        is a job object path of the form `/org/freedesktop/systemd1/job/<n>`
        (not a unit path); anything else is refused. `replace` also replaces
        a start job the manager has queued for the broker.
        """
        reply = self._exchange(
            MANAGER_INTERFACE, "StopUnit", "ss", list(_STOP_CONTEXTD_BODY))
        path = self._one(reply, "o", "StopUnit")
        if type(path) is not str or _JOB_PATH.fullmatch(path) is None:
            raise UnitOperationFailed("systemd returned an invalid stop job")
        return path

    def contextd_active_state(self, unit: str) -> str:
        """The broker's exact `ActiveState`; `inactive` when systemd holds no object."""
        if unit != CONTEXTD_UNIT:
            raise UnitOperationFailed(
                "the systemd client refused a state read outside the stop scope")
        unit_reply = self._exchange(
            MANAGER_INTERFACE, "GetUnit", "s", [unit], allow_no_such_unit=True)
        if getattr(unit_reply, "no_such_unit", False) is True:
            return "inactive"
        expected_path = _unit_object_path(unit)
        if self._one(unit_reply, "o", "GetUnit") != expected_path:
            raise UnitOperationFailed("systemd returned an invalid unit object")
        reply = self._exchange(
            PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, "ActiveState"],
            path=expected_path)
        value = getattr(self._one(reply, "v", "Properties.Get"), "value", None)
        if not isinstance(value, str) or value not in _ACTIVE_STATES:
            raise UnitOperationFailed("systemd returned an invalid active state")
        return value

    def contextd_file_state(self, unit: str) -> str:
        """The broker's exact `UnitFileState`, as systemd spells it."""
        if unit != CONTEXTD_UNIT:
            raise UnitOperationFailed(
                "the systemd client refused a state read outside the stop scope")
        return self("GetUnitFileState", unit)

    def unit_job(self, unit: str) -> tuple:
        """The broker's `Job` property as `(id, path)`; `(0, "/")` is no job.

        Read-only and for the Knowledge Context broker alone. A unit systemd
        holds no object for has no job.
        """
        if unit != CONTEXTD_UNIT:
            raise UnitOperationFailed(
                "the systemd client refused a job read outside the stop scope")
        unit_reply = self._exchange(
            MANAGER_INTERFACE, "GetUnit", "s", [unit], allow_no_such_unit=True)
        if getattr(unit_reply, "no_such_unit", False) is True:
            return (0, "/")
        expected_path = _unit_object_path(unit)
        if self._one(unit_reply, "o", "GetUnit") != expected_path:
            raise UnitOperationFailed("systemd returned an invalid unit object")
        reply = self._exchange(
            PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, "Job"],
            path=expected_path)
        variant = self._one(reply, "v", "Properties.Get")
        value = getattr(variant, "value", None)
        if (getattr(variant, "signature", None) != "(uo)"
                or type(value) not in (list, tuple) or len(value) != 2):
            raise UnitOperationFailed("systemd returned an invalid job property")
        number, path = value
        if type(number) is not int or type(path) is not str or number < 0:
            raise UnitOperationFailed("systemd returned an invalid job property")
        if number == 0:
            if path != "/":
                raise UnitOperationFailed("systemd returned an invalid job property")
            return (0, "/")
        match = _JOB_PATH.fullmatch(path)
        if match is None or int(match.group(1)) != number:
            raise UnitOperationFailed("systemd returned an invalid job property")
        return (number, path)

    def loaded_unit(self, unit: str) -> Optional[dict]:
        """The manager's loaded definition of one marker-guarded unit, or None.

        Read-only: `GetUnit`, which never loads a unit, then one
        `Properties.GetAll` of the `Unit` interface (one snapshot, not reads
        spread over time), from which only `_LOADED_UNIT_PROPERTIES` are
        kept. None means systemd holds no unit object, so no start job can
        be queued for it; a later load reads the files the pass measured.
        Every kept value is type-checked and copied.
        """
        if unit not in MARKER_GUARDED_UNITS:
            raise UnitOperationFailed(
                "the systemd client refused a unit outside the marker-guarded set"
            )
        unit_reply = self._exchange(
            MANAGER_INTERFACE, "GetUnit", "s", [unit], allow_no_such_unit=True
        )
        if getattr(unit_reply, "no_such_unit", False) is True:
            return None
        expected_path = _unit_object_path(unit)
        if self._one(unit_reply, "o", "GetUnit") != expected_path:
            raise UnitOperationFailed("systemd returned an invalid unit object")
        reply = self._exchange(
            PROPERTIES_INTERFACE, "GetAll", "s", [UNIT_INTERFACE], path=expected_path
        )
        properties = self._one(reply, "a{sv}", "Unit.GetAll")
        if (type(properties) is not dict or len(properties) > _ALL_PROPERTIES_LIMIT
                or any(type(name) is not str for name in properties)):
            raise UnitOperationFailed("systemd loaded unit properties refused")
        loaded: dict = {}
        for name, signature in _LOADED_UNIT_PROPERTIES:
            if name not in properties:
                raise UnitOperationFailed("systemd loaded unit property missing")
            variant = properties[name]
            loaded[name] = _loaded_value(
                getattr(variant, "signature", None), getattr(variant, "value", None), signature
            )
        if unit == CONTEXTD_UNIT:
            service = self._exchange(
                PROPERTIES_INTERFACE, "GetAll", "s", [SERVICE_INTERFACE], path=expected_path
            )
            service_properties = self._one(service, "a{sv}", "Service.GetAll")
            if (type(service_properties) is not dict
                    or len(service_properties) > _ALL_PROPERTIES_LIMIT
                    or any(type(name) is not str for name in service_properties)):
                raise UnitOperationFailed("systemd loaded unit properties refused")
            for name, signature in _IP_FILTER_PROPERTIES:
                if name not in service_properties:
                    raise UnitOperationFailed("systemd loaded unit property missing")
                variant = service_properties[name]
                loaded[name] = _loaded_value(
                    getattr(variant, "signature", None), getattr(variant, "value", None),
                    signature)
        return loaded

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


def _loaded_value(signature, value, expected: str):
    """One bounded, type-checked copy of a loaded-unit property value."""
    if signature != expected:
        raise UnitOperationFailed("systemd loaded unit property refused")
    if expected == "s":
        if type(value) is not str or len(value) > _TEXT_LIMIT:
            raise UnitOperationFailed("systemd loaded unit property refused")
        return value
    if type(value) is not list or len(value) > _PROPERTY_LIMIT:
        raise UnitOperationFailed("systemd loaded unit property refused")
    if expected == "as":
        if any(type(item) is not str or len(item) > _TEXT_LIMIT for item in value):
            raise UnitOperationFailed("systemd loaded unit property refused")
        return list(value)
    if expected == "a(iayu)":
        return _ip_filter(value)
    copied = []
    for item in value:
        if (type(item) not in (list, tuple) or len(item) != len(_CONDITION_TYPES)
                or any(type(field) is not kind for field, kind in zip(item, _CONDITION_TYPES))
                or len(item[0]) > _TEXT_LIMIT or len(item[3]) > _TEXT_LIMIT):
            raise UnitOperationFailed("systemd loaded unit condition refused")
        copied.append(tuple(item))
    return copied


def _ip_filter(value: list) -> list:
    """`a(iayu)` as sorted `(family, packed address, prefix length)` triples.

    Bounded in count, in address width per family and in prefix length; the
    result is canonical (sorted, bytes), so equal filters compare equal.
    """
    if len(value) > _IP_FILTER_LIMIT:
        raise UnitOperationFailed("systemd loaded unit property refused")
    copied = []
    for item in value:
        if type(item) not in (list, tuple) or len(item) != 3:
            raise UnitOperationFailed("systemd loaded unit IP filter refused")
        family, address, prefix = item
        if type(address) is list and all(type(b) is int and 0 <= b < 256 for b in address):
            address = bytes(address)
        elif type(address) is bytearray:
            address = bytes(address)
        width = _IP_FAMILY_BYTES.get(family) if type(family) is int else None
        if (width is None or type(address) is not bytes or len(address) != width
                or type(prefix) is not int or not 0 <= prefix <= 8 * width):
            raise UnitOperationFailed("systemd loaded unit IP filter refused")
        copied.append((family, address, prefix))
    return sorted(copied)


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
        self._remaining: Optional[Callable[[], float]] = None
        #: True after a call timed out or was cancelled: the session sends
        #: nothing more and must be replaced.
        self.broken = False

    def set_remaining(self, remaining: Optional[Callable[[], float]]) -> None:
        """Seconds left of the caller's budget; each call is limited to it."""
        self._remaining = remaining

    @classmethod
    def connect(cls, remaining: Optional[Callable[[], float]] = None) -> "SystemdBusSession":
        """Connect only to the system bus; fail if the pinned client is absent.

        `remaining` (seconds left of the caller's budget) bounds each step of
        the connection, so that connecting counts against the budget.
        """

        def step() -> float:
            left = _BUS_TIMEOUT_SECONDS if remaining is None else min(
                _BUS_TIMEOUT_SECONDS, remaining())
            if left <= 0:
                raise UnitOperationFailed("the time budget ended before the bus connected")
            return left

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
            limit = step()
            loop.run_until_complete(asyncio.wait_for(bus.connect(), limit))
            from .bootstrap_manager_identity import inspect_bootstrap_manager_identity

            identity = loop.run_until_complete(inspect_bootstrap_manager_identity(
                bus=bus, message_factory=Message, message_type=MessageType,
                timeout_seconds=step(),
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
                    # The cleanup is charged to the caller's budget too: no
                    # fixed ten seconds that nobody counted.
                    left = (_BUS_TIMEOUT_SECONDS if remaining is None
                            else max(0.0, min(_BUS_TIMEOUT_SECONDS, remaining())))
                    if pending and left > 0:
                        loop.run_until_complete(asyncio.wait(pending, timeout=left))
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
        session = cls(
            bus=bus,
            loop=loop,
            previous_loop=previous_loop,
            message_type=MessageType,
            message_factory=Message,
        )
        # A session connected under a deadline is bound to it from the start: a
        # replacement session never gets a fresh, unbounded allowance per exchange.
        session.set_remaining(remaining)
        return session

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
                "Reload": "",
                "StopUnit": "ss",
            }
            if allowed.get(member) != signature or path != MANAGER_PATH:
                raise UnitOperationFailed("the systemd client refused a call shape")
            if member == "Reload" and list(body) != []:
                raise UnitOperationFailed("the systemd client refused a call shape")
            if member == "StopUnit" and tuple(body) != _STOP_CONTEXTD_BODY:
                raise UnitOperationFailed("the systemd client refused a call shape")
        elif member == "GetAll":
            # The pass's loaded-definition read: the Unit interface of a
            # marker-guarded unit's object, and nothing else. This read-only
            # scope does not widen Mask/Unmask/Enable authority.
            # U49: the broker's cgroup IP filter lives on the Service interface;
            # that read is allowed on the broker's object alone.
            service_read = (list(body) == [SERVICE_INTERFACE]
                            and path == _unit_object_path(CONTEXTD_UNIT))
            if (signature != "s"
                    or (list(body) != [UNIT_INTERFACE] and not service_read)
                    or path not in {_unit_object_path(unit) for unit in MARKER_GUARDED_UNITS}):
                raise UnitOperationFailed("the systemd client refused a property call")
        elif member != "Get" or signature != "ss":
            raise UnitOperationFailed("the systemd client refused a property call")
        elif path == MANAGER_PATH:
            if (len(body) != 2 or body[0] != MANAGER_INTERFACE
                    or type(body[1]) is not str
                    or body[1] not in {"Version", "UnitPath"}):
                raise UnitOperationFailed("the systemd client refused a manager property")
        elif (path in {_unit_object_path(unit) for unit in _STATE_READ_UNITS}
                and len(body) == 2
                and body[0] == UNIT_INTERFACE and type(body[1]) is str
                and body[1] in _EDGE_UNIT_PROPERTIES):
            pass  # The three state reads, on a fixed unit's object only.
        elif (path == _unit_object_path(CONTEXTD_UNIT)
                and list(body) == [UNIT_INTERFACE, "Job"]):
            pass  # The broker's pending job, for the stop authority.
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
        if self.broken:
            raise UnitOperationFailed(
                "the bus session is finished after a call did not complete")
        timeout = _BUS_TIMEOUT_SECONDS
        if self._remaining is not None:
            timeout = min(timeout, self._remaining())
            if timeout <= 0:
                raise UnitOperationFailed(
                    f"the time budget ended before systemd D-Bus call {member}")
        try:
            reply = self._loop.run_until_complete(
                asyncio.wait_for(self._bus.call(message), timeout)
            )
        except Exception as exc:  # noqa: BLE001 - translated at the trust boundary
            self._poison()
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

    def _poison(self) -> None:
        """A call did not complete: this session is finished.

        Pending work is cancelled and given a bounded moment to unwind (never
        more than the time that is left), the bus is disconnected, and from
        here on no call is sent on this session. A session is never reused
        after a timeout or a cancellation: the caller narrows on a new one.
        """
        self.broken = True
        limit = 1.0 if self._remaining is None else max(0.0, min(1.0, self._remaining()))
        try:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending and limit > 0:
                self._loop.run_until_complete(asyncio.wait(pending, timeout=limit))
        except Exception:  # noqa: BLE001 - the session is finished whatever this does
            pass
        try:
            self._bus.disconnect()
        except Exception:  # noqa: BLE001
            pass

    def __call__(self, method: str, unit: str) -> object:
        return self.calls(method, unit)

    def bootstrap_profile(self):
        """Read manager compatibility facts; performs no control operation."""
        return self.calls.bootstrap_profile()

    def loaded_unit(self, unit: str):
        """Read one grantable unit's loaded definition; performs no control operation."""
        return self.calls.loaded_unit(unit)

    def reload(self) -> None:
        """Manager.Reload (argument-less); see `SystemdUnitCalls.reload`."""
        self.calls.reload()

    def stop_contextd(self) -> str:
        """Stop the Knowledge Context broker; see `SystemdUnitCalls.stop_contextd`."""
        return self.calls.stop_contextd()

    def unit_job(self, unit: str) -> tuple:
        """The broker's pending job; see `SystemdUnitCalls.unit_job`."""
        return self.calls.unit_job(unit)

    def contextd_active_state(self, unit: str) -> str:
        """The broker's exact ActiveState; see `SystemdUnitCalls`."""
        return self.calls.contextd_active_state(unit)

    def contextd_file_state(self, unit: str) -> str:
        """The broker's exact UnitFileState; see `SystemdUnitCalls`."""
        return self.calls.contextd_file_state(unit)

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


#: What systemd holding no unit object for the Edge unit is reported as.
#: ``not-loaded`` is this module's word, not a systemd LoadState: ``GetUnit``
#: never loads a unit, so ``NoSuchUnit`` means nothing is running it.
_EDGE_NOT_LOADED = {"LoadState": "not-loaded", "ActiveState": "inactive", "SubState": "dead"}


def _read_edge_unit_state(exchange: Callable[..., _Reply]) -> dict:
    """Resolve the Edge unit object and read its three state properties."""

    return _read_unit_state(exchange, _EDGE_UNIT)


def _read_unit_state(exchange: Callable[..., _Reply], unit: str) -> dict:
    """Resolve one fixed unit's object and read its three state properties."""

    if unit not in _STATE_READ_UNITS:
        raise UnitOperationFailed("the unit state reader refused a unit outside its list")
    unit_reply = exchange(
        MANAGER_INTERFACE, "GetUnit", "s", [unit], allow_no_such_unit=True
    )
    if getattr(unit_reply, "no_such_unit", False) is True:
        return dict(_EDGE_NOT_LOADED)
    expected_path = _unit_object_path(unit)
    if SystemdUnitCalls._one(unit_reply, "o", "GetUnit") != expected_path:
        raise UnitOperationFailed("systemd returned an invalid unit object")
    state: dict[str, str] = {}
    for name in _EDGE_UNIT_PROPERTIES:
        reply = exchange(
            PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, name], path=expected_path
        )
        variant = SystemdUnitCalls._one(reply, "v", f"Unit.{name}")
        value = getattr(variant, "value", None)
        if getattr(variant, "signature", None) != "s" or type(value) is not str:
            raise UnitOperationFailed(f"systemd returned an invalid {name}")
        if ((name == "LoadState" and value not in _LOAD_STATES)
                or (name == "ActiveState" and value not in _ACTIVE_STATES)
                or (name == "SubState" and not _SUB_STATE.fullmatch(value))):
            raise UnitOperationFailed(f"systemd returned an unknown {name}")
        state[name] = value
    return state


def _read_only(exchange: Callable[..., _Reply]) -> Callable[..., _Reply]:
    """Pass through only the two call shapes ``_read_edge_unit_state`` sends."""

    def read(interface, member, signature, body, **kwargs) -> _Reply:
        if (interface, member, signature) not in {
            (MANAGER_INTERFACE, "GetUnit", "s"),
            (PROPERTIES_INTERFACE, "Get", "ss"),
        }:
            raise UnitOperationFailed("the edge unit reader refused a non-read call")
        return exchange(interface, member, signature, body, **kwargs)

    return read


class EdgeUnitStateReader:
    """The read-only systemd view ``az-edge-probed`` is given (#72, #195).

    Callable as ``read(method, unit)``, the shape the probe uses, and it
    answers exactly one question: ``GetUnitProperties`` of
    ``edge_package.EDGE_UNIT``, as ``LoadState``/``ActiveState``/``SubState``.
    Any other method or unit is refused before the bus is touched. It keeps
    no session and no ``SystemdUnitCalls``, only an exchange that passes
    ``GetUnit`` and ``Properties.Get``, so mask, unmask and enable have no
    verb here. (Python is not a sandbox; the probe also runs unprivileged,
    where systemd's polkit policy refuses those calls anyway. This keeps the
    probe's own code from being able to name them.)

    It connects over the same fixed transport as ``SystemdBusSession`` -- the
    fixed socket, the manager-identity check, the timeouts -- lazily, on the
    first read, so a probe that never reads never connects. A connection
    failure is raised to the caller, which reports it as not checked.
    """

    __slots__ = ("_connect", "_exchange", "_close", "_closed")

    def __init__(self, connect: Optional[Callable[[], SystemdBusSession]] = None) -> None:
        self._connect = connect if connect is not None else SystemdBusSession.connect
        self._exchange: Optional[Callable[..., _Reply]] = None
        self._close: Optional[Callable[[], None]] = None
        self._closed = False

    def __call__(self, method: str, unit: str) -> dict:
        if method != "GetUnitProperties" or unit != _EDGE_UNIT:
            raise UnitOperationFailed("the edge unit reader refused a call outside its one read")
        if self._closed:
            raise UnitOperationFailed("the edge unit reader is closed")
        if self._exchange is None:
            session = self._connect()
            self._exchange, self._close = _read_only(session._exchange), session.close
        return _read_edge_unit_state(self._exchange)

    def close(self) -> None:
        """Disconnect if connected. Never raises: the finding is already made."""

        self._closed = True
        close, self._close, self._exchange = self._close, None, None
        if close is not None:
            try:
                close()
            except Exception:  # noqa: BLE001 - a probe never raises for the node
                pass


class UnitStatesReader:
    """The read-only systemd view the unit-state observer is given (U2).

    ``EdgeUnitStateReader`` generalised to a fixed list, and nothing more: it
    reads ``LoadState``/``ActiveState``/``SubState`` of each name in
    ``operator_snapshots.OBSERVED_UNITS`` (the packaged services), through
    the same ``_read_only`` exchange that passes ``GetUnit`` and
    ``Properties.Get`` and refuses every other call, over the same fixed
    transport. It takes no unit name from anyone. Reading these properties
    needs no privilege on the system bus; the observer runs unprivileged,
    where systemd's polkit policy refuses mask, start and stop anyway.
    """

    __slots__ = ("_connect",)

    def __init__(self, connect: Optional[Callable[[], SystemdBusSession]] = None) -> None:
        self._connect = connect if connect is not None else SystemdBusSession.connect

    def read_all(self) -> dict:
        """`{unit: state}` for every observed unit. Never raises.

        A unit whose read failed or was refused maps to ``read_refused``;
        when the bus cannot be reached at all, every unit maps to
        ``bus_unavailable``. No exception text leaves this method.
        """

        try:
            session = self._connect()
        except Exception:  # noqa: BLE001 - reported as a fixed code
            return {unit: "bus_unavailable" for unit in OBSERVED_UNITS}
        states: dict = {}
        try:
            exchange = _read_only(session._exchange)
            for unit in OBSERVED_UNITS:
                try:
                    states[unit] = _read_unit_state(exchange, unit)
                except Exception:  # noqa: BLE001 - one unit's failure is its own
                    states[unit] = "read_refused"
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001 - the reading is already made
                pass
        return states
