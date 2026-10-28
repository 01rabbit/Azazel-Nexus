"""The fixed systemd Manager calls used by Nexus activation.

This module does not accept D-Bus destinations, interfaces, object paths,
signatures, or unit names from callers. It maps the runtime's narrow semantic
verbs onto the systemd system-bus API and validates every reply. In
particular, it never exposes ``StartUnit``.

``EdgeUnitStateReader`` is the narrower, read-only view handed to
``az-edge-probed``: one verb, one unit, three properties, and no route to the
mask/unmask/enable calls the controller uses.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from azazel_nexus.edge_package import EDGE_UNIT as _EDGE_UNIT
from azazel_nexus.operator_snapshots import OBSERVED_UNITS

from .activation_markers import GRANTABLE_UNITS
from .bootstrap_systemd_profile import observe_bootstrap_systemd_profile
from .systemd_socket import FixedSystemBusSocket, SYSTEM_BUS_ADDRESS, require_supported_dbus_next
from .units import UNIT_NAMES, UnitOperationFailed

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

    def loaded_unit(self, unit: str) -> Optional[dict]:
        """The manager's loaded definition of one grantable unit, or None.

        Read-only: `GetUnit`, which never loads a unit, then one
        `Properties.GetAll` of the `Unit` interface (one snapshot, not reads
        spread over time), from which only `_LOADED_UNIT_PROPERTIES` are
        kept. None means systemd holds no unit object, so no start job can
        be queued for it; a later load reads the files the pass measured.
        Every kept value is type-checked and copied.
        """
        if unit not in GRANTABLE_UNITS:
            raise UnitOperationFailed("the systemd client refused a unit outside the grantable set")
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
    copied = []
    for item in value:
        if (type(item) not in (list, tuple) or len(item) != len(_CONDITION_TYPES)
                or any(type(field) is not kind for field, kind in zip(item, _CONDITION_TYPES))
                or len(item[0]) > _TEXT_LIMIT or len(item[3]) > _TEXT_LIMIT):
            raise UnitOperationFailed("systemd loaded unit condition refused")
        copied.append(tuple(item))
    return copied


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
        elif member == "GetAll":
            # The pass's loaded-definition read: the Unit interface of a
            # grantable unit's object, and nothing else.
            if (signature != "s" or list(body) != [UNIT_INTERFACE]
                    or path not in {_unit_object_path(unit) for unit in GRANTABLE_UNITS}):
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

    def loaded_unit(self, unit: str):
        """Read one grantable unit's loaded definition; performs no control operation."""
        return self.calls.loaded_unit(unit)

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
