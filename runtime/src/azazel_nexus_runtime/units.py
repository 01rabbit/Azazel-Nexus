"""Addressing a systemd unit without ever being handed its name (#39).

The constraint this module exists to satisfy:

    `az-activated` has no shell and no arbitrary `systemctl`. A fixed
    allowlist is all it handles, and unit names, arguments, environment and
    paths are never passed in from a caller.

So the type of a unit reference is not `str`. It is `UnitKey`, an enumeration
this daemon declares, and the mapping from a key to a unit name lives here and
is not configurable. A caller sends `"auditd"`; nothing a caller sends is ever
concatenated into a command.

## Why the adapter is injected

`UnitManager` is an interface with four verbs and no implementation that runs
anything. Two implementations exist: one that records what it was asked for,
used by every test, and one that speaks to systemd over D-Bus.

The second is not exercised in CI and cannot be: there is no service manager
on a GitHub runner. What CI establishes is that the controller asks for the
right thing and rolls back correctly; what systemd then does is `HG-01` and
`HG-02` in `docs/hardware-gates.md`.

## Why D-Bus rather than `systemctl`

`systemctl` takes a command line, and a command line is a place where a string
becomes an argument. The D-Bus interface takes a unit name as a typed
parameter to a typed method, so there is no shell, no `PATH` lookup, no
argument splitting and no environment to inherit. The names it is given still
come only from the table below.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Optional

from azazel_nexus.activation import UnitState

__all__ = [
    "UNIT_NAMES",
    "DbusUnitManager",
    "RecordingUnitManager",
    "UnitKey",
    "UnitManager",
    "UnitOperationFailed",
    "resolve",
]


class UnitOperationFailed(Exception):
    """The service manager did not do what it was asked."""


class UnitKey(str, Enum):
    """How a caller refers to a unit. Never by name.

    The controller's own unit is absent: it is not a unit this daemon
    governs, and a key for it would be a way to ask for it.
    """

    COMMISSIOND = "commissiond"
    AUDITD = "auditd"
    WATCHDOG = "watchdog"
    EDGE_CORE = "edge-core"
    EDGE_PROBE = "edge-probe"
    INCIDENT_EXPLAIN = "incident-explain"
    EDGE_INTAKE = "edge-intake"
    MODEL_FETCH = "model-fetch"
    MIO_LOCAL = "mio-local"
    MIO_REMOTE = "mio-remote"
    MIO_ENTRY = "mio-entry"
    KNOWLEDGE_LITE = "knowledge-lite"
    DECOY_NETWORK = "decoy-network"
    DECOY_LISTENER = "decoy-listener"


#: The whole mapping, and it is not configurable.
#:
#: A table an operator could extend would be a table through which an
#: operator could name any unit on the host, which is the thing the key type
#: exists to prevent.
UNIT_NAMES: dict[UnitKey, str] = {
    UnitKey.COMMISSIOND: "azazel-commissiond.service",
    UnitKey.AUDITD: "azazel-auditd.service",
    UnitKey.WATCHDOG: "azazel-watchdog.service",
    UnitKey.EDGE_CORE: "azazel-edge-core.service",
    UnitKey.EDGE_PROBE: "azazel-edge-probed.service",
    UnitKey.INCIDENT_EXPLAIN: "azazel-incident-explaind.service",
    UnitKey.EDGE_INTAKE: "azazel-edge-intaked.service",
    UnitKey.MODEL_FETCH: "azazel-model-fetchd.service",
    UnitKey.MIO_LOCAL: "azazel-mio-locald.service",
    UnitKey.MIO_REMOTE: "azazel-mio-remoted.service",
    UnitKey.MIO_ENTRY: "azazel-mio-entryd.service",
    UnitKey.KNOWLEDGE_LITE: "azazel-knowledge-lited.service",
    UnitKey.DECOY_NETWORK: "azazel-decoy-netd.service",
    UnitKey.DECOY_LISTENER: "azazel-decoyd.service",
}


def resolve(key: str) -> str:
    """A key to a unit name, or a refusal. No other way in.

    `key` arrives as a string because it came off a socket. It is looked up,
    never interpolated: a value that is not a key produces a refusal rather
    than a unit name nobody declared.
    """

    try:
        return UNIT_NAMES[UnitKey(key)]
    except (KeyError, ValueError) as exc:
        raise UnitOperationFailed(
            f"{key!r} is not a unit this daemon governs. Units are addressed "
            "by a key from a fixed table; a name from a caller is not one"
        ) from exc


class UnitManager:
    """The narrow operations a controller may ask of a service manager.

    Narrowing (`mask`) and widening (`unmask_and_enable`) are separate verbs
    because they carry different authority, and `is_active` is separate from
    both because reading is not doing. Inactivity is a separate positive
    observation: not-ready does not mean stopped.
    """

    def state(self, unit: str) -> UnitState:
        raise NotImplementedError

    def mask(self, unit: str) -> None:
        raise NotImplementedError

    def unmask_and_enable(self, unit: str) -> None:
        raise NotImplementedError

    def is_active(self, unit: str) -> bool:
        raise NotImplementedError

    def is_inactive(self, unit: str) -> bool:
        """Positive inactivity evidence, never the negation of readiness."""
        raise NotImplementedError


class RecordingUnitManager(UnitManager):
    """An in-memory service manager that keeps the call log.

    Used by every test here. `fail_on` makes one unit's widening fail, which
    is how the rollback path is exercised without a service manager that can
    be made to fail on demand.
    """

    def __init__(
        self,
        units: Iterable[str] = (),
        *,
        fail_on: Optional[str] = None,
        inactive: Iterable[str] = (),
    ) -> None:
        self._states = {name: UnitState.MASKED for name in units}
        self._fail_on = fail_on
        self._inactive = set(inactive)
        self.calls: list[tuple[str, str]] = []

    def state(self, unit: str) -> UnitState:
        return self._states.get(unit, UnitState.MASKED)

    def mask(self, unit: str) -> None:
        self._states[unit] = UnitState.MASKED
        self.calls.append(("mask", unit))

    def unmask_and_enable(self, unit: str) -> None:
        if unit == self._fail_on:
            # The half that succeeded, before the half that did not: a
            # failure that changed nothing would let a missing rollback pass.
            self._states[unit] = UnitState.ENABLED
            self.calls.append(("unmask_and_enable", unit))
            raise UnitOperationFailed(f"{unit} could not be enabled")
        self._states[unit] = UnitState.ENABLED
        self.calls.append(("unmask_and_enable", unit))

    def is_active(self, unit: str) -> bool:
        return unit not in self._inactive and self.state(unit) is UnitState.ENABLED

    def is_inactive(self, unit: str) -> bool:
        # This model is synthetic; production checks systemd independently.
        return not self.is_active(unit)


@dataclass
class DbusUnitManager(UnitManager):
    """systemd over D-Bus, through an injected call.

    `call` receives `(method, unit)` and nothing else: no command line, no
    argument list, no environment. There is no code path here that builds a
    string to be executed, and `tests/unit/test_runtime_units.py` checks that
    against the source.

    **Not exercised in CI.** What these methods do on a host is `HG-01` and
    `HG-02`. What CI establishes is which method is asked for.
    """

    call: Callable[[str, str], object]

    #: The methods this daemon may invoke. `StartUnit` is deliberately absent:
    #: activation decides what may run at the next boot, and starting a
    #: service now is a different act with a different blast radius.
    METHODS = (
        "MaskUnitFiles",
        "UnmaskUnitFiles",
        "EnableUnitFiles",
        "GetUnitFileState",
        "GetActiveState",
        "GetInactiveState",
    )

    def _known_unit(self, unit: str) -> str:
        if unit not in UNIT_NAMES.values():
            raise UnitOperationFailed(
                "the service manager was asked about a unit outside the fixed "
                "Nexus allowlist"
            )
        return unit

    def state(self, unit: str) -> UnitState:
        answer = self.call("GetUnitFileState", self._known_unit(unit))
        text = str(answer or "").strip().lower()
        if text in {"masked", "masked-runtime"}:
            return UnitState.MASKED
        # Only a persistent `enabled` is the state a grant produces (#251 L-6).
        # `enabled-runtime` vanishes at reboot, and `linked`/`alias` mean the
        # unit file is not the vendor file the generation measured. None of
        # them is ENABLED; read as DISABLED, the activation path's postcondition
        # (`unmask_and_enable`) refuses them and rolls back. The only other
        # caller (bootstrap, `is UnitState.MASKED`) reads them as before.
        if text == "enabled":
            return UnitState.ENABLED
        if text in {
            "enabled-runtime",
            "linked",
            "linked-runtime",
            "alias",
            "disabled",
            "static",
            "indirect",
            "generated",
            "transient",
            "invalid",
        }:
            return UnitState.DISABLED
        raise UnitOperationFailed("systemd returned an unknown unit-file state")

    def mask(self, unit: str) -> None:
        unit = self._known_unit(unit)
        self.call("MaskUnitFiles", unit)
        if self.state(unit) is not UnitState.MASKED:
            raise UnitOperationFailed(
                "systemd did not report the governed unit as masked"
            )

    def unmask_and_enable(self, unit: str) -> None:
        unit = self._known_unit(unit)
        self.call("UnmaskUnitFiles", unit)
        self.call("EnableUnitFiles", unit)
        if self.state(unit) is not UnitState.ENABLED:
            raise UnitOperationFailed(
                "systemd did not report the governed unit as enabled"
            )

    def is_active(self, unit: str) -> bool:
        answer = self.call("GetActiveState", self._known_unit(unit))
        if not isinstance(answer, bool):
            raise UnitOperationFailed("systemd returned an invalid active-state result")
        return answer

    def is_inactive(self, unit: str) -> bool:
        answer = self.call("GetInactiveState", self._known_unit(unit))
        if type(answer) is not bool:
            raise UnitOperationFailed("systemd returned an invalid inactivity result")
        return answer
