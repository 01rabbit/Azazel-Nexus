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
from pathlib import Path
from typing import Callable, Iterable, Optional

from azazel_nexus.activation import UnitState

__all__ = [
    "CONTEXTD_UNIT",
    "ContextdStopAuthority",
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
    AUDIT_LOOP = "audit-loop"
    WATCHDOG = "watchdog"
    EDGE_CORE = "edge-core"
    EDGE_PROBE = "edge-probe"
    INCIDENT_EXPLAIN = "incident-explain"
    EDGE_INTAKE = "edge-intake"
    MODEL_FETCH = "model-fetch"
    MIO_LOCAL = "mio-local"
    MIO_REMOTE = "mio-remote"
    KNOWLEDGE_CONTEXT = "knowledge-context"
    MIO_ENTRY = "mio-entry"
    MIO_REFERENCE = "mio-reference"
    KNOWLEDGE_LITE = "knowledge-lite"
    DECOY_NAMESPACE = "decoy-namespace"
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
    UnitKey.AUDIT_LOOP: "azazel-auditd-loop.service",
    UnitKey.WATCHDOG: "azazel-watchdog.service",
    UnitKey.EDGE_CORE: "azazel-edge-core.service",
    UnitKey.EDGE_PROBE: "azazel-edge-probed.service",
    UnitKey.INCIDENT_EXPLAIN: "azazel-incident-explaind.service",
    UnitKey.EDGE_INTAKE: "azazel-edge-intaked.service",
    UnitKey.MODEL_FETCH: "azazel-model-fetchd.service",
    UnitKey.MIO_LOCAL: "azazel-mio-locald.service",
    UnitKey.MIO_REMOTE: "azazel-mio-remoted.service",
    UnitKey.KNOWLEDGE_CONTEXT: "azazel-knowledge-contextd.service",
    UnitKey.MIO_ENTRY: "azazel-mio-entryd.service",
    UnitKey.MIO_REFERENCE: "azazel-mio-referenced.service",
    UnitKey.KNOWLEDGE_LITE: "azazel-knowledge-lited.service",
    UnitKey.DECOY_NAMESPACE: "azazel-decoy-nsd.service",
    UnitKey.DECOY_NETWORK: "azazel-decoy-netd.service",
    UnitKey.DECOY_LISTENER: "azazel-decoyd.service",
}


#: The Knowledge Context broker: the one unit anything here may stop.
CONTEXTD_UNIT = UNIT_NAMES[UnitKey.KNOWLEDGE_CONTEXT]


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

    def reload(self) -> None:
        """Ask the manager to re-read unit files (Manager.Reload, no argument).

        A mask, unmask or enable changes files on disk. A manager that loaded
        a unit earlier keeps acting on the definition it loaded until it is
        reloaded, so each batch of such changes ends with one reload.
        """
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
        fail_reload: bool = False,
    ) -> None:
        self._states = {name: UnitState.MASKED for name in units}
        self._fail_on = fail_on
        self._inactive = set(inactive)
        self._fail_reload = fail_reload
        self.calls: list[tuple[str, str]] = []
        #: Every operation in order, `reload` included. `calls` keeps its
        #: earlier shape (unit operations only) so that existing assertions
        #: on it stay exact; ordering questions are asked of `timeline`.
        self.timeline: list[tuple[str, str]] = []

    def state(self, unit: str) -> UnitState:
        return self._states.get(unit, UnitState.MASKED)

    def mask(self, unit: str) -> None:
        self._states[unit] = UnitState.MASKED
        self.calls.append(("mask", unit))
        self.timeline.append(("mask", unit))

    def unmask_and_enable(self, unit: str) -> None:
        if unit == self._fail_on:
            # The half that succeeded, before the half that did not: a
            # failure that changed nothing would let a missing rollback pass.
            self._states[unit] = UnitState.ENABLED
            self.calls.append(("unmask_and_enable", unit))
            self.timeline.append(("unmask_and_enable", unit))
            raise UnitOperationFailed(f"{unit} could not be enabled")
        self._states[unit] = UnitState.ENABLED
        self.calls.append(("unmask_and_enable", unit))
        self.timeline.append(("unmask_and_enable", unit))

    def is_active(self, unit: str) -> bool:
        return unit not in self._inactive and self.state(unit) is UnitState.ENABLED

    def is_inactive(self, unit: str) -> bool:
        # This model is synthetic; production checks systemd independently.
        return not self.is_active(unit)

    def reload(self) -> None:
        self.timeline.append(("reload", ""))
        if self._fail_reload:
            raise UnitOperationFailed("manager reload failed")


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

    def reload(self) -> None:
        """Manager.Reload through the session's own fixed verb.

        `call` is the `(method, unit)` adapter and has no argument-less
        form, so the reload is the session's separate, argument-less method.
        An adapter without one cannot reload and the batch is unconfirmed.
        """
        reload = getattr(self.call, "reload", None)
        if not callable(reload):
            raise UnitOperationFailed("the service manager adapter cannot reload")
        reload()


class ContextdStopAuthority:
    """The authority to stop the Knowledge Context broker, and nothing else.

    A separate type, not a method of `DbusUnitManager`: the watchdog and the
    other users of the manager adapter are not handed a stop. It holds four
    callables (the session's fixed `stop_contextd`, `unit_job` and the two
    exact state reads) and
    refuses any unit but the broker before either is called, so a caller
    cannot turn it into a way to stop another unit. The session below it
    refuses a second time and sends a constant body.
    """

    def __init__(self, *, stop: Callable[[], object],
                 job: Callable[[str], object],
                 state: Callable[[str], object],
                 file_state: Callable[[str], object],
                 cgroup: Optional[Callable[[str], object]] = None) -> None:
        if not all(callable(verb) for verb in (stop, job, state, file_state)):
            raise UnitOperationFailed("a stop authority needs its four verbs")
        self._stop = stop
        self._job = job
        self._state = state
        self._file_state = file_state
        #: Takes the broker's ActiveState; None reads nothing, so the answer is `unknown`.
        self._cgroup = cgroup if callable(cgroup) else None

    @classmethod
    def from_session(cls, session, *, cgroup_root: Path = Path("/")) -> "ContextdStopAuthority":
        """Built from the controller's own D-Bus session.

        The cgroup is read from files under `cgroup_root` (`/` in production),
        not from the session: no D-Bus property is added for it.
        """
        from .contextd_cgroup import read_contextd_cgroup
        return cls(stop=getattr(session, "stop_contextd", None),
                   job=getattr(session, "unit_job", None),
                   state=getattr(session, "contextd_active_state", None),
                   file_state=getattr(session, "contextd_file_state", None),
                   cgroup=lambda active: read_contextd_cgroup(active, root=cgroup_root))

    @staticmethod
    def _check(unit: str) -> str:
        if unit != CONTEXTD_UNIT:
            raise UnitOperationFailed(
                "the stop authority was asked about a unit outside its scope")
        return unit

    def job(self, unit: str) -> tuple:
        """The broker's pending job as `(id, path)`; `(0, "/")` means none."""
        answer = self._job(self._check(unit))
        if (type(answer) not in (tuple, list) or len(answer) != 2
                or type(answer[0]) is not int or type(answer[1]) is not str):
            raise UnitOperationFailed("systemd returned an invalid job result")
        return (answer[0], answer[1])

    def active_state(self, unit: str) -> str:
        """The broker's exact `ActiveState` (`inactive` when it is not loaded)."""
        answer = self._state(self._check(unit))
        if type(answer) is not str or not answer:
            raise UnitOperationFailed("systemd returned an invalid active-state result")
        return answer

    def file_state(self, unit: str) -> str:
        """The broker's exact `UnitFileState` (`masked` is not `masked-runtime`)."""
        answer = self._file_state(self._check(unit))
        if type(answer) is not str or not answer:
            raise UnitOperationFailed("systemd returned an invalid unit-file state result")
        return answer

    def cgroup_state(self, unit: str) -> str:
        """`empty`, `populated` or `unknown` for the broker's cgroup.

        Anything this cannot establish (no reader, an unreadable ActiveState, a
        reader that fails or answers something else) is `unknown`, never `empty`.
        """
        self._check(unit)
        if self._cgroup is None:
            return "unknown"
        try:
            answer = self._cgroup(self.active_state(unit))
        except Exception:  # noqa: BLE001 - unreadable is unknown
            return "unknown"
        return answer if answer in ("empty", "populated") else "unknown"

    def stop(self, unit: str) -> str:
        """Ask the manager to stop the broker (mode `replace`); the job path."""
        self._check(unit)
        answer = self._stop()
        if type(answer) is not str or not answer:
            raise UnitOperationFailed("systemd returned an invalid stop result")
        return answer
