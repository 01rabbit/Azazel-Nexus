"""Fixed-pair inactive/PID/cgroup observations under a revalidated close fence.

The trusted root descriptor must identify the admitted host cgroup-v2 mount.
No production opener is provided. The supported unit layout is system.slice;
other layouts require explicit review, not a fallback to observed paths.
"""

from dataclasses import dataclass

from .bootstrap_cgroup import observe_cgroup_at, validate_cgroup_root
from .bootstrap_masked import _variant_value, _observe_profile
from .bootstrap_stop import NOT_LOADED, BootstrapStopJobs, _validate_expected_owner
from .systemd_bus import PROPERTIES_INTERFACE, UNIT_INTERFACE, _unit_object_path
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed

_PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
_SERVICE = "org.freedesktop.systemd1.Service"


@dataclass(frozen=True)
class StoppedBootstrapPair:
    owner: str
    cgroups: tuple


class BootstrapStoppedPairInspector:
    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 cgroup_root_fd, owner_uid, expected_owner, check_closed):
        self._owner = _validate_expected_owner(expected_owner)
        if self._owner is None or not callable(check_closed):
            raise ValueError("enclosing owner and closed-fence revalidator required")
        validate_cgroup_root(cgroup_root_fd, owner_uid)
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds,
        )
        self._root = cgroup_root_fd
        self._uid = owner_uid
        self._check = check_closed
        self._used = False

    async def inspect(self):
        if self._used:
            raise UnitOperationFailed("stopped pair inspection is single-use")
        self._used = True
        reader = self._reader

        async def guard():
            if await self._check() is not None or await reader._owner() != self._owner:
                raise UnitOperationFailed("bootstrap containment fence changed")

        async def properties(path, interface):
            body = await reader._call("GetAll", "s", [interface], "a{sv}",
                                      path=path, interface=PROPERTIES_INTERFACE)
            if (len(body) != 1 or type(body[0]) is not dict or len(body[0]) > 2048
                    or any(type(key) is not str for key in body[0])):
                raise UnitOperationFailed("bootstrap stopped properties refused")
            return body[0]

        async def snapshot():
            result = []
            for unit in _PAIR:
                await guard()
                name = UNIT_NAMES[unit]
                path = _unit_object_path(name)
                # The enclosing check_closed fence requires the masked closure;
                # the reader additionally demands fresh masked file state.
                if not await reader._get_unit(name, path, masked_not_loaded=True):
                    expected = "/system.slice/" + name
                    observed = observe_cgroup_at(self._root, expected,
                                                 owner_uid=self._uid)
                    if observed[0] != "absent":
                        raise UnitOperationFailed("unattributed bootstrap cgroup remains")
                    result.append((unit, NOT_LOADED, observed))
                    await guard()
                    continue
                props = await properties(path, UNIT_INTERFACE)
                if (_variant_value(props, "Id", "s", str) != name
                        or _variant_value(props, "ActiveState", "s", str) != "inactive"):
                    raise UnitOperationFailed("bootstrap unit not inactive")
                service = await properties(path, _SERVICE)
                for field in ("MainPID", "ControlPID"):
                    if _variant_value(service, field, "u", int) != 0:
                        raise UnitOperationFailed("bootstrap service PID remains")
                expected = "/system.slice/" + name
                declared = _variant_value(service, "ControlGroup", "s", str)
                if declared not in {"", expected}:
                    raise UnitOperationFailed("bootstrap cgroup path changed")
                observed = observe_cgroup_at(self._root, expected, owner_uid=self._uid)
                if declared == "" and observed[0] != "absent":
                    raise UnitOperationFailed("unattributed bootstrap cgroup remains")
                result.append((unit, declared, observed))
                await guard()
            return tuple(result)

        async def operation():
            reader._manager_owner = self._owner
            await guard()
            profile = await _observe_profile(reader)
            before = await snapshot()
            after = await snapshot()
            await guard()
            if before != after or await _observe_profile(reader) != profile:
                raise UnitOperationFailed("bootstrap stopped pair changed")
            await guard()
            return StoppedBootstrapPair(self._owner, after)

        try:
            return await reader._bounded(operation())
        except Exception:
            raise UnitOperationFailed("bootstrap stopped/cgroup observation refused") from None
