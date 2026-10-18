"""Read-only on-device prerequisites; this is not HIL evidence or admission."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from uuid import UUID

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.hil_preflight import PROTECTION_KEY, TARGET_PROFILE
from azazel_nexus.resource_profile import (
    UsableMemoryUnavailable,
    read_usable_mib,
    select_profile,
)

from .core_reserve_probe import SUBSYSTEM_UNITS
from .systemd_socket import (
    SYSTEM_BUS_ADDRESS,
    FixedSystemBusSocket,
    require_supported_dbus_next,
)

BUILD_COMMIT = Path("/usr/share/azazel/build-commit")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
MACHINE_ID = Path("/etc/machine-id")
REQUIRED_UNITS = tuple(SUBSYSTEM_UNITS.values()) + ("azazel.slice",)
CAPTURE_UNITS = tuple(sorted(set(REQUIRED_UNITS) | {unit.name for unit in CORE_UNITS}))
_MANAGER = "org.freedesktop.systemd1.Manager"
_PROPERTIES = "org.freedesktop.DBus.Properties"
_UNIT = "org.freedesktop.systemd1.Unit"
_PATH = "/org/freedesktop/systemd1"


def protection_key(path: Path = PROTECTION_KEY) -> bytes:
    """Read only a root-owned regular 0600 key in a root-owned 0700 directory."""

    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent = os.fstat(parent_fd)
        if (parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError("commissioning key directory owner/mode refused")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 32):
            raise ValueError("commissioning key owner/mode/size refused")
        key = os.read(fd, 33)
        if len(key) != 32:
            raise ValueError("commissioning key size refused")
        return key
    finally:
        os.close(fd)


def digest(value: str, *, key: bytes, domain: str) -> str:
    """Domain-separated HMAC; no raw identity reaches a report."""

    if not key or not value:
        raise ValueError("empty protected fingerprint input")
    return "hmac-sha256:" + hmac.new(
        key, ("azazel-nexus/" + domain + "/v1\0" + value).encode(), hashlib.sha256
    ).hexdigest()


def _boot_id() -> str:
    boot = BOOT_ID.read_text().strip()
    UUID(boot)
    return boot


def _machine_id() -> str:
    host = MACHINE_ID.read_text().strip()
    if not host:
        raise ValueError("host identity unavailable")
    return host


def _build_commit() -> str:
    commit = BUILD_COMMIT.read_text().strip()
    if len(commit) not in (40, 64) or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("build identity unavailable")
    return commit


#: The fixed inputs of an identity observation, in the order they are read.
#: Names are a closed vocabulary an operator can be told; values never are.
IDENTITY_INPUTS = (
    ("commissioning_key", protection_key),
    ("boot_id", _boot_id),
    ("machine_id", _machine_id),
    ("build_commit", _build_commit),
)


def run_identity() -> dict:
    key = protection_key()
    boot = _boot_id()
    host = _machine_id()
    commit = _build_commit()
    return {
        "boot_fingerprint": digest(boot, key=key, domain="hil-boot"),
        "host_digest": digest(host, key=key, domain="hil-host"),
        "build_commit": commit,
        "kernel_release": os.uname().release,
    }


class ReadOnlySystemd:
    """Fixed system-bus destination and read-only methods, with bounded calls.

    GetUnit does not load an absent unit. ListUnitFiles establishes installed
    presence separately from the manager's loaded state.
    """

    def __enter__(self):
        from dbus_next import Message, MessageType
        from dbus_next.aio import MessageBus

        require_supported_dbus_next()

        class FixedBus(FixedSystemBusSocket, MessageBus):
            pass

        self._message = Message
        self._type = MessageType
        self._previous = None
        try:
            self._previous = asyncio.get_running_loop()
        except RuntimeError:
            pass
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._bus = None
        try:
            self._bus = FixedBus(bus_address=SYSTEM_BUS_ADDRESS)
            self._loop.run_until_complete(asyncio.wait_for(self._bus.connect(), 10))
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        if self._bus is not None:
            self._bus.disconnect()
        self._loop.close()
        asyncio.set_event_loop(self._previous)

    def _read(self, member, signature="", body=None, *, path=_PATH, interface=_MANAGER):
        if (interface, member) not in {
            (_MANAGER, "GetUnit"), (_MANAGER, "ListUnitFiles"), (_PROPERTIES, "Get")
        }:
            raise ValueError("read-only method refused")
        reply = self._loop.run_until_complete(asyncio.wait_for(self._bus.call(self._message(
            destination="org.freedesktop.systemd1", path=path, interface=interface,
            member=member, signature=signature, body=body or [],
        )), 10))
        if reply.message_type != self._type.METHOD_RETURN:
            raise ValueError("systemd observation unavailable")
        return reply

    def version(self):
        reply = self._read("Get", "ss", [_MANAGER, "Version"], interface=_PROPERTIES)
        if reply.signature != "v" or len(reply.body) != 1:
            raise ValueError("systemd version unavailable")
        value = reply.body[0].value
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("systemd version unavailable")
        return value

    def unit_files(self):
        reply = self._read("ListUnitFiles")
        if reply.signature != "a(ss)" or len(reply.body) != 1:
            raise ValueError("systemd unit-file list unavailable")
        # Paths and unrelated local units can carry host identity. Emit only
        # governed unit basenames and their file states.
        return {Path(path).name: state for path, state in reply.body[0]
                if Path(path).name in CAPTURE_UNITS}

    def __call__(self, method, unit):
        if method != "GetUnitProperties" or unit not in CAPTURE_UNITS:
            raise ValueError("unit observation outside fixed allowlist")
        reply = self._read("GetUnit", "s", [unit])
        if reply.signature != "o" or len(reply.body) != 1:
            raise ValueError("systemd unit unavailable")
        result = {}
        for name in ("LoadState", "ActiveState", "SubState"):
            prop = self._read("Get", "ss", [_UNIT, name], path=reply.body[0],
                              interface=_PROPERTIES)
            if prop.signature != "v" or len(prop.body) != 1:
                raise ValueError("systemd unit property unavailable")
            value = prop.body[0].value
            allowed = {
                "LoadState": {"stub", "loaded", "not-found", "bad-setting", "error", "merged", "masked"},
                "ActiveState": {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"},
            }
            if not isinstance(value, str) or len(value) > 64:
                raise ValueError("systemd property invalid")
            if name in allowed and value not in allowed[name]:
                raise ValueError("systemd property unknown")
            result[name] = value
        return result


def readiness(manager=None, *, key_reader=protection_key, memory_reader=read_usable_mib):
    """Report each missing/unknown prerequisite without exposing host facts."""

    files = None
    if manager is not None:
        try:
            files = manager.unit_files()
        except Exception:  # noqa: BLE001 - observation failure must not imply presence
            files = None
    units = {}
    for unit in REQUIRED_UNITS:
        state = {"present": None if files is None else unit in files, "active": None}
        if manager is not None:
            try:
                props = manager("GetUnitProperties", unit)
                state["active"] = (props.get("ActiveState") == "active"
                                   and (unit == "azazel.slice" or props.get("SubState") == "running"))
            except Exception:  # noqa: BLE001 - no identity-bearing diagnostics
                state["active"] = None
        units[unit] = state
    try:
        key_reader()
        key_ready = True
    except (OSError, ValueError):
        key_ready = False
    try:
        target = select_profile(memory_reader()) is TARGET_PROFILE
    except (OSError, ValueError, UsableMemoryUnavailable):
        target = False
    missing = [unit for unit, state in units.items()
               if state["present"] is not True or state["active"] is not True]
    return {
        "schema": "azazel-nexus/hil-readiness/1", "units": units,
        "commissioning_key_ready": key_ready, "target_class": TARGET_PROFILE.value,
        "target_class_present": target,
        "ready": not missing and key_ready and target,
        "edge_core_prerequisites_missing_or_unobserved": missing,
        "prerequisite": "Install and run Edge Core subsystems in azazel.slice before HG-05.",
    }


def main(argv=None):
    argparse.ArgumentParser(prog="az-hil-readiness", description=__doc__).parse_args(argv)
    try:
        with ReadOnlySystemd() as manager:
            report = readiness(manager)
    except Exception:  # noqa: BLE001 - connection failure means unobserved
        report = readiness()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ready"] else 2
