"""Fail-closed tests for the read-only masked bootstrap pair observer."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_masked import (
    BootstrapMaskedPairInspector,
    MaskedBootstrapPair,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed


DESTINATION = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
DBUS_INTERFACE = "org.freedesktop.DBus"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
UNIT_INTERFACE = "org.freedesktop.systemd1.Unit"
OWNER = ":1.42"
PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
PROFILE_VERSION = "257.13-1~deb13u1"
PROFILE_PATHS = [
    "/etc/systemd/system.control", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached",
    "/run/systemd/generator", "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/generator.late",
]


@dataclass(frozen=True)
class Variant:
    signature: str
    value: object


class Message:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class FakeBus:
    def __init__(self, *, mutate=None, owner_changes=False, bad_sender=None,
                 wrong_path=False, hang_member=None, unsupported_profile=False,
                 profile_drift=False):
        self.calls = []
        self.mutate = mutate
        self.owner_changes = owner_changes
        self.bad_sender = bad_sender
        self.wrong_path = wrong_path
        self.hang_member = hang_member
        self.unsupported_profile = unsupported_profile
        self.profile_drift = profile_drift
        self.owner_calls = 0
        self.property_calls = 0
        self.profile_calls = 0
        self.active = {unit: "active" for unit in PAIR}

    async def call(self, message):
        self.calls.append(message)
        if message.member == self.hang_member:
            await asyncio.Event().wait()
        if message.destination == "org.freedesktop.DBus":
            assert message.member == "GetNameOwner"
            self.owner_calls += 1
            owner = ":1.43" if self.owner_changes and self.owner_calls > 1 else OWNER
            return _reply("s", owner, sender="wrong.owner" if self.bad_sender == "owner" else "org.freedesktop.DBus")
        assert message.destination == OWNER
        if message.member == "GetUnit":
            assert message.interface == MANAGER_INTERFACE
            name = message.body[0]
            path = _object_path(name)
            if self.wrong_path:
                path += "_wrong"
            return _reply("o", path, sender="wrong.owner" if self.bad_sender == "systemd" else OWNER)
        assert message.member == "GetAll"
        assert message.interface == PROPERTIES_INTERFACE
        if message.body == [MANAGER_INTERFACE]:
            assert message.path == MANAGER_PATH
            self.profile_calls += 1
            version = "258.1-1~deb13u1" if self.unsupported_profile else PROFILE_VERSION
            if self.profile_drift and self.profile_calls > 1:
                version = "257.13-2~deb13u1"
            paths = list(PROFILE_PATHS)
            values = {
                "Version": Variant("s", version),
                "UnitPath": Variant("as", paths),
            }
            sender = "wrong.owner" if self.bad_sender == "properties" else OWNER
            return _reply("a{sv}", values, sender=sender)
        assert message.body == [UNIT_INTERFACE]
        assert message.path.startswith("/org/freedesktop/systemd1/unit/")
        self.property_calls += 1
        name = next(name for name in UNIT_NAMES.values()
                    if message.path == _object_path(name))
        properties = _properties(name)
        properties["ActiveState"] = Variant("s", self.active[next(
            unit for unit in PAIR if UNIT_NAMES[unit] == name
        )])
        if self.mutate is not None:
            properties = self.mutate(self.property_calls, name, properties)
        sender = "wrong.owner" if self.bad_sender == "properties" else OWNER
        return _reply("a{sv}", properties, sender=sender)


def _reply(signature, *body, sender=OWNER):
    return SimpleNamespace(message_type=1, signature=signature, body=list(body), sender=sender)


def _object_path(name):
    encoded = "".join(char if char.isalnum() or char == "_" else f"_{ord(char):02x}"
                      for char in name)
    return f"/org/freedesktop/systemd1/unit/{encoded}"


def _properties(name):
    return {
        "Id": Variant("s", name),
        "Names": Variant("as", [name]),
        "Following": Variant("s", ""),
        "LoadState": Variant("s", "masked"),
        "NeedDaemonReload": Variant("b", False),
        "FragmentPath": Variant("s", f"/etc/systemd/system/{name}"),
    }


def _inspector(bus, timeout_seconds=0.2):
    return BootstrapMaskedPairInspector(
        bus=bus,
        message_factory=Message,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=timeout_seconds,
    )


def test_inspection_returns_immutable_pair_after_two_identical_snapshots():
    async def run():
        bus = FakeBus()
        result = await _inspector(bus).inspect()
        assert isinstance(result, MaskedBootstrapPair)
        assert result.owner == OWNER
        assert result.fragments == tuple(
            (unit, f"/etc/systemd/system/{UNIT_NAMES[unit]}") for unit in PAIR
        )
        assert result.fingerprint.startswith("sha256:")
        assert [call.member for call in bus.calls] == [
            "GetNameOwner", "GetAll", "GetNameOwner",
            "GetUnit", "GetAll", "GetUnit", "GetAll",
            "GetUnit", "GetAll", "GetUnit", "GetAll", "GetAll", "GetNameOwner",
        ]
        assert {call.member for call in bus.calls} <= {"GetNameOwner", "GetUnit", "GetAll"}
        assert all(call.member != "GetAll" or call.body in ([UNIT_INTERFACE], [MANAGER_INTERFACE])
                   for call in bus.calls)
        assert [call.body for call in bus.calls if call.member == "GetAll"] == [
            [MANAGER_INTERFACE], [UNIT_INTERFACE], [UNIT_INTERFACE], [UNIT_INTERFACE],
            [UNIT_INTERFACE], [MANAGER_INTERFACE],
        ]
        with pytest.raises((AttributeError, TypeError)):
            result.owner = ":1.99"
    asyncio.run(run())


@pytest.mark.parametrize("bad", [
    "second_unmasked", "stale_reload", "wrong_id", "wrong_names", "following",
    "wrong_loadstate", "wrong_bool_type", "wrong_signature", "relative_path",
    "unnormalized_path", "empty_path", "wrong_path_type", "names_non_string",
    "root_path", "double_slash_path", "control_path",
])
def test_rejects_invalid_properties_on_either_pair_member(bad):
    async def run():
        def mutate(call_number, name, props):
            is_commissiond = name == UNIT_NAMES[UnitKey.COMMISSIOND]
            should_corrupt = (bad == "second_unmasked" and is_commissiond
                              and call_number == 4) or (
                bad != "second_unmasked" and name == UNIT_NAMES[UnitKey.AUDITD]
                and call_number == 1
            )
            if not should_corrupt:
                return props
            field = {
                "second_unmasked": "LoadState", "stale_reload": "NeedDaemonReload",
                "wrong_id": "Id", "wrong_names": "Names", "following": "Following",
                "wrong_loadstate": "LoadState", "wrong_bool_type": "NeedDaemonReload",
                "wrong_signature": "Id", "relative_path": "FragmentPath",
                "unnormalized_path": "FragmentPath", "empty_path": "FragmentPath",
                "wrong_path_type": "FragmentPath", "names_non_string": "Names",
                "root_path": "FragmentPath", "double_slash_path": "FragmentPath",
                "control_path": "FragmentPath",
            }[bad]
            value = {
                "second_unmasked": Variant("s", "loaded"),
                "stale_reload": Variant("b", True),
                "wrong_id": Variant("s", "unexpected.service"),
                "wrong_names": Variant("as", [name, "alias.service"]),
                "following": Variant("s", "other.service"),
                "wrong_loadstate": Variant("s", "loaded"),
                "wrong_bool_type": Variant("s", "false"),
                "wrong_signature": Variant("as", [name]),
                "relative_path": Variant("s", "etc/systemd/file"),
                "unnormalized_path": Variant("s", "/etc/../etc/systemd/file"),
                "empty_path": Variant("s", ""),
                "wrong_path_type": Variant("o", "/etc/systemd/file"),
                "names_non_string": Variant("as", [type("Name", (), {
                    "__eq__": lambda self, other: other == name,
                })()]),
                "root_path": Variant("s", "/"),
                "double_slash_path": Variant("s", "//etc/systemd/file"),
                "control_path": Variant("s", "/etc/systemd/file\nextra"),
            }[bad]
            props[field] = value
            return props

        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(mutate=mutate)).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("bad_sender", ["owner", "systemd", "properties"])
def test_rejects_wrong_reply_sender(bad_sender):
    async def run():
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(bad_sender=bad_sender)).inspect()
    asyncio.run(run())


def test_rejects_owner_change_and_wrong_unit_object_path():
    async def run():
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(owner_changes=True)).inspect()
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(wrong_path=True)).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("bus_options", [
    {"unsupported_profile": True}, {"profile_drift": True},
])
def test_rejects_unsupported_or_drifting_pinned_owner_profile(bus_options):
    async def run():
        bus = FakeBus(**bus_options)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()
        assert bus.profile_calls >= 1
        assert all(call.member in {"GetNameOwner", "GetUnit", "GetAll"}
                   for call in bus.calls)
    asyncio.run(run())


def test_rejects_snapshot_change_between_pair_observations():
    async def run():
        def change_path(call_number, name, props):
            if call_number == 3:
                props["FragmentPath"] = Variant("s", f"/run/systemd/system/{name}")
            return props
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(mutate=change_path)).inspect()
    asyncio.run(run())


def test_timeout_and_single_use_refuse_further_bus_access():
    async def run():
        bus = FakeBus(hang_member="GetNameOwner")
        inspector = _inspector(bus, timeout_seconds=0.01)
        with pytest.raises(UnitOperationFailed):
            await inspector.inspect()
        calls = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await inspector.inspect()
        assert len(bus.calls) == calls
    asyncio.run(run())


def test_masked_active_unit_is_observed_without_claiming_inactivity():
    async def run():
        bus = FakeBus()
        result = await _inspector(bus).inspect()
        assert all(state == "active" for state in bus.active.values())
        assert len(result.fragments) == 2
        assert all(call.member != "Get" for call in bus.calls)
    asyncio.run(run())
