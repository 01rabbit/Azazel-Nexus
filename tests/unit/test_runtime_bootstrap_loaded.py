"""Fail-closed tests for inspecting the loaded systemd bootstrap unit."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_loaded import (
    BootstrapLoadedUnitInspector,
    LoadedBootstrapUnit,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT


DESTINATION = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
DBUS_INTERFACE = "org.freedesktop.DBus"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
UNIT_INTERFACE = "org.freedesktop.systemd1.Unit"
SERVICE_INTERFACE = "org.freedesktop.systemd1.Service"
OWNER = ":1.42"
CONTROLLER = "azazel-activated.service"
AUDIT_UNIT = "azazel-auditd.service"
COMMISSION_UNIT = "azazel-commissiond.service"
EXECUTABLE = "/usr/libexec/azazel/az-auditd"
SYSTEMD_OWNER_DESTINATION = OWNER
SERVICE_TIMER_FIXTURE = {
    "TimeoutStartUSec": 101,
    "TimeoutStopUSec": 202,
    "RuntimeMaxUSec": 303,
    "WatchdogUSec": 404,
}

DEPENDENCY_KEYS = frozenset(
    {
        "After",
        "Before",
        "Requires",
        "Wants",
        "BindsTo",
        "Requisite",
        "Upholds",
        "PartOf",
        "Conflicts",
        "ConflictedBy",
        "OnFailure",
        "OnSuccess",
        "Triggers",
        "TriggeredBy",
        "PropagatesStopTo",
        "StopPropagatedFrom",
        "JoinsNamespaceOf",
        "RequiredBy",
        "RequisiteOf",
        "WantedBy",
        "BoundBy",
        "UpheldBy",
        "ConsistsOf",
        "OnSuccessOf",
        "OnFailureOf",
        "PropagatesReloadTo",
        "ReloadPropagatedFrom",
    }
)


@dataclass(frozen=True)
class Reply:
    signature: str
    body: list


@dataclass(frozen=True)
class Variant:
    signature: str
    value: object


class Message:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class FakeBus:
    """Answer only the fixed read calls made by the inspector."""

    def __init__(self, unit: UnitKey, *, mutate=None):
        self.unit = unit
        self.unit_name = UNIT_NAMES[unit]
        self.path = _object_path(self.unit_name)
        self.owner = OWNER
        self.calls = []
        self.mutate = mutate
        self.snapshot_number = 0

    async def call(self, message):
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            assert message.path == "/org/freedesktop/DBus"
            assert message.interface == DBUS_INTERFACE
            if message.member == "GetNameOwner":
                assert message.signature == "s"
                assert message.body == [DESTINATION]
                return _reply("s", self.owner, sender="org.freedesktop.DBus")
            raise AssertionError(message.member)

        assert message.destination == SYSTEMD_OWNER_DESTINATION
        if message.interface == MANAGER_INTERFACE:
            assert message.path == MANAGER_PATH
            if message.member == "GetUnit":
                assert message.signature == "s"
                assert message.body == [self.unit_name]
                return _reply("o", self.path, sender=OWNER)
            raise AssertionError(message.member)

        assert message.interface == PROPERTIES_INTERFACE
        assert message.path == self.path
        assert message.member == "GetAll"
        assert message.signature == "s"
        assert len(message.body) == 1
        self.snapshot_number += 1
        interface = message.body[0]
        if interface == UNIT_INTERFACE:
            props = _unit_properties(self.unit_name, self.path)
        elif interface == SERVICE_INTERFACE:
            props = _service_properties(self.unit)
        else:
            raise AssertionError(interface)
        if self.mutate is not None:
            props = self.mutate(self.snapshot_number, interface, props)
        return _reply("a{sv}", props, sender=OWNER)

    def disconnect(self):
        pass


def _reply(signature, *body, sender=OWNER):
    fields = {"message_type": 1, "signature": signature, "body": list(body)}
    if sender is not None:
        fields["sender"] = sender
    return SimpleNamespace(**fields)


def _object_path(unit_name):
    encoded = "".join(
        chr(byte)
        if 65 <= byte <= 90 or 97 <= byte <= 122 or (index > 0 and 48 <= byte <= 57)
        else f"_{byte:02x}"
        for index, byte in enumerate(unit_name.encode("utf-8"))
    ) or "_"
    return f"/org/freedesktop/systemd1/unit/{encoded}"


def _unit_properties(unit_name, _object_path):
    dependencies = {key: [] for key in DEPENDENCY_KEYS}
    dependencies.update(
        After=[CONTROLLER], Requires=[CONTROLLER], BindsTo=[CONTROLLER]
    )
    if unit_name == COMMISSION_UNIT:
        dependencies["After"].append(AUDIT_UNIT)
        dependencies["Requires"].append(AUDIT_UNIT)
        dependencies["BindsTo"].append(AUDIT_UNIT)
    elif unit_name == AUDIT_UNIT:
        dependencies["Before"].append(COMMISSION_UNIT)
        dependencies["RequiredBy"].append(COMMISSION_UNIT)
        dependencies["BoundBy"].append(COMMISSION_UNIT)
    properties = {
        "Id": unit_name,
        "Names": [unit_name],
        "Following": "",
        "LoadState": "loaded",
        "DefaultDependencies": False,
        "ActiveState": "inactive",
        "Job": [0, "/"],
        "FragmentPath": f"/run/systemd/system.control/{unit_name}",
        "SourcePath": "",
        "DropInPaths": [],
        "NeedDaemonReload": False,
    }
    properties.update(dependencies)
    signatures = {
        "Id": "s", "Names": "as", "Following": "s", "LoadState": "s",
        "DefaultDependencies": "b",
        "ActiveState": "s",
        "Job": "(uo)",
        "FragmentPath": "s", "SourcePath": "s", "DropInPaths": "as",
        "NeedDaemonReload": "b",
    }
    signatures.update({name: "as" for name in DEPENDENCY_KEYS})
    return {name: Variant(signatures[name], value) for name, value in properties.items()}


def _service_properties(unit):
    from azazel_nexus_runtime.hardening import PROFILES

    profile = next(item for item in PROFILES if item.unit == UNIT_NAMES[unit])
    executable = profile.executable
    # ExecStartEx is a(sasasttttuii): path, argv, flags and seven metadata ints.
    command = [executable, [executable], [], 0, 0, 0, 0, 0, 0, 0]
    properties = {
        "Type": "notify",
        "NotifyAccess": "main",
        "Restart": "no",
        "RemainAfterExit": False,
        "KillMode": "control-group",
        "SendSIGKILL": True,
        "TimeoutStartFailureMode": "kill",
        "TimeoutStopFailureMode": "kill",
        "FinalKillSignal": 9,
        "KillSignal": 15,
        "ExitType": "main",
        "User": profile.account,
        "Group": "",
        "DynamicUser": False,
        "Environment": [],
        "EnvironmentFiles": [],
        "PassEnvironment": [],
        "UnsetEnvironment": list(BOOTSTRAP_UNSET_ENVIRONMENT),
        "PAMName": "",
        "SupplementaryGroups": [],
        "RootDirectory": "",
        "RootImage": "",
        **SERVICE_TIMER_FIXTURE,
        "SetLoginEnvironment": False,
        "ExecStartEx": [command],
    }
    properties.update(
        {
            f"Exec{name}Ex": []
            for name in (
                "Condition",
                "StartPre",
                "StartPost",
                "Reload",
                "Stop",
                "StopPost",
            )
        }
    )
    signatures = {
        "Type": "s", "NotifyAccess": "s", "Restart": "s",
        "RemainAfterExit": "b", "KillMode": "s", "SendSIGKILL": "b",
        "ExitType": "s", "User": "s", "Group": "s", "DynamicUser": "b",
        "TimeoutStartFailureMode": "s", "TimeoutStopFailureMode": "s",
        "FinalKillSignal": "i", "KillSignal": "i",
        "Environment": "as", "EnvironmentFiles": "a(sb)",
        "PassEnvironment": "as", "UnsetEnvironment": "as",
        "PAMName": "s",
        "SupplementaryGroups": "as", "RootDirectory": "s", "RootImage": "s",
        **{name: "t" for name in SERVICE_TIMER_FIXTURE},
        "SetLoginEnvironment": "b",
        "ExecStartEx": "a(sasasttttuii)",
    }
    signatures.update({
        f"Exec{name}Ex": "a(sasasttttuii)"
        for name in ("Condition", "StartPre", "StartPost", "Reload", "Stop", "StopPost")
    })
    return {name: Variant(signatures[name], value) for name, value in properties.items()}


def _dependencies(unit=UnitKey.AUDITD, **overrides):
    expected = {name: frozenset() for name in DEPENDENCY_KEYS}
    expected["After"] = frozenset({CONTROLLER})
    expected["Requires"] = frozenset({CONTROLLER})
    expected["BindsTo"] = frozenset({CONTROLLER})
    if unit is UnitKey.COMMISSIOND:
        for key in ("After", "Requires", "BindsTo"):
            expected[key] = expected[key] | {AUDIT_UNIT}
    elif unit is UnitKey.AUDITD:
        expected["Before"] = frozenset({COMMISSION_UNIT})
        expected["RequiredBy"] = frozenset({COMMISSION_UNIT})
        expected["BoundBy"] = frozenset({COMMISSION_UNIT})
    expected.update(overrides)
    return expected


def _service_settings(**overrides):
    settings = {**SERVICE_TIMER_FIXTURE, "SetLoginEnvironment": False}
    settings.update(overrides)
    return settings


def _inspector(
    bus, *, timeout_seconds=0.25, expected_service_settings=None,
    expected_owner=None,
):
    return BootstrapLoadedUnitInspector(
        bus=bus,
        message_factory=Message,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=timeout_seconds,
        expected_service_settings=(
            _service_settings()
            if expected_service_settings is None
            else expected_service_settings
        ),
        expected_owner=expected_owner,
    )


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
def test_inspection_pins_owner_path_and_compares_two_immutable_snapshots(unit):
    async def run():
        bus = FakeBus(unit)
        result = await _inspector(bus, expected_owner=OWNER).inspect(
            unit, expected_dependencies=_dependencies(unit)
        )

        assert result == LoadedBootstrapUnit(
            unit=unit,
            owner=OWNER,
            fingerprint=result.fingerprint,
        )
        assert isinstance(result.fingerprint, str) and result.fingerprint
        assert [call.member for call in bus.calls] == [
            "GetNameOwner",
            "GetUnit",
            "GetAll",
            "GetAll",
            "GetNameOwner",
            "GetUnit",
            "GetAll",
            "GetAll",
            "GetNameOwner",
        ]
        assert [call.body[0] for call in bus.calls if call.member == "GetAll"] == [
            UNIT_INTERFACE,
            SERVICE_INTERFACE,
            UNIT_INTERFACE,
            SERVICE_INTERFACE,
        ]
        assert bus.calls[0].destination == "org.freedesktop.DBus"
        assert all(
            call.destination == (
                "org.freedesktop.DBus" if call.member == "GetNameOwner" else OWNER
            )
            for call in bus.calls
        )

    asyncio.run(run())


def test_expected_owner_mismatch_refuses_before_get_unit():
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus, expected_owner=":1.99").inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        assert [call.member for call in bus.calls] == ["GetNameOwner"]

    asyncio.run(run())


@pytest.mark.parametrize("expected_owner", ["", ":1", ":1.2.extra", 7, True])
def test_invalid_inspector_expected_owner_is_rejected_before_bus_io(expected_owner):
    bus = FakeBus(UnitKey.AUDITD)
    with pytest.raises(ValueError):
        _inspector(bus, expected_owner=expected_owner)
    assert bus.calls == []


@pytest.mark.parametrize("edge", ["After", "Requires", "BindsTo"])
def test_commission_requires_forward_audit_lifetime_edge(edge):
    async def run():
        def remove_audit_edge(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                observed = list(props[edge].value)
                observed.remove(AUDIT_UNIT)
                props[edge] = Variant("as", observed)
            return props

        bus = FakeBus(UnitKey.COMMISSIOND, mutate=remove_audit_edge)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.COMMISSIOND,
                expected_dependencies=_dependencies(UnitKey.COMMISSIOND),
            )

    asyncio.run(run())


@pytest.mark.parametrize("edge", ["Before", "RequiredBy", "BoundBy"])
def test_observed_audit_cannot_omit_independently_expected_reverse_edge(edge):
    async def run():
        def remove_reverse(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                props[edge] = Variant("as", [])
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=remove_reverse)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies(UnitKey.AUDITD),
            )
        assert any(call.member == "GetAll" for call in bus.calls)

    asyncio.run(run())


def test_audit_reverse_commission_edges_are_allowed():
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        result = await _inspector(bus).inspect(
            UnitKey.AUDITD, expected_dependencies=_dependencies(UnitKey.AUDITD),
        )
        assert result.unit is UnitKey.AUDITD
        properties = _unit_properties(AUDIT_UNIT, "unused")
        assert properties["Before"].value == [COMMISSION_UNIT]
        assert properties["RequiredBy"].value == [COMMISSION_UNIT]
        assert properties["BoundBy"].value == [COMMISSION_UNIT]

    asyncio.run(run())


@pytest.mark.parametrize("edge", ["After", "Requires", "BindsTo"])
def test_audit_forward_commission_edges_are_rejected_as_cycle_or_reverse_mismatch(edge):
    async def run():
        def add_forward_commission(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                props[edge] = Variant("as", [*props[edge].value, COMMISSION_UNIT])
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=add_forward_commission)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies(UnitKey.AUDITD),
            )

    asyncio.run(run())


def test_unrelated_azazel_unit_dependency_is_rejected():
    async def run():
        def add_unrelated(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                props["After"] = Variant("as", [*props["After"].value, "azazel-watchdog.service"])
            return props

        bus = FakeBus(UnitKey.COMMISSIOND, mutate=add_unrelated)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.COMMISSIOND,
                expected_dependencies=_dependencies(UnitKey.COMMISSIOND),
            )

    asyncio.run(run())


@pytest.mark.parametrize("edge", ["After", "Requires", "BindsTo"])
def test_expected_commission_policy_cannot_omit_required_audit_edge_before_bus_io(edge):
    async def run():
        expected = _dependencies(UnitKey.COMMISSIOND)
        expected[edge] = expected[edge] - {AUDIT_UNIT}
        bus = FakeBus(UnitKey.COMMISSIOND)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.COMMISSIOND, expected_dependencies=expected,
            )
        assert bus.calls == []

    asyncio.run(run())


@pytest.mark.parametrize("edge", ["After", "Requires", "BindsTo"])
def test_expected_audit_policy_cannot_create_forward_commission_cycle_before_bus_io(edge):
    async def run():
        expected = _dependencies(UnitKey.AUDITD)
        expected[edge] = expected[edge] | {COMMISSION_UNIT}
        bus = FakeBus(UnitKey.AUDITD)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=expected,
            )
        assert bus.calls == []

    asyncio.run(run())


def test_expected_policy_rejects_unrelated_azazel_edge_before_bus_io():
    async def run():
        expected = _dependencies(UnitKey.COMMISSIOND)
        expected["After"] = expected["After"] | {"azazel-watchdog.service"}
        bus = FakeBus(UnitKey.COMMISSIOND)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.COMMISSIOND, expected_dependencies=expected,
            )
        assert bus.calls == []

    asyncio.run(run())


@pytest.mark.parametrize("bad_unit", ["auditd", "azazel-auditd.service", None])
def test_rejects_anything_but_an_exact_unit_key_before_bus_io(bad_unit):
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        with pytest.raises((UnitOperationFailed, ValueError, TypeError)):
            await _inspector(bus).inspect(
                bad_unit, expected_dependencies=_dependencies()
            )
        assert bus.calls == []

    asyncio.run(run())


@pytest.mark.parametrize(
    "dependencies",
    [
        {},
        {"After": frozenset()},
        {**_dependencies(), "Unexpected": frozenset()},
        {**_dependencies(), "After": {CONTROLLER}},
        {**_dependencies(), "After": [CONTROLLER]},
    ],
)
def test_expected_dependencies_require_exact_keys_and_frozenset_values(dependencies):
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        with pytest.raises((UnitOperationFailed, ValueError, TypeError)):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=dependencies
            )
        assert bus.calls == []

    asyncio.run(run())


@pytest.mark.parametrize("edge", ["Requires", "Wants"])
def test_unordered_positive_expected_dependency_refuses_before_bus_io(edge):
    async def run():
        expected = _dependencies()
        expected[edge] = expected[edge] | {"basic.target"}
        bus = FakeBus(UnitKey.AUDITD)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=expected,
            )
        assert bus.calls == []

    asyncio.run(run())


@pytest.mark.parametrize("edge", ["Requires", "Wants"])
def test_ordered_external_positive_dependency_is_inspected(edge):
    async def run():
        expected = _dependencies()
        expected["After"] = expected["After"] | {"basic.target"}
        expected[edge] = expected[edge] | {"basic.target"}

        def add_ordered_edge(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                for key in ("After", edge):
                    props[key] = Variant(
                        "as", sorted(set(props[key].value) | {"basic.target"}),
                    )
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=add_ordered_edge)
        result = await _inspector(bus).inspect(
            UnitKey.AUDITD, expected_dependencies=expected,
        )

        assert result.unit is UnitKey.AUDITD
        assert any(call.member == "GetAll" for call in bus.calls)

    asyncio.run(run())


@pytest.mark.parametrize(
    ("property_name", "value"),
    [
        ("Id", "azazel-other.service"),
        ("Names", ["azazel-auditd.service", "alias.service"]),
        ("LoadState", "not-found"),
        ("FragmentPath", "/etc/systemd/system/azazel-auditd.service"),
        ("SourcePath", "/etc/systemd/system/azazel-auditd.service"),
        ("DropInPaths", ["/run/systemd/system.control/override.conf"]),
        ("After", []),
        ("BindsTo", []),
    ],
)
def test_unit_properties_must_be_loaded_pinned_and_match_each_dependency(
    property_name, value
):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                props[property_name] = Variant(props[property_name].signature, value)
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        target_interface = (
            UNIT_INTERFACE
            if property_name in {
                "Id", "Names", "LoadState", "FragmentPath", "SourcePath",
                "DropInPaths", "After", "BindsTo",
            }
            else SERVICE_INTERFACE
        )
        assert any(
            call.member == "GetAll" and call.body == [target_interface]
            for call in bus.calls
        )

    asyncio.run(run())


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
@pytest.mark.parametrize("fault", ["missing", "true", "wrong-signature", "wrong-type"])
def test_helpers_require_default_dependencies_exact_false(unit, fault):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                if fault == "missing":
                    props.pop("DefaultDependencies")
                elif fault == "true":
                    props["DefaultDependencies"] = Variant("b", True)
                elif fault == "wrong-signature":
                    props["DefaultDependencies"] = Variant("s", "false")
                else:
                    props["DefaultDependencies"] = Variant("b", 0)
            return props

        bus = FakeBus(unit, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(unit, expected_dependencies=_dependencies(unit))
        assert any(
            call.member == "GetAll" and call.body == [UNIT_INTERFACE]
            for call in bus.calls
        )

    asyncio.run(run())


@pytest.mark.parametrize(
    ("property_name", "value"),
    [
        ("Type", "simple"),
        ("NotifyAccess", "all"),
        ("Restart", "always"),
        ("RemainAfterExit", True),
        ("KillMode", "process"),
        ("SendSIGKILL", False),
        ("User", "root"),
        ("Group", "root"),
        ("DynamicUser", True),
        ("Environment", ["TOKEN=secret"]),
        ("EnvironmentFiles", [("/etc/environment", False)]),
        ("PassEnvironment", ["PATH"]),
        ("UnsetEnvironment", ["TOKEN"]),
        ("SupplementaryGroups", ["wheel"]),
        ("TimeoutStartUSec", 999),
        ("TimeoutStopUSec", 999),
        ("RuntimeMaxUSec", 999),
        ("WatchdogUSec", 999),
        ("TimeoutStartFailureMode", "terminate"),
        ("TimeoutStopFailureMode", "terminate"),
        ("FinalKillSignal", 15),
        ("KillSignal", 9),
        ("SetLoginEnvironment", True),
        ("RootDirectory", "/"),
        ("RootImage", "/image.raw"),
        ("ExecStartEx", []),
        ("ExecStopEx", [(EXECUTABLE, [EXECUTABLE], False)]),
    ],
)
def test_service_properties_must_match_the_fixed_generated_profile(
    property_name, value
):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == SERVICE_INTERFACE:
                props[property_name] = Variant(props[property_name].signature, value)
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        assert any(
            call.member == "GetAll" and call.body == [SERVICE_INTERFACE]
            for call in bus.calls
        )

    asyncio.run(run())


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {**_service_settings(), "Extra": 1},
        _service_settings(TimeoutStartUSec=True),
        _service_settings(TimeoutStartUSec=0),
        _service_settings(TimeoutStartUSec=30_000_001),
        _service_settings(TimeoutStartUSec=float("inf")),
        _service_settings(TimeoutStopUSec=-1),
        _service_settings(TimeoutStopUSec=0),
        _service_settings(TimeoutStopUSec=10_000_001),
        _service_settings(TimeoutStopUSec=float("inf")),
        _service_settings(RuntimeMaxUSec=2**64),
        _service_settings(WatchdogUSec=1.5),
        _service_settings(SetLoginEnvironment=1),
        _service_settings(SetLoginEnvironment=True),
    ],
)
def test_invalid_service_policy_is_rejected_by_constructor_before_bus_io(settings):
    bus = FakeBus(UnitKey.AUDITD)
    with pytest.raises(UnitOperationFailed):
        _inspector(bus, expected_service_settings=settings)
    assert bus.calls == []


@pytest.mark.parametrize(
    "property_name,signature,value",
    [
        ("TimeoutStartFailureMode", "i", 1),
        ("TimeoutStopFailureMode", "i", 1),
        ("FinalKillSignal", "s", "9"),
        ("KillSignal", "s", "15"),
    ],
)
def test_service_kill_policy_requires_exact_dbus_signature(
    property_name, signature, value
):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == SERVICE_INTERFACE:
                props[property_name] = Variant(signature, value)
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())


@pytest.mark.parametrize(
    "property_name,value",
    [
        ("TimeoutStartFailureMode", 1),
        ("TimeoutStopFailureMode", 1),
        ("FinalKillSignal", True),
        ("KillSignal", "15"),
    ],
)
def test_service_kill_policy_rejects_wrong_value_type(property_name, value):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == SERVICE_INTERFACE:
                props[property_name] = Variant(
                    props[property_name].signature, value
                )
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())


@pytest.mark.parametrize(
    "property_name",
    [
        "TimeoutStartFailureMode", "TimeoutStopFailureMode",
        "FinalKillSignal", "KillSignal",
    ],
)
def test_service_kill_policy_missing_property_fails_closed(property_name):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == SERVICE_INTERFACE:
                props.pop(property_name)
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())


def test_service_policy_is_a_required_constructor_argument():
    bus = FakeBus(UnitKey.AUDITD)
    with pytest.raises(TypeError):
        BootstrapLoadedUnitInspector(
            bus=bus,
            message_factory=Message,
            message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
            timeout_seconds=0.25,
        )
    assert bus.calls == []


@pytest.mark.parametrize(
    "bad_exec",
    [
        [],
        [(EXECUTABLE, [EXECUTABLE], False), (EXECUTABLE, [EXECUTABLE], False)],
        [("/usr/bin/env", ["env", EXECUTABLE], False)],
        [(EXECUTABLE, [EXECUTABLE], True)],
        [(EXECUTABLE, [EXECUTABLE, "x" * 4096], False)],
        [(EXECUTABLE, [EXECUTABLE, "\x00bad"], False)],
    ],
)
def test_execstart_must_be_one_bounded_valid_runtime_command(bad_exec):
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == SERVICE_INTERFACE:
                props["ExecStartEx"] = Variant(props["ExecStartEx"].signature, bad_exec)
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        assert any(
            call.member == "GetAll" and call.body == [SERVICE_INTERFACE]
            for call in bus.calls
        )

    asyncio.run(run())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda snapshot, _interface, props: (
            {**props, "Names": Variant("as", ["alias.service"])}
            if snapshot == 3
            else props
        ),
        lambda snapshot, interface, props: (
            {**props, "ExecStartEx": Variant("a(sasasttttuii)", [])}
            if snapshot == 4 and interface == SERVICE_INTERFACE
            else props
        ),
    ],
)
def test_second_snapshot_changes_fail_even_when_both_objects_reply(mutation):
    async def run():
        bus = FakeBus(UnitKey.AUDITD, mutate=mutation)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())


@pytest.mark.parametrize(
    ("member", "reply"),
    [
        (
            "GetNameOwner",
            _reply("o", "/not/an/owner", sender="org.freedesktop.DBus"),
        ),
        ("GetUnit", _reply("s", "/wrong/path", sender=OWNER)),
        ("GetAll", _reply("a{sv}", {}, sender=OWNER)),
    ],
)
def test_wrong_dbus_signature_or_object_path_fails_closed(member, reply):
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        original = bus.call

        async def call(message):
            if message.member == member:
                bus.calls.append(message)
                return reply
            return await original(message)

        bus.call = call
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        assert any(call.member == member for call in bus.calls)
        if member == "GetNameOwner":
            assert not any(call.member == "GetAll" for call in bus.calls)

    asyncio.run(run())


def test_invalid_variants_and_missing_properties_fail_closed():
    async def run():
        def mutate(_snapshot, interface, props):
            if interface == UNIT_INTERFACE:
                props.pop("FragmentPath")
            else:
                props["User"] = "azaudit"  # Missing the D-Bus variant.
            return props

        bus = FakeBus(UnitKey.AUDITD, mutate=mutate)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        assert any(
            call.member == "GetAll" and call.body == [UNIT_INTERFACE]
            for call in bus.calls
        )

    asyncio.run(run())


def test_owner_change_between_pinned_observations_fails_closed():
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        original = bus.call
        owner_calls = 0

        async def call(message):
            nonlocal owner_calls
            if message.member == "GetNameOwner":
                owner_calls += 1
                bus.calls.append(message)
                return _reply(
                    "s",
                    OWNER if owner_calls == 1 else ":1.99",
                    sender="org.freedesktop.DBus",
                )
            return await original(message)

        bus.call = call
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())


def test_owner_path_recheck_must_match_the_initial_pin():
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        original = bus.call
        get_unit_calls = 0

        async def call(message):
            nonlocal get_unit_calls
            if message.member == "GetUnit":
                get_unit_calls += 1
                bus.calls.append(message)
                return _reply(
                    "o",
                    bus.path if get_unit_calls == 1 else _object_path("alias.service"),
                    sender=OWNER,
                )
            return await original(message)

        bus.call = call
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())


@pytest.mark.parametrize(
    ("member", "sender"),
    [
        ("GetNameOwner", ":1.99"),
        ("GetNameOwner", None),
        ("GetUnit", ":1.99"),
        ("GetUnit", None),
        ("GetAll", ":1.99"),
        ("GetAll", None),
    ],
)
def test_reply_sender_must_match_the_pinned_unique_owner(member, sender):
    async def run():
        bus = FakeBus(UnitKey.AUDITD)
        original = bus.call

        async def call(message):
            if message.member == member:
                bus.calls.append(message)
                if member == "GetNameOwner":
                    return _reply("s", OWNER, sender=sender)
                if member == "GetUnit":
                    return _reply("o", bus.path, sender=sender)
                return _reply(
                    "a{sv}", _unit_properties(bus.unit_name, bus.path), sender=sender
                )
            return await original(message)

        bus.call = call
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )
        assert any(call.member == member for call in bus.calls)
        if member == "GetNameOwner":
            assert not any(call.member in {"GetUnit", "GetAll"} for call in bus.calls)
        elif member == "GetUnit":
            assert not any(call.member == "GetAll" for call in bus.calls)

    asyncio.run(run())


def test_expired_call_is_bounded_and_translated_to_refusal():
    async def run():
        class NeverReply(FakeBus):
            async def call(self, message):
                self.calls.append(message)
                await asyncio.Event().wait()

        bus = NeverReply(UnitKey.AUDITD)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus, timeout_seconds=0.001).inspect(
                UnitKey.AUDITD, expected_dependencies=_dependencies()
            )

    asyncio.run(run())
