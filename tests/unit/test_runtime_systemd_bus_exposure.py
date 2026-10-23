"""The exposure tier's bus reads (#196 G6, `docs/deception-exposure-wiring.md` §4.5).

Read-only, through the controller's session: `GetUnitFileState` and, after
`GetUnit`, the Unit interface's `LoadState`/`ActiveState` and the Service
interface's `AppArmorProfile`, of fixed units only. Exactly two errors map
to None -- `org.freedesktop.DBus.Error.FileNotFound` from `GetUnitFileState`
and `org.freedesktop.systemd1.NoSuchUnit` from `GetUnit` -- and every other
error, reply or value refuses (`UnitOperationFailed`). `LoadUnit` is never
called and no write verb accepts the host firewall loaders. A fake exchange
or bus stands in for systemd; nothing here is VM evidence (§8 step 7).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import exposure_withholding, systemd_bus
from azazel_nexus_runtime.decoy_apparmor import (
    DECOY_APPARMOR_PROFILES,
    loaded_unit_profile_refusal,
)
from azazel_nexus_runtime.decoy_residue import exposure_residue_departures
from azazel_nexus_runtime.exposure_withholding import host_firewall_refusal
from azazel_nexus_runtime.systemd_bus import (
    HOST_FIREWALL_UNITS,
    MANAGER_INTERFACE,
    PROPERTIES_INTERFACE,
    SERVICE_INTERFACE,
    UNIT_INTERFACE,
    SystemdBusSession,
    SystemdUnitCalls,
    _Reply as Reply,
    _unit_object_path,
)
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_systemd_bus import _BusStub, _LoopStub, _MessageStub

FILE_NOT_FOUND = "org.freedesktop.DBus.Error.FileNotFound"
NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
EXPOSURE = ("azazel-decoy-nsd.service", "azazel-decoy-netd.service", "azazel-decoyd.service")
VERIFY = "azazel-decoy-verify.service"


def _variant(value, signature="s"):
    return SimpleNamespace(signature=signature, value=value)


class FakeManager:
    """`exchange` as systemd answers: per unit, a file state and an object."""

    def __init__(self, files=None, objects=None):
        #: unit -> file state, or FILE_NOT_FOUND.
        self.files = files or {}
        #: unit -> {property: value}, absent: no unit object.
        self.objects = objects or {}
        self.calls: list[tuple] = []

    def __call__(self, interface, member, signature, body, *, path=systemd_bus.MANAGER_PATH,
                 allow_no_such_unit=False, allow_file_not_found=False):
        self.calls.append((interface, member, tuple(body), path))
        assert member != "LoadUnit"
        if member == "GetUnitFileState":
            state = self.files.get(body[0], FILE_NOT_FOUND)
            if state == FILE_NOT_FOUND:
                assert allow_file_not_found
                return Reply("", [], file_not_found=True)
            return Reply("s", [state])
        if member == "GetUnit":
            if body[0] not in self.objects:
                assert allow_no_such_unit
                return Reply("", [], no_such_unit=True)
            return Reply("o", [_unit_object_path(body[0])])
        assert member == "Get" and interface == PROPERTIES_INTERFACE
        unit = next(u for u in self.objects if _unit_object_path(u) == path)
        name = body[1]
        value = self.objects[unit][name]
        return Reply("v", [_variant(value, "(bs)" if name == "AppArmorProfile" else "s")])


def test_a_loader_with_no_file_and_no_object_is_none_as_a_whole():
    manager = FakeManager()
    states = SystemdUnitCalls(manager).host_firewall_states()
    assert states == {unit: None for unit in HOST_FIREWALL_UNITS}
    assert host_firewall_refusal(states) is None


def test_a_disabled_loader_without_an_object_reads_active_state_none_and_passes():
    """As observed on the VM (§2): `nftables.service` answered `disabled`."""
    manager = FakeManager(files={"nftables.service": "disabled"})
    states = SystemdUnitCalls(manager).host_firewall_states()
    assert states["nftables.service"] == {"UnitFileState": "disabled", "ActiveState": None}
    assert host_firewall_refusal(states) is None


def test_an_enabled_or_active_loader_is_read_as_it_is():
    manager = FakeManager(files={"nftables.service": "enabled",
                                 "firewalld.service": "disabled"},
                          objects={"nftables.service": {"ActiveState": "active"},
                                   "firewalld.service": {"ActiveState": "active"}})
    states = SystemdUnitCalls(manager).host_firewall_states()
    assert states["nftables.service"] == {"UnitFileState": "enabled", "ActiveState": "active"}
    assert host_firewall_refusal(states).startswith("host_firewall_enabled:")
    del manager.files["nftables.service"]
    del manager.objects["nftables.service"]
    assert host_firewall_refusal(SystemdUnitCalls(manager).host_firewall_states()
                                 ).startswith("host_firewall_active:")


def test_the_firewall_units_are_the_parts():
    assert HOST_FIREWALL_UNITS == exposure_withholding.HOST_FIREWALL_UNITS


def test_the_exposure_units_states_feed_the_residue_judgement():
    manager = FakeManager(
        files={unit: "masked" for unit in EXPOSURE},
        objects={EXPOSURE[2]: {"LoadState": "masked", "ActiveState": "inactive"}})
    states = SystemdUnitCalls(manager).exposure_unit_states()
    assert states[EXPOSURE[0]] == {"LoadState": None, "UnitFileState": "masked",
                                   "ActiveState": None}
    assert states[EXPOSURE[2]] == {"LoadState": "masked", "UnitFileState": "masked",
                                   "ActiveState": "inactive"}
    assert exposure_residue_departures(states, (0, None), ("lo", "lan0")) == ()
    manager.objects[EXPOSURE[2]]["ActiveState"] = "active"
    assert exposure_residue_departures(
        SystemdUnitCalls(manager).exposure_unit_states(), (0, None), ("lo",)) == (
        "exposure_unit_masked_running",)


def test_the_profiles_are_read_as_bs_pairs_and_a_masked_unit_passes():
    objects = {unit: {"LoadState": "masked", "AppArmorProfile": [False, ""]}
               for unit in EXPOSURE}
    objects[VERIFY] = {"LoadState": "loaded", "AppArmorProfile": [False, "azazel-decoy-verify"]}
    states = SystemdUnitCalls(FakeManager(objects=objects)).decoy_profile_states()
    assert states[VERIFY] == {"LoadState": "loaded",
                              "AppArmorProfile": (False, "azazel-decoy-verify")}
    assert states[EXPOSURE[0]] == {"LoadState": "masked", "AppArmorProfile": (False, "")}
    assert set(states) == {unit for unit, _ in DECOY_APPARMOR_PROFILES}
    assert loaded_unit_profile_refusal(states) is None
    del objects[VERIFY]
    assert SystemdUnitCalls(FakeManager(objects=objects)).decoy_profile_states()[VERIFY] is None


@pytest.mark.parametrize("value", [(True, "azazel-decoy-verify"), [False], "azazel",
                                   [0, "x"], [False, 7], None])
def test_a_profile_of_another_shape_refuses(value):
    objects = {VERIFY: {"LoadState": "loaded", "AppArmorProfile": value}}
    calls = SystemdUnitCalls(FakeManager(objects=objects))
    if type(value) in (list, tuple) and len(value) == 2 and type(value[0]) is bool \
            and type(value[1]) is str:
        assert loaded_unit_profile_refusal(calls.decoy_profile_states()) is not None
    else:
        with pytest.raises(UnitOperationFailed):
            calls.decoy_profile_states()


@pytest.mark.parametrize("name,value", [("LoadState", "Loaded"), ("ActiveState", "running"),
                                        ("ActiveState", 1)])
def test_a_state_outside_its_closed_set_refuses(name, value):
    manager = FakeManager(files={unit: "masked" for unit in EXPOSURE},
                          objects={EXPOSURE[0]: {"LoadState": "masked",
                                                 "ActiveState": "inactive", name: value}})
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(manager).exposure_unit_states()


def test_an_unknown_file_state_refuses():
    manager = FakeManager(files={"nftables.service": "weird"})
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(manager).host_firewall_states()


def test_the_reads_name_only_their_fixed_units():
    calls = SystemdUnitCalls(FakeManager())
    for unit in ("azazel-auditd.service", "ssh.service", "azazel-edge-core.service"):
        with pytest.raises(UnitOperationFailed, match="outside the exposure reads"):
            calls._unit_file_state_or_none(unit)
        with pytest.raises(UnitOperationFailed, match="outside the exposure reads"):
            calls._object_or_none(unit)
    # No write verb accepts a host firewall loader.
    for method in ("MaskUnitFiles", "UnmaskUnitFiles", "EnableUnitFiles", "GetUnitFileState"):
        with pytest.raises(UnitOperationFailed, match="outside the fixed allowlist"):
            calls(method, "nftables.service")


# -- the session: the two error names and nothing else ---------------------------


def _session(reply):
    return SystemdBusSession(
        bus=_BusStub(reply), loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )


def _error(name):
    return SimpleNamespace(message_type=3, signature="", body=[], error_name=name)


def test_file_not_found_from_get_unit_file_state_is_none_only_when_opted_in():
    session = _session(_error(FILE_NOT_FOUND))
    outcome = session._exchange(MANAGER_INTERFACE, "GetUnitFileState", "s",
                                ["nftables.service"], allow_file_not_found=True)
    assert outcome.file_not_found is True
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "GetUnitFileState", "s", ["nftables.service"])
    # FileNotFound from GetUnit is not "no unit object".
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "GetUnit", "s", ["nftables.service"],
                          allow_no_such_unit=True, allow_file_not_found=True)


def test_no_such_unit_from_get_unit_file_state_is_unreadable():
    """Review of #301, finding 7: NoSuchUnit means None only from GetUnit."""
    session = _session(_error(NO_SUCH_UNIT))
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "GetUnitFileState", "s", ["nftables.service"],
                          allow_no_such_unit=True, allow_file_not_found=True)
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(session._exchange).host_firewall_states()


@pytest.mark.parametrize("name", [
    "org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.FileNotFound.X",
    "org.freedesktop.dbus.error.filenotfound", "", None, 7,
])
def test_any_other_error_from_get_unit_file_state_refuses(name):
    session = _session(_error(name))
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "GetUnitFileState", "s", ["nftables.service"],
                          allow_file_not_found=True)


def test_file_not_found_from_another_owner_refuses():
    reply = SimpleNamespace(**vars(_error(FILE_NOT_FOUND)), sender=":1.99")
    session = _session(reply)
    session._admitted_owner = ":1.1"
    with pytest.raises(UnitOperationFailed, match="owner"):
        session._exchange(MANAGER_INTERFACE, "GetUnitFileState", "s", ["nftables.service"],
                          allow_file_not_found=True)


@pytest.mark.parametrize("unit,body,allowed", [
    ("nftables.service", [UNIT_INTERFACE, "ActiveState"], True),
    ("nftables.service", [UNIT_INTERFACE, "LoadState"], True),
    (VERIFY, [UNIT_INTERFACE, "LoadState"], True),
    (VERIFY, [SERVICE_INTERFACE, "AppArmorProfile"], True),
    ("azazel-decoyd.service", [SERVICE_INTERFACE, "AppArmorProfile"], True),
    ("nftables.service", [SERVICE_INTERFACE, "AppArmorProfile"], False),
    ("nftables.service", [UNIT_INTERFACE, "SubState"], False),
    ("azazel-auditd.service", [SERVICE_INTERFACE, "AppArmorProfile"], False),
    ("azazel-decoyd.service", [SERVICE_INTERFACE, "ExecStart"], False),
    ("ssh.service", [UNIT_INTERFACE, "ActiveState"], False),
])
def test_the_property_reads_are_fixed(unit, body, allowed):
    reply = SimpleNamespace(message_type=1, signature="v", body=[_variant("x")])
    session = _session(reply)
    path = _unit_object_path(unit)
    if allowed:
        session._exchange(PROPERTIES_INTERFACE, "Get", "ss", body, path=path)
    else:
        with pytest.raises(UnitOperationFailed):
            session._exchange(PROPERTIES_INTERFACE, "Get", "ss", body, path=path)


def test_the_session_offers_the_three_reads_and_no_new_verb():
    for name in ("host_firewall_states", "exposure_unit_states", "decoy_profile_states"):
        assert callable(getattr(SystemdBusSession, name))
    source = systemd_bus.__file__
    text = open(source, encoding="utf-8").read()
    for verb in ("StartUnit", "StopUnit", "LoadUnit", "RestartUnit", "KillUnit"):
        assert f'"{verb}"' not in text, verb


# -- the None cases at the parts (review of #317) ---------------------------------


@pytest.mark.parametrize("load,active", [(None, "inactive"), ("masked", None)])
def test_the_residue_judgement_refuses_one_of_load_and_active_none_alone(load, active):
    units = {unit: {"LoadState": "masked", "UnitFileState": "masked", "ActiveState": "inactive"}
             for unit in EXPOSURE}
    units[EXPOSURE[1]] = {"LoadState": load, "UnitFileState": "masked", "ActiveState": active}
    assert exposure_residue_departures(units, (0, None), ("lo",)) == (
        "exposure_state_unreadable",)


def test_the_residue_judgement_reads_both_none_as_no_unit_object():
    units = {unit: {"LoadState": None, "UnitFileState": "masked", "ActiveState": None}
             for unit in EXPOSURE}
    assert exposure_residue_departures(units, (0, None), ("lo",)) == ()
    # With no object at all, a present namespace is a leftover of a stopped unit.
    assert exposure_residue_departures(units, (0, 0o100444), ("lo",)) == (
        "exposure_leftovers_present",)


def test_a_firewall_entry_with_both_values_none_is_unreadable():
    """The bus maps that case to None as a whole; a dict of two Nones is
    not a reading."""
    states = {unit: None for unit in HOST_FIREWALL_UNITS}
    states["nftables.service"] = {"UnitFileState": None, "ActiveState": None}
    assert host_firewall_refusal(states).startswith("host_firewall_unreadable:")
