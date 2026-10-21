"""The Deception Lite namespace unit, option (a) (#196, docs/deception-redirect-prerequisites.md §5, §10).

Option (a) splits D1 into three one-shot steps: a namespace unit
(`CAP_SYS_ADMIN` and `CAP_NET_ADMIN`) creates `/run/netns/azazel-decoy`, the
veth pair and the inside of the namespace, the helper (`CAP_NET_ADMIN`)
configures the host side (bridge and rules), and the decoy joins the
namespace with no capability (§13). These tests pin:

* the namespace unit's profile, exactly: the one unit without the shared
  mount-namespace settings (n3, VM-checked), and that no other unit may hold
  `CAP_SYS_ADMIN`, run as root, declare `/run/netns` writable, or override or
  drop any shared setting;
* the dependency chain (helper -> namespace unit, decoy -> helper) and the
  tier rule that closes review n1: the three units are governed, scoped and
  marked **together or not at all**, so a dependency skipped for a missing
  grant marker can never count as success for a granted dependent;
* that the unit is still never granted. Its body is tested in
  `test_decoy_network_body.py`.

No test runs `ip` or `unshare`, creates a namespace or opens a socket. None
of this is VM or hardware evidence; the VM check of n2 and n3 (a mechanism
check, not hardware evidence) is recorded in the design, §10.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from azazel_nexus.activation import (
    ACTIVATION_CONTROLLER_UNIT,
    CORE_UNITS,
    DECEPTION_EXPOSURE_UNITS,
    DECOY_NAMESPACE_UNIT,
    DECOY_NETWORK_HELPER_UNIT,
    DECOY_UNIT,
    ActivationController,
    ActivationLease,
    ActivationRefused,
    RecordingUnitController,
    UnitDefinition,
    UnitState,
    UnitTier,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.commissioning import CommissioningRecord
from azazel_nexus.generation import GenerationStore, tree_digest
from azazel_nexus_runtime import activation_markers
from azazel_nexus_runtime.hardening import (
    ALL_PROFILES,
    DECOY_NAMESPACE_PATH,
    DECOY_NAMESPACE_SANDBOX,
    DECOY_NAMESPACE_SHARED_OMISSIONS,
    DECOY_NAMESPACE_SHARED_OVERRIDES,
    PROFILES,
    SHARED_HARDENING,
    render_unit,
)

ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = ROOT / "packaging" / "systemd"
INSTALLER = (ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
PRESET = (ROOT / "packaging" / "azazel-nexus.preset").read_text(encoding="utf-8")
NSD = DECOY_NAMESPACE_UNIT
NOW = "2026-09-20T00:00:00Z"
ACTOR = "operator@console"


def _settings(name: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in (UNIT_DIR / name).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key, []).append(value)
    return found


def _profile(unit):
    return next(p for p in PROFILES if p.unit == unit)


# -- the unit -----------------------------------------------------------------

#: The mount-namespace settings of `SHARED_HARDENING` (n3): the namespace
#: unit carries none of them, and no other unit may drop any.
MOUNT_NAMESPACE_KEYS = ("ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
                        "ProtectKernelTunables", "ProtectKernelModules",
                        "ProtectControlGroups")

#: Unit settings that make systemd build a mount namespace (systemd.exec),
#: none of which the namespace unit may carry.
MOUNT_NAMESPACE_SETTINGS = MOUNT_NAMESPACE_KEYS + (
    "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "ExecPaths", "NoExecPaths",
    "TemporaryFileSystem", "BindPaths", "BindReadOnlyPaths", "ProtectProc", "ProcSubset",
    "ProtectKernelLogs", "ProtectHostname", "ProtectClock", "PrivateNetwork",
    "PrivateMounts", "PrivateUsers", "PrivateIPC", "MountAPIVFS", "RootDirectory",
    "RootImage", "RuntimeDirectory", "StateDirectory", "CacheDirectory", "LogsDirectory",
    "ConfigurationDirectory", "NetworkNamespacePath", "IPCNamespacePath", "MountImages",
    "ExtensionImages", "ExtensionDirectories", "DynamicUser", "LoadCredential",
    "SetCredential", "LoadCredentialEncrypted", "ImportCredential",
)


def test_the_namespace_unit_runs_once_as_root_with_exactly_its_two_capabilities():
    settings = _settings(NSD)
    assert NSD == "azazel-decoy-nsd.service"
    assert settings["Type"] == ["oneshot"]
    assert settings["RemainAfterExit"] == ["yes"]
    assert settings["User"] == ["root"]
    assert settings["ExecStart"] == ["/usr/libexec/azazel/az-decoy-nsd"]
    assert settings["ExecStop"] == ["/usr/libexec/azazel/az-decoy-nsd stop"]
    # CAP_NET_ADMIN as well: every act inside the namespace needs it (§13).
    assert settings["CapabilityBoundingSet"] == ["CAP_SYS_ADMIN CAP_NET_ADMIN"]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["NoNewPrivileges"] == ["yes"]
    # Route netlink only, the family `ip netns add` was VM-checked with.
    assert settings["RestrictAddressFamilies"] == ["AF_NETLINK"]
    assert settings["IPAddressDeny"] == ["any"]
    assert DECOY_NAMESPACE_PATH == "/run/netns/azazel-decoy"
    # Of every namespace type, only a network namespace, and the mount
    # namespace `ip -n` makes for itself (§13).
    assert settings["RestrictNamespaces"] == ["net mnt"]
    # setns allowed (ip returns to its own namespace after creating one;
    # without it, SIGSYS, VM-checked), and not in the deny list.
    assert settings["SystemCallFilter"] == [
        "@system-service mount umount2 unshare setns",
        "~@aio @chown @ipc @keyring @memlock @setuid @timer capset",
    ]
    assert "setns" not in settings["SystemCallFilter"][1]
    for key in ("RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute",
                "SystemCallArchitectures", "UMask"):
        assert settings[key] == [dict(SHARED_HARDENING)[key]], key
    assert settings["RestrictRealtime"] == ["yes"]


def test_the_namespace_unit_builds_no_mount_namespace():
    """n3, VM-checked: a mount made inside a mount namespace never reaches the host."""

    settings = _settings(NSD)
    for key in MOUNT_NAMESPACE_SETTINGS:
        assert key not in settings, key
    for key in ("IPAddressAllow", "SupplementaryGroups", "Environment", "EnvironmentFile",
                "ExecStartPre", "ExecStartPost", "ExecStopPost",
                "JoinsNamespaceOf", "DeviceAllow"):
        assert key not in settings, key


def test_the_namespace_unit_overrides_and_omits_exactly_what_is_declared():
    profile = _profile(NSD)
    assert profile.shared_overrides == DECOY_NAMESPACE_SHARED_OVERRIDES
    assert {key for key, _ in DECOY_NAMESPACE_SHARED_OVERRIDES} == {
        "RestrictNamespaces", "SystemCallFilter"}
    assert profile.shared_omissions == DECOY_NAMESPACE_SHARED_OMISSIONS
    assert DECOY_NAMESPACE_SHARED_OMISSIONS == MOUNT_NAMESPACE_KEYS
    assert set(DECOY_NAMESPACE_SHARED_OMISSIONS) <= {key for key, _ in SHARED_HARDENING}
    # Kept: everything else of the shared set.
    kept = [key for key, _ in SHARED_HARDENING if key not in MOUNT_NAMESPACE_KEYS]
    assert kept == ["NoNewPrivileges", "RestrictNamespaces", "RestrictSUIDSGID",
                    "LockPersonality", "MemoryDenyWriteExecute",
                    "SystemCallArchitectures", "SystemCallFilter",
                    "CapabilityBoundingSet", "AmbientCapabilities", "IPAddressDeny",
                    "UMask"]
    assert profile.extra == DECOY_NAMESPACE_SANDBOX
    assert [p.unit for p in ALL_PROFILES if p.shared_overrides] == [NSD]
    assert [p.unit for p in ALL_PROFILES if p.shared_omissions] == [NSD]
    # The deny list follows the allow list: a deny list first would make
    # the second line remove names from it instead.
    lines = [line for line in render_unit(profile).splitlines()
             if line.startswith("SystemCallFilter=")]
    assert lines[0].startswith("SystemCallFilter=@system-service")
    assert lines[1].startswith("SystemCallFilter=~")


def test_every_other_unit_carries_the_whole_mount_sandbox():
    for profile in ALL_PROFILES:
        if profile.unit == NSD:
            continue
        settings = _settings(profile.unit)
        for key in MOUNT_NAMESPACE_KEYS:
            assert settings.get(key) == [dict(SHARED_HARDENING)[key]], (profile.unit, key)


def test_cap_sys_admin_is_held_by_the_namespace_unit_alone():
    holders = [p.unit for p in ALL_PROFILES if "CAP_SYS_ADMIN" in p.capability_bounding_set]
    assert holders == [NSD]
    for path in UNIT_DIR.glob("*.service"):
        if path.name == NSD:
            continue
        for key in ("CapabilityBoundingSet", "AmbientCapabilities"):
            assert not any("CAP_SYS_ADMIN" in value
                           for value in _settings(path.name).get(key, [])), path.name


def test_no_unit_declares_run_netns_writable():
    writers = [p.unit for p in ALL_PROFILES
               if any(path.removeprefix("-").rstrip("/") == "/run/netns"
                      for path in p.read_write_paths + p.optional_read_write_paths)]
    assert writers == []


@pytest.mark.parametrize("unit", [
    "azazel-mio-entryd.service", DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT,
    ACTIVATION_CONTROLLER_UNIT,
])
def test_no_other_unit_can_take_cap_sys_admin(unit):
    profile = _profile(unit)
    with pytest.raises(ValueError, match="CAP_SYS_ADMIN"):
        replace(profile, capability_bounding_set=profile.capability_bounding_set
                + ("CAP_SYS_ADMIN",))


@pytest.mark.parametrize("unit", ["azazel-mio-entryd.service", DECOY_UNIT, NSD])
@pytest.mark.parametrize("path", ["/run/netns", "/run/netns/"])
def test_no_unit_can_declare_run_netns_writable(unit, path):
    with pytest.raises(ValueError, match="/run/netns|no writable path"):
        replace(_profile(unit), read_write_paths=_profile(unit).read_write_paths + (path,))


@pytest.mark.parametrize("unit", ["azazel-mio-entryd.service", DECOY_NETWORK_HELPER_UNIT,
                                  DECOY_UNIT, ACTIVATION_CONTROLLER_UNIT])
@pytest.mark.parametrize("change", [
    {"shared_overrides": (("RestrictNamespaces", "net"),)},
    {"shared_overrides": DECOY_NAMESPACE_SHARED_OVERRIDES},
    {"shared_overrides": (("SystemCallFilter", "@system-service @mount"),)},
    {"shared_omissions": DECOY_NAMESPACE_SHARED_OMISSIONS},
    {"shared_omissions": ("ProtectSystem",)},
    {"shared_omissions": ("PrivateTmp",)},
], ids=lambda change: f"{next(iter(change))}-{len(next(iter(change.values())))}")
def test_no_other_unit_may_loosen_the_shared_hardening(unit, change):
    with pytest.raises(ValueError, match="override the shared hardening"):
        replace(_profile(unit), **change)


@pytest.mark.parametrize("change", [
    {"capability_bounding_set": ("CAP_SYS_ADMIN",)},
    {"capability_bounding_set": ("CAP_NET_ADMIN", "CAP_SYS_ADMIN")},
    {"capability_bounding_set": ("CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE")},
    {"capability_bounding_set": ("CAP_SYS_ADMIN", "CAP_SYS_PTRACE")},
    {"capability_bounding_set": ("CAP_NET_ADMIN",)},
    {"capability_bounding_set": ()},
    {"account": "azdecoy"},
    {"supplementary_groups": ("azazel-operator",)},
    {"address_families": ("AF_UNIX",)},
    {"address_families": ("AF_UNIX", "AF_NETLINK")},
    {"address_families": ("AF_NETLINK", "AF_INET")},
    {"read_write_paths": ("/var/lib/azazel/decoy",)},
    {"optional_read_write_paths": ("/var/lib/azazel/decoy",)},
    {"runtime_directory": "azazel"},
    {"unit_type": "exec"},
    {"shared_overrides": ()},
    {"shared_overrides": (("RestrictNamespaces", "net"),)
     + DECOY_NAMESPACE_SHARED_OVERRIDES[1:]},
    {"shared_overrides": (("RestrictNamespaces", "net mnt user"),)
     + DECOY_NAMESPACE_SHARED_OVERRIDES[1:]},
    {"shared_overrides": DECOY_NAMESPACE_SHARED_OVERRIDES[:2]},
    {"shared_overrides": (DECOY_NAMESPACE_SHARED_OVERRIDES[0],
                          ("SystemCallFilter", "@system-service @mount unshare setns"),
                          DECOY_NAMESPACE_SHARED_OVERRIDES[2])},
    {"shared_omissions": ()},
    {"shared_omissions": DECOY_NAMESPACE_SHARED_OMISSIONS + ("NoNewPrivileges",)},
    {"shared_omissions": DECOY_NAMESPACE_SHARED_OMISSIONS + ("CapabilityBoundingSet",)},
    {"shared_omissions": DECOY_NAMESPACE_SHARED_OMISSIONS + ("IPAddressDeny",)},
    {"shared_omissions": DECOY_NAMESPACE_SHARED_OMISSIONS[1:]},
    {"extra": DECOY_NAMESPACE_SANDBOX[:-1]},
    {"extra": tuple(item for item in DECOY_NAMESPACE_SANDBOX if item[0] != "ExecStop")},
    {"extra": tuple(("ExecStop", "/usr/sbin/ip netns delete azazel-decoy")
                    if item[0] == "ExecStop" else item
                    for item in DECOY_NAMESPACE_SANDBOX)},
    {"extra": DECOY_NAMESPACE_SANDBOX + (("NetworkNamespacePath", DECOY_NAMESPACE_PATH),)},
    {"extra": DECOY_NAMESPACE_SANDBOX + (("Environment", "AZAZEL_NETNS=other"),)},
    {"extra": DECOY_NAMESPACE_SANDBOX + (("ProtectProc", "invisible"),)},
    {"is_decoy_listener": True},
], ids=lambda change: next(iter(change)))
def test_the_namespace_unit_cannot_be_declared_wider_or_different(change):
    with pytest.raises(ValueError):
        replace(_profile(NSD), **change)


@pytest.mark.parametrize("unit", ["azazel-mio-entryd.service", DECOY_UNIT,
                                  "azazel-edge-core.service"])
def test_only_the_controller_and_the_two_one_shot_decoy_units_may_run_as_root(unit):
    with pytest.raises(ValueError, match="would run as root"):
        replace(_profile(unit), account="root", is_decoy_listener=False,
                address_families=("AF_UNIX",))
    roots = [p.unit for p in ALL_PROFILES if p.account == "root"]
    assert roots == [ACTIVATION_CONTROLLER_UNIT, NSD, DECOY_NETWORK_HELPER_UNIT]


# -- the chain and the marker lines -------------------------------------------


def test_the_chain_is_namespace_then_helper_then_decoy():
    nsd, netd, decoyd = (_settings(u) for u in DECEPTION_EXPOSURE_UNITS)
    assert DECEPTION_EXPOSURE_UNITS == (NSD, DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT)
    assert nsd["After"] == [ACTIVATION_CONTROLLER_UNIT]
    assert nsd["Requires"] == [ACTIVATION_CONTROLLER_UNIT]
    assert netd["After"] == [ACTIVATION_CONTROLLER_UNIT, NSD]
    assert netd["Requires"] == [ACTIVATION_CONTROLLER_UNIT, NSD]
    assert decoyd["After"] == [ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT]
    assert decoyd["Requires"] == [ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT]
    # No other unit depends on the namespace unit, and none of the three
    # pulls another in by Wants= or binds to it.
    for profile in ALL_PROFILES:
        if profile.unit != DECOY_NETWORK_HELPER_UNIT:
            assert NSD not in profile.after + profile.requires + profile.binds_to
    for unit in DECEPTION_EXPOSURE_UNITS:
        for key in ("Wants", "BindsTo", "PartOf", "Requisite", "Upholds"):
            assert key not in _settings(unit), (unit, key)


def test_all_three_carry_the_marker_lines_and_pass_the_content_check():
    from azazel_nexus_runtime.activation_unit_files import (
        require_governed_unit_content,
        required_unit_lines,
    )

    for unit in DECEPTION_EXPOSURE_UNITS:
        text = (UNIT_DIR / unit).read_text(encoding="ascii")
        section = text.split("[Unit]", 1)[1].split("[Service]", 1)[0].splitlines()
        assert set(required_unit_lines(unit)) <= set(section)
        assert f"ConditionPathExists=/run/azazel-activation/granted/{unit}" in section
        assert f"Requires={ACTIVATION_CONTROLLER_UNIT}" in section
        assert f"After={ACTIVATION_CONTROLLER_UNIT}" in section
        require_governed_unit_content(unit, text.encode("ascii"))


def test_the_installer_masks_and_never_enables_the_namespace_unit():
    assert f'install -m 0644 "$HERE"/systemd/{NSD} "$UNIT_DIR"' in INSTALLER
    assert f"systemctl mask {NSD}" in INSTALLER
    assert f"systemctl enable {NSD}" not in INSTALLER
    assert f"systemctl start {NSD}" not in INSTALLER
    assert f"disable {NSD}" in PRESET.splitlines()
    assert f"enable {NSD}" not in PRESET.splitlines()
    assert " az-decoy-nsd " in INSTALLER
    # Nothing the installer does creates a namespace or touches /run/netns.
    assert "/run/netns" not in INSTALLER
    assert "ip netns" not in INSTALLER and "unshare" not in INSTALLER


# -- the tier: together or not at all (review n1) -----------------------------


def test_the_three_are_grantable_for_the_253_checks_and_nameable_by_nothing():
    from azazel_nexus.activation_approval_v2 import _V2_UNITS
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    from azazel_nexus_runtime.activation_pass import POLICY_UNIT_SCOPE

    exposure = set(DECEPTION_EXPOSURE_UNITS)
    assert activation_markers.EXPOSURE_UNITS == exposure
    assert exposure <= activation_markers.GRANTABLE_UNITS
    assert not exposure & set(ACTIVATION_UNIT_ALLOWLIST)
    assert not exposure & set(_V2_UNITS)
    assert not exposure & POLICY_UNIT_SCOPE
    tiers = {d.name: d.tier for d in CORE_UNITS if d.name in exposure}
    assert tiers == {unit: UnitTier.DECEPTION_EXPOSURE for unit in exposure}


def _store(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    record = CommissioningRecord(roles=(), profiles_present=("hardware", "resource", "topology"),
                                 created_at=NOW)
    store.create({"suricata.yaml": b"role: observation\n"}, created_at=NOW,
                 commissioning_digest=record.digest())
    return store


def _controller(tmp_path, definitions=CORE_UNITS):
    units = RecordingUnitController(d.name for d in definitions)
    controller = ActivationController(
        units=units, generations=_store(tmp_path),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"), definitions=definitions)
    return controller, units


def _lease(units=None):
    return ActivationLease(
        granted_by=ACTOR, granted_at="2026-09-19T00:00:00Z",
        expires_at="2026-09-21T00:00:00Z",
        generation_digest=tree_digest({"suricata.yaml": b"role: observation\n"}),
        units=units)


@pytest.mark.parametrize("kept", [
    (NSD,), (DECOY_NETWORK_HELPER_UNIT,), (DECOY_UNIT,),
    (NSD, DECOY_NETWORK_HELPER_UNIT), (DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT),
    (NSD, DECOY_UNIT),
])
def test_a_governed_set_with_part_of_the_tier_is_refused(tmp_path, kept):
    definitions = [d for d in CORE_UNITS
                   if d.tier is not UnitTier.DECEPTION_EXPOSURE or d.name in kept]
    with pytest.raises(ActivationRefused, match="together or not at all"):
        _controller(tmp_path, definitions)


def test_an_exposure_unit_moved_to_another_tier_is_refused(tmp_path):
    definitions = [
        UnitDefinition(d.name, UnitTier.SUPPORTING, d.account, d.purpose)
        if d.name == NSD else d
        for d in CORE_UNITS
    ]
    with pytest.raises(ActivationRefused, match="together or not at all"):
        _controller(tmp_path, definitions)


def test_an_exposure_unit_with_a_wiring_of_its_own_is_refused(tmp_path):
    """A wiring held by one of the three would let their verdicts differ."""
    definitions = [
        UnitDefinition(d.name, d.tier, d.account, d.purpose, wiring="decoy_namespace")
        if d.name == NSD else d
        for d in CORE_UNITS
    ]
    with pytest.raises(ActivationRefused, match="together or not at all"):
        _controller(tmp_path, definitions)


def test_a_governed_set_without_the_tier_is_accepted(tmp_path):
    definitions = [d for d in CORE_UNITS if d.tier is not UnitTier.DECEPTION_EXPOSURE]
    _controller(tmp_path, definitions)


@pytest.mark.parametrize("named", [
    (NSD,), (DECOY_NETWORK_HELPER_UNIT,), (DECOY_UNIT,),
    (DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT), (NSD, DECOY_NETWORK_HELPER_UNIT),
])
def test_a_lease_naming_part_of_the_tier_withholds_all_three(tmp_path, named):
    controller, units = _controller(tmp_path)
    lease = _lease(frozenset(d.name for d in CORE_UNITS
                             if d.tier is not UnitTier.DECEPTION_EXPOSURE) | set(named))
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=lease)
    verdicts = {v.unit: v for v in outcome.verdicts if v.unit in DECEPTION_EXPOSURE_UNITS}
    assert set(verdicts) == set(DECEPTION_EXPOSURE_UNITS)
    for unit, verdict in verdicts.items():
        assert not verdict.granted
        expected = ("exposure_tier_partial" if unit in named
                    else "outside_lease_scope")
        assert verdict.reason.startswith(expected), (unit, verdict.reason)
        assert units.state(unit) is UnitState.MASKED
        assert ("unmask_and_enable", unit) not in units.calls


@pytest.mark.parametrize("scoped", [False, True])
def test_the_three_always_get_the_same_verdict_and_it_is_withheld(tmp_path, scoped):
    controller, units = _controller(tmp_path)
    lease = _lease(frozenset(d.name for d in CORE_UNITS) if scoped else None)
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=lease)
    verdicts = [v for v in outcome.verdicts if v.unit in DECEPTION_EXPOSURE_UNITS]
    assert len(verdicts) == 3
    assert {(v.granted, v.reason) for v in verdicts} == {
        (False, verdicts[0].reason)}
    assert verdicts[0].reason.startswith("isolation_evidence_absent")
    assert not set(outcome.granted) & set(DECEPTION_EXPOSURE_UNITS)


@pytest.fixture
def marker_root(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    parent = tmp_path / "run" / "azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    return tmp_path


@pytest.mark.parametrize("partial", [
    (NSD,), (DECOY_NETWORK_HELPER_UNIT,), (DECOY_UNIT,),
    (NSD, DECOY_NETWORK_HELPER_UNIT), (DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT),
    (NSD, DECOY_UNIT),
])
def test_the_marker_writer_refuses_part_of_the_tier(marker_root, partial):
    with pytest.raises(activation_markers.GrantMarkerRefused, match="part of"):
        activation_markers.write_grant_markers(
            ("azazel-mio-entryd.service",) + partial, root=marker_root)
    assert not (marker_root / "run" / "azazel-activation" / "granted").exists()


def test_the_marker_writer_is_unchanged_for_the_rest(marker_root):
    written = activation_markers.write_grant_markers(
        ("azazel-mio-entryd.service",), root=marker_root)
    assert written == ("azazel-mio-entryd.service",)


# -- the executable: its body is tested in test_decoy_network_body.py ------


def test_the_unit_table_addresses_the_namespace_unit_by_fixed_key_only():
    from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed, resolve

    assert resolve("decoy-namespace") == NSD
    assert UNIT_NAMES[UnitKey.DECOY_NAMESPACE] == NSD
    with pytest.raises(UnitOperationFailed):
        resolve(NSD)


# -- review of #271: extra cannot restate a reserved key; nsd's wiring is pinned


RESERVED = sorted({key for key, _ in SHARED_HARDENING} | {
    "ReadWritePaths", "BindPaths", "InaccessiblePaths", "SystemCallFilter", "User",
    "CapabilityBoundingSet", "AmbientCapabilities",
    "ExecStop", "ExecStopPost", "ExecStartPost", "ExecReload"})


@pytest.mark.parametrize("unit", ["azazel-mio-entryd.service", DECOY_NETWORK_HELPER_UNIT,
                                  DECOY_UNIT, ACTIVATION_CONTROLLER_UNIT])
@pytest.mark.parametrize("key", RESERVED)
def test_no_other_unit_can_restate_a_reserved_key_in_extra(unit, key):
    profile = _profile(unit)
    with pytest.raises(ValueError, match="in extra"):
        replace(profile, extra=profile.extra + ((key, "anything"),))


def test_no_packaged_unit_states_a_reserved_key_in_extra():
    """Except the two one-shot decoy units, whose extra is pinned whole."""

    for profile in ALL_PROFILES:
        if profile.unit in (NSD, DECOY_NETWORK_HELPER_UNIT):
            continue
        assert not {key for key, _ in profile.extra} & set(RESERVED), profile.unit


@pytest.mark.parametrize("change", [
    {"executable": "/usr/sbin/ip"},
    {"executable": "/usr/libexec/azazel/az-decoy-netd"},
    {"after": ()},
    {"after": (ACTIVATION_CONTROLLER_UNIT, DECOY_UNIT)},
    {"requires": ()},
    {"requires": (ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT)},
    {"binds_to": (ACTIVATION_CONTROLLER_UNIT,)},
    {"before": (DECOY_NETWORK_HELPER_UNIT,)},
    {"conflicts": ("shutdown.target",)},
    {"default_dependencies": False},
    {"conditions": ()},
    {"conditions": (("ConditionPathExists",
                     "/run/azazel-activation/granted/azazel-decoyd.service"),)},
    {"conditions": (("ConditionPathExists",
                     "/run/azazel-activation/granted/azazel-decoy-nsd.service"),
                    ("ConditionPathExists", "/"))},
], ids=lambda change: next(iter(change)))
def test_the_namespace_unit_wiring_is_pinned(change):
    with pytest.raises(ValueError, match="az-decoy-nsd|grant marker"):
        replace(_profile(NSD), **change)
