"""The controller is ordered after /data and time-sync.target, never bound to them (#251).

docs/activation-observe-baseline.md §10. M-7: the pass's node-health
`resources` floor measures `mission_available_mib` on `/data`
(`resource_assessment._mission_space`), so the controller gains `After=` on
`data.mount`. M-1: it gains `After=time-sync.target`, a passive target that
orders nothing unless a wait-sync service pulls it in. L-9: the watchdog, a
`Requires=` dependent of the controller, is now also ordered after it.

Only `After=`, as for the commissioning storage (#242,
test_commissioning_storage_ordering.py): a `Requires=`, `Wants=`, `BindsTo=`
or `RequiresMountsFor=` (or a path setting below /data, which makes systemd
add an implicit `RequiresMountsFor=`) would let a missing, locked or failed
/data stop the controller, whose preflight remask is what narrows.

These are declaration checks on the packaged unit files. They do not show
that systemd orders the boot this way; that needs the VM.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT
from azazel_nexus_runtime import resource_assessment
from azazel_nexus_runtime.hardening import (
    ALL_PROFILES,
    MISSION_STORAGE_MOUNTS,
    PROFILES,
    TIME_SYNC_TARGET,
    render_unit,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO_ROOT / "packaging" / "systemd"
WATCHDOG = "azazel-watchdog.service"
STRONG = ("Requires", "Wants", "BindsTo", "Requisite", "Upholds",
          "RequiresMountsFor", "PartOf")
#: Settings whose paths make systemd add an implicit `RequiresMountsFor=`, or
#: that would otherwise tie the controller to a path below /data.
PATH_SETTINGS = (
    "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "ExecPaths",
    "NoExecPaths", "BindPaths", "BindReadOnlyPaths", "WorkingDirectory",
    "RootDirectory", "RootImage", "TemporaryFileSystem", "StateDirectory",
    "ConfigurationDirectory", "LoadCredential", "LoadCredentialEncrypted",
    "EnvironmentFile", "CacheDirectory", "LogsDirectory",
)


def _settings(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, separator, value = line.partition("=")
        if separator:
            found.setdefault(key, []).append(value)
    return found


def _unit(name: str) -> str:
    return (UNIT_DIR / name).read_text(encoding="utf-8")


def test_the_mount_is_the_path_the_resources_floor_measures():
    """`mission_available_mib` is measured on /data, and /data is data.mount."""
    assert MISSION_STORAGE_MOUNTS == ("data.mount",)
    source = inspect.getsource(resource_assessment._mission_space)
    assert 'os.open("/data"' in source
    assert "mission_available_mib" in inspect.getsource(resource_assessment.assess_resources)


def test_controller_is_ordered_after_data_and_time_sync_once():
    after = _settings(_unit(ACTIVATION_CONTROLLER_UNIT))["After"]
    assert after.count("data.mount") == 1
    assert after.count(TIME_SYNC_TARGET) == 1
    assert TIME_SYNC_TARGET == "time-sync.target"


def test_controller_has_no_strong_dependency_at_all():
    settings = _settings(_unit(ACTIVATION_CONTROLLER_UNIT))
    for key in STRONG:
        assert key not in settings, f"{key}= on the controller"
    profile = next(p for p in PROFILES if p.unit == ACTIVATION_CONTROLLER_UNIT)
    assert profile.requires == ()
    assert profile.binds_to == ()


def test_no_unit_requires_or_wants_data_or_time_sync():
    for profile in ALL_PROFILES:
        settings = _settings(render_unit(profile))
        for key in STRONG:
            for value in settings.get(key, []):
                assert "data.mount" not in value, f"{profile.unit} has {key}={value}"
                assert "time-sync.target" not in value, f"{profile.unit} has {key}={value}"
                assert "/data" not in value.split(), f"{profile.unit} has {key}={value}"


def test_only_the_controller_is_ordered_after_data_and_time_sync():
    for profile in ALL_PROFILES:
        if profile.unit == ACTIVATION_CONTROLLER_UNIT:
            continue
        assert "data.mount" not in profile.after, profile.unit
        assert TIME_SYNC_TARGET not in profile.after, profile.unit


def _below_data(value: str) -> bool:
    for token in value.split():
        path = token.lstrip("-+:").split(":")[0]
        if path == "/data" or path.startswith("/data/"):
            return True
    return False


def test_controller_paths_do_not_reach_into_data():
    settings = _settings(_unit(ACTIVATION_CONTROLLER_UNIT))
    for key in PATH_SETTINGS:
        for value in settings.get(key, []):
            assert not _below_data(value), f"{key}={value}"
    assert _below_data("-/data/azazel/mission-packs")
    assert _below_data("/data")
    assert not _below_data("/database")
    assert not _below_data("/var/lib/azazel")


def test_watchdog_waits_for_the_controller_like_every_requires_dependent():
    """L-9: every unit that `Requires=` the controller is also `After=` it."""
    settings = _settings(_unit(WATCHDOG))
    assert settings["After"].count(ACTIVATION_CONTROLLER_UNIT) == 1
    assert settings["Requires"] == [ACTIVATION_CONTROLLER_UNIT]
    assert "BindsTo" not in settings and "Wants" not in settings
    for profile in PROFILES:
        if ACTIVATION_CONTROLLER_UNIT in profile.requires:
            assert ACTIVATION_CONTROLLER_UNIT in profile.after, profile.unit
