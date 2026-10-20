"""The controller is ordered after the commissioning storage, never bound to it (#242).

docs/commissioning-storage-at-boot.md §4: the activation controller gains
`After=` on the commissioning LUKS mount and (§5 Q3) the secrets mount on the
same device. Only `After=`: a `Requires=`, `Wants=`, `BindsTo=` or
`RequiresMountsFor=` would let locked or failed storage stop the controller,
whose preflight remask is what narrows. With the storage absent the pass still
runs and still refuses, because the evidence is not LUKS-backed.

These are declaration checks on the packaged unit file. They do not show that
systemd orders the boot this way; that is the P1 VM rehearsal.
"""

from __future__ import annotations

from pathlib import Path

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT
from azazel_nexus_runtime.hardening import (
    ALL_PROFILES,
    COMMISSIONING_STORAGE_MOUNTS,
    PROFILES,
    render_unit,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO_ROOT / "packaging" / "systemd"
MOUNTS = ("etc-azazel-commissioning.mount", "var-lib-azazel-secrets.mount")
STRONG = ("Requires", "Wants", "BindsTo", "Requisite", "Upholds",
          "RequiresMountsFor", "PartOf")


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


def _controller() -> str:
    return (UNIT_DIR / ACTIVATION_CONTROLLER_UNIT).read_text(encoding="utf-8")


STORAGE_PATHS = ("/etc/azazel/commissioning", "/var/lib/azazel/secrets")
#: Settings whose paths make systemd add an implicit `RequiresMountsFor=`, or
#: that would otherwise tie the controller to a path below the storage.
PATH_SETTINGS = (
    "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "ExecPaths",
    "NoExecPaths", "BindPaths", "BindReadOnlyPaths", "WorkingDirectory",
    "RootDirectory", "RootImage", "TemporaryFileSystem", "StateDirectory",
    "ConfigurationDirectory", "LoadCredential", "LoadCredentialEncrypted",
    "EnvironmentFile",
)


def _mount_unit(path: str) -> str:
    """systemd's path escaping, for plain ASCII paths without `-` or `\\`."""

    assert path.startswith("/") and "-" not in path and "\\" not in path
    return path.strip("/").replace("/", "-") + ".mount"


def test_mount_names_are_the_escaped_storage_paths():
    assert COMMISSIONING_STORAGE_MOUNTS == tuple(
        _mount_unit(path) for path in STORAGE_PATHS
    )
    assert COMMISSIONING_STORAGE_MOUNTS == MOUNTS


def test_controller_is_ordered_after_both_storage_mounts():
    after = _settings(_controller())["After"]
    for mount in MOUNTS:
        assert after.count(mount) == 1


def test_controller_has_no_strong_dependency_on_storage():
    settings = _settings(_controller())
    for key in STRONG:
        assert key not in settings, f"{key}= on the controller"
    profile = next(p for p in PROFILES if p.unit == ACTIVATION_CONTROLLER_UNIT)
    assert profile.requires == ()
    assert profile.binds_to == ()


def test_no_unit_requires_or_wants_the_storage_mounts():
    for profile in ALL_PROFILES:
        settings = _settings(render_unit(profile))
        for key in STRONG:
            for value in settings.get(key, []):
                assert not any(mount in value for mount in MOUNTS), (
                    f"{profile.unit} has {key}={value}"
                )
                assert "/etc/azazel/commissioning" not in value
                assert "/var/lib/azazel/secrets" not in value


def test_only_the_controller_is_ordered_after_storage():
    for profile in ALL_PROFILES:
        if profile.unit == ACTIVATION_CONTROLLER_UNIT:
            continue
        assert not set(MOUNTS) & set(profile.after), profile.unit


def _below_storage(value: str) -> bool:
    for token in value.split():
        path = token.lstrip("-+:").split(":")[0]
        for storage in STORAGE_PATHS:
            if path == storage or path.startswith(storage + "/"):
                return True
    return False


def test_controller_paths_do_not_reach_into_storage():
    settings = _settings(_controller())
    for key in PATH_SETTINGS:
        for value in settings.get(key, []):
            assert not _below_storage(value), f"{key}={value}"
    assert _below_storage("-/var/lib/azazel/secrets/x")
    assert not _below_storage("/var/lib/azazel")
