"""Pure, explicit host-install planning (#93).

This module identifies the current Debian installer *shape* and projects the
repository's existing layout, account, unit, and preset declarations into
immutable data. It does not install files, inspect the running host, select a
CPU architecture, or establish HIL compatibility. Adding another platform
requires an explicit reviewed profile; an OS match is not an architecture or
hardware-support claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Sequence

from azazel_nexus.layout import LAYOUT
from azazel_nexus_runtime.hardening import PROFILES, SYSTEM_ACCOUNTS

__all__ = [
    "CURRENT_INSTALL_PLATFORM_PROFILES",
    "DirectoryDestination",
    "FileDestination",
    "InstallPlan",
    "InstallPlatformProfile",
    "ServiceManagerIntent",
    "build_install_plan",
    "parse_os_release",
    "parse_preset_declarations",
    "select_install_profile",
]


_KEY = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_UNQUOTED = re.compile(r"[A-Za-z0-9._+:/-]+\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.@-]+\.service\Z")


def _require_absolute(value: str, name: str) -> None:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{name} must be an absolute normalized path")
    if str(path) != value:
        raise ValueError(f"{name} must be normalized")


@dataclass(frozen=True)
class InstallPlatformProfile:
    """Reviewed OS installer layout; intentionally contains no CPU claim."""

    profile_id: str
    os_id: str
    version_id: str
    unit_directory: str
    preset_directory: str
    libexec_directory: str
    service_manager: str
    required_tools: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.required_tools, tuple):
            raise ValueError("required_tools must be immutable tuple data")
        for name in ("profile_id", "os_id", "version_id", "service_manager"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must be non-empty")
        for name in ("unit_directory", "preset_directory", "libexec_directory"):
            _require_absolute(getattr(self, name), name)
        if not self.required_tools or any(
            not item.strip() for item in self.required_tools
        ):
            raise ValueError("required_tools must contain non-empty tool names")
        if len(set(self.required_tools)) != len(self.required_tools):
            raise ValueError("required_tools must not contain duplicates")


@dataclass(frozen=True)
class DirectoryDestination:
    """One absolute directory destination and its existing layout ownership."""

    path: str
    mode: int
    owner: str
    group: str

    def __post_init__(self) -> None:
        _require_absolute(self.path, "directory path")


@dataclass(frozen=True)
class FileDestination:
    """A repository-relative declared input and an absolute install target."""

    source: str
    destination: str
    mode: int = 0o644

    def __post_init__(self) -> None:
        source = PurePosixPath(self.source)
        if source.is_absolute() or ".." in source.parts or not source.parts:
            raise ValueError("source must be a safe repository-relative path")
        _require_absolute(self.destination, "file destination")
        if not 0 <= self.mode <= 0o777:
            raise ValueError("file mode must be an ordinary permission mode")


@dataclass(frozen=True)
class ServiceManagerIntent:
    """Declarative service-manager outcome; this object performs no action."""

    manager: str
    mask_units: tuple[str, ...]
    enable_units: tuple[str, ...]
    start_units: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(
            not isinstance(items, tuple)
            for items in (self.mask_units, self.enable_units, self.start_units)
        ):
            raise ValueError("unit intents must be immutable tuple data")
        units = (*self.mask_units, *self.enable_units, *self.start_units)
        if any(not _UNIT.fullmatch(unit) for unit in units):
            raise ValueError("service-manager intent contains an invalid unit name")
        if len(set(units)) != len(units):
            raise ValueError("service-manager intent contains duplicate units")
        if set(self.mask_units) & set(self.enable_units):
            raise ValueError("a unit cannot be both masked and enabled")


@dataclass(frozen=True)
class InstallPlan:
    """Immutable output data. It is not an instruction runner."""

    profile_id: str
    files: tuple[FileDestination, ...]
    directories: tuple[DirectoryDestination, ...]
    accounts: tuple[str, ...]
    groups: tuple[str, ...]
    required_tools: tuple[str, ...]
    service_manager: ServiceManagerIntent
    architecture_evaluated: bool = False
    hardware_compatibility_established: bool = False

    def __post_init__(self) -> None:
        if any(
            not isinstance(items, tuple)
            for items in (
                self.files,
                self.directories,
                self.accounts,
                self.groups,
                self.required_tools,
            )
        ):
            raise ValueError("install plan collections must be immutable tuple data")
        if not isinstance(self.service_manager, ServiceManagerIntent):
            raise ValueError("service_manager must be declarative intent data")


CURRENT_INSTALL_PLATFORM_PROFILES: tuple[InstallPlatformProfile, ...] = (
    InstallPlatformProfile(
        profile_id="debian-13-systemd-installer-v1",
        os_id="debian",
        version_id="13",
        unit_directory="/lib/systemd/system",
        preset_directory="/lib/systemd/system-preset",
        libexec_directory="/usr/libexec/azazel",
        service_manager="systemd",
        required_tools=(
            "/bin/sh",
            "id",
            "python3",
            "dirname",
            "install",
            "getent",
            "useradd",
            "groupadd",
            "systemctl",
        ),
    ),
)


def parse_os_release(text: str) -> dict[str, str]:
    """Parse a conservative os-release subset without shell evaluation.

    Empty lines and whole-line comments are accepted. Values may be simple
    unquoted tokens, single-quoted strings, or double-quoted strings with the
    os-release backslash escapes for ``\\``, ``\"``, ``$`` and backtick.
    Duplicate keys, substitutions, malformed quoting, and unsupported syntax
    are rejected rather than interpreted as shell.
    """

    values: dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or not _KEY.fullmatch(key) or key in values:
            raise ValueError(f"malformed os-release entry on line {line_number}")
        if not raw_value:
            raise ValueError(f"empty os-release value on line {line_number}")
        if raw_value.startswith("'"):
            if len(raw_value) < 2 or not raw_value.endswith("'"):
                raise ValueError(f"malformed os-release quote on line {line_number}")
            value = raw_value[1:-1]
            if "'" in value or "\n" in value:
                raise ValueError(f"malformed os-release value on line {line_number}")
        elif raw_value.startswith('"'):
            if len(raw_value) < 2 or not raw_value.endswith('"'):
                raise ValueError(f"malformed os-release quote on line {line_number}")
            value = _unescape_double_quoted(raw_value[1:-1], line_number)
        else:
            if not _UNQUOTED.fullmatch(raw_value):
                raise ValueError(f"unsupported os-release value on line {line_number}")
            value = raw_value
        values[key] = value
    if not values.get("ID") or not values.get("VERSION_ID"):
        raise ValueError("os-release must contain non-empty ID and VERSION_ID")
    return values


def _unescape_double_quoted(value: str, line_number: int) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == '"':
            raise ValueError(f"malformed os-release quote on line {line_number}")
        if char == "\\":
            index += 1
            if index >= len(value) or value[index] not in '\\"$`':
                raise ValueError(f"unsupported os-release escape on line {line_number}")
            char = value[index]
        output.append(char)
        index += 1
    return "".join(output)


def select_install_profile(
    os_release: Mapping[str, str],
    *,
    registry: Sequence[InstallPlatformProfile] = CURRENT_INSTALL_PLATFORM_PROFILES,
) -> InstallPlatformProfile:
    """Select an exact OS/release match from the supplied reviewed registry.

    ``registry`` injection exists for synthetic tests and future reviewed
    profiles. This selector does not inspect architecture or establish HIL
    support; callers must keep those gates separate.
    """

    os_id = os_release.get("ID")
    version_id = os_release.get("VERSION_ID")
    if (
        not isinstance(os_id, str)
        or not os_id
        or not isinstance(version_id, str)
        or not version_id
    ):
        raise ValueError("os-release must contain non-empty string ID and VERSION_ID")
    matches = [
        profile
        for profile in registry
        if profile.os_id == os_id and profile.version_id == version_id
    ]
    if len(matches) != 1:
        raise ValueError("unknown or ambiguous installation platform profile")
    return matches[0]


def parse_preset_declarations(text: str) -> tuple[tuple[str, str], ...]:
    """Parse exact systemd preset directives as data; reject globs/commands."""

    declarations: list[tuple[str, str]] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if (
            len(parts) != 2
            or parts[0] not in {"enable", "disable"}
            or not _UNIT.fullmatch(parts[1])
        ):
            raise ValueError(f"unsupported preset declaration on line {line_number}")
        if any(unit == parts[1] for _, unit in declarations):
            raise ValueError(f"duplicate preset unit on line {line_number}")
        declarations.append((parts[0], parts[1]))
    if not declarations:
        raise ValueError("preset declaration set is empty")
    return tuple(declarations)


def build_install_plan(
    profile: InstallPlatformProfile,
    *,
    preset_declarations: Sequence[tuple[str, str]],
) -> InstallPlan:
    """Project repository declarations into immutable install-intent data."""

    declared_units = {service.unit for service in PROFILES}
    declarations = tuple(preset_declarations)
    if not declarations or any(
        action not in {"enable", "disable"} or unit not in declared_units
        for action, unit in declarations
    ):
        raise ValueError("preset intent must reference declared service units")
    if len({unit for _, unit in declarations}) != len(declarations):
        raise ValueError("preset intent contains duplicate units")

    enabled = tuple(unit for action, unit in declarations if action == "enable")
    disabled = tuple(unit for action, unit in declarations if action == "disable")
    if enabled != ("azazel-activated.service",):
        raise ValueError("install plan must enable only the activation controller")

    files = tuple(
        FileDestination(
            source=f"packaging/systemd/{service.unit}",
            destination=f"{profile.unit_directory}/{service.unit}",
        )
        for service in PROFILES
    ) + (
        FileDestination(
            source="packaging/azazel-nexus.preset",
            destination=f"{profile.preset_directory}/99-azazel-nexus.preset",
        ),
    )
    directories = tuple(
        DirectoryDestination(spec.path, spec.mode, spec.owner, spec.group)
        for spec in LAYOUT
    ) + (
        DirectoryDestination(profile.unit_directory, 0o755, "root", "root"),
        DirectoryDestination(profile.preset_directory, 0o755, "root", "root"),
        DirectoryDestination(profile.libexec_directory, 0o755, "root", "root"),
    )
    groups = tuple(
        sorted(
            set(SYSTEM_ACCOUNTS)
            | {
                identity
                for spec in LAYOUT
                for identity in (spec.owner, spec.group)
                if identity != "root"
            }
        )
    )
    intent = ServiceManagerIntent(
        manager=profile.service_manager,
        mask_units=disabled,
        enable_units=enabled,
    )
    return InstallPlan(
        profile_id=profile.profile_id,
        files=files,
        directories=directories,
        accounts=SYSTEM_ACCOUNTS,
        groups=groups,
        required_tools=profile.required_tools,
        service_manager=intent,
    )
