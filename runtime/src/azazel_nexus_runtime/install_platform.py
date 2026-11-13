"""Pure, explicit host-install planning (#93).

This module identifies the current Debian installer *shape* and projects the
repository's existing layout, account, unit, and preset declarations into
immutable data. It does not install files, inspect the running host, or
establish HIL compatibility. Adding another platform requires an explicit
reviewed profile; an OS match is not an architecture or hardware-support claim.

The CPU is evaluated separately, by `evaluate_install_architecture`, from a
`platform_observation.HostObservation` the caller supplies (ADR-0003 R6): an
unreviewed CPU, a foreign dpkg userland, a non-LP64 libc or another byte
order is refused with its reason code, and a reviewed CPU is identified by
the `platform_profile` purpose it has. arm64 is identified as
``lab-software-verification``; identifying it admits nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Sequence

from azazel_nexus import platform_profile
from azazel_nexus.layout import LAYOUT
from .decoy_apparmor import DECOY_APPARMOR_PROFILES
from azazel_nexus.activation import DECOY_NAMESPACE_UNIT
from .hardening import (
    ALL_PROFILES,
    DECOY_NAMESPACE_IP,
    EDGE_PROBE_PREFLIGHT_UNIT,
    PROFILES,
    RECHECK_TIMER,
    SYSTEM_ACCOUNTS,
    UI_SOCKET,
    UI_UNIT,
    packaged_unit_files,
)

__all__ = [
    "APPARMOR_DIRECTORY",
    "CURRENT_INSTALL_PLATFORM_PROFILES",
    "DirectoryDestination",
    "FileDestination",
    "InstallPlan",
    "InstallPlatformProfile",
    "ServiceManagerIntent",
    "build_install_plan",
    "evaluate_install_architecture",
    "parse_os_release",
    "parse_preset_declarations",
    "select_install_profile",
]


#: Where the Deception Lite AppArmor profiles are installed (#196 G3), the
#: directory `apparmor.service` (Debian package `apparmor`) loads at boot.
APPARMOR_DIRECTORY = "/etc/apparmor.d"

_KEY = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_UNQUOTED = re.compile(r"[A-Za-z0-9._+:/-]+\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.@-]+\.service\Z")
#: A preset line may also name the read-only UI's socket unit (U5).
_PRESET_UNIT = re.compile(r"[A-Za-z0-9_.@-]+\.(?:service|socket|timer)\Z")
#: Disabled in the preset and **not masked** by the installer: the read-only
#: UI (U5) is not governed, so no pass would ever unmask it, and an operator
#: enables its socket explicitly. Every other `disable` is a mask.
DISABLED_NOT_MASKED = (UI_SOCKET, UI_UNIT)
_PROFILE_ID = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_TOOL = re.compile(r"(?:/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+|[A-Za-z0-9_+-]+)\Z")


def _require_absolute(value: str, name: str) -> None:
    if type(value) is not str:
        raise ValueError(f"{name} must be a string path")
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
    account_tools: tuple[str, ...] = ()
    service_manager_tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("profile_id", "os_id", "version_id", "service_manager"):
            if type(getattr(self, name)) is not str:
                raise ValueError(f"{name} must be a string")
        for name in ("required_tools", "account_tools", "service_manager_tools"):
            tools = getattr(self, name)
            if type(tools) is not tuple:
                raise ValueError(f"{name} must be immutable tuple data")
        if not _PROFILE_ID.fullmatch(self.profile_id):
            raise ValueError("profile_id must be a normalized lowercase identifier")
        for name in ("os_id", "version_id", "service_manager"):
            value = getattr(self, name)
            if not value or value != value.strip() or any(c.isspace() for c in value):
                raise ValueError(f"{name} must be non-empty")
        for name in ("unit_directory", "preset_directory", "libexec_directory"):
            _require_absolute(getattr(self, name), name)
        paths = tuple(
            PurePosixPath(getattr(self, name))
            for name in ("unit_directory", "preset_directory", "libexec_directory")
        )
        if any(
            left == right or left in right.parents or right in left.parents
            for index, left in enumerate(paths)
            for right in paths[index + 1:]
        ):
            raise ValueError("profile destinations must not overlap")
        for name in ("required_tools", "account_tools", "service_manager_tools"):
            tools = getattr(self, name)
            if any(type(item) is not str or not _TOOL.fullmatch(item) for item in tools):
                raise ValueError(f"{name} must contain safe tool names")
            if len(set(tools)) != len(tools):
                raise ValueError(f"{name} must not contain duplicates")
        if not self.required_tools:
            raise ValueError("required_tools must not be empty")
        seen_tools: set[str] = set()
        for name in ("required_tools", "account_tools", "service_manager_tools"):
            tools = set(getattr(self, name))
            if seen_tools & tools:
                raise ValueError("profile tool sets must be disjoint")
            seen_tools.update(tools)


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
        # A service, or the recheck's timer (the one enabled timer).
        if any(not (_UNIT.fullmatch(unit) or unit == RECHECK_TIMER) for unit in units):
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
            "python3",
            "dirname",
            "install",
        ),
        account_tools=("id", "getent", "useradd", "groupadd"),
        # `apparmor_parser` stands for the Debian package `apparmor` (not
        # `apparmor-utils`, which is for authoring): it checks the
        # Deception Lite profiles at install, and its `apparmor.service`
        # loads them at boot (#196 G3). Needed with the service manager
        # only: a DESTDIR staging run places the files and loads nothing.
        service_manager_tools=("systemctl", "systemd-tmpfiles", "apparmor_parser"),
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


def evaluate_install_architecture(
    profile: InstallPlatformProfile, observed: object,
) -> platform_profile.PlatformProfile:
    """The reviewed platform profile for the selected OS and the observed CPU.

    Refuses (`platform_profile.PlatformRefused`, with its reason code) an
    unknown CPU name, a non-Linux kernel, a non-LP64 libc, another byte
    order, a dpkg native architecture that is not the kernel's, and an
    OS x CPU pair no reviewed profile has. The Python ABI is deliberately
    not part of this decision: the installer accepts any interpreter from
    3.11 for a staging run, and the AppArmor wrapper check pins the
    interpreter of a real install separately.

    The result only *identifies* the platform. A ``lab-software-verification``
    profile installs exactly as it did before this check existed; it never
    becomes a deployment baseline, an admission input or hardware evidence,
    which `platform_profile.require_deployment_baseline` refuses at each
    production consumer.
    """

    from .platform_observation import check_host_abi

    if type(profile) is not InstallPlatformProfile:
        raise ValueError("a reviewed install profile is required")
    architecture = check_host_abi(observed)  # type: ignore[arg-type]
    matches = [
        reviewed for reviewed in platform_profile.REVIEWED_PROFILES.values()
        if reviewed.architecture == architecture
        and reviewed.os_id == profile.os_id
        and reviewed.os_version_id == profile.version_id
    ]
    if not matches:
        raise platform_profile.PlatformRefused(
            platform_profile.UNREVIEWED_COMBINATION, (profile.profile_id, architecture))
    if len(matches) != 1:
        raise platform_profile.PlatformRefused(
            platform_profile.UNREVIEWED_COMBINATION, tuple(p.profile_id for p in matches))
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
            or not _PRESET_UNIT.fullmatch(parts[1])
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
    with_accounts: bool = True,
    with_service_manager: bool = True,
) -> InstallPlan:
    """Project repository declarations into immutable install-intent data."""

    if type(with_accounts) is not bool or type(with_service_manager) is not bool:
        raise ValueError("install modes must be explicit booleans")

    declared_units = ({service.unit for service in ALL_PROFILES}
                      | {UI_SOCKET, RECHECK_TIMER})
    declarations = tuple(preset_declarations)
    if not declarations or any(
        action not in {"enable", "disable"} or unit not in declared_units
        for action, unit in declarations
    ):
        raise ValueError("preset intent must reference declared service units")
    if len({unit for _, unit in declarations}) != len(declarations):
        raise ValueError("preset intent contains duplicate units")

    enabled = tuple(unit for action, unit in declarations if action == "enable")
    disabled = tuple(unit for action, unit in declarations
                     if action == "disable" and unit not in DISABLED_NOT_MASKED)
    if any(action != "disable" for action, unit in declarations if unit in DISABLED_NOT_MASKED):
        raise ValueError("the read-only UI's units are disabled in the preset, never enabled")
    # The controller, the ungoverned read-only Edge probe preflight that runs
    # before it (#206 P5), and the timer of the activation recheck, which can
    # only withdraw the Knowledge Context broker's grant. Nothing governed is
    # ever enabled here.
    if enabled != ("azazel-activated.service", EDGE_PROBE_PREFLIGHT_UNIT,
                   RECHECK_TIMER):
        raise ValueError(
            "install plan must enable only the activation controller, the "
            "Edge probe preflight and the activation recheck timer"
        )

    # Nexus stages Python wrappers; the separately verified Edge package owns its binary,
    # and the decoy namespace unit runs the system's iproute2 `ip` itself (#196 G4
    # follow-up), which Nexus neither stages nor ships.
    for service in PROFILES:
        if (service.unit == "azazel-edge-core.service"
                and service.executable != "/opt/azazel/edge-core/bin/azazel-edge-core"):
            raise ValueError("Edge Core must use its fixed package executable")
        if (service.unit == DECOY_NAMESPACE_UNIT
                and service.executable != DECOY_NAMESPACE_IP):
            raise ValueError("the decoy namespace unit must run the fixed ip executable")
    declared_exec_directories = {
        str(PurePosixPath(service.executable).parent) for service in PROFILES
        if service.unit not in ("azazel-edge-core.service", DECOY_NAMESPACE_UNIT)
    }
    if declared_exec_directories != {profile.libexec_directory}:
        raise ValueError(
            "install profile libexec path differs from rendered systemd entrypoints"
        )

    # Every packaged unit file: each service, and the Deception Lite watch's
    # timer and trip unit (#196 G2), which are installed and never enabled.
    files = tuple(
        FileDestination(
            source=f"packaging/systemd/{unit}",
            destination=f"{profile.unit_directory}/{unit}",
        )
        for unit, _ in packaged_unit_files()
    ) + (
        FileDestination(
            source="packaging/azazel-nexus.preset",
            destination=f"{profile.preset_directory}/99-azazel-nexus.preset",
        ),
    ) + tuple(
        FileDestination(
            source=f"packaging/apparmor/{name}",
            destination=f"{APPARMOR_DIRECTORY}/{name}",
        )
        for _, name in DECOY_APPARMOR_PROFILES
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
        required_tools=(
            *profile.required_tools,
            *(profile.account_tools if with_accounts else ()),
            *(profile.service_manager_tools if with_service_manager else ()),
        ),
        service_manager=intent,
    )
