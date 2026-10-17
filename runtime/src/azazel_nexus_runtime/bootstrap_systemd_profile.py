"""Read-only compatibility gate for explicitly reviewed systemd profiles.

This reports whether observed Manager properties match a reviewed profile. It
does not authorize overlay writes, reloads, starts, stops or bootstrap grants.
Unknown versions or search paths must be reviewed as a new profile, not
accepted by a broad fallback.
"""

import hashlib
import json
import re
from dataclasses import dataclass

from .units import UnitOperationFailed

_DEBIAN13_V257_VERSION = re.compile(r"257\.13-[0-9]+~deb13u[0-9]+\Z")
_DEBIAN13_V257_UNIT_PATH = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/generator.late",
)


@dataclass(frozen=True)
class SystemdBootstrapProfile:
    """A manager-property match; not OS authentication or control capability."""

    name: str
    version: str
    unit_path: tuple[str, ...]


def bootstrap_systemd_profile_digest(profile: SystemdBootstrapProfile) -> str:
    """Return a canonical pin suitable for an independently approved policy.

    This identifies the reviewed compatibility tuple only; it authenticates
    neither the host nor systemd binary/package and grants no manager authority.
    """
    if type(profile) is not SystemdBootstrapProfile:
        raise UnitOperationFailed("reviewed systemd bootstrap profile required")
    checked = observe_bootstrap_systemd_profile(
        version=profile.version, unit_path=list(profile.unit_path)
    )
    if checked != profile:
        raise UnitOperationFailed("systemd bootstrap profile identity refused")
    raw = json.dumps({
        "schema": "azazel-nexus/systemd-bootstrap-profile/v1",
        "name": checked.name,
        "version": checked.version,
        "unit_path": checked.unit_path,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class _ReviewedProfileDefinition:
    """One measured compatibility profile; entries are additive and explicit."""

    name: str
    version: re.Pattern[str]
    unit_path: tuple[str, ...]


_REVIEWED_PROFILES = (
    _ReviewedProfileDefinition(
        name="systemd-257.13-deb13-path-v1",
        version=_DEBIAN13_V257_VERSION,
        unit_path=_DEBIAN13_V257_UNIT_PATH,
    ),
)


def observe_bootstrap_systemd_profile(*, version: str, unit_path: list[str]) -> SystemdBootstrapProfile:
    """Accept only a reviewed version and complete ordered UnitPath pair.

    Add a profile only after measuring its manager properties and reviewing
    unit lookup precedence. No broad version or path fallback is permitted.
    This observation does not authenticate the host OS or package provenance.
    """
    if type(version) is not str or len(version) > 128:
        raise UnitOperationFailed("unsupported systemd version profile")
    if (
        type(unit_path) is not list
        or not unit_path
        or len(unit_path) > 64
        or any(
            type(path) is not str or len(path) > 256 or not path.startswith("/")
            for path in unit_path
        )
    ):
        raise UnitOperationFailed("unsupported systemd unit search path")
    for profile in _REVIEWED_PROFILES:
        if (profile.version.fullmatch(version) is not None
                and tuple(unit_path) == profile.unit_path):
            return SystemdBootstrapProfile(
                name=profile.name,
                version=version,
                unit_path=profile.unit_path,
            )
    if not any(profile.version.fullmatch(version) for profile in _REVIEWED_PROFILES):
        raise UnitOperationFailed("unsupported systemd version profile")
    raise UnitOperationFailed("unsupported systemd unit search path")
