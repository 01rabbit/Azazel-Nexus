"""Observe the facts a platform profile is selected from (ADR-0003).

`azazel_nexus.platform_profile` interprets strings and does no I/O. This
module is its host side: it reads, and only reads,

* ``uname`` (``sysname``, ``release``, ``machine``),
* ``/etc/os-release`` ``ID`` and ``VERSION_ID`` (the conservative parser in
  `install_platform`, never shell evaluation),
* the running interpreter's ``SOABI``,
* whether the C ``long`` is 64-bit (LP64),
* ``sys.byteorder``,
* dpkg's native architecture (the ``dpkg`` package row, read by the
  reviewed `debian_packages` observer), or ``unavailable`` when it cannot be
  read,

and `select` matches them against `platform_profile.REVIEWED_PROFILES`.
Anything outside a reviewed profile is refused with a reason code; nothing is
guessed, defaulted or folded into the nearest profile.

What an observation is not
--------------------------
These are values the running kernel, libc and interpreter *report*. Code
running as root, a modified kernel, an emulator (qemu-user, Rosetta), a
container with a substituted ``/etc/os-release`` or a patched interpreter can
report other values. An observation therefore narrows what a record may
claim -- an Arm VM cannot quietly produce a record that *says* amd64 -- but it
is not attestation and not hardware evidence. The ADR-0003 section
"Limits of host observation" states this for every consumer.

Selecting a lab profile is not a refusal here: `select` identifies the host.
Whether a profile may back a production use is decided only by
`platform_profile.require_deployment_baseline`, at the consumer.
"""

from __future__ import annotations

import ctypes
import os
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from azazel_nexus import platform_profile
from azazel_nexus.platform_profile import PlatformProfile, PlatformRefused

__all__ = [
    "DPKG_ARCHITECTURE_MISMATCH",
    "DPKG_UNOBSERVED",
    "HostObservation",
    "LP64_NOT_OBSERVED",
    "OS_RELEASE",
    "REVIEWED_BYTE_ORDER",
    "UNAVAILABLE",
    "UNREVIEWED_BYTE_ORDER",
    "UNREVIEWED_KERNEL",
    "check_host_abi",
    "observe",
    "select",
]

#: The value of a field that could not be read. Never a reviewed value.
UNAVAILABLE = "unavailable"

OS_RELEASE = Path("/etc/os-release")

#: Both reviewed CPUs run little-endian Linux. Big-endian aarch64 (aarch64_be)
#: already fails at the machine name; this catches an interpreter reporting
#: otherwise.
REVIEWED_BYTE_ORDER = "little"
REVIEWED_SYSNAME = "Linux"

#: Reason codes, in addition to those of `platform_profile`.
UNREVIEWED_KERNEL = "UNREVIEWED_KERNEL"
LP64_NOT_OBSERVED = "LP64_NOT_OBSERVED"
UNREVIEWED_BYTE_ORDER = "UNREVIEWED_BYTE_ORDER"
DPKG_ARCHITECTURE_MISMATCH = "DPKG_ARCHITECTURE_MISMATCH"
DPKG_UNOBSERVED = "DPKG_UNOBSERVED"
UNOBSERVED = "UNOBSERVED"


@dataclass(frozen=True)
class HostObservation:
    """What the host reported. Every field is a plain value; none is trusted."""

    sysname: str
    release: str
    machine: str
    os_id: str
    os_version_id: str
    soabi: str
    lp64: bool
    byteorder: str
    dpkg_architecture: str

    def as_record(self) -> dict:
        return {
            "sysname": self.sysname, "release": self.release, "machine": self.machine,
            "os_id": self.os_id, "os_version_id": self.os_version_id, "soabi": self.soabi,
            "lp64": self.lp64, "byteorder": self.byteorder,
            "dpkg_architecture": self.dpkg_architecture,
        }


def _text_or_unavailable(value: object) -> str:
    return value if type(value) is str and value else UNAVAILABLE


def _read_os_release(path: Path) -> tuple[str, str]:
    from .install_platform import parse_os_release

    try:
        values = parse_os_release(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return UNAVAILABLE, UNAVAILABLE
    return _text_or_unavailable(values.get("ID")), _text_or_unavailable(values.get("VERSION_ID"))


def read_dpkg_architecture() -> str:
    """dpkg's native architecture, or `UNAVAILABLE`.

    Read through the already-reviewed `debian_packages` observer (fixed
    absolute ``dpkg-query`` argv, fixed environment, bounded output and time,
    no shell): the architecture of the installed, unqualified ``dpkg`` row.
    This module starts no process of its own.
    """

    from .debian_packages import observe_installed_packages

    try:
        return observe_installed_packages().native_architecture
    except Exception:  # noqa: BLE001 - any refusal or failure is "unavailable"
        return UNAVAILABLE


def observe(
    *,
    uname: Callable[[], object] = os.uname,
    os_release_path: Path = OS_RELEASE,
    soabi: Callable[[], object] = lambda: sysconfig.get_config_var("SOABI"),
    long_size: Callable[[], int] = lambda: ctypes.sizeof(ctypes.c_long),
    byteorder: Callable[[], str] = lambda: sys.byteorder,
    dpkg_architecture: Callable[[], str] = read_dpkg_architecture,
) -> HostObservation:
    """Read the host. Each reader is injectable so tests are not the host."""

    name = uname()
    os_id, os_version_id = _read_os_release(os_release_path)
    return HostObservation(
        sysname=_text_or_unavailable(getattr(name, "sysname", None)),
        release=_text_or_unavailable(getattr(name, "release", None)),
        machine=_text_or_unavailable(getattr(name, "machine", None)),
        os_id=os_id,
        os_version_id=os_version_id,
        soabi=_text_or_unavailable(soabi()),
        lp64=long_size() == 8,
        byteorder=_text_or_unavailable(byteorder()),
        dpkg_architecture=_text_or_unavailable(dpkg_architecture()),
    )


def check_host_abi(observed: HostObservation) -> str:
    """The canonical architecture of ``observed``, after the checks every
    profile shares (kernel, CPU, LP64, byte order, dpkg). Refuses otherwise.

    The Python ABI and OS are not checked here; `select` adds them.
    """

    if type(observed) is not HostObservation:
        raise PlatformRefused(UNOBSERVED, type(observed).__name__)
    if observed.sysname != REVIEWED_SYSNAME:
        raise PlatformRefused(UNREVIEWED_KERNEL, observed.sysname)
    architecture = platform_profile.from_boundary("kernel", observed.machine)
    if observed.lp64 is not True:
        raise PlatformRefused(LP64_NOT_OBSERVED, observed.machine)
    if observed.byteorder != REVIEWED_BYTE_ORDER:
        raise PlatformRefused(UNREVIEWED_BYTE_ORDER, observed.byteorder)
    # Every reviewed profile is Debian, so dpkg is always there. A dpkg that
    # cannot be read (missing, refused, garbage) is an anomaly, not an absent
    # fact: without it a foreign userland on this kernel could not be seen.
    if observed.dpkg_architecture == UNAVAILABLE:
        raise PlatformRefused(DPKG_UNOBSERVED, observed.dpkg_architecture)
    # A dpkg that names another architecture is a foreign userland on this
    # kernel (armhf on an arm64 kernel, i386 on amd64): its packages, wheels
    # and native extensions are not the profile's.
    if observed.dpkg_architecture != platform_profile.debian_name(architecture):
        raise PlatformRefused(DPKG_ARCHITECTURE_MISMATCH, observed.dpkg_architecture)
    return architecture


def select(observed: HostObservation) -> PlatformProfile:
    """The reviewed profile ``observed`` matches exactly, or a reasoned refusal.

    The first check that fails is the reason: kernel, CPU name
    (``UNKNOWN_ARCHITECTURE``), LP64, byte order, dpkg (unreadable:
    ``DPKG_UNOBSERVED``; another architecture: ``DPKG_ARCHITECTURE_MISMATCH``),
    then OS and Python ABI
    through `platform_profile.select_profile`. A lab profile is returned, not
    refused: identifying the host is this function's job, admitting it is
    `platform_profile.require_deployment_baseline`'s.
    """

    architecture = check_host_abi(observed)
    selected = platform_profile.select_profile(
        os_id=observed.os_id, os_version_id=observed.os_version_id,
        machine=observed.machine, soabi=observed.soabi,
    )
    if selected.architecture != architecture:  # pragma: no cover - same table
        raise PlatformRefused(platform_profile.UNREVIEWED_COMBINATION, selected.profile_id)
    return selected
