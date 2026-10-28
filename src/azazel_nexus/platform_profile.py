"""CPU architecture names and reviewed platform profiles, in one place (ADR-0003).

Every boundary Nexus talks to spells the two CPUs differently:

    boundary            amd64               arm64
    Linux ``uname -m``  x86_64              aarch64
    Debian / dpkg       amd64               arm64
    systemd             x86-64              arm64
    Python SOABI        x86_64-linux-gnu    aarch64-linux-gnu
    Fabric contracts    amd64               arm64

The internal canonical name follows Fabric (``Architecture =
Literal["amd64", "arm64"]`` in ``provisioning_contracts``), so a value that
crosses into a shared contract needs no translation. Each boundary has one
reader and one writer here; a spelling that no table lists is refused with a
reason code rather than passed through, guessed, or folded into its nearest
neighbour.

A *profile* is a reviewed combination of OS, CPU and Python ABI, and every
profile carries a **purpose**:

* ``deployment-baseline`` -- the ADR-0002 baseline (Debian 13 / amd64). Only
  this purpose may back a production use: model admission, the HIL preflight,
  a hardware-gate (HG) record, a core-reserve record, product admission.
* ``lab-software-verification`` -- an Arm VM on which the *software* is
  exercised. Its results are VM software-integration evidence and nothing
  more; `DeploymentBaseline` cannot be constructed from it.

A profile does not authorize anything by itself, and it does not move the
deployment baseline: `hil_preflight.BASELINE_ARCHITECTURE` and
`compatibility.ADMITTED_ARCHITECTURE` keep their values, and a test holds
them equal to the kernel name of `DEPLOYMENT_BASELINE`. Asset digests that
legitimately differ per CPU (the llama runtime, native extensions, wheels,
Edge binaries) stay in the module that owns each pin, keyed by the boundary
name that module already uses.

Pure library: no I/O, no observation. Reading ``uname``, ``os-release`` or
``SOABI`` from a host is a runtime concern; this module only interprets the
strings it is given.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

AMD64 = "amd64"
ARM64 = "arm64"
#: Canonical names, in a stable order. Matches Fabric's ``Architecture``.
ARCHITECTURES: tuple[str, ...] = (AMD64, ARM64)

#: Boundary names, written once per CPU.
BOUNDARIES: tuple[str, ...] = ("kernel", "debian", "systemd", "multiarch", "fabric")
_NAMES: Mapping[str, Mapping[str, str]] = MappingProxyType({
    AMD64: MappingProxyType({
        "kernel": "x86_64", "debian": "amd64", "systemd": "x86-64",
        "multiarch": "x86_64-linux-gnu", "fabric": "amd64",
    }),
    ARM64: MappingProxyType({
        "kernel": "aarch64", "debian": "arm64", "systemd": "arm64",
        "multiarch": "aarch64-linux-gnu", "fabric": "arm64",
    }),
})

#: ``platform.machine()`` / ``uname -m`` spellings. Linux reports ``aarch64``;
#: ``arm64`` is what macOS and the BSDs report for the same CPU, and the
#: modules that read ``platform.machine()`` accepted it before this module
#: existed. ``amd64`` is deliberately absent: no caller of the machine reader
#: accepted it, and accepting it now would widen what they admit.
_MACHINE_ALIASES: Mapping[str, str] = MappingProxyType({
    "x86_64": AMD64, "aarch64": ARM64, "arm64": ARM64,
})

PURPOSE_DEPLOYMENT_BASELINE = "deployment-baseline"
PURPOSE_LAB_SOFTWARE_VERIFICATION = "lab-software-verification"
PURPOSES: tuple[str, ...] = (PURPOSE_DEPLOYMENT_BASELINE, PURPOSE_LAB_SOFTWARE_VERIFICATION)

#: Uses that need the deployment baseline. A lab profile is refused for each.
PRODUCTION_USES: frozenset[str] = frozenset({
    "model-admission",
    "product-admission",
    "hil-preflight",
    "hardware-gate-record",
    "core-reserve-record",
})

#: Reason codes. Stable strings: callers and records compare them.
UNKNOWN_ARCHITECTURE = "UNKNOWN_ARCHITECTURE"
UNKNOWN_BOUNDARY = "UNKNOWN_BOUNDARY"
UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
UNKNOWN_USE = "UNKNOWN_USE"
UNREVIEWED_OS = "UNREVIEWED_OS"
UNREVIEWED_PYTHON_ABI = "UNREVIEWED_PYTHON_ABI"
UNREVIEWED_COMBINATION = "UNREVIEWED_COMBINATION"
LAB_PROFILE_NOT_FOR_PRODUCTION = "LAB_PROFILE_NOT_FOR_PRODUCTION"


class PlatformRefused(ValueError):
    """A name or combination this module has not reviewed. Never a default."""

    def __init__(self, reason: str, value: object = None) -> None:
        super().__init__(f"{reason}: {value!r}")
        self.reason = reason
        self.value = value


def _text(value: object) -> str:
    if type(value) is not str or not value:
        raise PlatformRefused(UNKNOWN_ARCHITECTURE, value)
    return value


def canonical(architecture: object) -> str:
    """Return ``architecture`` if it is already a canonical name; refuse otherwise."""

    if _text(architecture) not in _NAMES:
        raise PlatformRefused(UNKNOWN_ARCHITECTURE, architecture)
    return architecture  # type: ignore[return-value]


def to_boundary(architecture: object, boundary: str) -> str:
    """The name ``boundary`` uses for a canonical architecture."""

    if boundary not in BOUNDARIES:
        raise PlatformRefused(UNKNOWN_BOUNDARY, boundary)
    return _NAMES[canonical(architecture)][boundary]


def from_boundary(boundary: str, raw: object) -> str:
    """Read exactly the spelling ``boundary`` uses. No aliases, no case folding."""

    if boundary not in BOUNDARIES:
        raise PlatformRefused(UNKNOWN_BOUNDARY, boundary)
    value = _text(raw)
    for architecture, names in _NAMES.items():
        if names[boundary] == value:
            return architecture
    raise PlatformRefused(UNKNOWN_ARCHITECTURE, raw)


def kernel_name(architecture: object) -> str:
    return to_boundary(architecture, "kernel")


def debian_name(architecture: object) -> str:
    return to_boundary(architecture, "debian")


def systemd_name(architecture: object) -> str:
    return to_boundary(architecture, "systemd")


def fabric_name(architecture: object) -> str:
    return to_boundary(architecture, "fabric")


def from_machine(raw: object) -> str:
    """Read a ``platform.machine()`` / ``uname -m`` value."""

    value = _text(raw)
    if value not in _MACHINE_ALIASES:
        raise PlatformRefused(UNKNOWN_ARCHITECTURE, raw)
    return _MACHINE_ALIASES[value]


def normalize_machine(raw: object) -> str:
    """Read a machine name or a Debian/Fabric name (``x86_64``, ``amd64``,
    ``aarch64``, ``arm64``). Used where a caller may hand either spelling,
    e.g. a runtime pin requested for a named target. systemd's ``x86-64`` is
    not accepted here; it is read only through `from_boundary`."""

    value = _text(raw)
    if value in _MACHINE_ALIASES:
        return _MACHINE_ALIASES[value]
    return from_boundary("debian", value)


#: Kernel names of the CPUs whose Linux LP64 libc boundary (``c_long`` is
#: 64-bit; ``statfs`` begins with a native long) has been reviewed.
LP64_REVIEWED_KERNEL_MACHINES: frozenset[str] = frozenset(
    kernel_name(architecture) for architecture in ARCHITECTURES
)


@dataclass(frozen=True)
class PlatformProfile:
    """A reviewed OS x CPU x Python ABI combination, and what it is for."""

    profile_id: str
    purpose: str
    os_id: str
    os_version_id: str
    architecture: str
    python_tag: str
    soabi: str
    features: frozenset[str]

    def __post_init__(self) -> None:
        canonical(self.architecture)
        if self.purpose not in PURPOSES:
            raise PlatformRefused(UNKNOWN_PROFILE, self.purpose)
        expected = f"cpython-{self.python_tag[2:]}-{to_boundary(self.architecture, 'multiarch')}"
        if self.soabi != expected:
            raise PlatformRefused(UNREVIEWED_PYTHON_ABI, self.soabi)
        is_lab = self.purpose == PURPOSE_LAB_SOFTWARE_VERIFICATION
        if self.profile_id.endswith("-lab") is not is_lab:
            # The identifier says what the profile is for, so a record that
            # carries only the id is still distinguishable from production.
            raise PlatformRefused(UNKNOWN_PROFILE, self.profile_id)

    @property
    def is_deployment_baseline(self) -> bool:
        """The reviewed baseline itself: purpose alone is not enough, since
        anyone can construct a profile that claims it."""

        return (self.purpose == PURPOSE_DEPLOYMENT_BASELINE
                and REVIEWED_PROFILES.get(self.profile_id) == self)


def _profile(profile_id, purpose, architecture):
    return PlatformProfile(
        profile_id=profile_id, purpose=purpose, os_id="debian", os_version_id="13",
        architecture=architecture, python_tag="cp313",
        soabi=f"cpython-313-{to_boundary(architecture, 'multiarch')}",
        features=frozenset({"linux-lp64-libc-reviewed", "systemd", "cgroup2"}),
    )


DEPLOYMENT_BASELINE = _profile(
    "debian-13-amd64-cp313", PURPOSE_DEPLOYMENT_BASELINE, AMD64)
ARM64_LAB = _profile(
    "debian-13-arm64-cp313-lab", PURPOSE_LAB_SOFTWARE_VERIFICATION, ARM64)

REVIEWED_PROFILES: Mapping[str, PlatformProfile] = MappingProxyType({
    profile.profile_id: profile for profile in (DEPLOYMENT_BASELINE, ARM64_LAB)
})


def profile(profile_id: object) -> PlatformProfile:
    if type(profile_id) is not str or profile_id not in REVIEWED_PROFILES:
        raise PlatformRefused(UNKNOWN_PROFILE, profile_id)
    return REVIEWED_PROFILES[profile_id]


def select_profile(*, os_id: object, os_version_id: object, machine: object,
                   soabi: object) -> PlatformProfile:
    """The reviewed profile for observed host facts, or a reasoned refusal.

    Exact matches only: ``os-release`` ``ID`` and ``VERSION_ID`` (never
    ``PRETTY_NAME``), the kernel's machine name, and the interpreter's SOABI.
    The first field that no reviewed profile has is the reason.
    """

    architecture = from_boundary("kernel", machine)
    candidates = [p for p in REVIEWED_PROFILES.values() if p.architecture == architecture]
    candidates = [p for p in candidates
                  if p.os_id == os_id and p.os_version_id == os_version_id]
    if not candidates:
        raise PlatformRefused(UNREVIEWED_OS, (os_id, os_version_id))
    matches = [p for p in candidates if p.soabi == soabi]
    if not matches:
        raise PlatformRefused(UNREVIEWED_PYTHON_ABI, soabi)
    if len(matches) != 1:
        raise PlatformRefused(UNREVIEWED_COMBINATION, tuple(p.profile_id for p in matches))
    return matches[0]


def _check_production_use(profile: object, use: object) -> None:
    if type(use) is not str or use not in PRODUCTION_USES:
        raise PlatformRefused(UNKNOWN_USE, use)
    if type(profile) is not PlatformProfile:
        raise PlatformRefused(LAB_PROFILE_NOT_FOR_PRODUCTION, profile)
    if profile.purpose != PURPOSE_DEPLOYMENT_BASELINE:
        raise PlatformRefused(LAB_PROFILE_NOT_FOR_PRODUCTION, profile.profile_id)
    if not profile.is_deployment_baseline:
        raise PlatformRefused(UNKNOWN_PROFILE, profile.profile_id)


@dataclass(frozen=True)
class DeploymentBaseline:
    """Proof that a profile was checked for a production use.

    The ordinary construction paths -- the constructor, `require_deployment_baseline`,
    `copy` and `pickle` (which re-run the constructor) -- refuse a lab profile,
    an unreviewed look-alike and an unknown use, and the class cannot be
    subclassed. Python cannot stop ``object.__new__`` plus
    ``object.__setattr__``, so a consumer that acts on one checks it again
    with `verify_deployment_baseline` rather than trusting the type alone.
    """

    profile: PlatformProfile
    use: str

    def __init_subclass__(cls, **kwargs):
        raise TypeError("DeploymentBaseline cannot be subclassed")

    def __post_init__(self) -> None:
        _check_production_use(self.profile, self.use)

    def __reduce__(self):
        # Restoring goes back through the constructor, so a pickled or
        # copied value is validated again rather than restored field by field.
        return (DeploymentBaseline, (self.profile, self.use))


def require_deployment_baseline(profile: PlatformProfile, use: str) -> DeploymentBaseline:
    """Refuse a lab (or unknown) profile for ``use``; never widen it."""

    return DeploymentBaseline(profile, use)


def verify_deployment_baseline(value: object, use: str) -> DeploymentBaseline:
    """What a production consumer calls on a value it was handed: the exact
    type, the use it needs, and the same checks as construction, again."""

    if type(value) is not DeploymentBaseline:
        raise PlatformRefused(LAB_PROFILE_NOT_FOR_PRODUCTION, type(value).__name__)
    _check_production_use(value.profile, value.use)
    if value.use != use:
        raise PlatformRefused(UNKNOWN_USE, value.use)
    return value
