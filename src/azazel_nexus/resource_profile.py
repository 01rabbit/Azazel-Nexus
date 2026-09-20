"""Which hardware class this node is, measured and nothing more (#26).

The selector answers one question — how much usable RAM does the OS report —
and turns the answer into one of four names. It answers no other question.
In particular it does not decide whether a capability fits, whether an
interface may carry a role, or whether anything may be enforced. Those are
settled elsewhere and on other evidence (`IMPLEMENTATION_SPEC.md` §2.2).

**The input is usable RAM as the OS reports it.** Nothing is subtracted from
it here. The thresholds already carry the firmware-reservation allowance --
7168 is 8192 − 1024, 15360 is 16384 − 1024, 31744 is 32768 − 1024 -- so
subtracting again applies the allowance twice and selects one tier low. That
is not a hypothetical: on the host the specification measured, 16,095 MiB
selects `lite`, and the same reading with a second 1024 MiB removed selects
`core`. The allowance exists precisely to keep a nominal 16 GB machine in the
tier its size deserves, and subtracting twice undoes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

__all__ = [
    "PROFILE_ORDER",
    "ResourceProfile",
    "ResourceReading",
    "UsableMemoryUnavailable",
    "read_usable_mib",
    "reduce_for_non_memory_resources",
    "select_profile",
    "take_reading",
]


class ResourceProfile(str, Enum):
    """A hardware class. Never a permission and never a capability."""

    DIAGNOSTIC = "diagnostic"
    CORE = "core"
    LITE = "lite"
    STANDARD = "standard"


#: Weakest to strongest, so that "may only reduce" is expressible as a
#: comparison rather than as a set of special cases.
PROFILE_ORDER = (
    ResourceProfile.DIAGNOSTIC,
    ResourceProfile.CORE,
    ResourceProfile.LITE,
    ResourceProfile.STANDARD,
)

#: `(floor in MiB, profile)`, strongest first.
#:
#: Each floor is a nominal module size minus a 1024 MiB firmware-reservation
#: allowance. A floor set at the nominal size itself would be wrong: usable
#: RAM is always below nominal, because firmware keeps memory for UEFI runtime
#: services, ACPI tables, kernel-reserved regions and -- the large, variable
#: term -- integrated-GPU stolen memory.
_FLOORS = (
    (31744, ResourceProfile.STANDARD),
    (15360, ResourceProfile.LITE),
    (7168, ResourceProfile.CORE),
)

_MEMTOTAL = re.compile(r"^MemTotal:\s+(?P<kib>\d+)\s+kB\s*$", re.M)


class UsableMemoryUnavailable(Exception):
    """The reading could not be taken, and no profile is guessed from that.

    A default here would be a hardware class asserted on no measurement. Every
    other refusal in this package works the same way: a fact the product does
    not hold is a refusal, never a default.
    """


def select_profile(usable_mib: int) -> ResourceProfile:
    """The whole selector. One input, one of four names.

    `usable_mib` is what the OS reports. It is used as given -- see the module
    docstring on why nothing is subtracted from it here.
    """

    if not isinstance(usable_mib, int) or isinstance(usable_mib, bool):
        raise UsableMemoryUnavailable(
            f"usable RAM must be an integer count of MiB, got {usable_mib!r}"
        )
    if usable_mib <= 0:
        raise UsableMemoryUnavailable(
            f"usable RAM reported as {usable_mib} MiB; a running system has "
            "memory, so this is a failed reading rather than a small machine"
        )

    for floor, profile in _FLOORS:
        if usable_mib >= floor:
            return profile
    return ResourceProfile.DIAGNOSTIC


def read_usable_mib(meminfo: Optional[Path] = None) -> int:
    """Usable RAM in MiB, from `MemTotal`.

    `MemTotal` is what the kernel reports as available to it after firmware
    has taken its share, which is the quantity the thresholds are written
    against. It is read as-is.
    """

    path = meminfo or Path("/proc/meminfo")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsableMemoryUnavailable(f"{path} could not be read: {exc}") from exc

    match = _MEMTOTAL.search(text)
    if match is None:
        raise UsableMemoryUnavailable(
            f"{path} has no MemTotal line; the reading failed rather than "
            "returning a small number"
        )
    return int(match.group("kib")) // 1024


@dataclass(frozen=True)
class ResourceReading:
    """What was measured, and the class it amounts to.

    `cpu_cores` and `storage_gib` are recorded because they may *reduce* the
    envelope. They are kept beside the profile rather than folded into it, so
    that a reader can see the memory-selected class and the reduction
    separately -- a single collapsed answer cannot say which input caused it.
    """

    usable_mib: int
    profile: ResourceProfile
    cpu_cores: Optional[int] = None
    storage_gib: Optional[int] = None

    def __post_init__(self) -> None:
        if self.profile is not select_profile(self.usable_mib):
            raise ValueError(
                f"{self.profile.value!r} is not what {self.usable_mib} MiB "
                "selects; the reading and its class must agree"
            )


def take_reading(
    meminfo: Optional[Path] = None,
    *,
    cpu_cores: Optional[int] = None,
    storage_gib: Optional[int] = None,
) -> ResourceReading:
    """Measure, classify, and record. Raises rather than guessing."""

    usable_mib = read_usable_mib(meminfo)
    return ResourceReading(
        usable_mib=usable_mib,
        profile=select_profile(usable_mib),
        cpu_cores=cpu_cores,
        storage_gib=storage_gib,
    )


def reduce_for_non_memory_resources(
    reading: ResourceReading, *, to: ResourceProfile
) -> ResourceProfile:
    """Apply a non-memory constraint. It may only ever lower the class.

    CPU count and storage are recorded and may independently reduce the
    envelope; they must not raise it above the RAM-selected value
    (`IMPLEMENTATION_SPEC.md` §2.1). Expressed as a refusal rather than a
    `min()` so that an attempt to raise it is an error a caller sees, not a
    silent no-op they never learn about.
    """

    if PROFILE_ORDER.index(to) > PROFILE_ORDER.index(reading.profile):
        raise ValueError(
            f"{reading.usable_mib} MiB selects {reading.profile.value!r}; a "
            f"non-memory resource cannot raise it to {to.value!r}. CPU and "
            "storage reduce the envelope and never extend it"
        )
    return to
