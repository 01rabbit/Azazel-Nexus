"""Read-only resource observations, not a profile, benchmark or admission.

The mission filesystem must exist independently of the root filesystem; a
missing /data must never silently measure available space on the root disk.
No device is opened and no capacity/performance/accelerator value is guessed.

Superblock rule: the root controller runs under ProtectSystem=strict, where
/data is a read-only bind mount, so statvfs reports ST_RDONLY for the mount
even though the filesystem is writable. That per-mount flag is accepted only
when /proc/self/mountinfo has exactly one entry for mount point /data whose
major:minor equals the opened /data descriptor's st_dev and whose superblock
options contain "rw" (and not "ro"). A missing, duplicate, ambiguous or
malformed /data entry, or a read-only superblock, refuses the measurement.
The per-mount ro flag is deliberately ignored: the figure is free space on a
writable filesystem, not proof that this process may write there; the
existing "storage-trust-unverified" limitation covers it (the observation
limitation set is a fixed Fabric contract). Writes still need an explicit grant.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import re

from azazel_nexus import platform_profile
from azazel_nexus.resource_profile import UsableMemoryUnavailable, read_usable_mib


def _online_cores() -> int:
    text = Path("/sys/devices/system/cpu/online").read_text(encoding="ascii").strip()
    if len(text) > 65536 or not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", text):
        raise ValueError("invalid online CPU set")
    seen = set()
    for part in text.split(","):
        ends = part.split("-")
        start, end = int(ends[0]), int(ends[-1])
        if not 0 <= start <= end < 65536:
            raise ValueError("invalid CPU range")
        values = set(range(start, end + 1))
        if seen & values:
            raise ValueError("overlapping CPU range")
        seen.update(values)
    return len(seen)


_MOUNTINFO_LIMIT = 1024 * 1024


def _read_mountinfo() -> str:
    fd = os.open("/proc/self/mountinfo", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MOUNTINFO_LIMIT:
                raise ValueError("mountinfo too large")
            chunks.append(chunk)
    finally:
        os.close(fd)
    # The kernel escapes only whitespace and backslash in paths; other bytes
    # pass through, so never fail the whole read on one non-UTF-8 mount point.
    return b"".join(chunks).decode("utf-8", errors="surrogateescape")


def _superblock_writable(device: int) -> bool:
    """True only for exactly one /data mount of `device` with an rw superblock.

    Only lines that could be the /data entry are validated strictly; an
    unrelated exotic mount elsewhere in the namespace does not refuse admission.
    A line too short to rule out is treated as a candidate and refuses.
    """
    wanted = f"{os.major(device)}:{os.minor(device)}"
    matches = []
    for line in _read_mountinfo().split("\n"):
        if not line:
            continue
        fields = line.split(" ")
        if len(fields) < 5:
            raise ValueError("malformed mountinfo")
        if fields[2] != wanted and fields[4] != "/data":
            continue
        try:
            sep = fields.index("-", 6)
        except ValueError:
            raise ValueError("malformed mountinfo") from None
        if (len(fields) - sep != 4 or not all(fields[:2]) or not fields[0].isascii()
                or not fields[0].isdigit() or not fields[1].isdigit()
                or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2]) or not fields[4].startswith("/")):
            raise ValueError("malformed mountinfo")
        if fields[2] == wanted and fields[4] == "/data":
            matches.append(fields[sep + 3].split(","))
    if len(matches) != 1:
        return False
    return "rw" in matches[0] and "ro" not in matches[0]


def _mission_space() -> int:
    fd = os.open("/data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if os.fstat(fd).st_dev == os.stat("/").st_dev:
            raise ValueError("mission storage is not separate from root")
        usage = os.fstatvfs(fd)
        if (usage.f_frsize <= 0 or not 0 <= usage.f_bavail <= usage.f_bfree <= usage.f_blocks):
            raise ValueError("mission filesystem space is unavailable")
        if usage.f_flag & os.ST_RDONLY and not _superblock_writable(os.fstat(fd).st_dev):
            raise ValueError("mission filesystem space is unavailable")
        return usage.f_bavail * usage.f_frsize // (1024 * 1024)
    finally:
        os.close(fd)


def assess_resources() -> dict:
    """Aggregate-only observations; missing measurements stay explicitly null.

    CPU count is online logical CPUs, not physical cores or throughput.
    Storage is caller-available filesystem space, not raw disk capacity and
    not proof of encryption, durable mounting or trust. GPU is unmeasured.
    """
    readings = {}
    unavailable = []
    collectors = {
        "usable_memory_mib": read_usable_mib,
        "online_logical_cpus": _online_cores,
        "mission_available_mib": _mission_space,
    }
    for field, collect in collectors.items():
        try:
            value = collect()
            if type(value) is not int or value < 0 or (field != "mission_available_mib" and value == 0):
                raise ValueError("invalid observation")
            readings[field] = value
        except (OSError, ValueError, UsableMemoryUnavailable):
            readings[field] = None
            unavailable.append(field)
    # Fabric's ResourceProfile.cpu_architecture spelling (ADR-0003).
    try:
        architecture = platform_profile.fabric_name(platform_profile.from_machine(platform.machine()))
    except platform_profile.PlatformRefused:
        architecture = None
        unavailable.append("architecture")
    return {
        "schema": "azazel-nexus/resource-observation/v1",
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "architecture": architecture,
        "measurements": readings,
        "unavailable": unavailable,
        "limitations": ["gpu-unmeasured", "throughput-unmeasured", "thermal-power-unmeasured",
                        "cgroup-limits-unmeasured", "storage-trust-unverified"],
        "admission": "not-evaluated",
    }
