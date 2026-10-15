"""Read-only resource observations, not a profile, benchmark or admission.

The mission filesystem must exist independently of the root filesystem; a
missing /data must never silently measure available space on the root disk.
No device is opened and no capacity/performance/accelerator value is guessed.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import re

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


def _mission_space() -> int:
    fd = os.open("/data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if os.fstat(fd).st_dev == os.stat("/").st_dev:
            raise ValueError("mission storage is not separate from root")
        usage = os.fstatvfs(fd)
        if (usage.f_frsize <= 0 or not 0 <= usage.f_bavail <= usage.f_bfree <= usage.f_blocks
                or usage.f_flag & os.ST_RDONLY):
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
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if architecture is None:
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
