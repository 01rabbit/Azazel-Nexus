"""Bounded file-only virtualization observations, with no command execution.

``cpu_hypervisor`` reads the x86 ``hypervisor`` cpuinfo flag. A cpuinfo
without an x86 ``flags`` line (aarch64 publishes ``Features`` instead) cannot
show that flag, so the sensor reads ``unobservable`` there, never ``clear``
(ADR-0003 R1; `azazel_nexus.virtualization`).
"""
import re
from pathlib import Path

from azazel_nexus.model_paths import bounded_read
from azazel_nexus.virtualization import UNOBSERVABLE

_FILES = {
    "hypervisor_type": "/sys/hypervisor/type", "cpu_hypervisor": "/proc/cpuinfo",
    "systemd_container": "/run/systemd/container", "dockerenv": "/.dockerenv",
    "dmi_vendor": "/sys/class/dmi/id/sys_vendor",
    "dmi_product": "/sys/class/dmi/id/product_name", "init_cgroup": "/proc/1/cgroup",
}
_VIRTUAL = re.compile(r"qemu|kvm|vmware|virtualbox|innotek|xen|microsoft corporation|"
                      r"virtual machine|bochs|parallels|bhyve|amazon ec2|google compute|"
                      r"openstack|apple virtualization|docker|lxc|kubepods|containerd|podman",
                      re.IGNORECASE)
_X86_FLAGS = re.compile(r"^flags\s*:", re.MULTILINE)


def observe_virtualization():
    result = {}
    for sensor, name in _FILES.items():
        try:
            # Sysfs DMI leaves may have legitimate kernel symlink ancestors;
            # these fixed kernel observation paths never carry admission data.
            if sensor in ("systemd_container", "dockerenv") and Path(name).exists():
                result[sensor] = "observed"
                continue
            value = bounded_read(Path(name), 1024 * 1024).decode("utf-8")
            if sensor == "hypervisor_type":
                observed = bool(value.strip())
            elif sensor == "cpu_hypervisor":
                observed = bool(re.search(r"\bhypervisor\b", value))
                if not observed and not _X86_FLAGS.search(value):
                    result[sensor] = UNOBSERVABLE
                    continue
            else:
                observed = bool(_VIRTUAL.search(value))
            result[sensor] = "observed" if observed else "clear"
        except FileNotFoundError:
            result[sensor] = "absent"
        except (OSError, ValueError, UnicodeError):
            result[sensor] = "unknown"
    return result
