"""Bounded file-only virtualization observations, with no command execution."""
import re
from pathlib import Path

from azazel_nexus.model_paths import bounded_read

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
            else:
                observed = bool(_VIRTUAL.search(value))
            result[sensor] = "observed" if observed else "clear"
        except FileNotFoundError:
            result[sensor] = "absent"
        except (OSError, ValueError, UnicodeError):
            result[sensor] = "unknown"
    return result
