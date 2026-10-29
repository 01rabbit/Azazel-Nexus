"""Negative virtualization filter contract; absence of a signal proves no hardware property.

Each sensor reads one of:

* ``observed`` -- a virtualization/container signal was seen;
* ``clear`` -- the sensor was read and showed no such signal (a negative
  finding, and only that);
* ``absent`` -- the file the sensor reads does not exist;
* ``unknown`` -- the file could not be read;
* ``unobservable`` -- ``cpu_hypervisor`` only: ``/proc/cpuinfo`` carries no
  x86 ``flags`` line, so the x86 ``hypervisor`` flag cannot be read at all
  (aarch64; ADR-0003 R1). It is not a negative finding.

The filter never counts ``unobservable``, ``absent`` or ``unknown`` as a
negative finding. ``dmi_vendor``, ``dmi_product`` and ``init_cgroup`` must
each read ``clear`` on every CPU, so a host where those cannot be observed
(for example an Arm board without DMI) is refused: nothing observed is not
"not virtualized". On arm64 the decision rests on those generic sensors only;
that DMI names the hypervisor was observed on one VMware Fusion Arm guest and
is not assumed of any other platform.

``architecture`` is the CPU the observations were taken on (a canonical name
or a ``uname -m`` spelling). On arm64 ``cpu_hypervisor`` must read
``unobservable``: ``clear`` there is the reading of a flag that does not exist
(observers before 2026-10-30 wrote it) and is refused, not reinterpreted. On
amd64, and when no architecture is given (every amd64-only reader), the x86
flag must have been read: ``clear``. Any other architecture is refused.
"""

SENSORS = ("hypervisor_type", "cpu_hypervisor", "systemd_container", "dockerenv",
           "dmi_vendor", "dmi_product", "init_cgroup")

#: ``cpu_hypervisor`` on a CPU whose cpuinfo has no x86 ``flags`` line.
UNOBSERVABLE = "unobservable"

#: Sensors that must have been read and found clear on every CPU.
REQUIRED_CLEAR = ("dmi_vendor", "dmi_product", "init_cgroup")


def expected_cpu_flag(architecture) -> str | None:
    """The only ``cpu_hypervisor`` value a negative finding may carry on
    ``architecture``; None refuses the architecture."""

    if architecture is None:
        return "clear"
    from . import platform_profile

    try:
        canonical = platform_profile.normalize_machine(architecture)
    except platform_profile.PlatformRefused:
        return None
    return {platform_profile.AMD64: "clear",
            platform_profile.ARM64: UNOBSERVABLE}.get(canonical)


def virtualization_not_observed(observations, architecture=None) -> bool:
    if not (type(observations) is dict and set(observations) == set(SENSORS)
            and all(type(v) is str for v in observations.values())):
        return False
    expected = expected_cpu_flag(architecture)
    if expected is None or observations["cpu_hypervisor"] != expected:
        return False
    return (all(observations[sensor] in ("absent", "clear")
                for sensor in SENSORS if sensor != "cpu_hypervisor")
            and all(observations[sensor] == "clear" for sensor in REQUIRED_CLEAR))
