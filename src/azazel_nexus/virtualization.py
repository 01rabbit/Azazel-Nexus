"""Negative virtualization filter contract; absence of a signal proves no hardware property."""
SENSORS = ("hypervisor_type", "cpu_hypervisor", "systemd_container", "dockerenv",
           "dmi_vendor", "dmi_product", "init_cgroup")


def virtualization_not_observed(observations) -> bool:
    return (type(observations) is dict and set(observations) == set(SENSORS)
            and all(type(v) is str and v in ("absent", "clear")
                    for v in observations.values())
            and observations["cpu_hypervisor"] == "clear"
            and observations["dmi_vendor"] == "clear"
            and observations["dmi_product"] == "clear"
            and observations["init_cgroup"] == "clear")
