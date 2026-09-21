"""What each daemon may be, declared once and rendered into its unit (#42).

Issue #36's fourth boundary: **not every daemon is root.** A design where all
four run as root is one where least privilege is a comment, and the only
thing standing between a bug in the netlink parser and the whole host is that
the parser has no bug.

| Daemon | Account | Address families | Capabilities |
| --- | --- | --- | --- |
| `az-commissiond` | `azcommission` | `AF_UNIX AF_NETLINK` | none |
| `az-auditd` | `azaudit` | `AF_UNIX` | none |
| `az-watchdog` | `azwatch` | `AF_UNIX` | none |
| `az-activated` | `root` | `AF_UNIX` | none beyond root's |

`az-commissiond` reads `IFLA_PERM_ADDRESS` over a route netlink socket, which
needs no `CAP_NET_ADMIN` and no internet address family. It therefore gets
neither. `az-activated` is the exception and the reason the others are not:
unmasking a unit means writing under `/etc/systemd/system`, and isolating
that in one daemon is what makes the other three unprivileged.

## The units are generated from this table

`render_unit` produces the file, and `tests/unit/test_runtime_hardening.py`
asserts the committed files are exactly what it produces. A hardening setting
in a unit file that this table does not declare, or one declared here and
missing from the file, fails.

Hand-edited unit files drift. A generated one that nothing compares against
drifts silently, which is worse, so the comparison is the point rather than
the generation.

## What this proves, and what it does not

It proves the distribution is internally consistent: the units say what the
declaration says, the installer creates what the layout declares, and the
accounts each daemon needs are the accounts it is given.

It proves **nothing about what the operating system enforces**. Whether
systemd honours `RestrictAddressFamilies`, whether `IPAddressDeny=any`
actually blocks a socket, whether an unprivileged account is refused
`systemctl unmask` -- those are `HG-01` and `HG-02` in
`docs/hardware-gates.md`, and no CI run touches them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT, CORE_UNITS
from azazel_nexus.layout import LAYOUT

__all__ = [
    "PROFILES",
    "SHARED_HARDENING",
    "ServiceProfile",
    "SYSTEM_ACCOUNTS",
    "render_unit",
]

#: Applied to every unit, with no per-daemon exceptions.
#:
#: Ordered, because the rendered file is compared byte for byte against the
#: committed one and a set would render differently on different runs.
SHARED_HARDENING: tuple[tuple[str, str], ...] = (
    ("NoNewPrivileges", "yes"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "yes"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectControlGroups", "yes"),
    ("RestrictNamespaces", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("LockPersonality", "yes"),
    ("MemoryDenyWriteExecute", "yes"),
    ("SystemCallArchitectures", "native"),
    ("SystemCallFilter", "@system-service"),
    # Empty on purpose. A bounding set is what a daemon may ever acquire, and
    # none of these needs anything: the one that talks to the kernel does it
    # over a route netlink socket, which is a read.
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    # Nothing here listens on a network. The static scan proves the code has
    # no such path; this is the same statement to the service manager, which
    # is the half that would stop one if it appeared.
    ("IPAddressDeny", "any"),
    ("UMask", "0027"),
)


@dataclass(frozen=True)
class ServiceProfile:
    """One daemon, and everything its unit says about what it may be."""

    unit: str
    executable: str
    account: str
    description: str
    documentation: str
    address_families: tuple[str, ...]
    read_write_paths: tuple[str, ...]
    after: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    unit_type: str = "notify"
    runtime_directory: str = "azazel"
    runtime_directory_mode: str = "0750"
    extra: tuple[tuple[str, str], ...] = ()
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.address_families:
            raise ValueError(
                f"{self.unit} declares no address family. `AF_UNIX` at least "
                "is required to be reachable at all, and a unit whose families "
                "are unstated inherits whatever systemd's default is"
            )
        forbidden = {"AF_INET", "AF_INET6", "AF_PACKET"}
        overlap = sorted(set(self.address_families) & forbidden)
        if overlap:
            raise ValueError(
                f"{self.unit} would be allowed {overlap}. Nothing in this "
                "product listens on a network, and a daemon that could open "
                "an internet socket makes `IPAddressDeny=any` the only thing "
                "standing between it and one"
            )
        declared = {spec.path for spec in LAYOUT} | {"/etc/systemd/system"}
        outside = sorted(set(self.read_write_paths) - declared)
        if outside:
            raise ValueError(
                f"{self.unit} would write to {outside}, which the filesystem "
                "layout does not declare. A writable path nobody declared is a "
                "path nobody set the mode or the owner of"
            )


#: The accounts the installer creates. `root` is not among them: it exists.
SYSTEM_ACCOUNTS = ("azcommission", "azaudit", "azwatch", "azprobe")


PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        unit=ACTIVATION_CONTROLLER_UNIT,
        executable="/usr/libexec/azazel/az-activated",
        account="root",
        description="Azazel-Nexus activation controller",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/IMPLEMENTATION_SPEC.md",
        address_families=("AF_UNIX",),
        read_write_paths=(
            "/var/lib/azazel",
            "/var/lib/azazel/generations",
            "/var/lib/azazel/state",
            "/etc/systemd/system",
        ),
        unit_type="oneshot",
        extra=(("RemainAfterExit", "yes"),),
        rationale=(
            "The one daemon that runs as root, and the reason the other three "
            "do not: unmasking a unit means writing under /etc/systemd/system, "
            "and isolating that here is what leaves the rest unprivileged."
        ),
    ),
    ServiceProfile(
        unit="azazel-commissiond.service",
        executable="/usr/libexec/azazel/az-commissiond",
        account="azcommission",
        description="Azazel-Nexus commissioning daemon",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/commissioning.md",
        address_families=("AF_UNIX", "AF_NETLINK"),
        read_write_paths=("/etc/azazel/commissioning", "/var/lib/azazel/run"),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        rationale=(
            "Reads IFLA_PERM_ADDRESS over a route netlink socket, which needs "
            "neither CAP_NET_ADMIN nor an internet address family. It gets "
            "neither. It is not root."
        ),
    ),
    ServiceProfile(
        unit="azazel-auditd.service",
        executable="/usr/libexec/azazel/az-auditd",
        account="azaudit",
        description="Azazel-Nexus audit ledger",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/IMPLEMENTATION_SPEC.md",
        address_families=("AF_UNIX",),
        read_write_paths=("/var/lib/azazel/run", "/var/lib/azazel/state"),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        rationale=(
            "Appends to a hash chain on local storage. It needs no capability "
            "and no network, and it is the single writer, so nothing else "
            "needs write access to the chain."
        ),
    ),
    ServiceProfile(
        unit="azazel-watchdog.service",
        executable="/usr/libexec/azazel/az-watchdog",
        account="azwatch",
        description="Azazel-Nexus degradation coordinator",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/capability-model.md",
        address_families=("AF_UNIX",),
        read_write_paths=("/var/lib/azazel/run", "/var/lib/azazel/state"),
        after=("azazel-auditd.service",),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        rationale=(
            "Can mask and cannot unmask. Masking a unit it does not own is "
            "brokered by the activation controller's socket, so it needs no "
            "privilege of its own."
        ),
    ),
    ServiceProfile(
        unit="azazel-edge-probed.service",
        executable="/usr/libexec/azazel/az-edge-probed",
        account="azprobe",
        description="Azazel-Nexus Edge health and running probe",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/edge-package-verification.md",
        address_families=("AF_UNIX",),
        read_write_paths=("/var/lib/azazel/run",),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        unit_type="oneshot",
        rationale=(
            "Runs once and exits. It executes exactly two things -- the Edge "
            "health contract at a fixed path, and a read-only D-Bus property "
            "query -- and it writes one bounded file. It is not root, it "
            "takes no argument that could redirect it, and `AF_UNIX` is all "
            "it needs: "
            "the D-Bus connection it reads unit state over is one. It writes "
            "into the operator plane's own directory, which already answers "
            "who may read what is there, and the result holds no secret: a "
            "version, a digest, two verdicts and their reasons."
        ),
    ),
)


def render_unit(profile: ServiceProfile) -> str:
    """The unit file for one profile, byte for byte.

    Deterministic: every sequence is ordered by the declaration rather than by
    a set, so two runs produce the same file and the committed one can be
    compared against it.
    """

    lines = [
        "# Generated from azazel_nexus_runtime.hardening. Do not edit by hand:",
        "# tests/unit/test_runtime_hardening.py compares this file against what",
        "# the declaration renders, and a hand edit is a difference.",
        "#",
    ]
    for line in profile.rationale.split(". "):
        if line.strip():
            lines.append("# " + line.strip().rstrip(".") + ".")
    lines += [
        "",
        "[Unit]",
        f"Description={profile.description}",
        f"Documentation={profile.documentation}",
    ]
    for unit in profile.after:
        lines.append(f"After={unit}")
    for unit in profile.requires:
        lines.append(f"Requires={unit}")
    lines += [
        "",
        "[Service]",
        f"Type={profile.unit_type}",
        f"User={profile.account}",
        f"ExecStart={profile.executable}",
        f"RuntimeDirectory={profile.runtime_directory}",
        f"RuntimeDirectoryMode={profile.runtime_directory_mode}",
    ]
    for key, value in profile.extra:
        lines.append(f"{key}={value}")
    lines.append(
        "RestrictAddressFamilies=" + " ".join(profile.address_families)
    )
    for path in profile.read_write_paths:
        lines.append(f"ReadWritePaths={path}")
    for key, value in SHARED_HARDENING:
        lines.append(f"{key}={value}")
    lines += ["", "[Install]", "WantedBy=multi-user.target", ""]
    return "\n".join(lines)


def governed_units() -> tuple[str, ...]:
    """The units the activation controller governs, from the library."""

    return tuple(definition.name for definition in CORE_UNITS)
