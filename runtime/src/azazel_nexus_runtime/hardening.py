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
| `az-activated` | `root` | `AF_UNIX AF_NETLINK` | `CAP_DAC_READ_SEARCH` only |

`az-commissiond` reads `IFLA_PERM_ADDRESS` over a route netlink socket, which
needs no `CAP_NET_ADMIN` and no internet address family. It therefore gets
neither. Activation also rechecks that read-only inventory before consuming
full commissioning evidence; its capability bounding set is exactly
CAP_DAC_READ_SEARCH (to read the audit state and reach the operator-group
sockets, with supplementary group azazel-operator) and no internet family
is added. `az-activated` is the root-account exception:
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
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT

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
    binds_to: tuple[str, ...] = ()
    unit_type: str = "notify"
    runtime_directory: str = "azazel"
    runtime_directory_mode: str = "0750"
    extra: tuple[tuple[str, str], ...] = ()
    rationale: str = ""
    #: Whether this unit is the artifact fetch service.
    #:
    #: Exactly one profile sets it, and setting it is the only way an
    #: internet address family may appear below. It is a field rather than a
    #: list of exempt unit names because a unit that wanted egress has to be
    #: *declared* as the fetcher -- and `test_runtime_hardening.py` asserts
    #: that at most one profile is, so a second would be a diff a reviewer
    #: sees rather than a set that grew.
    #:
    #: It does **not** open the address range. `IPAddressDeny=any` still
    #: applies; the addresses a fetcher may reach arrive as a commissioning
    #: drop-in built from the Source Registry, so shipping this unit ships a
    #: service that can reach nothing.
    is_artifact_fetcher: bool = False
    #: Whether this unit is the local model runtime host.
    #:
    #: Same containment discipline as `is_artifact_fetcher`, for the opposite
    #: hazard. The fetcher may reach the network and may not run a program;
    #: this one may run a program -- from `model_runtime.RUNTIMES`, which is
    #: pinned -- and may reach nothing.
    #:
    #: Setting it **requires** the resource ceilings below, because a process
    #: this node did not write is a process whose appetite this node did not
    #: choose. A host declared without them cannot be built, so the ceilings
    #: cannot be dropped in a refactor that keeps the flag.
    is_model_host: bool = False
    #: Whether this unit is the remote inference transport.
    #:
    #: The third and last exemption kind, and the one that carries the most:
    #: the fetcher pulls public bytes **in**, this pushes what the node
    #: **saw** out. It is a separate flag rather than reuse of
    #: `is_artifact_fetcher` precisely so that the fetcher's account,
    #: allowlist and egress exception are not the ones this runs under.
    #:
    #: Like the fetcher it may take an internet address family, and like the
    #: fetcher it still carries `IPAddressDeny=any`: the addresses it may
    #: reach arrive as a commissioning drop-in built from the signed Provider
    #: Registry, so shipping this unit ships a service that can reach nothing.
    is_inference_transport: bool = False
    #: Extra systemd unit conditions, rendered in declaration order.
    conditions: tuple[tuple[str, str], ...] = ()
    default_dependencies: bool = True
    before: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    #: Explicit supplementary groups for the controller and trust publisher.
    supplementary_groups: tuple[str, ...] = ()
    #: Capability bounding set override; empty means the shared empty set.
    #: AmbientCapabilities stays empty for every unit (uid 0 gains the
    #: bounding-set capabilities on exec; nothing is granted to non-root).
    capability_bounding_set: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.address_families:
            raise ValueError(
                f"{self.unit} declares no address family. `AF_UNIX` at least "
                "is required to be reachable at all, and a unit whose families "
                "are unstated inherits whatever systemd's default is"
            )
        reaches_network = self.is_artifact_fetcher or self.is_inference_transport
        forbidden = {"AF_PACKET"} | (
            set() if reaches_network else {"AF_INET", "AF_INET6"}
        )
        overlap = sorted(set(self.address_families) & forbidden)
        if overlap:
            raise ValueError(
                f"{self.unit} would be allowed {overlap}. Nothing in this "
                "product listens on a network, and a daemon that could open "
                "an internet socket makes `IPAddressDeny=any` the only thing "
                "standing between it and one"
            )
        if reaches_network and not (
            set(self.address_families) & {"AF_INET", "AF_INET6"}
        ):
            raise ValueError(
                f"{self.unit} is declared a network-reaching service and is "
                "allowed no internet address family. An exemption nothing uses "
                "is a hole held open for nothing"
            )
        roles = [
            name
            for name, held in (
                ("artifact fetcher", self.is_artifact_fetcher),
                ("model host", self.is_model_host),
                ("inference transport", self.is_inference_transport),
            )
            if held
        ]
        if len(roles) > 1:
            raise ValueError(
                f"{self.unit} would hold {roles} at once. Pulling public bytes "
                "in, running a program, and pushing what this node observed "
                "out are three acts with three blast radii; a unit holding two "
                "of them is a node where one compromise is two"
            )
        if self.is_model_host:
            settings = dict(self.extra)
            # What a unit file can state without a measurement: a share of
            # the CPU, a process ceiling, a file-size ceiling, and no network
            # stack at all.
            missing = [
                key
                for key in ("CPUQuota", "TasksMax", "LimitFSIZE", "PrivateNetwork")
                if key not in settings
            ]
            if missing:
                raise ValueError(
                    f"{self.unit} hosts a model runtime and declares no "
                    f"{missing}. An unbounded provider decides how much of "
                    "this node the deterministic path gets"
                )
            if settings["PrivateNetwork"] != "yes":
                raise ValueError(
                    f"{self.unit} hosts a model runtime and is not on a "
                    "private network namespace. A model that can open a "
                    "connection is a model that can carry what it was shown"
                )
            # MemoryMax is an aggregate safety ceiling, never evidence of
            # fit. Admission still derives qualified provider needs from HG-05.
            # `RuntimeMaxSec` bounds how long the **unit** runs. The deadline
            # this product needs bounds one inference. Putting the inference
            # deadline on the host would terminate a healthy long-running
            # service on a timer and call it a failure -- a restart loop
            # indistinguishable, from the journal, from a provider that keeps
            # dying.
            forbidden = [
                key for key in ("RuntimeMaxSec",) if key in settings
            ]
            if forbidden:
                raise ValueError(
                    f"{self.unit} states {forbidden} in its unit file. Those "
                    "are per-provider bounds derived from a measurement this "
                    "node does not have, and a static value for either is an "
                    "invented one. They belong to the scope one provider runs "
                    "in, not to the host"
                )
        declared = {spec.path for spec in LAYOUT} | {
            "/etc/systemd/system", "/run/systemd/system.control",
            "/run/azazel-nexus-bootstrap",
        }
        if ("/run/systemd/system.control" in self.read_write_paths
                and self.unit != ACTIVATION_CONTROLLER_UNIT):
            raise ValueError("bootstrap overlay is writable only by the activation controller")
        outside = sorted(set(self.read_write_paths) - declared)
        if outside:
            raise ValueError(
                f"{self.unit} would write to {outside}, which the filesystem "
                "layout does not declare. A writable path nobody declared is a "
                "path nobody set the mode or the owner of"
            )


#: The accounts the installer creates. `root` is not among them: it exists.
SYSTEM_ACCOUNTS = (
    "azcommission",
    "azaudit",
    "azwatch",
    "azprobe",
    "azfetch",
    "azmio",
    "azmioentry",
    "azremote",
    "azknowledge",
)


PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        unit=ACTIVATION_CONTROLLER_UNIT,
        executable="/usr/libexec/azazel/az-activated",
        account="root",
        description="Azazel-Nexus activation controller",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/IMPLEMENTATION_SPEC.md",
        after=("systemd-tmpfiles-setup.service", "sysinit.target", "basic.target"),
        address_families=("AF_UNIX", "AF_NETLINK"),
        read_write_paths=(
            "/var/lib/azazel",
            "/var/lib/azazel/generations",
            "/var/lib/azazel/state",
            "/etc/systemd/system",
            "/run/systemd/system.control",
            "/run/azazel-nexus-bootstrap",
        ),
        conditions=(
            ("ConditionPathExists", "!/run/azazel-nexus-bootstrap/controller-used"),
        ),
        default_dependencies=False,
        before=("shutdown.target",),
        conflicts=("shutdown.target",),
        # Owner-approved: the root controller runs without CAP_DAC_*, so it
        # could not open the 0700 audit state or traverse the 2710 operator
        # run directories and connect to the 0660 operator-group sockets.
        # Exactly one capability (CAP_DAC_READ_SEARCH, bit 2, mask 0x4) and
        # exactly one supplementary group; Ambient stays empty.
        supplementary_groups=("azazel-operator",),
        capability_bounding_set=("CAP_DAC_READ_SEARCH",),
        # The owner-adopted controller lifetime is long-lived Type=notify:
        # mandatory preflight/admission must precede READY, and READY must
        # precede waits on helper units ordered After this controller. The
        # selected activated entrypoint retains this supervisor through cleanup.
        unit_type="notify",
        extra=(("Restart", "no"), ("KillMode", "control-group"),
               ("NotifyAccess", "main"), ("WatchdogSec", "30s"),
               ("WatchdogSignal", "SIGKILL"),
               ("TimeoutStartSec", "30s"), ("TimeoutStopSec", "10s"),
               ("TimeoutStartFailureMode", "kill"),
               ("TimeoutStopFailureMode", "kill"),
               ("KillSignal", "SIGTERM"), ("FinalKillSignal", "SIGKILL"),
               ("SendSIGKILL", "yes"),
               ("SetLoginEnvironment", "no"),
               # systemd >= 254 otherwise bind-mounts the unit's memory.pressure
               # writable below the read-only /sys/fs/cgroup; the cgroup mount
               # admission refuses any mount below it.
               ("MemoryPressureWatch", "off"),
               ("UnsetEnvironment", " ".join(BOOTSTRAP_UNSET_ENVIRONMENT))),
        rationale=(
            "The one daemon that runs as root, and the reason the other three "
            "do not: unmasking a unit means writing under /etc/systemd/system, "
            "and isolating that here is what leaves the rest unprivileged. "
            "Read-only route netlink rechecks full commissioning evidence; "
            "no network-admin capability or internet address family is granted."
        ),
    ),
    ServiceProfile(
        unit="azazel-model-fetchd.service",
        executable="/usr/libexec/azazel/az-model-fetchd",
        account="azfetch",
        description="Azazel-Nexus artifact fetch service",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/source-registry.md",
        address_families=("AF_UNIX", "AF_INET", "AF_INET6"),
        # Its staging tree and its own socket leaf (installer-owned
        # azfetch:azazel-operator 2710), never the whole run tree: partials,
        # ready handoffs and refusals all live under /var/lib/azazel/fetch,
        # and fetch.sock is the only thing it creates under run.
        read_write_paths=("/var/lib/azazel/fetch", "/var/lib/azazel/run/fetch"),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        is_artifact_fetcher=True,
        # Its own runtime directory, not the one shared with the operator
        # plane: the socket this service answers on is reachable only by
        # whatever is commissioned to ask for a fetch.
        runtime_directory="azazel/fetch",
        runtime_directory_mode="0750",
        extra=(
            # A transfer that fails repeatedly must not fill the journal with
            # the same refusal, and a journal nobody can read is a journal
            # nobody reads.
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "50"),
            ("LogExtraFields", "AZ_SERVICE=model-fetch"),
        ),
        rationale=(
            "The only unit in this product allowed an internet address "
            "family, and the only one that needs one: it fetches model "
            "artifacts whose digest was declared before the connection was "
            "made. It is not root, it writes one directory, and it still "
            "carries IPAddressDeny=any -- the addresses it may reach arrive "
            "as a commissioning drop-in built from the signed Source "
            "Registry, so this unit as shipped can reach nothing. Adding a "
            "real endpoint is a change to commissioned data that is reviewed "
            "and signed, never a change to this file."
        ),
    ),
    ServiceProfile(
        unit="azazel-mio-remoted.service",
        executable="/usr/libexec/azazel/az-mio-remoted",
        account="azremote",
        description="Azazel-Nexus remote inference transport",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/remote-inference.md",
        address_families=("AF_UNIX", "AF_INET", "AF_INET6"),
        # Its own socket leaf (installer-owned azremote:azazel-operator
        # 2710), never the whole run tree.
        read_write_paths=("/var/lib/azazel/remote", "/var/lib/azazel/run/remote"),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        is_inference_transport=True,
        # Its own runtime directory. The socket that could send what this
        # node observed is not the socket everything else answers on, and it
        # is not the fetcher's.
        runtime_directory="azazel/remote",
        runtime_directory_mode="0750",
        extra=(
            # A provider that fails repeatedly must not fill the journal with
            # the same refusal, and a journal nobody can read is a journal
            # nobody reads.
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "50"),
            ("LogExtraFields", "AZ_SERVICE=mio-remote"),
        ),
        rationale=(
            "The only unit that could send what this node observed, and it "
            "sends nothing: no Provider Registry is commissioned and no key "
            "holds the sanitizer role, so no provider symbol resolves and no "
            "envelope verifies. It is not root, it writes one directory, and "
            "it runs under its own account -- never the fetcher's and never "
            "the local runtime's. azfetch pulls public bytes in; azremote "
            "pushes what this node saw out; a node where one credential did "
            "both is a node where one compromise is two. IPAddressDeny=any "
            "stays on it: the addresses it may reach arrive as a "
            "commissioning drop-in built from the signed Provider Registry, "
            "so this unit as shipped can reach nothing."
        ),
    ),
    ServiceProfile(
        unit="azazel-mio-locald.service",
        executable="/usr/libexec/azazel/az-mio-locald",
        account="azmio",
        description="Azazel-Nexus local model runtime host",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/mio-local-runtime.md",
        address_families=("AF_UNIX",),
        # Its own socket leaf, never the whole run tree: the installer owns
        # /var/lib/azazel/run/mio as azmio:azazel-operator 2710, and nothing
        # else under /var/lib/azazel/run -- including the legacy unattested
        # core-reserve.json -- is this service's to write.
        read_write_paths=("/var/lib/azazel/mio", "/var/lib/azazel/run/mio"),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        is_model_host=True,
        supplementary_groups=("azknowledge-read", "azmission-read"),
        # Its own runtime directory. The socket that could start a process is
        # not the socket everything else answers on.
        runtime_directory="azazel/mio",
        runtime_directory_mode="0750",
        extra=(
            ("ExecStartPre", "+/usr/libexec/azazel/az-mio-identity"),
            # Fixed host safety limits; measured admission remains independent.
            ("ReadOnlyPaths", "-/etc/azazel/model-admission"),
            ("ReadOnlyPaths", "-/etc/azazel/operator-trust"),
            ("ReadOnlyPaths", "-/var/lib/azazel/models"),
            ("ReadOnlyPaths", "-/etc/azazel/mission-pack.json"),
            ("ReadOnlyPaths", "-/data/azazel/mission-packs"),
            # Two bounded 120s startups plus verification; not an inference deadline.
            ("TimeoutStartSec", "300s"),
            # Aggregate safety ceiling for daemon + both children, not HG-05 evidence.
            ("MemoryMax", "4G"),
            ("MemorySwapMax", "0"),
            ("CPUQuota", "40%"),
            ("TasksMax", "64"),
            ("LimitFSIZE", "16777216"),
            # On top of IPAddressDeny=any, which every unit here carries.
            # `IPAddressDeny` is a filter; this is no network stack at all.
            ("PrivateNetwork", "yes"),
            # A provider that fails in a loop must not fill the journal with
            # the same refusal, and a journal nobody can read is a journal
            # nobody reads.
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "50"),
            ("LogExtraFields", "AZ_SERVICE=mio-local"),
        ),
        rationale=(
            "The only unit that could ever start a model process, and it "
            "starts none until HG-05 and operator approval pass. Exactly one "
            "runtime is pinned in model_runtime.py. It is not root, it writes one "
            "directory, it has no network namespace at all, and it runs under "
            "its own account -- never the fetcher's. azfetch may reach the "
            "network and may not run a program; azmio may run one program "
            "from a fixed list and may reach nothing. Adding a runtime is a "
            "reviewed change to this package, never commissioned data: an "
            "endpoint is a fact about a deployment, and a binary is a thing "
            "that executes."
        ),
    ),
    ServiceProfile(
        unit="azazel-commissiond.service",
        executable="/usr/libexec/azazel/az-commissiond",
        account="azcommission",
        description="Azazel-Nexus commissioning daemon",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/commissioning.md",
        address_families=("AF_UNIX", "AF_NETLINK"),
        supplementary_groups=("azknowledge",),
        read_write_paths=(
            "/var/lib/azazel/run/commission",
            "/var/lib/azazel/state/commission",
            "/var/lib/azazel/lite-trust",
        ),
        after=(ACTIVATION_CONTROLLER_UNIT, "azazel-auditd.service", "sysinit.target", "basic.target"),
        requires=(ACTIVATION_CONTROLLER_UNIT, "azazel-auditd.service"),
        binds_to=(ACTIVATION_CONTROLLER_UNIT, "azazel-auditd.service"),
        default_dependencies=False,
        before=("shutdown.target",),
        conflicts=("shutdown.target",),
        extra=(("Restart", "no"), ("KillMode", "control-group"),
               ("NotifyAccess", "main"),
               ("TimeoutStartSec", "30s"), ("TimeoutStopSec", "10s"),
               ("TimeoutStartFailureMode", "kill"),
               ("TimeoutStopFailureMode", "kill"),
               ("KillSignal", "SIGTERM"), ("FinalKillSignal", "SIGKILL"),
               ("SendSIGKILL", "yes"),
               ("SetLoginEnvironment", "no"),
               ("UnsetEnvironment", " ".join(BOOTSTRAP_UNSET_ENVIRONMENT))),
        rationale=(
            "Reads IFLA_PERM_ADDRESS over a route netlink socket, which needs "
            "neither CAP_NET_ADMIN nor an internet address family. It gets "
            "neither. It is not root. Its notify startup waits for auditd, "
            "and loss of auditd also stops commissioning."
        ),
    ),
    ServiceProfile(
        unit="azazel-auditd.service",
        executable="/usr/libexec/azazel/az-auditd",
        account="azaudit",
        description="Azazel-Nexus audit ledger",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/IMPLEMENTATION_SPEC.md",
        address_families=("AF_UNIX",),
        # Its socket leaf (azaudit:azazel-operator 2710), its chain and its
        # refusal records. Nothing else under the run tree is its to write.
        read_write_paths=(
            "/var/lib/azazel/run/audit",
            "/var/lib/azazel/state/audit",
            "/var/lib/azazel/state/auditd",
        ),
        after=(ACTIVATION_CONTROLLER_UNIT, "sysinit.target", "basic.target"),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        binds_to=(ACTIVATION_CONTROLLER_UNIT,),
        default_dependencies=False,
        before=("shutdown.target",),
        conflicts=("shutdown.target",),
        extra=(("Restart", "no"), ("KillMode", "control-group"),
               ("NotifyAccess", "main"),
               ("TimeoutStartSec", "30s"), ("TimeoutStopSec", "10s"),
               ("TimeoutStartFailureMode", "kill"),
               ("TimeoutStopFailureMode", "kill"),
               ("KillSignal", "SIGTERM"), ("FinalKillSignal", "SIGKILL"),
               ("SendSIGKILL", "yes"),
               ("SetLoginEnvironment", "no"),
               ("UnsetEnvironment", " ".join(BOOTSTRAP_UNSET_ENVIRONMENT))),
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
        # Its socket leaf (azwatch:azazel-operator 2710) and its fence and
        # refusal records. Masking is brokered over the controller's socket,
        # which is a connect, not a write.
        read_write_paths=(
            "/var/lib/azazel/run/watchdog",
            "/var/lib/azazel/state/watchdog",
        ),
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
        # The one remaining run-tree grant, kept on purpose: the result is
        # `edge_package.PROBE_STATE_PATH` (run/edge-probe.json, at the run
        # root), written as a temporary file in the same directory and moved
        # into place. A rename needs the directory, not the file, writable,
        # so no narrower mount target exists without moving the record into
        # a leaf of its own -- a data-location change, not a sandbox one.
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
    ServiceProfile(
        unit="azazel-mio-entryd.service",
        executable="/usr/libexec/azazel/az-mio-entryd",
        account="azmioentry",
        supplementary_groups=("azazel-operator",),
        description="Azazel-Nexus M.I.O. routing entry service",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/mio-runtime.md",
        address_families=("AF_UNIX",),
        read_write_paths=(
            "/var/lib/azazel/state/mio", "/var/lib/azazel/run/mio-entry",
        ),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        rationale=(
            "Routes and records handoffs over Unix sockets only. "
            "Holds no provider, network family or capability."
        ),
    ),
    ServiceProfile(
        unit="azazel-knowledge-lited.service",
        executable="/usr/libexec/azazel/az-knowledge-lited",
        account="azknowledge",
        description="Azazel-Nexus Knowledge Lite read service",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/knowledge-lite-consumer.md",
        address_families=("AF_UNIX",),
        read_write_paths=(
            "/var/lib/azazel/knowledge", "/var/lib/azazel/run/knowledge",
            "/var/lib/azazel/run/knowledge-read",
            "/var/lib/azazel/state/knowledge",
        ),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        extra=(("ReadOnlyPaths", "/var/lib/azazel/lite-trust"),),
        rationale=(
            "Serves read-only Lite verbs with read-only public trust. "
            "Imports and trust promotion remain on their existing paths."
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
    if not profile.default_dependencies:
        lines.append("DefaultDependencies=no")
    for unit in profile.after:
        lines.append(f"After={unit}")
    for key, value in profile.conditions:
        lines.append(f"{key}={value}")
    for unit in profile.before:
        lines.append(f"Before={unit}")
    for unit in profile.conflicts:
        lines.append(f"Conflicts={unit}")
    for unit in profile.requires:
        lines.append(f"Requires={unit}")
    for unit in profile.binds_to:
        lines.append(f"BindsTo={unit}")
    lines += [
        "",
        "[Service]",
        f"Type={profile.unit_type}",
        f"User={profile.account}",
    ]
    if profile.supplementary_groups:
        lines.append(
            "SupplementaryGroups=" + " ".join(profile.supplementary_groups)
        )
    lines += [
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
        if key == "CapabilityBoundingSet" and profile.capability_bounding_set:
            value = " ".join(profile.capability_bounding_set)
        lines.append(f"{key}={value}")
    lines += ["", "[Install]", "WantedBy=multi-user.target", ""]
    return "\n".join(lines)


def governed_units() -> tuple[str, ...]:
    """The units the activation controller governs, from the library."""

    return tuple(definition.name for definition in CORE_UNITS)
