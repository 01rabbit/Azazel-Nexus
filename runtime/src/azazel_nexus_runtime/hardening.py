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

import re
from dataclasses import dataclass, field, replace
from typing import Mapping, Sequence

from azazel_nexus.activation import (
    ACTIVATION_CONTROLLER_UNIT,
    CORE_UNITS,
    DECOY_NAMESPACE_UNIT,
    DECOY_NETWORK_HELPER_UNIT,
    DECOY_UNIT,
)

from .decoy_addresses import (
    BRIDGE_ADDRESS,
    DECOY_ADDRESS,
    DECOY_SUBNET,
    HOST_VETH,
    NAMESPACE,
    PREFIX_LENGTH,
)
from .decoy_apparmor import apparmor_profile_for
from .decoy_netns import DECOY_VETH
from azazel_nexus.layout import LAYOUT
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT
from azazel_nexus_runtime.activation_markers import grant_marker_path

__all__ = [
    "ALL_PROFILES",
    "DECOY_HELPER_SANDBOX",
    "DECOY_MANAGER_SOCKETS_INACCESSIBLE",
    "DECOY_NAMESPACE_CAPABILITIES",
    "DECOY_NAMESPACE_IP",
    "DECOY_NAMESPACE_PATH",
    "DECOY_NAMESPACE_SANDBOX",
    "DECOY_NAMESPACE_SHARED_OMISSIONS",
    "DECOY_NAMESPACE_SHARED_OVERRIDES",
    "DECOY_NAMESPACE_START",
    "DECOY_NAMESPACE_UNDO",
    "DECOY_SCOPE_CREDENTIAL",
    "DECOY_TRIP_CONFLICTS",
    "DECOY_TRIP_UNIT",
    "DECOY_VERIFY_SANDBOX",
    "DECOY_VERIFY_TIMER",
    "DECOY_VERIFY_UNIT",
    "DECOY_WATCH_PERIOD",
    "DECOY_WATCH_PROFILES",
    "DECOY_WATCH_UNIT_FILES",
    "EDGE_PROBE_PREFLIGHT_UNIT",
    "GRANT_MARKER_UNITS",
    "HOST_FIREWALL_UNIT",
    "HOST_FIREWALL_UNITS",
    "PROFILES",
    "UNGOVERNED_PROFILES",
    "SHARED_HARDENING",
    "ServiceProfile",
    "SYSTEM_ACCOUNTS",
    "UI_LISTEN_STREAM",
    "UI_LOGIN_DIRECTORY",
    "UI_PROFILES",
    "UI_SOCKET",
    "UI_UNIT",
    "packaged_unit_files",
    "render_trip_target",
    "render_ui_socket",
    "render_unit",
    "render_verify_timer",
    "OBSERVER_PROFILES",
    "OBSERVER_SERVICE_UNITS",
    "OBSERVER_UNIT_FILES",
    "render_observer_timer",
]

#: The operator observers (U2): oneshot units that only read and write one
#: operator-readable snapshot, each started by its own timer. Not governed,
#: never masked or enabled by the installer, required and bound to by
#: nothing, so stopping one (or its timer) stops nothing else.
UNITS_OBSERVE_UNIT = "azazel-units-observe.service"
UNITS_OBSERVE_TIMER = "azazel-units-observe.timer"
NOC_OBSERVE_UNIT = "azazel-noc-observe.service"
NOC_OBSERVE_TIMER = "azazel-noc-observe.timer"
OBSERVER_SERVICE_UNITS = (UNITS_OBSERVE_UNIT, NOC_OBSERVE_UNIT)

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

#: The read-only operator UI (U5, docs/operator-ui.md): its service, the
#: socket systemd listens on for it, and the one leaf it writes (the
#: operator-readable login code). Not governed by the activation controller,
#: never masked, never enabled by the installer (`disable` in the preset).
UI_UNIT = "azazel-ui.service"
UI_SOCKET = "azazel-ui.socket"
UI_LISTEN_STREAM = "127.0.0.1:8443"
UI_LOGIN_DIRECTORY = "/var/lib/azazel/run/ui-login"

#: Keys no profile but the decoy namespace unit's (whose `extra` is pinned
#: whole) may put in `ServiceProfile.extra`: every shared key, and the
#: identity, capability, address-family, system-call and path settings the
#: declaration renders from its own fields (#196 (a) review). Not
#: `ReadOnlyPaths=`: it narrows, and `azazel-mio-locald.service` states it
#: in `extra` on purpose.
_RESERVED_EXTRA_KEYS = frozenset({key for key, _ in SHARED_HARDENING}) | {
    "User", "Group", "SupplementaryGroups", "DynamicUser", "ExecStart",
    "CapabilityBoundingSet", "AmbientCapabilities", "SystemCallFilter",
    "RestrictAddressFamilies", "ReadWritePaths",
    "InaccessiblePaths", "BindPaths", "BindReadOnlyPaths",
    # A second program in a unit is a declaration too (#196 body): only the
    # helper names an `ExecStop=`, and only the namespace unit more
    # `ExecStart=` lines and its `ExecStopPost=` lines (G4 follow-up), each
    # in its pinned extra.
    "ExecStop", "ExecStopPost", "ExecStartPost", "ExecReload",
    # The LSM profile comes only from `apparmor_profile` (#196 G3), so no
    # unit can name one, or one with `-`, through `extra`.
    "AppArmorProfile",
}


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
    #: Writable when present, rendered `ReadWritePaths=-PATH`. Only for a leaf
    #: the daemon can run without: a runtime upgraded without re-running
    #: install.sh lacks it, and a plain entry would fail the unit's namespace
    #: setup (226/NAMESPACE) before the daemon could log and carry on.
    optional_read_write_paths: tuple[str, ...] = ()
    after: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    binds_to: tuple[str, ...] = ()
    unit_type: str = "notify"
    #: Empty (the default) for a unit that owns nothing under /run. systemd
    #: chowns a runtime directory to the unit's user and removes it on stop,
    #: which a unit that owns nothing there has no business doing. A unit that
    #: does own something there names its own leaf (`azazel/mio`,
    #: `azazel/remote`, ...), never the bare `azazel` (#206 P6): when that
    #: name was shared, the controller -- which sends READY and exits within
    #: milliseconds -- removed `/run/azazel` exactly as the granted loop units
    #: ordered after it set up their execution directories, and they failed
    #: with 233/RUNTIME_DIRECTORY. For a nested name systemd creates the
    #: parents root-owned 0755 and removes only the leaf on stop.
    runtime_directory: str = ""
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
    #: Whether this unit is the Deception Lite decoy (#196 P1, design D1).
    #:
    #: The fourth exemption kind, and the only one that **accepts** rather
    #: than initiates: it may take an internet address family so that it can
    #: listen inside the decoy network namespace, and it must declare that
    #: namespace (`NetworkNamespacePath=` exactly `DECOY_NAMESPACE_PATH`) and
    #: `PrivateUsers=yes`, hold no capability and not run as root. Like the
    #: other two it keeps `IPAddressDeny=any`; its only `IPAddressAllow=` is
    #: the fixed decoy subnet (`decoy_addresses.DECOY_SUBNET`, #196 body),
    #: stated statically because #253 refuses drop-ins on every grantable
    #: unit; the commissioned prefix arrives in a later phase. The runtime half of the same boundary is the
    #: listener exemption in `tests/unit/test_runtime_boundary.py`: bind and
    #: listen, never connect.
    is_decoy_listener: bool = False
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
    #: Replacements for `SHARED_HARDENING` entries, rendered in their place
    #: (several entries for one key render as several lines, in order).
    #: Empty for every unit but the Deception Lite namespace unit, whose
    #: overrides are exactly `DECOY_NAMESPACE_SHARED_OVERRIDES` (#196 (a)):
    #: creating a network namespace needs `unshare` of a net namespace and a
    #: bind mount, which the shared `RestrictNamespaces=yes` and
    #: `SystemCallFilter=@system-service` refuse. Nothing else may loosen the
    #: shared sandbox, and that unit may loosen nothing else.
    shared_overrides: tuple[tuple[str, str], ...] = ()
    #: `SHARED_HARDENING` keys not rendered at all. Empty for every unit but
    #: the Deception Lite namespace unit, whose omissions are exactly
    #: `DECOY_NAMESPACE_SHARED_OMISSIONS` (#196 (a)): the settings that make
    #: systemd build a mount namespace for the unit, because a mount made
    #: inside one never reaches the host (n3, VM-checked).
    shared_omissions: tuple[str, ...] = ()
    #: The AppArmor profile the unit names in `AppArmorProfile=` (#196 G3,
    #: docs/deception-exposure-grant.md §7). Exactly
    #: `decoy_apparmor.apparmor_profile_for(unit)`: the profile of each of
    #: the three Deception Lite exposure units, and empty for every other
    #: unit. Rendered without `-` and with `AssertSecurity=apparmor` in
    #: `[Unit]`: with AppArmor enabled a start without the profile loaded
    #: fails; with AppArmor disabled systemd ignores `AppArmorProfile=`, and
    #: the assertion fails the start instead. Never unconfined.
    apparmor_profile: str = ""
    #: Fixed words after the executable in `ExecStart=`. Empty for every
    #: unit but two: the Deception Lite verify unit, whose one word is
    #: exactly `verify` (#196 G2, docs/deception-exposure-grant.md §6.1): the
    #: helper's executable, with one more fixed word; and the namespace unit,
    #: whose first `ExecStart=` is exactly `DECOY_NAMESPACE_START[0]` (G4
    #: follow-up: `ip` itself, no Python body).
    arguments: tuple[str, ...] = ()
    #: `OnFailure=` units. Empty for every unit but the verify unit, whose
    #: failure starts exactly `DECOY_TRIP_UNIT` (#196 G2).
    on_failure: tuple[str, ...] = ()
    #: `WantedBy=` of the `[Install]` section. Every unit has
    #: `multi-user.target` but the verify unit, which has no `[Install]`
    #: section at all (#196 G2, grant §6.1): it starts only because the decoy
    #: pulls it in, never because something enabled it.
    wanted_by: tuple[str, ...] = ("multi-user.target",)

    def __post_init__(self) -> None:
        if self.apparmor_profile != apparmor_profile_for(self.unit):
            raise ValueError(
                f"{self.unit}: AppArmorProfile is exactly "
                f"{apparmor_profile_for(self.unit) or 'absent'}; only the "
                "Deception Lite exposure units name a profile, each its own"
            )
        # The verify unit's three own fields (#196 G2): its fixed word, its
        # trip and its missing [Install] belong to it and to no other unit.
        # The namespace unit's first command line is its own (G4 follow-up).
        is_verify = self.unit == DECOY_VERIFY_UNIT
        if self.unit == DECOY_NAMESPACE_UNIT:
            if self.arguments != DECOY_NAMESPACE_START[0][1:]:
                raise ValueError(
                    f"{self.unit}: its first ExecStart= is exactly "
                    "DECOY_NAMESPACE_START[0]")
        elif self.arguments != (("verify",) if is_verify else ()):
            raise ValueError(
                f"{self.unit}: only {DECOY_VERIFY_UNIT} runs its executable with "
                "the word verify; no other unit but the namespace unit names an "
                "argument")
        # The operator observers (U2, U3) are started by their own timers,
        # and the read-only UI service (U5) only when its socket is connected
        # to (an operator enables the socket, never the service): none of
        # them has an [Install] section; nothing else may lack one.
        no_install = (is_verify or self.unit in OBSERVER_SERVICE_UNITS
                      or self.unit == UI_UNIT)
        if (self.on_failure != ((DECOY_TRIP_UNIT,) if is_verify else ())
                or self.wanted_by != (() if no_install else ("multi-user.target",))):
            raise ValueError(
                f"{self.unit}: only {DECOY_VERIFY_UNIT} has "
                f"OnFailure={DECOY_TRIP_UNIT}, and only it, the operator observers "
                f"and {UI_UNIT} have no [Install] section")
        if not self.address_families:
            raise ValueError(
                f"{self.unit} declares no address family. `AF_UNIX` at least "
                "is required to be reachable at all, and a unit whose families "
                "are unstated inherits whatever systemd's default is"
            )
        reaches_network = (self.is_artifact_fetcher or self.is_inference_transport
                           or self.is_decoy_listener)
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
                ("decoy listener", self.is_decoy_listener),
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
        if (self.unit in (DECOY_NETWORK_HELPER_UNIT, DECOY_VERIFY_UNIT)
                and self.address_families != ("AF_NETLINK",)):
            raise ValueError(
                f"{self.unit} is root: with AF_UNIX it could reach the service "
                "manager over D-Bus and unmask what the controller withholds, "
                "so it gets netlink only (any netlink protocol: systemd "
                "cannot narrow it to route or nftables)"
            )
        # CAP_SYS_ADMIN belongs to exactly one unit, the one-shot
        # decoy namespace unit, and that unit holds nothing else (#196 (a)).
        if (("CAP_SYS_ADMIN" in self.capability_bounding_set)
                != (self.unit == DECOY_NAMESPACE_UNIT)):
            raise ValueError(
                f"{self.unit}: CAP_SYS_ADMIN is held by "
                f"{DECOY_NAMESPACE_UNIT} and by no other unit"
            )
        # CAP_NET_ADMIN belongs to exactly the three one-shot decoy units: the
        # network helper (the host side), the namespace unit (the inside,
        # which only a process in the namespace can configure; #196 body) and
        # the verify unit, which only lists the table (#196 G2, grant §10
        # Q7: a listing needs it).
        if (("CAP_NET_ADMIN" in self.capability_bounding_set)
                != (self.unit in (DECOY_NETWORK_HELPER_UNIT, DECOY_NAMESPACE_UNIT,
                                  DECOY_VERIFY_UNIT))):
            raise ValueError(
                f"{self.unit}: CAP_NET_ADMIN is held by "
                f"{DECOY_NETWORK_HELPER_UNIT}, {DECOY_NAMESPACE_UNIT} and "
                f"{DECOY_VERIFY_UNIT} and by no other unit"
            )
        if (self.unit in (DECOY_NETWORK_HELPER_UNIT, DECOY_VERIFY_UNIT)
                and self.capability_bounding_set != ("CAP_NET_ADMIN",)):
            raise ValueError(
                f"{self.unit} holds exactly CAP_NET_ADMIN; anything wider is "
                "a reviewed change to this declaration"
            )
        # The exposure scope is the helper's input and the verify unit's
        # (#196 G1b, G2): another unit loading it, or the grant directory it
        # lives in, as a credential would read what only those two may act on
        # or compare with.
        if self.unit not in (DECOY_NETWORK_HELPER_UNIT, DECOY_VERIFY_UNIT) and any(
                key.startswith(("LoadCredential", "SetCredential", "ImportCredential"))
                and ("decoy-scope" in value or "/run/azazel-activation" in value)
                for key, value in self.extra):
            raise ValueError(
                f"{self.unit}: the decoy scope is {DECOY_NETWORK_HELPER_UNIT}'s "
                f"and {DECOY_VERIFY_UNIT}'s credential alone")
        if self.unit == UI_UNIT:
            self._check_ui_unit()
        if self.unit == DECOY_NAMESPACE_UNIT:
            self._check_namespace_unit()
        elif self.shared_overrides or self.shared_omissions:
            raise ValueError(
                f"{self.unit} would override the shared hardening; only "
                f"{DECOY_NAMESPACE_UNIT} does, and only as declared"
            )
        elif self.unit == DECOY_NETWORK_HELPER_UNIT:
            # The helper's extra is pinned whole (#196 body, m2): it carries
            # the reserved `InaccessiblePaths=` and `ExecStop=`, and nothing
            # else may be added to or taken from it.
            if self.extra != DECOY_HELPER_SANDBOX:
                raise ValueError(
                    f"{self.unit} states exactly DECOY_HELPER_SANDBOX in extra")
            # Its one writable place is its own runtime directory, for the
            # isolation record (#196 §14), and nothing else.
            if (self.runtime_directory != DECOY_ISOLATION_DIRECTORY
                    or self.runtime_directory_mode != DECOY_ISOLATION_DIRECTORY_MODE
                    or self.read_write_paths or self.optional_read_write_paths):
                raise ValueError(
                    f"{self.unit} writes only its runtime directory "
                    f"{DECOY_ISOLATION_DIRECTORY} ({DECOY_ISOLATION_DIRECTORY_MODE})")
            # What it is ordered against, fixed (#276 F1, #196 G2 §6.2):
            # after the controller, the namespace unit and the three host
            # firewall loaders; requiring only the first two; nothing else.
            if (self.after != (ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT,
                               *HOST_FIREWALL_UNITS)
                    or self.requires != (ACTIVATION_CONTROLLER_UNIT,
                                         DECOY_NAMESPACE_UNIT)
                    or self.binds_to or self.before or self.conflicts
                    or not self.default_dependencies):
                raise ValueError(
                    f"{self.unit} is after {ACTIVATION_CONTROLLER_UNIT}, "
                    f"{DECOY_NAMESPACE_UNIT} and {', '.join(HOST_FIREWALL_UNITS)}, "
                    "and requires only the first two")
        elif self.unit == DECOY_VERIFY_UNIT:
            self._check_verify_unit()
        else:
            # `extra` renders before the shared lines, so a shared key, an
            # identity, a capability or a path setting placed there would sit
            # beside the declared one and loosen or contradict it (systemd
            # merges or resets list settings). Each has its own field or is
            # shared; the namespace unit's `extra` is pinned whole instead.
            reserved = _RESERVED_EXTRA_KEYS
            if self.unit == DECOY_UNIT:
                # The decoy's one reserved key, checked whole below (#276 F10).
                reserved = reserved - {"InaccessiblePaths"}
            restated = sorted({key for key, _ in self.extra} & reserved)
            if restated:
                raise ValueError(
                    f"{self.unit} states {restated} in extra; those come only "
                    "from the declaration's own fields and the shared hardening"
                )
        if self.is_decoy_listener:
            settings = dict(self.extra)
            if (self.unit != DECOY_UNIT or self.account == "root"
                    or self.capability_bounding_set or self.supplementary_groups):
                raise ValueError(
                    f"{self.unit}: the decoy listener is {DECOY_UNIT}, runs "
                    "under its own account and holds no capability or group"
                )
            # The watch (#196 G2, grant §6.1): the decoy pulls in the verify
            # unit and its timer, and starts only after a verify that passed.
            if (self.after != (ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT,
                               DECOY_VERIFY_UNIT)
                    or self.requires != (ACTIVATION_CONTROLLER_UNIT,
                                         DECOY_NETWORK_HELPER_UNIT,
                                         DECOY_VERIFY_UNIT, DECOY_VERIFY_TIMER)
                    or self.binds_to or self.before or self.conflicts):
                raise ValueError(
                    f"{self.unit} is after {ACTIVATION_CONTROLLER_UNIT}, "
                    f"{DECOY_NETWORK_HELPER_UNIT} and {DECOY_VERIFY_UNIT}, and "
                    f"requires those three and {DECOY_VERIFY_TIMER}")
            allowed = [value for key, value in self.extra if key == "IPAddressAllow"]
            # Least privilege (#276 F10): it binds the IPv4 wildcard only
            # (`decoy_listener.open_namespace_listener`), so no AF_INET6; it
            # writes no file, so no writable path; and the manager's sockets
            # are out of its reach as they are out of the helper's.
            if self.address_families != ("AF_UNIX", "AF_INET"):
                raise ValueError(
                    f"{self.unit} is allowed exactly AF_UNIX (its report to the "
                    "intake) and AF_INET (its IPv4 listener)")
            if tuple(item for item in self.extra
                     if item[0] == "InaccessiblePaths") != DECOY_MANAGER_SOCKETS_INACCESSIBLE:
                raise ValueError(
                    f"{self.unit} states exactly DECOY_MANAGER_SOCKETS_INACCESSIBLE "
                    "as its InaccessiblePaths")
            if [value for key, value in self.extra if key in ("ProtectProc", "ProcSubset")] != [
                    "invisible"] or "ProcSubset" in settings:
                raise ValueError(
                    f"{self.unit} states ProtectProc=invisible exactly once and no "
                    "ProcSubset= (it reads /proc/sys/kernel/random/boot_id)")
            if (settings.get("NetworkNamespacePath") != DECOY_NAMESPACE_PATH
                    or settings.get("PrivateUsers") != "yes"
                    or "PrivateNetwork" in settings
                    or allowed != [DECOY_SUBNET]):
                raise ValueError(
                    f"{self.unit} listens only inside {DECOY_NAMESPACE_PATH}, "
                    f"with PrivateUsers=yes and IPAddressAllow={DECOY_SUBNET} "
                    "as its only address allowance"
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
            "/run/azazel-nexus-bootstrap", "/run/azazel-activation",
        }
        # No unit declares the namespace directory writable. The namespace
        # unit writes it as root with no file-system sandbox at all (a
        # `ReadWritePaths=` would itself build the mount namespace that keeps
        # its mount from the host); every other unit has no business there.
        if any(path.removeprefix("-").rstrip("/") == NETNS_DIRECTORY
               for path in self.read_write_paths + self.optional_read_write_paths):
            raise ValueError(
                f"{self.unit}: {NETNS_DIRECTORY} is not a declared writable path; "
                f"only {DECOY_NAMESPACE_UNIT} writes it, without a mount namespace")
        # Nor may any unit declare `/run` itself, or the record's directory
        # or anything under it, writable (review of #274): the helper's
        # runtime directory is the only way to it.
        isolation = f"/run/{DECOY_ISOLATION_DIRECTORY}"
        for path in self.read_write_paths + self.optional_read_write_paths:
            bare = path.removeprefix("-").rstrip("/")
            if bare == "/run" or bare == isolation or bare.startswith(isolation + "/"):
                raise ValueError(
                    f"{self.unit}: {path} is not a declared writable path; the "
                    f"isolation record is written only through "
                    f"{DECOY_NETWORK_HELPER_UNIT}'s runtime directory")
        # The isolation record's directory is the helper's alone (#196 §14):
        # another unit naming it as its runtime directory would own or
        # remove the record the decoy trusts.
        if (self.unit != DECOY_NETWORK_HELPER_UNIT and any(
                name.split("/")[0] == DECOY_ISOLATION_DIRECTORY
                for name in self.runtime_directory.split())):
            raise ValueError(
                f"{self.unit}: {DECOY_ISOLATION_DIRECTORY} is "
                f"{DECOY_NETWORK_HELPER_UNIT}'s runtime directory alone")
        if ("/run/systemd/system.control" in self.read_write_paths
                and self.unit != ACTIVATION_CONTROLLER_UNIT):
            raise ValueError("bootstrap overlay is writable only by the activation controller")
        if (("/run/azazel-activation" in self.read_write_paths
                or "/run/azazel-activation" in self.optional_read_write_paths)
                and self.unit != ACTIVATION_CONTROLLER_UNIT):
            raise ValueError("grant markers are writable only by the activation controller")
        outside = sorted((set(self.read_write_paths)
                          | set(self.optional_read_write_paths)) - declared)
        if outside:
            raise ValueError(
                f"{self.unit} would write to {outside}, which the filesystem "
                "layout does not declare. A writable path nobody declared is a "
                "path nobody set the mode or the owner of"
            )
        # root is the controller's, the decoy network helper's and the decoy
        # namespace unit's, and no other unit's (#196 P1 review, #196 (a)):
        # another root unit is a diff a reviewer sees, not a profile that
        # quietly chose an account.
        if self.account == "root" and self.unit not in ROOT_UNITS:
            raise ValueError(
                f"{self.unit} would run as root; only {', '.join(ROOT_UNITS)} do"
            )
        # The decoy writes no file (#276 F10). Checked last, so that a path
        # the checks above refuse for a reason of their own says so.
        if self.is_decoy_listener and (self.read_write_paths
                                       or self.optional_read_write_paths):
            raise ValueError(f"{self.unit} writes no file and declares no writable path")

    def _check_ui_unit(self) -> None:
        """The read-only operator UI (U5), pinned whole.

        Its own account (`azui`) with no supplementary group at all -- not
        `azazel-operator`, not a daemon's socket group -- so it can reach no
        daemon socket and read only what any account may. `AF_UNIX` only and
        `PrivateNetwork=yes`: it accepts on the loopback socket systemd
        passes (`UI_SOCKET`) and can open no internet socket and has no
        network of its own. It writes only the login-code leaf. It requires
        only its own socket, is not governed (no grant marker), and has no
        `[Install]` section.
        """

        settings = dict(self.extra)
        if (self.account != "azui" or self.supplementary_groups
                or self.capability_bounding_set or self.address_families != ("AF_UNIX",)
                or settings.get("PrivateNetwork") != "yes"):
            raise ValueError(
                f"{self.unit} runs as azui with no supplementary group, no "
                "capability, AF_UNIX only and PrivateNetwork=yes")
        if (self.read_write_paths != (UI_LOGIN_DIRECTORY,)
                or self.optional_read_write_paths or self.runtime_directory):
            raise ValueError(f"{self.unit} writes only {UI_LOGIN_DIRECTORY}")
        if (self.after != (UI_SOCKET,) or self.requires != (UI_SOCKET,)
                or self.binds_to or self.before or self.conflicts or self.conditions
                or self.wanted_by or not self.default_dependencies):
            raise ValueError(
                f"{self.unit} is after and requires {UI_SOCKET} only, has no "
                "grant marker and no [Install] section")
        if (self.is_artifact_fetcher or self.is_model_host
                or self.is_inference_transport or self.is_decoy_listener):
            raise ValueError(f"{self.unit} holds no network role")

    def _check_verify_unit(self) -> None:
        """The Deception Lite verify unit, pinned whole (#196 G2, grant §6.1).

        The helper's executable with the one word `verify`, the helper's
        identity and sandbox (root, exactly `CAP_NET_ADMIN` as a bounding
        set, netlink only, the scope as its one credential, the manager's
        sockets inaccessible) and nothing it does not need: no writable path,
        no runtime directory, no `ExecStop=`, no `RemainAfterExit=` (it runs
        again every period). After the helper, requiring nothing; no grant
        marker condition; its failure starts the trip unit.
        """

        if (self.executable != "/usr/libexec/azazel/az-decoy-netd"
                or self.account != "root" or self.supplementary_groups
                or self.unit_type != "oneshot" or self.extra != DECOY_VERIFY_SANDBOX):
            raise ValueError(
                f"{self.unit} runs az-decoy-netd verify as root, one-shot, with "
                "exactly DECOY_VERIFY_SANDBOX in extra")
        if (self.runtime_directory or self.read_write_paths
                or self.optional_read_write_paths):
            raise ValueError(f"{self.unit} writes nothing: no runtime directory, "
                             "no writable path")
        if (self.after != (DECOY_NETWORK_HELPER_UNIT,) or self.requires
                or self.binds_to or self.before or self.conflicts
                or not self.default_dependencies or self.conditions):
            raise ValueError(
                f"{self.unit} is after {DECOY_NETWORK_HELPER_UNIT}, requires "
                "nothing and has no condition (no grant marker)")
        if (self.is_artifact_fetcher or self.is_model_host
                or self.is_inference_transport or self.is_decoy_listener):
            raise ValueError(f"{self.unit} holds no network role")

    def _check_namespace_unit(self) -> None:
        """The decoy namespace unit, pinned whole (#196 (a)).

        One unit, one privilege, one act: root so that its bounding set
        reaches it, exactly `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`, netlink as
        its only family (which admits every netlink protocol, nftables
        included: `RestrictAddressFamilies=` cannot narrow the protocol), no
        declared
        writable path, and the sandbox, the shared overrides and the shared
        omissions exactly as declared. Anything different is a reviewed
        change to this declaration, not a profile that drifted.
        """

        if (self.account != "root"
                or self.capability_bounding_set != DECOY_NAMESPACE_CAPABILITIES
                or self.supplementary_groups):
            raise ValueError(
                f"{self.unit} is root and holds exactly CAP_SYS_ADMIN and "
                "CAP_NET_ADMIN and no group; anything wider is a reviewed "
                "change to this declaration"
            )
        if self.address_families != ("AF_NETLINK",):
            raise ValueError(
                f"{self.unit} gets netlink only (any netlink protocol): no "
                "AF_UNIX that could reach the service manager, no internet "
                "family"
            )
        if (self.read_write_paths or self.optional_read_write_paths
                or self.runtime_directory):
            raise ValueError(
                f"{self.unit} declares no writable path and no runtime "
                "directory: either would build a mount namespace"
            )
        if (self.shared_overrides != DECOY_NAMESPACE_SHARED_OVERRIDES
                or self.shared_omissions != DECOY_NAMESPACE_SHARED_OMISSIONS
                or self.extra != DECOY_NAMESPACE_SANDBOX
                or self.unit_type != "oneshot"):
            raise ValueError(
                f"{self.unit} is a one-shot unit with exactly the declared "
                "sandbox, shared overrides and shared omissions"
            )
        if (self.is_artifact_fetcher or self.is_model_host
                or self.is_inference_transport or self.is_decoy_listener):
            raise ValueError(f"{self.unit} holds no network role")
        # Where it runs from and what it is ordered against, fixed as well:
        # `ip` and nothing else, only the controller to wait for, and only
        # this boot's grant marker as a condition.
        if (self.executable != DECOY_NAMESPACE_IP
                or self.after != (ACTIVATION_CONTROLLER_UNIT,)
                or self.requires != (ACTIVATION_CONTROLLER_UNIT,)
                or self.binds_to or self.before or self.conflicts
                or not self.default_dependencies
                or self.conditions != (
                    ("ConditionPathExists", grant_marker_path(self.unit)),)):
            raise ValueError(
                f"{self.unit} runs {DECOY_NAMESPACE_IP}, after and requiring "
                f"only {ACTIVATION_CONTROLLER_UNIT}, on its grant marker alone"
            )


#: The governed units that start only with this boot's grant marker (#206
#: §5): the six loop units, and the four other `Requires=` dependents of the
#: controller (watchdog, fetch, local and remote model hosts), for which no
#: pass writes a marker, so the controller's READY can never release a stale
#: queued start of theirs. Not auditd or commissiond: the supporting-only
#: bootstrap starts those and writes no marker; they stay masked on the
#: ordinary path and are bound to the controller (`BindsTo=`).
GRANT_MARKER_UNITS = (
    "azazel-decoy-netd.service",
    "azazel-decoy-nsd.service",
    "azazel-decoyd.service",
    "azazel-edge-core.service",
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
    "azazel-mio-locald.service",
    "azazel-mio-referenced.service",
    "azazel-mio-remoted.service",
    "azazel-model-fetchd.service",
    "azazel-watchdog.service",
)


def _grant_condition(unit: str) -> tuple[tuple[str, str], ...]:
    """`ConditionPathExists=` on this boot's grant marker for `unit`."""
    if unit not in GRANT_MARKER_UNITS:
        raise ValueError(f"{unit} is not a grant-marker unit")
    return (("ConditionPathExists", grant_marker_path(unit)),)


#: The commissioning storage mounts the controller is ordered after (#242,
#: docs/commissioning-storage-at-boot.md §4, §5 Q3): the operator-installed
#: LUKS volume at /etc/azazel/commissioning and, on the same device,
#: /var/lib/azazel/secrets. Ordering only -- never `Requires=`, `Wants=`,
#: `BindsTo=` or `RequiresMountsFor=`: storage that is absent, locked or
#: failed must not stop the controller, whose preflight remask is what
#: narrows, and whose pass then refuses because the evidence is not
#: LUKS-backed. `After=` on a mount that does not exist is a no-op.
COMMISSIONING_STORAGE_MOUNTS = (
    "etc-azazel-commissioning.mount",
    "var-lib-azazel-secrets.mount",
)


#: The mission storage mount the controller is ordered after (#251 M-7). The
#: pass's node-health producer checks the `resources` floor
#: (`activation_health` -> `bootstrap_resources.require_bootstrap_resources`
#: -> `resource_assessment.assess_resources`), whose `mission_available_mib`
#: opens `/data`, refuses when it is not a filesystem separate from `/`, and
#: compares its free space with the policy's `min_mission_available_mib`.
#: Without this ordering a `nofail` /data mount could race the pass: a
#: measurement before the mount refuses (fail-closed, but every unit stays
#: withheld for that boot). Ordering only, as for the commissioning storage:
#: never `Requires=`, `Wants=`, `BindsTo=` or `RequiresMountsFor=`, and no
#: controller path setting below /data (which would add an implicit
#: `RequiresMountsFor=`), so an absent, locked or failed /data cannot stop the
#: controller; the pass then refuses the resources floor. How an encrypted
#: mission volume is opened at boot is outside #242 and undecided.
MISSION_STORAGE_MOUNTS = ("data.mount",)


#: Passive ordering on time synchronization (#251 M-1). `time-sync.target` is
#: a passive target. When something pulls it in (an enabled timesyncd does)
#: the controller is ordered after it, but reaching it does not wait for
#: synchronization to complete; only a wait-sync service such as
#: `systemd-time-wait-sync.service` (disabled on Debian 13, not enabled by
#: this package) holds it until the clock is synchronized. Without one the
#: controller does **not** wait for synchronization, and a node without a
#: trustworthy clock can still pass an
#: approval that has expired in real time (docs/activation-observe-baseline.md
#: §10.2). Ordering only: no `Wants=`/`Requires=`, so it never pulls the target
#: in by itself.
TIME_SYNC_TARGET = "time-sync.target"


#: The system bus the controller's close path speaks to systemd through
#: (#324). Every unit operation of the bootstrap containment -- the start
#: fence's Reload, mask, StopUnit, the inactivity and mask observations and
#: the withdrawal -- is a call over `/run/dbus/system_bus_socket`
#: (`systemd_socket.SYSTEM_BUS_SOCKET`). With `DefaultDependencies=no` and no
#: ordering on the bus, a shutdown stops `dbus.service` in parallel with the
#: controller, so a READY controller stopped by a reboot lost the bus in the
#: middle of its close (EOF, then "emergency narrowing unconfirmed", or a
#: hang to TimeoutStopSec and SIGKILL), leaving the grant and journal for the
#: next boot's recovery. Stop order is the reverse of start order, so
#: `After=` here keeps the bus up until the controller has stopped. The
#: 2026-10-26 VM rehearsal (not hardware evidence) showed the calls failing
#: with "Transport endpoint is not connected" without it and succeeding with
#: it. Ordering only: no `Wants=`/`Requires=`, so a node without the bus is
#: not changed by this line and the controller still fails closed there.
SYSTEM_BUS_UNITS = ("dbus.socket", "dbus.service")


#: The accounts the installer creates. `root` is not among them: it exists.
SYSTEM_ACCOUNTS = (
    "azcommission",
    "azaudit",
    "azwatch",
    "azprobe",
    "azintake",
    "azexplain",
    "azedge",
    "azfetch",
    "azmio",
    "azmioentry",
    "azmioref",
    "azremote",
    "azknowledge",
    "azdecoy",
    # The passive NOC observer (U3). Not a specification service account:
    # no daemon classifies it as a service principal, and it is in no
    # socket group.
    "aznoc",
    "azui",
)


#: The Deception Lite watch (#196 G2, docs/deception-exposure-grant.md §6.1,
#: decided as §10 Q6 and Q7): a one-shot verify unit, the timer that re-runs
#: it, and the trip unit its failure starts. None of the three carries a
#: grant marker or an `[Install]` section: the decoy pulls the verify unit
#: and the timer in (`Requires=`), so a marker could only let systemd skip
#: them as a success and leave the decoy running unwatched (the n1 problem).
#: Not governed, never masked or unmasked by a pass, and in no lease: each
#: can only read or stop.
DECOY_VERIFY_UNIT = "azazel-decoy-verify.service"
DECOY_VERIFY_TIMER = "azazel-decoy-verify.timer"
#: A target, not a service: its whole content is `Conflicts=` on the
#: namespace unit, and systemd 257 refuses a service with no `ExecStart=`,
#: `ExecStop=` or `SuccessAction=` ("Refusing", container-checked with
#: `systemd-analyze verify`). A target runs nothing and holds nothing.
DECOY_TRIP_UNIT = "azazel-decoy-trip.target"
#: The units the trip unit conflicts with, each by name (#196 G4, grant
#: §6.3): the namespace unit, the network helper and the decoy. Naming all
#: three makes the job engine queue a stop job for each directly, so the
#: trip does not depend on the `Requires=` chain from the decoy to the
#: namespace unit. The 2026-10-22 VM rehearsal (not hardware evidence)
#: showed that chain can be gone: after a mask and a daemon-reload the
#: running units' definitions were `/dev/null`, and a trip that named only
#: the namespace unit stopped it alone. Ordered as the units are started
#: (`After=`); stop jobs run in the reverse of that order, so the decoy and
#: the helper stop before the namespace unit and its `ExecStopPost=` runs
#: last. A conflict holds both ways: starting any of the three stops the
#: target, which re-arms it, as starting the namespace unit already did.
DECOY_TRIP_CONFLICTS = (DECOY_NAMESPACE_UNIT, DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT)
#: How often the timer re-runs the verify unit (§10 Q6: 10 s).
DECOY_WATCH_PERIOD = "10s"


#: The units that run as root: the activation controller, and the three
#: one-shot Deception Lite units whose bounding-set capabilities reach only
#: uid 0 without an ambient grant (#196 P1, #196 (a), #196 G2).
ROOT_UNITS = (ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT,
              DECOY_NETWORK_HELPER_UNIT, DECOY_VERIFY_UNIT)


#: Where named network namespaces live (iproute2's convention; `ip netns
#: add` creates it). No unit declares it writable (see `ServiceProfile`).
NETNS_DIRECTORY = "/run/netns"

#: The decoy's network namespace (#196 P1, design D1). A fixed handle path,
#: never a parameter. Creating it needs a mount and CAP_SYS_ADMIN, which the
#: CAP_NET_ADMIN helper does not hold and cannot under its sandbox, so per
#: the design (option (a), docs/deception-redirect-prerequisites.md §5, §10)
#: a third one-shot unit, `azazel-decoy-nsd.service`, creates it and
#: configures its inside (`DECOY_NAMESPACE_START`, #196 body). The
#: unit is never granted in this build, so on a node nothing creates it, and
#: a decoy unit started anyway fails at namespace setup before its
#: executable runs.
DECOY_NAMESPACE_PATH = f"{NETNS_DIRECTORY}/azazel-decoy"

#: The network helper's runtime directory, where it writes this boot's
#: isolation record (#196 §14; `azazel_nexus.decoy_isolation.EVIDENCE_DIRECTORY`
#: is `/run/` and this, a test keeps them equal). The helper's and no other
#: unit's: systemd creates it root-owned when the helper starts and removes
#: it when the helper stops, so the record lives exactly as long as the
#: network it describes. `0755`, not the usual `0750`: the decoy reads the
#: record under its own account; the record is root's `0644` and holds fixed
#: results only.
DECOY_ISOLATION_DIRECTORY = "azazel-decoy-isolation"
DECOY_ISOLATION_DIRECTORY_MODE = "0755"

#: The host firewall unit the network helper is ordered after (#276 F1,
#: docs/deception-redirect-prerequisites.md §10). Debian's `nftables.service`
#: loads `/etc/nftables.conf`, which begins with `flush ruleset`, and is only
#: `WantedBy=sysinit.target` with no `Before=` on it, so without this the
#: helper could load the decoy table at boot and the firewall load could then
#: remove it. Ordering only -- never `Requires=`, `Wants=`, `BindsTo=` or
#: `PartOf=`: a host without the unit, or with it failed, must not stop or
#: pull in anything, and `After=` on a unit that does not exist is a no-op.
#: No `Before=` either: the helper has to come later, and at shutdown the
#: reverse order stops the helper (removing its table) before the firewall's
#: stop flushes the ruleset. It covers the boot only: a later reload, stop,
#: restart or start of the firewall still removes the table, and nothing
#: notices (§10, "Before any grant").
HOST_FIREWALL_UNIT = "nftables.service"

#: Every host firewall loader the network helper is ordered after (#196 G2,
#: docs/deception-exposure-grant.md §6.2): Debian's `nftables.service`,
#: `firewalld.service` and `netfilter-persistent.service`, each of which can
#: flush the ruleset when it loads. Ordering only, as for the first: a no-op
#: where the unit does not exist. The pass is to withhold the tier while any
#: of them is enabled (G6); a reload later in the boot is the watch's (§6.1).
HOST_FIREWALL_UNITS: tuple[str, ...] = (
    HOST_FIREWALL_UNIT, "firewalld.service", "netfilter-persistent.service")

#: The `SHARED_HARDENING` entries the decoy namespace unit does not carry
#: (#196 (a), n3), and only it: every shared setting that makes systemd
#: build a mount namespace for the unit. systemd cuts propagation from such
#: a namespace to the host, so the bind mount that makes a named network
#: namespace is never seen outside it: VM-checked on Debian 13 with systemd
#: 257.13 (a mechanism check, not hardware evidence), `ip netns add` in a unit
#: with `ProtectSystem=strict`/`ReadWritePaths=/run/netns` succeeded while
#: the host's handle stayed an empty file, and a unit joining it failed with
#: 225/NETWORK. Nothing is lost by leaving them out: a unit holding
#: CAP_SYS_ADMIN and the `mount` system call could undo any of them inside
#: its own mount namespace anyway, so for this unit they were never a wall.
#:
#: **A compromised body is host root.** Root with CAP_SYS_ADMIN and `mount`
#: can mount a fresh /proc or /sys and rewrite `kernel.core_pattern` and the
#: like, or remount the cgroup file system read-write; no unit setting here
#: stops that. The bounding set, the system call filter,
#: `RestrictNamespaces=net mnt`, netlink as its only family (every netlink
#: protocol, so nftables as well as routes) and
#: `NoNewPrivileges=` narrow what it is handed, but its containment rests on
#: what it runs: only `ip`, with the fixed command lines of
#: `DECOY_NAMESPACE_START` and `DECOY_NAMESPACE_UNDO` in its own unit file
#: (no argument, file, environment or socket from anyone), statically
#: reviewed, under its AppArmor profile (#196 G3). The body phase is to weigh removing the
#: privilege instead: let systemd hold the namespace (the helper and the
#: decoy sharing one with `PrivateNetwork=yes` and `JoinsNamespaceOf=`, the
#: helper moving one veth end to the host), so that no unit needs
#: CAP_SYS_ADMIN at all (docs/deception-redirect-prerequisites.md §10).
DECOY_NAMESPACE_SHARED_OMISSIONS: tuple[str, ...] = (
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "PrivateDevices",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectControlGroups",
)

#: The two `SHARED_HARDENING` entries the decoy namespace unit replaces, and
#: what it replaces them with (#196 (a)). Pinned: `ServiceProfile` refuses
#: any other override, on that unit or any other.
#:
#: * `RestrictNamespaces=net mnt`: of every namespace type, only a network
#:   namespace (`ip netns add`) and a mount namespace. The second is what
#:   `ip -n` makes for itself after `setns` into the decoy namespace, to
#:   mount that namespace's `/sys` without it reaching the host (strace-checked
#:   in a container, #196 body). It adds nothing a unit with CAP_SYS_ADMIN,
#:   `mount` and no file-system sandbox could not already do on the host.
#: * `SystemCallFilter=`, two lines in this order: the shared
#:   `@system-service` set plus `mount`, `umount2`, `unshare` and `setns`
#:   (the bind mount of the namespace handle, its removal, the namespace
#:   itself, and the return to the original namespace that `ip netns add`
#:   makes after creating it: without `setns` it is killed with SIGSYS,
#:   VM-checked); then a deny list that takes back what creating a namespace
#:   never needs: asynchronous I/O, ownership changes, IPC, keyrings, memory
#:   locking, identity changes, timers and `capset`.
DECOY_NAMESPACE_SHARED_OVERRIDES: tuple[tuple[str, str], ...] = (
    ("RestrictNamespaces", "net mnt"),
    ("SystemCallFilter", "@system-service mount umount2 unshare setns"),
    ("SystemCallFilter",
     "~@aio @chown @ipc @keyring @memlock @setuid @timer capset"),
)

#: The one program the decoy namespace unit runs (G4 follow-up): iproute2's
#: `ip`, by the absolute path Debian 13 installs (`decoy_network.IP`; a test
#: keeps them equal). The unit used to run a Python body that started `ip` in
#: a child AppArmor profile; under `NoNewPrivileges=yes` the kernel refused
#: that transition (`info="no new privs"`, VM-checked on Debian 13 with
#: AppArmor 4.1, a mechanism check and not hardware evidence;
#: docs/deception-exposure-grant.md §11). Now systemd starts `ip` directly
#: under the unit's one profile, and only `ip` holds the bounding set.
DECOY_NAMESPACE_IP = "/usr/bin/ip"


def _inside(*args: str) -> tuple[str, ...]:
    return (DECOY_NAMESPACE_IP, "-n", NAMESPACE, *args)


#: The namespace unit's six steps, in order, each one `ExecStart=` line
#: (G4 follow-up; the former `decoy_network.NAMESPACE_STEPS`): the
#: namespace, the veth pair with the decoy's end placed directly into it,
#: then the inside (`lo` up, the decoy's fixed address, its link up, its
#: default route via the bridge). Nothing is checked first: `ip netns add`
#: and the veth pair each refuse to replace an existing one, and that
#: refusal fails the start.
DECOY_NAMESPACE_START: tuple[tuple[str, ...], ...] = (
    (DECOY_NAMESPACE_IP, "netns", "add", NAMESPACE),
    (DECOY_NAMESPACE_IP, "link", "add", "name", HOST_VETH, "type", "veth",
     "peer", "name", DECOY_VETH, "netns", NAMESPACE),
    _inside("link", "set", "dev", "lo", "up"),
    _inside("address", "add", f"{DECOY_ADDRESS}/{PREFIX_LENGTH}", "dev", DECOY_VETH),
    _inside("link", "set", "dev", DECOY_VETH, "up"),
    _inside("route", "add", "default", "via", BRIDGE_ADDRESS, "dev", DECOY_VETH),
)

#: Its undo, in reverse: the veth pair (the host end; the decoy's end goes
#: with it), then the namespace. An address, a link state and a route go
#: with their link or namespace, so steps 3 to 6 need none of their own.
DECOY_NAMESPACE_UNDO: tuple[tuple[str, ...], ...] = (
    (DECOY_NAMESPACE_IP, "link", "delete", HOST_VETH),
    (DECOY_NAMESPACE_IP, "netns", "delete", NAMESPACE),
)

#: What a word of those command lines may be: no space, quote, `%`
#: (a systemd specifier), `$` (a variable), `;` or `\`, so that systemd's
#: command-line parsing hands `ip` exactly these words and nothing else.
_COMMAND_WORD = re.compile(r"-?[A-Za-z0-9][A-Za-z0-9./_-]*", re.ASCII)


def _command_line(argv: tuple[str, ...]) -> str:
    """One fixed `ip` command as a systemd command line, or `ValueError`."""

    if (argv[0] != DECOY_NAMESPACE_IP
            or not all(_COMMAND_WORD.fullmatch(word) for word in argv[1:])):
        raise ValueError("the namespace unit runs only fixed ip words")
    return " ".join(argv)


#: The decoy namespace unit's own settings, on top of what it keeps of
#: `SHARED_HARDENING` (#196 (a)). Pinned like the overrides. Nothing here
#: may build a mount namespace: `ProtectProc=`, `ProcSubset=`,
#: `InaccessiblePaths=`, `PrivateNetwork=`, `ProtectKernelLogs=`,
#: `ProtectHostname=` and `ProtectClock=` were in the first revision and are
#: gone for that reason (n3).
DECOY_NAMESPACE_SANDBOX: tuple[tuple[str, str], ...] = (
    # The other five steps, in order, rendered right after the first
    # `ExecStart=` (G4 follow-up). A one-shot unit runs them one after the
    # other and stops at the first that fails: the rest never run and the
    # start fails (fail closed).
    *(("ExecStart", _command_line(argv)) for argv in DECOY_NAMESPACE_START[1:]),
    # Stays active after it ran, so that the helper's `Requires=` holds while
    # the namespace exists, and stopping it (and, through `Requires=`, the
    # helper and the decoy first) is the hook for removing it last.
    ("RemainAfterExit", "yes"),
    # The deadlines that replace the former body's 2 s per step: 30 s for
    # the whole start, and up to 30 s for each undo command (*inferred*:
    # systemd may re-arm the stop timer per `ExecStopPost=` command; to be
    # measured, grant §11 item 4). Past either, systemd kills the `ip` that
    # is running; a start killed that way fails, and the undo below runs.
    ("TimeoutStartSec", "30s"),
    ("TimeoutStopSec", "30s"),
    # The undo, in reverse order: the veth pair, then the namespace. Not
    # `ExecStop=`: systemd runs that only after a start that succeeded.
    # `ExecStopPost=` runs after every stop and after every start that
    # failed or timed out at any step (systemd.service(5), systemd 257), so
    # one list is both the stop and the roll-back. `-` on the first only: a
    # failing command would skip the ones after it, and the pair is absent
    # whenever the start failed before step 2; the namespace's removal keeps
    # its status, so a stop that leaves it behind fails the unit.
    ("ExecStopPost", "-" + _command_line(DECOY_NAMESPACE_UNDO[0])),
    ("ExecStopPost", _command_line(DECOY_NAMESPACE_UNDO[1])),
    ("RestrictRealtime", "yes"),
)

#: The decoy namespace unit's bounding set (#196 body). CAP_SYS_ADMIN to
#: create the namespace and to enter it (`setns`); CAP_NET_ADMIN because
#: every act inside it (`lo` up, an address, a route, the veth pair) needs
#: CAP_NET_ADMIN in that namespace, and only a process inside it can do them
#: (container-checked: with CAP_SYS_ADMIN alone `ip -n ... link set lo up`
#: is refused, EPERM). The helper cannot do them: it has no `setns`. Adding
#: CAP_NET_ADMIN here adds nothing real to a unit that is already host root
#: when compromised (see `DECOY_NAMESPACE_SHARED_OMISSIONS`).
DECOY_NAMESPACE_CAPABILITIES: tuple[str, ...] = ("CAP_SYS_ADMIN", "CAP_NET_ADMIN")

#: The D-Bus and systemd private sockets, inaccessible to the decoy network
#: helper and to the decoy (#276 F10): a second barrier behind each unit's
#: address families. `-` keeps a host without one of them from failing the
#: unit at namespace setup.
DECOY_MANAGER_SOCKETS_INACCESSIBLE: tuple[tuple[str, str], ...] = (
    ("InaccessiblePaths", "-/run/dbus/system_bus_socket"),
    ("InaccessiblePaths", "-/run/systemd/private"),
)

#: The decoy network helper's one input (#196 G1b,
#: docs/deception-exposure-grant.md §4.3 H3): the closed scope file the
#: activation pass will render (G6) beside its grant markers, handed to the
#: helper as the credential `decoy-scope`, which it reads from
#: `/run/credentials/azazel-decoy-netd.service/decoy-scope`
#: (`azazel_nexus.decoy_scope.SCOPE_CREDENTIAL_PATH`; a test keeps them
#: equal). An immutable snapshot for the whole run. No `SetCredential=`
#: fallback, on purpose: a missing source file fails the start (fail
#: closed). The helper's and no other unit's.
DECOY_SCOPE_CREDENTIAL = "decoy-scope:/run/azazel-activation/decoy-scope.json"

#: The decoy network helper's own settings, pinned whole (#196 body, m2 of
#: the review of #268). On top of the shared sandbox: the clock, the host
#: name and the kernel log are out of reach, no realtime scheduling, and
#: the D-Bus and systemd private sockets are inaccessible, a second barrier
#: behind `AF_NETLINK` as its only family. `-` keeps a host without one of
#: them from failing the unit at namespace setup.
DECOY_HELPER_SANDBOX: tuple[tuple[str, str], ...] = (
    # Stays active after it ran, so that stopping it (and, through
    # Requires=, the decoy first) removes the host side only after the decoy
    # has stopped.
    ("RemainAfterExit", "yes"),
    ("TimeoutStartSec", "30s"),
    ("ExecStop", "/usr/libexec/azazel/az-decoy-netd stop"),
    # Its one input (#196 G1b, docs/deception-exposure-grant.md §4.3 H3).
    ("LoadCredential", DECOY_SCOPE_CREDENTIAL),
    ("ProtectClock", "yes"),
    ("ProtectHostname", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("RestrictRealtime", "yes"),
) + DECOY_MANAGER_SOCKETS_INACCESSIBLE

#: The verify unit's own settings, pinned whole (#196 G2, grant §6.1, §10
#: Q7): the helper's sandbox without what makes it a builder. The scope
#: arrives the same way and from the same file; no `RemainAfterExit=` (it is
#: started again every period, and a successful one-shot that has exited
#: does not stop the decoy that `Requires=` it, *inferred*, §11 item 3), no
#: `ExecStop=` and no runtime directory (it writes nothing).
DECOY_VERIFY_SANDBOX: tuple[tuple[str, str], ...] = (
    ("TimeoutStartSec", "30s"),
    ("LoadCredential", DECOY_SCOPE_CREDENTIAL),
    ("ProtectClock", "yes"),
    ("ProtectHostname", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("RestrictRealtime", "yes"),
) + DECOY_MANAGER_SOCKETS_INACCESSIBLE


PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        unit=ACTIVATION_CONTROLLER_UNIT,
        executable="/usr/libexec/azazel/az-activated",
        account="root",
        description="Azazel-Nexus activation controller",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/IMPLEMENTATION_SPEC.md",
        after=("systemd-tmpfiles-setup.service", "sysinit.target", "basic.target",
               *COMMISSIONING_STORAGE_MOUNTS, *MISSION_STORAGE_MOUNTS,
               TIME_SYNC_TARGET, *SYSTEM_BUS_UNITS),
        address_families=("AF_UNIX", "AF_NETLINK"),
        read_write_paths=(
            "/var/lib/azazel",
            "/var/lib/azazel/generations",
            "/var/lib/azazel/state",
            "/etc/systemd/system",
            "/run/systemd/system.control",
            "/run/azazel-nexus-bootstrap",
        ),
        # Optional: a node upgraded without re-running install.sh lacks the
        # tmpfiles-created directory, and the controller must still narrow.
        # Without it no marker can be written, so nothing granted can start.
        optional_read_write_paths=("/run/azazel-activation",),
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
        conditions=_grant_condition("azazel-model-fetchd.service"),
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
        conditions=_grant_condition("azazel-mio-remoted.service"),
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
        conditions=_grant_condition("azazel-mio-locald.service"),
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
        # Its socket leaves (azaudit:azazel-operator 2710, and the explainer's
        # append-only azaudit:azaudit-submit 2710), its chain and its refusal
        # records. Nothing else under the run tree is its to write, except
        # its operator-readable capacity snapshot (azaudit:azazel-operator
        # 2750, #211), which is optional: auditd is bootstrap-critical and
        # must start on a node where install.sh has not created that leaf.
        read_write_paths=(
            "/var/lib/azazel/run/audit",
            "/var/lib/azazel/run/audit-submit",
            "/var/lib/azazel/state/audit",
            "/var/lib/azazel/state/auditd",
        ),
        optional_read_write_paths=("/var/lib/azazel/run/audit-status",),
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
        # After the controller like every other `Requires=` dependent
        # (#251 L-9): its marker condition is then evaluated only after the
        # controller has reset the markers and sent READY. No pass writes
        # this marker, and the supporting-only bootstrap starts only auditd
        # and commissiond, so ordering changes no start.
        after=("azazel-auditd.service", ACTIVATION_CONTROLLER_UNIT),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-watchdog.service"),
        rationale=(
            "Can mask and cannot unmask. Masking a unit it does not own is "
            "brokered by the activation controller's socket, so it needs no "
            "privilege of its own."
        ),
    ),
    ServiceProfile(
        unit="azazel-edge-core.service",
        executable="/opt/azazel/edge-core/bin/azazel-edge-core",
        account="azedge",
        description="Azazel-Nexus observe-only Edge Core",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/edge-package-verification.md",
        address_families=("AF_UNIX",),
        read_write_paths=("/var/lib/azazel/edge-core",),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-edge-core.service"),
        unit_type="exec",
        # It only connects to the intake socket, which lives under
        # /var/lib/azazel/run and belongs to the intake.
        runtime_directory="",
        extra=(
            # Optional: Edge Core waits for eve.json, it does not need it to start.
            ("ReadOnlyPaths", "-/var/log/suricata"),
            ("Environment", "AZAZEL_DEFENSE_ENFORCE=false"),
            ("Environment", "AZAZEL_DEFENSE_DRY_RUN=true"),
            ("Environment", "AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory"),
            ("Environment", "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO=false"),
            ("Environment", "AZAZEL_FORWARD_AI=true"),
            ("Environment", "AZAZEL_AI_SOCKET=/var/lib/azazel/run/edge-intake/edge-intake.sock"),
            # Edge's own JSONL copy has no rotation and no ceiling. The intake
            # keeps the bounded record; stdout still reaches the journal.
            ("Environment", "AZAZEL_FORWARD_LOG=false"),
            ("Environment", "AZAZEL_REDIRECT_POLICY_PATH=/opt/azazel/edge-core/config/redirect_policy.yaml"),
            ("Environment", "AZAZEL_DEFENSE_RELEASE_LEDGER=/var/lib/azazel/edge-core/release-ledger.json"),
            ("Environment", "AZAZEL_EVE_PATH=/var/log/suricata/eve.json"),
            # A path socket needs no network stack; IPAddressDeny is a filter,
            # this is none at all.
            ("PrivateNetwork", "yes"),
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "200"),
            # Detection comes first when the node is busy: a flood's parsing,
            # explanation or a local model must not delay Edge's own loop.
            # A weight, not a cap; an idle node runs everything as before.
            ("CPUWeight", "400"),
        ),
        rationale=(
            "The verified package path is fixed; no manifest supplies a command. "
            "Observe-only detection needs no capabilities or internet sockets. "
            "Only its private state leaf is writable; Suricata access is read-only."
        ),
    ),
    ServiceProfile(
        unit="azazel-edge-intaked.service",
        executable="/usr/libexec/azazel/az-edge-intaked",
        account="azintake",
        description="Azazel-Nexus receive-only Edge findings intake",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/integration-loop.md",
        address_families=("AF_UNIX",),
        runtime_directory="",
        read_write_paths=("/var/lib/azazel/edge-incidents", "/var/lib/azazel/edge-intake", "/var/lib/azazel/run/edge-intake",
                          "/var/lib/azazel/run/edge-intake-status"),
        # The decoy's interaction socket (#196 P2), bound by this daemon in
        # its own leaf. Optional: without it the intake serves Edge alone and
        # counts decoy_listener_unavailable, rather than not starting.
        optional_read_write_paths=("/var/lib/azazel/run/decoy-intake",),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-edge-intaked.service"),
        # No Restart=: systemd's default is no, and only the bootstrap pair
        # may declare lifecycle settings (test_runtime_bootstrap_lifetime).
        extra=(("PrivateNetwork", "yes"),
               ("TimeoutStartSec", "30s"), ("MemoryMax", "256M"),
               ("TasksMax", "32"), ("LimitNOFILE", "256"),
               ("LimitFSIZE", "128M")),
        rationale="Receives bounded observations; no Edge control or enforcement authority.",
    ),
    ServiceProfile(
        unit="azazel-incident-explaind.service",
        executable="/usr/libexec/azazel/az-incident-explaind",
        account="azexplain",
        description="Azazel-Nexus local incident explanation",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/integration-loop.md",
        address_families=("AF_UNIX",),
        runtime_directory="",
        read_write_paths=("/var/lib/azazel/incident-explain",
                          "/var/lib/azazel/run/incident-explain-status"),
        # Each group reaches exactly one thing: the incident chains, and the
        # explainer-only listeners of Knowledge, auditd and M.I.O. entry. Not
        # azazel-operator: that would reach every operator socket (#213 O1).
        supplementary_groups=("azincident-read", "azknowledge-read", "azaudit-submit", "azmio-advise"),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-incident-explaind.service"),
        # No Restart=: systemd's default is no, and only the bootstrap pair
        # may declare lifecycle settings (test_runtime_bootstrap_lifetime).
        extra=(("PrivateNetwork", "yes"),
               ("TimeoutStartSec", "30s"), ("MemoryMax", "256M"),
               ("TasksMax", "32"), ("LimitNOFILE", "256"),
               ("LimitFSIZE", "128M")),
        rationale="Receives bounded observations; no Edge control or enforcement authority.",
    ),
    ServiceProfile(
        unit="azazel-edge-probed.service",
        executable="/usr/libexec/azazel/az-edge-probed",
        account="azprobe",
        description="Azazel-Nexus Edge health and running probe",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/edge-package-verification.md",
        address_families=("AF_UNIX",),
        # Only its own result leaf (azprobe:azazel-operator 2750). The result
        # is `edge_package.PROBE_STATE_PATH`, written as a temporary file in
        # that leaf and renamed into place; a rename needs the directory
        # writable, and the leaf is the smallest directory that holds both.
        read_write_paths=("/var/lib/azazel/run/edge-probe",),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-edge-probed.service"),
        unit_type="oneshot",
        rationale=(
            "Runs once and exits. It executes exactly two things -- the Edge "
            "health contract at a fixed path, and a read-only D-Bus property "
            "query -- and it writes one bounded file. It is not root, it "
            "takes no argument that could redirect it, and `AF_UNIX` is all "
            "it needs: "
            "the D-Bus connection it reads unit state over is one. It writes "
            "only into its own result leaf, which the operator group may "
            "read, and the result holds no secret: a "
            "version, a digest, two verdicts and their reasons."
        ),
    ),
    ServiceProfile(
        unit="azazel-mio-entryd.service",
        executable="/usr/libexec/azazel/az-mio-entryd",
        account="azmioentry",
        supplementary_groups=("azazel-operator",),
        # Private read-only snapshot: no commissioning key or permission change.
        # The two proposal files carry raw identity and are read from the
        # encrypted commissioning volume itself, never copied out (#244); only
        # the reviewed signature lives in /etc/azazel/mio-profile. A locked
        # volume leaves the sources missing, and the fallback selects CORE.
        extra=(("LoadCredential", "mio-profile_commissioning-proposal.expected.json:"
                                  "/etc/azazel/commissioning/commissioning-proposal.expected.json"),
               ("LoadCredential", "mio-profile_commissioning-proposal.json:"
                                  "/etc/azazel/commissioning/commissioning-proposal.json"),
               ("LoadCredential", "mio-profile_commissioning-proposal.sig:"
                                  "/etc/azazel/mio-profile/commissioning-proposal.sig"),
               ("LoadCredential", "mio-trust:/etc/azazel/operator-trust/operators.json"),
               ("LoadCredential", "mio-node:/etc/azazel/node.yaml"),
               ("SetCredential", "mio-profile_commissioning-proposal.expected.json:absent"),
               ("SetCredential", "mio-profile_commissioning-proposal.json:absent"),
               ("SetCredential", "mio-profile_commissioning-proposal.sig:absent"),
               ("SetCredential", "mio-trust:absent"),
               ("SetCredential", "mio-node:absent")),
        description="Azazel-Nexus M.I.O. routing entry service",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/mio-runtime.md",
        address_families=("AF_UNIX",),
        read_write_paths=(
            "/var/lib/azazel/state/mio", "/var/lib/azazel/run/mio-entry",
            "/var/lib/azazel/run/mio-advise",
        ),
        # Its operator-readable capability snapshot (U2): the ledger stays
        # 0700, and a missing leaf (install.sh not re-run) does not stop it.
        optional_read_write_paths=("/var/lib/azazel/run/mio-status",),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-mio-entryd.service"),
        rationale=(
            "Routes and records handoffs over Unix sockets only. "
            "Holds no provider, network family or capability."
        ),
    ),
    ServiceProfile(
        unit="azazel-mio-referenced.service",
        executable="/usr/libexec/azazel/az-mio-referenced",
        account="azmioref",
        description="Azazel-Nexus M.I.O. playbook reference service",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/mio-runtime.md",
        address_families=("AF_UNIX",),
        # Its own ledger leaf and socket leaf. No model store, model
        # admission, operator trust or Knowledge access: a reference is
        # verified playbook prose and nothing a model needs.
        read_write_paths=(
            "/var/lib/azazel/state/mio-reference", "/var/lib/azazel/run/mio-reference",
        ),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-mio-referenced.service"),
        supplementary_groups=("azmission-read",),
        extra=(
            ("ReadOnlyPaths", "-/etc/azazel/mission-pack.json"),
            ("ReadOnlyPaths", "-/data/azazel/mission-packs"),
            ("PrivateNetwork", "yes"),
            ("TimeoutStartSec", "30s"),
            ("MemoryMax", "256M"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "16"),
            ("LimitNOFILE", "256"),
            ("LimitFSIZE", "16777216"),
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "50"),
        ),
        rationale=(
            "Serves verified playbook references for the deterministic handoff. "
            "It runs no model, holds no model path, starts no process and has "
            "no network namespace. Model execution stays with the model host "
            "and its own wiring and admission, which this unit neither needs "
            "nor satisfies."
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
        # Its operator-readable status snapshot (U2), optional so that a
        # node upgraded without re-running install.sh still starts it.
        optional_read_write_paths=("/var/lib/azazel/run/knowledge-status",),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition("azazel-knowledge-lited.service"),
        extra=(("ReadOnlyPaths", "/var/lib/azazel/lite-trust"),),
        rationale=(
            "Serves read-only Lite verbs with read-only public trust. "
            "Imports and trust promotion remain on their existing paths."
        ),
    ),
    ServiceProfile(
        unit=DECOY_NAMESPACE_UNIT,
        # `ip` itself, no Python body (G4 follow-up): the first of its six
        # steps; the other five and the undo are in its pinned extra.
        executable=DECOY_NAMESPACE_IP,
        arguments=DECOY_NAMESPACE_START[0][1:],
        account="root",
        description="Azazel-Nexus Deception Lite namespace",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/deception-redirect-prerequisites.md",
        # Netlink only, the family VM-checked with `ip netns add`. This does
        # not narrow the netlink protocol: route and nftables netlink (and
        # the rest) are all open to it. No AF_UNIX: it is root, and an
        # AF_UNIX socket would reach the service manager over D-Bus. No
        # internet family.
        address_families=("AF_NETLINK",),
        # No writable path declared: `ReadWritePaths=` would build the mount
        # namespace that keeps the namespace handle from the host (n3). It
        # writes /run/netns as root, with no file-system sandbox.
        read_write_paths=(),
        after=(ACTIVATION_CONTROLLER_UNIT,),
        requires=(ACTIVATION_CONTROLLER_UNIT,),
        conditions=_grant_condition(DECOY_NAMESPACE_UNIT),
        unit_type="oneshot",
        runtime_directory="",
        # Root only so that the bounding set reaches it without an ambient
        # grant; the bounding set is CAP_SYS_ADMIN and CAP_NET_ADMIN.
        capability_bounding_set=DECOY_NAMESPACE_CAPABILITIES,
        extra=DECOY_NAMESPACE_SANDBOX,
        shared_overrides=DECOY_NAMESPACE_SHARED_OVERRIDES,
        shared_omissions=DECOY_NAMESPACE_SHARED_OMISSIONS,
        apparmor_profile=apparmor_profile_for(DECOY_NAMESPACE_UNIT),
        rationale=(
            "Runs once. The only unit that holds CAP_SYS_ADMIN, with "
            "CAP_NET_ADMIN, as a bounding set and never as an ambient "
            "capability: it creates the decoy network namespace at "
            "/run/netns/azazel-decoy, the veth pair with the decoy's end inside "
            "it, and the inside's fixed address and route. It runs /usr/bin/ip "
            "and nothing else: six fixed ExecStart lines, run in order until "
            "one fails, and two fixed ExecStopPost lines, which remove the pair "
            "and the namespace after every stop and after a start that failed "
            "or timed out; no Python body, so only ip holds its two "
            "capabilities. Netlink is its only address family, though that admits "
            "every netlink protocol, nftables included; it may create only a network "
            "namespace and the mount namespace ip -n makes for itself, and its "
            "syscall filter adds only mount, umount2, unshare and setns to the "
            "shared set and takes back what that act never needs. It is the "
            "one unit without the shared file-system sandbox: a mount namespace "
            "would keep the namespace handle from the host, and with "
            "CAP_SYS_ADMIN and mount that sandbox was never a wall for it. A "
            "compromised ip would be host root; its containment is fixed "
            "command lines that take no input, static review and its AppArmor "
            "profile azazel-decoy-nsd, which denies writes to the activation state, "
            "the unit files and the ledgers and any reach to the service "
            "manager; it starts only with AppArmor enabled and that profile "
            "loaded (AppArmorProfile= without a dash, AssertSecurity=apparmor). "
            "The activation pass never grants this unit in this build"
        ),
    ),
    ServiceProfile(
        unit=DECOY_NETWORK_HELPER_UNIT,
        executable="/usr/libexec/azazel/az-decoy-netd",
        account="root",
        description="Azazel-Nexus Deception Lite network helper",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/deception-redirect-prerequisites.md",
        # Netlink only; it uses route and nftables netlink, but the family
        # does not narrow the protocol, so every netlink protocol is open to
        # it. No internet family: it configures
        # links and rules, it never sends or receives traffic. No AF_UNIX
        # either: it runs as root, and an AF_UNIX socket would reach the
        # service manager over D-Bus (HG-02's claim is that only the
        # controller can unmask). Its journal output uses the stream systemd
        # hands it, which needs no socket() call.
        address_families=("AF_NETLINK",),
        # No declared writable path: its one writable place is its own
        # runtime directory, for this boot's isolation record (#196 §14).
        read_write_paths=(),
        # After and Requires the namespace unit (#196 (a)): it configures the
        # veth into a namespace that unit created. Granted together with it
        # or not at all, so a skipped namespace unit cannot count as success.
        # After, and only After, the host firewall loaders (#276 F1, #196
        # G2 §6.2): a boot-time `flush ruleset` must not run after the table
        # was loaded and checked.
        after=(ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT,
               *HOST_FIREWALL_UNITS),
        requires=(ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT),
        conditions=_grant_condition(DECOY_NETWORK_HELPER_UNIT),
        unit_type="oneshot",
        runtime_directory=DECOY_ISOLATION_DIRECTORY,
        runtime_directory_mode=DECOY_ISOLATION_DIRECTORY_MODE,
        # Root only so that the bounding set reaches it without an ambient
        # grant; the bounding set is CAP_NET_ADMIN and nothing else.
        capability_bounding_set=("CAP_NET_ADMIN",),
        extra=DECOY_HELPER_SANDBOX,
        apparmor_profile=apparmor_profile_for(DECOY_NETWORK_HELPER_UNIT),
        rationale=(
            "Runs once. It holds CAP_NET_ADMIN alone, as a bounding set and "
            "never as an ambient capability, in the host network namespace: "
            "with fixed nft and ip commands it loads the decoy table first, "
            "then sets up az-decoy0 and attaches the host end of the "
            "veth pair the namespace unit made; ExecStop cuts the path and then "
            "removes the table. Its one input is the closed exposure scope, "
            "the credential decoy-scope, decoded strictly; the table is "
            "rendered from it as one transaction, and a missing scope file "
            "fails the start. After building it reads back the table and "
            "the host's links with two fixed commands and writes this boot's "
            "isolation record, fixed results and the scope's digest only, to "
            "its runtime directory, which the decoy requires before it "
            "listens; a check that does "
            "not pass undoes the build. It reads no decoy observation and no Edge "
            "decision. It is root, so netlink is its only address family (any "
            "netlink protocol, not only route and nftables) and it has no AF_UNIX "
            "socket that could reach the service manager, whose private "
            "sockets are also inaccessible to it. It starts only with AppArmor "
            "enabled and its profile azazel-decoy-netd loaded (AppArmorProfile= "
            "without a dash, AssertSecurity=apparmor). The activation "
            "pass never grants this unit in this build"
        ),
    ),
    ServiceProfile(
        unit=DECOY_UNIT,
        executable="/usr/libexec/azazel/az-decoyd",
        account="azdecoy",
        description="Azazel-Nexus Deception Lite decoy",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/deception-redirect-prerequisites.md",
        # AF_UNIX for its one line to the intake's decoy socket; AF_INET only
        # to listen on the decoy namespace's IPv4 wildcard. No AF_INET6: it
        # binds no IPv6 address (#276 F10).
        address_families=("AF_UNIX", "AF_INET"),
        # No writable path (#276 F10): it reads the isolation record and
        # /proc, connects to the intake's socket (a connect, not a write to
        # the file system) and writes nothing. /var/lib/azazel/decoy stays in
        # the layout, the azdecoy account's, for a later phase that needs it.
        read_write_paths=(),
        # The watch (#196 G2, grant §6.1): it starts only after a verify
        # that passed, and pulls in the verify unit's timer, which re-runs
        # it every period; a failed verify starts the trip unit.
        after=(ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT,
               DECOY_VERIFY_UNIT),
        requires=(ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT,
                  DECOY_VERIFY_UNIT, DECOY_VERIFY_TIMER),
        conditions=_grant_condition(DECOY_UNIT),
        is_decoy_listener=True,
        unit_type="exec",
        runtime_directory="",
        extra=(
            ("NetworkNamespacePath", DECOY_NAMESPACE_PATH),
            ("PrivateUsers", "yes"),
            # Its peers are only in the fixed decoy subnet, on top of
            # IPAddressDeny=any. Without it the cgroup filter also drops what
            # the decoy itself receives (VM-checked on loopback, #196 body).
            ("IPAddressAllow", DECOY_SUBNET),
            # Other users' processes are invisible in its /proc (#289 F1):
            # its AppArmor rule for /proc/<pid>/net/dev cannot be `owner`
            # (that directory is root's, G4), so it matches every pid, and
            # this keeps it to the decoy's own. Not `ProcSubset=pid`: the
            # decoy reads /proc/sys/kernel/random/boot_id (its isolation
            # check), which that would hide.
            ("ProtectProc", "invisible"),
            ("TimeoutStartSec", "30s"),
            ("MemoryMax", "128M"),
            ("TasksMax", "16"),
            ("LimitNOFILE", "256"),
            ("LimitFSIZE", "16M"),
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "50"),
        ) + DECOY_MANAGER_SOCKETS_INACCESSIBLE,
        apparmor_profile=apparmor_profile_for(DECOY_UNIT),
        rationale=(
            "Holds no capability and runs under its own account, inside the "
            "decoy network namespace, with PrivateUsers=yes. It accepts and "
            "never initiates a network connection: its one connect is the "
            "AF_UNIX report to the intake's decoy socket, and the runtime "
            "boundary test allows its listener module bind and listen only. "
            "IPAddressDeny=any stays, and the fixed decoy subnet is the "
            "only address allowed. It opens no socket without the network "
            "helper's isolation record from this boot with every check "
            "passed. It binds IPv4 only and writes no file, so it gets no "
            "AF_INET6 and no writable path, and the service manager's "
            "private sockets are inaccessible to it. It starts only with AppArmor "
            "enabled and its profile azazel-decoyd loaded (AppArmorProfile= "
            "without a dash, AssertSecurity=apparmor). The activation pass "
            "never grants this unit in this build"
        ),
    ),
)


#: The Edge probe's boot preflight (#206 P5, design E1).
EDGE_PROBE_PREFLIGHT_UNIT = "azazel-edge-probe-preflight.service"


def _edge_probe_preflight() -> ServiceProfile:
    """`azazel-edge-probed.service`'s profile, ordered before the controller.

    Derived from the governed probe's declaration rather than restated, so the
    account, executable, address families, writable leaf and shared sandbox
    cannot drift apart: a change to one is a change to both. Only what makes
    it a boot preflight differs -- no `After=`/`Requires=` on the controller,
    `Before=` it instead, a start deadline so a hung probe cannot hold the
    boot, and no `RuntimeDirectory=` (it owns nothing under `/run`; no unit
    declares the bare `/run/azazel` any more, #206 P6).
    """

    probed = next(item for item in PROFILES if item.unit == "azazel-edge-probed.service")
    return replace(
        probed,
        unit=EDGE_PROBE_PREFLIGHT_UNIT,
        description="Azazel-Nexus Edge probe boot preflight",
        after=(),
        requires=(),
        before=(ACTIVATION_CONTROLLER_UNIT,),
        runtime_directory="",
        # Ungoverned and run before the pass: no grant marker can exist yet.
        conditions=(),
        extra=(("TimeoutStartSec", "60s"),),
        rationale=(
            "Not governed by the activation controller: it runs before it, at "
            "every boot, so that the pass reads Edge health from this boot "
            "(probe contract v2 binds the result to the boot id). It runs the "
            "same fixed az-edge-probed as the same unprivileged azprobe "
            "account, in the same sandbox as azazel-edge-probed.service, and "
            "writes only the same result leaf. It opens no network socket: "
            "`AF_UNIX` is all it is allowed, and `IPAddressDeny=any` holds. "
            "It grants nothing; a result it writes only narrows what the pass "
            "may grant, and its failure leaves Edge withheld"
        ),
    )


#: Units installed and enabled beside the controller that the controller
#: does **not** govern: never in `activation.CORE_UNITS`, never masked or
#: unmasked by a pass, and not admitted by any lease. Each is read-only with
#: respect to activation -- it can only narrow what a pass grants.
UNGOVERNED_PROFILES: tuple[ServiceProfile, ...] = (_edge_probe_preflight(),)

#: The Deception Lite verify unit (#196 G2, docs/deception-exposure-grant.md
#: §6.1). Not governed and not enabled: no grant marker, no `[Install]`;
#: `azazel-decoyd.service` pulls it in with `Requires=` and starts after it,
#: and its timer re-runs it every `DECOY_WATCH_PERIOD`. It runs the helper's
#: fixed executable with the one word `verify`: the read-back commands only
#: (`decoy_network.verify_plan`), the same comparison against the scope as
#: the helper's isolation check, and the re-reading of reachability R4. It
#: writes nothing; the isolation record stays the helper's.
DECOY_WATCH_PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        unit=DECOY_VERIFY_UNIT,
        executable="/usr/libexec/azazel/az-decoy-netd",
        arguments=("verify",),
        account="root",
        description="Azazel-Nexus Deception Lite watch",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/deception-exposure-grant.md",
        # The helper's family and nothing else: `nft` and `ip` reach the
        # kernel over netlink. No AF_UNIX: it is root.
        address_families=("AF_NETLINK",),
        read_write_paths=(),
        # After the helper, so that the verify before the decoy's start reads
        # what the helper built. Requiring nothing: the decoy requires it.
        after=(DECOY_NETWORK_HELPER_UNIT,),
        unit_type="oneshot",
        runtime_directory="",
        capability_bounding_set=("CAP_NET_ADMIN",),
        extra=DECOY_VERIFY_SANDBOX,
        apparmor_profile=apparmor_profile_for(DECOY_VERIFY_UNIT),
        on_failure=(DECOY_TRIP_UNIT,),
        wanted_by=(),
        rationale=(
            "Runs once per period, and before every decoy start. It holds "
            "CAP_NET_ADMIN alone, as a bounding set and never as an ambient "
            "capability, because listing the table needs it; it runs the "
            "network helper's executable with the one word verify, which "
            "starts only fixed read-back commands (the decoy table, the host's "
            "links, the IPv4 routing rules and the main table's routes) and "
            "reads forwarding and proxy_arp under /proc/sys/net. It compares "
            "them with the scope it receives as the credential decoy-scope, "
            "the helper's one input, and with the operator's reachability "
            "conditions, and writes nothing: the isolation record stays the "
            "helper's. A departure, an unreadable read or a refused scope "
            "makes it fail, and its failure starts azazel-decoy-trip.target, "
            "which stops the namespace unit, the helper and the decoy, each "
            "by name. It has no grant marker and no [Install] section: "
            "the decoy pulls it and its timer in. It is root, so netlink is "
            "its only address family and the service manager's private "
            "sockets are inaccessible to it. It starts only with AppArmor "
            "enabled and its profile azazel-decoy-verify loaded "
            "(AppArmorProfile= without a dash, AssertSecurity=apparmor)"
        ),
    ),
)

#: The operator observers (U2): each runs once per period of its timer and
#: writes one operator-readable snapshot. Ungoverned and not enabled by the
#: installer (an operator enables the timer), required by nothing.
OBSERVER_PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        unit=UNITS_OBSERVE_UNIT,
        executable="/usr/libexec/azazel/az-units-observe",
        account="azprobe",
        description="Azazel-Nexus unit state observer",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/operations.md",
        address_families=("AF_UNIX",),
        read_write_paths=(),
        optional_read_write_paths=("/var/lib/azazel/run/units-status",),
        unit_type="oneshot",
        extra=(("TimeoutStartSec", "30s"),),
        wanted_by=(),
        rationale=(
            "Runs once per period of azazel-units-observe.timer. It reads "
            "LoadState, ActiveState and SubState of the packaged services, a "
            "fixed list, over the system bus through a reader that passes "
            "GetUnit and Properties.Get and refuses every other call, and "
            "writes one snapshot into its own leaf, which the operator group "
            "may read. It runs as azprobe, the account that already reads the "
            "Edge unit's state for the probe, so no account gains a "
            "permission. `AF_UNIX` is all it needs and `IPAddressDeny=any` "
            "holds. It is not governed, has no [Install] section, and no unit "
            "requires or binds to it"
        ),
    ),
    ServiceProfile(
        unit=NOC_OBSERVE_UNIT,
        executable="/usr/libexec/azazel/az-noc-observe",
        account="aznoc",
        description="Azazel-Nexus passive NOC observer",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/noc-observation.md",
        # Netlink for the one NETLINK_ROUTE dump; no internet family, and
        # no PrivateNetwork, because the host's links are what it reads.
        address_families=("AF_NETLINK", "AF_UNIX"),
        read_write_paths=(),
        optional_read_write_paths=("/var/lib/azazel/run/noc-status",),
        unit_type="oneshot",
        extra=(("TimeoutStartSec", "60s"),),
        wanted_by=(),
        rationale=(
            "Runs once per period of azazel-noc-observe.timer. It makes the "
            "passive observation az-nexus-noc prints: one NETLINK_ROUTE dump "
            "of links, addresses and routes, sysfs counters read twice, the "
            "resolver files and DHCP lease files. It sends no packet, probes "
            "nothing and resolves no name, and `IPAddressDeny=any` holds. It "
            "writes counts and codes keyed by ifindex into its own leaf, "
            "which the operator group may read: no interface name, MAC or "
            "address. It runs as its own unprivileged account aznoc, which is "
            "in no socket group. It is not governed, has no [Install] "
            "section, and no unit requires or binds to it"
        ),
    ),
)

#: The read-only operator UI (U5). Not governed: no grant marker, never masked
#: or unmasked by a pass, in no lease, and no other unit requires it, so
#: stopping it stops nothing else. `disable` in the preset: an operator who
#: wants it enables `azazel-ui.socket`.
UI_PROFILES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        unit=UI_UNIT,
        executable="/usr/libexec/azazel/az-ui",
        account="azui",
        description="Azazel-Nexus read-only operator UI",
        documentation="https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/operator-ui.md",
        address_families=("AF_UNIX",),
        read_write_paths=(UI_LOGIN_DIRECTORY,),
        after=(UI_SOCKET,),
        requires=(UI_SOCKET,),
        unit_type="simple",
        extra=(
            ("PrivateNetwork", "yes"),
            ("ProtectProc", "invisible"),
            ("RemoveIPC", "yes"),
            ("Restart", "on-failure"),
            ("RestartSec", "5s"),
            ("TimeoutStopSec", "10s"),
            ("MemoryMax", "192M"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "32"),
            ("LimitNOFILE", "128"),
            ("LimitFSIZE", "65536"),
            ("LogRateLimitIntervalSec", "30"),
            ("LogRateLimitBurst", "50"),
        ),
        wanted_by=(),
        rationale=(
            "Read-only operator UI. It shows what azazel-nexus status --json "
            "and setup --json show and performs no action: no confirmation, "
            "approval, start or stop. It accepts on the loopback socket "
            "azazel-ui.socket passes and never creates a socket of an internet "
            "family: AF_UNIX only and PrivateNetwork=yes. It runs as azui with "
            "no supplementary group, so it reaches no daemon socket and reads "
            "only what any account may; a snapshot it cannot read is shown as "
            "permission denied. It writes only the login-code leaf, which the "
            "operator group reads. Not governed and required by no unit: "
            "stopping it stops nothing else"
        ),
    ),
)


def render_observer_timer(timer: str, service: str, period: str, description: str) -> str:
    """An observer's timer, byte for byte (U2).

    Runs `service` one `period` after boot and then every `period` after it
    last started. `AccuracySec=1s` keeps the period from stretching to
    systemd's default minute. `WantedBy=timers.target`, so an operator
    enables the timer and never the service. No `Persistent=`, no
    `WakeSystem=`, and nothing in it requires or binds to anything.
    """

    return "\n".join((
        *_GENERATED_HEADER,
        f"# Runs {service} every {period}. It reads and writes one snapshot only;",
        "# no unit requires or binds to it, so stopping it stops nothing else.",
        "# Not governed by the activation controller and not enabled by the installer.",
        "",
        "[Unit]",
        f"Description={description}",
        "Documentation=https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/operations.md",
        "",
        "[Timer]",
        f"OnBootSec={period}",
        f"OnUnitActiveSec={period}",
        "AccuracySec=1s",
        f"Unit={service}",
        "",
        "[Install]",
        "WantedBy=timers.target",
        "",
    ))


#: Every packaged service, governed or not, for the renderer and the installer.
ALL_PROFILES: tuple[ServiceProfile, ...] = (
    PROFILES + UNGOVERNED_PROFILES + DECOY_WATCH_PROFILES + OBSERVER_PROFILES
    + UI_PROFILES)

_GENERATED_HEADER = (
    "# Generated from azazel_nexus_runtime.hardening. Do not edit by hand:",
    "# tests/unit/test_runtime_hardening.py compares this file against what",
    "# the declaration renders, and a hand edit is a difference.",
    "#",
)

_GRANT_DOCUMENTATION = (
    "https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/deception-exposure-grant.md")


def render_verify_timer() -> str:
    """`azazel-decoy-verify.timer`, byte for byte (#196 G2, grant §6.1).

    Re-runs the verify unit every `DECOY_WATCH_PERIOD`, the first time one
    period after the decoy pulled the timer in (the decoy's own start already
    ran one verify). `AccuracySec=1s`: systemd's default of one minute would
    let the period stretch to that. `PartOf=` the decoy, so that stopping or
    restarting the decoy stops or restarts the watch with it; nothing else.
    No `[Install]`, no `Persistent=`, no `WakeSystem=`.
    """

    return "\n".join((
        *_GENERATED_HEADER,
        "# Re-runs azazel-decoy-verify.service every 10 seconds while the decoy runs.",
        "# The decoy pulls it in with Requires= and it stops with the decoy (PartOf=).",
        "# It has no grant marker and no [Install] section.",
        "",
        "[Unit]",
        "Description=Azazel-Nexus Deception Lite watch period",
        f"Documentation={_GRANT_DOCUMENTATION}",
        f"PartOf={DECOY_UNIT}",
        "",
        "[Timer]",
        f"OnActiveSec={DECOY_WATCH_PERIOD}",
        f"OnUnitActiveSec={DECOY_WATCH_PERIOD}",
        "AccuracySec=1s",
        f"Unit={DECOY_VERIFY_UNIT}",
        "",
    ))


def render_trip_target() -> str:
    """`azazel-decoy-trip.target`, byte for byte (#196 G2, grant §6.1).

    Its only content is `Conflicts=` on the namespace unit, the helper and
    the decoy (`DECOY_TRIP_CONFLICTS`, one line each): starting it (the
    verify unit's `OnFailure=`) makes systemd's job engine stop all three,
    each named directly rather than through `Requires=` (#196 G4: a chain
    that a mask and a daemon-reload can remove), the decoy and the helper
    first by the reverse of their `After=`. Nothing runs, nothing holds a
    privilege, no D-Bus call is made. Starting any of the three again stops
    the target (a conflict holds both ways), so a later failure trips
    again. Started by hand, it is a stop button for the three units and
    nothing more.
    """

    return "\n".join((
        *_GENERATED_HEADER,
        "# Started by azazel-decoy-verify.service on failure (OnFailure=); it runs nothing.",
        "# Conflicts= makes the job engine stop each of the three units directly, not",
        "# through Requires=; the decoy and the network helper stop before the namespace",
        "# unit, by the reverse of their After= order.",
        "# It has no grant marker and no [Install] section.",
        "",
        "[Unit]",
        "Description=Azazel-Nexus Deception Lite trip",
        f"Documentation={_GRANT_DOCUMENTATION}",
        *(f"Conflicts={unit}" for unit in DECOY_TRIP_CONFLICTS),
        "",
    ))


#: The watch's two units that are not services, with their rendering.
DECOY_WATCH_UNIT_FILES: tuple[tuple[str, str], ...] = (
    (DECOY_VERIFY_TIMER, render_verify_timer()),
    (DECOY_TRIP_UNIT, render_trip_target()),
)


#: The observers' timers (U2), with their rendering.
OBSERVER_UNIT_FILES: tuple[tuple[str, str], ...] = (
    (UNITS_OBSERVE_TIMER, render_observer_timer(
        UNITS_OBSERVE_TIMER, UNITS_OBSERVE_UNIT, "30s",
        "Azazel-Nexus unit state observer period")),
    (NOC_OBSERVE_TIMER, render_observer_timer(
        NOC_OBSERVE_TIMER, NOC_OBSERVE_UNIT, "60s",
        "Azazel-Nexus passive NOC observer period")),
)
def render_ui_socket() -> str:
    """`azazel-ui.socket`, byte for byte (U5).

    systemd, not the UI, listens: on `UI_LISTEN_STREAM` (IPv4 loopback) and
    nothing else, and hands the listening socket to `UI_UNIT` (fd 3), which
    only accepts on it. `IPAddressDeny=any` with `IPAddressAllow=localhost`
    applies to the listening socket and the connections it accepts (a
    socket-activated service's own lists cover only sockets it creates).
    `WantedBy=sockets.target`; the preset says `disable`, so only an
    operator's `systemctl enable` makes it listen at boot.
    """

    return "\n".join((
        *_GENERATED_HEADER,
        "# The read-only operator UI's listener (docs/operator-ui.md). systemd listens on",
        "# IPv4 loopback only and passes the socket to azazel-ui.service, which accepts",
        "# on it and never creates a network socket. Not enabled by the installer.",
        "",
        "[Unit]",
        "Description=Azazel-Nexus read-only operator UI (loopback listener)",
        "Documentation=https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/operator-ui.md",
        "",
        "[Socket]",
        f"ListenStream={UI_LISTEN_STREAM}",
        "Accept=no",
        "FreeBind=no",
        "Backlog=16",
        "MaxConnections=16",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
        f"Service={UI_UNIT}",
        "",
        "[Install]",
        "WantedBy=sockets.target",
        "",
    ))


#: The UI's socket unit, with its rendering.
UI_UNIT_FILES: tuple[tuple[str, str], ...] = ((UI_SOCKET, render_ui_socket()),)


def packaged_unit_files() -> tuple[tuple[str, str], ...]:
    """`(name, text)` of every file in `packaging/systemd/`, in order."""

    return tuple((profile.unit, render_unit(profile)) for profile in ALL_PROFILES) + (
        DECOY_WATCH_UNIT_FILES + OBSERVER_UNIT_FILES + UI_UNIT_FILES)


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
    if profile.apparmor_profile:
        # Without it a kernel with AppArmor disabled would run the unit
        # unconfined: systemd ignores AppArmorProfile= there (#196 G3).
        lines.append("AssertSecurity=apparmor")
    for unit in profile.before:
        lines.append(f"Before={unit}")
    for unit in profile.conflicts:
        lines.append(f"Conflicts={unit}")
    for unit in profile.requires:
        lines.append(f"Requires={unit}")
    for unit in profile.binds_to:
        lines.append(f"BindsTo={unit}")
    for unit in profile.on_failure:
        lines.append(f"OnFailure={unit}")
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
        "ExecStart=" + " ".join((profile.executable, *profile.arguments)),
    ]
    # Further `ExecStart=` lines (the namespace unit's alone, pinned in its
    # extra) follow the first, so that the steps read in order.
    lines += [f"ExecStart={value}" for key, value in profile.extra if key == "ExecStart"]
    if profile.apparmor_profile:
        lines.append(f"AppArmorProfile={profile.apparmor_profile}")
    if profile.runtime_directory:
        lines += [
            f"RuntimeDirectory={profile.runtime_directory}",
            f"RuntimeDirectoryMode={profile.runtime_directory_mode}",
        ]
    for key, value in profile.extra:
        if key != "ExecStart":
            lines.append(f"{key}={value}")
    lines.append(
        "RestrictAddressFamilies=" + " ".join(profile.address_families)
    )
    for path in profile.read_write_paths:
        lines.append(f"ReadWritePaths={path}")
    for path in profile.optional_read_write_paths:
        lines.append(f"ReadWritePaths=-{path}")
    overridden = {key for key, _ in profile.shared_overrides}
    for key, value in SHARED_HARDENING:
        if key in profile.shared_omissions:
            continue
        if key in overridden:
            lines += [f"{key}={override}" for name, override
                      in profile.shared_overrides if name == key]
            continue
        if key == "CapabilityBoundingSet" and profile.capability_bounding_set:
            value = " ".join(profile.capability_bounding_set)
        lines.append(f"{key}={value}")
    if profile.wanted_by:
        lines += ["", "[Install]", *(f"WantedBy={unit}" for unit in profile.wanted_by)]
    lines.append("")
    return "\n".join(lines)


def governed_units() -> tuple[str, ...]:
    """The units the activation controller governs, from the library."""

    return tuple(definition.name for definition in CORE_UNITS)
