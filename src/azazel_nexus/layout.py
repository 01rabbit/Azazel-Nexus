"""Where the node keeps things, as data rather than as prose (#28).

`docs/IMPLEMENTATION_SPEC.md` §3 gives the filesystem layout and calls its
permissions "mandatory defaults". A mandatory default that lives only in a
document is a default until the first installer that disagrees with it, and
nothing notices. So the layout is declared here and the installer is checked
against this declaration rather than against the document's good intentions.

Two properties matter and both are refusals rather than conventions:

*The layout is creatable without root.* `create_layout` takes a root, so the
same declaration that describes `/var/lib/azazel` can be materialised under a
temporary directory in a test. A layout that can only be exercised on the
target host is a layout that is exercised for the first time in production.

*Modes are part of the declaration, not of the installer.* `run/` is
traversal-only (`0711`), and each daemon socket directory uses setgid so Linux
assigns the reviewed operator group without granting daemons `CAP_CHOWN`. The
installer copies these numbers; it does not choose them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["LAYOUT", "PathSpec", "create_layout", "spec_for"]


@dataclass(frozen=True)
class PathSpec:
    """One directory the node requires, and why it has the mode and owner it has.

    `owner` and `group` are part of the declaration for the same reason the
    mode is: a directory the installer creates and nobody assigns is a
    directory owned by whoever ran the installer. The daemons run under their
    own accounts (§3), so which account may write where is the difference
    between least privilege and a set of directories that happen to work
    because everything is root.
    """

    path: str
    mode: int
    purpose: str
    owner: str = "root"
    group: str = "root"

    def __post_init__(self) -> None:
        if not self.path.startswith("/"):
            raise ValueError(
                f"{self.path!r} is not absolute; the layout describes where a "
                "node keeps things on the host, which is not a relative question"
            )
        # Set-group-ID preserves the reviewed reader group on trust and socket
        # directories. Linux assigns new children the declared reader/operator
        # group without granting the daemon CAP_CHOWN. Other special
        # permission bits are deliberately not part of this layout language.
        if (
            not 0 <= self.mode <= 0o2777
            or self.mode & ~0o2777
            or self.mode & 0o1000
        ):
            raise ValueError(f"{self.mode:o} is not a directory mode")
        if not self.purpose.strip():
            raise ValueError(
                f"{self.path!r} has no stated purpose; a directory nobody can "
                "say the reason for is a directory nobody can say the mode for"
            )
        for field_name in ("owner", "group"):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(
                    f"{self.path!r} names no {field_name}; it would then belong "
                    "to whoever ran the installer"
                )
        if self.group != "root" and not self.mode & 0o070:
            raise ValueError(
                f"{self.path!r} is grouped to {self.group!r} and gives the "
                f"group nothing ({self.mode:04o}); a group that grants no "
                "access is a group that explains nothing"
            )


#: The CORE subset of `IMPLEMENTATION_SPEC.md` §3.
#:
#: Unconditionally installed directories only. The Mission Pack store under
#: /data is provisioned separately by tools/provision_mission_read.py: adding it
#: here would let create_layout create state before the encrypted mount check.
#: Its reader modes and conditional creation are covered by installer tests.
LAYOUT = (
    PathSpec("/etc/azazel/mio-profile", 0o700, "minimal entryd proposal credential source"),
    PathSpec("/etc/azazel", 0o755, "node configuration; world-readable by design"),
    PathSpec(
        "/etc/azazel/commissioning",
        0o750,
        "operator-confirmed role bindings and the read-only inventory",
        group="azcommission",
    ),
    PathSpec(
        "/etc/azazel/bootstrap",
        0o700,
        "root-private administrator declarations, approvals and selected-file manifest",
    ),
    PathSpec(
        "/etc/azazel/systemd",
        0o755,
        "unit drop-ins installed by packages",
    ),
    PathSpec("/var/lib/azazel", 0o711, "small mutable state; private traversal only"),
    PathSpec(
        "/var/lib/azazel/edge-core",
        0o700,
        "private Edge event log and release ledger; no imported enforcement state",
        owner="azedge",
    ),
    PathSpec(
        "/var/lib/azazel/run",
        0o711,
        "socket traversal only; daemon-specific leaves enforce socket access",
    ),
    PathSpec(
        "/var/lib/azazel/run/audit",
        0o2710,
        "audit socket leaf; daemon-owned with operator-group socket inheritance",
        owner="azaudit",
        group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/run/audit-submit",
        0o2710,
        "explainer's append-only audit socket; no operator socket access",
        owner="azaudit",
        group="azaudit-submit",
    ),
    PathSpec(
        "/var/lib/azazel/run/audit-status",
        0o2750,
        "auditd's capacity snapshot; operator-readable sizes and counts, no records",
        owner="azaudit",
        group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/run/commission",
        0o2710,
        "commission socket leaf; daemon-owned with operator-group socket inheritance",
        owner="azcommission",
        group="azazel-operator",
    ),
    PathSpec("/var/lib/azazel/edge-incidents", 0o2750,
             "read-only incident chains for explainer", owner="azintake", group="azincident-read"),
    PathSpec("/var/lib/azazel/incident-explain", 0o700,
             "private explanation records and cursor", owner="azexplain"),
    PathSpec("/var/lib/azazel/run/incident-explain-status", 0o2750,
             "operator-readable explanation liveness", owner="azexplain", group="azazel-operator"),
    PathSpec("/var/lib/azazel/edge-intake", 0o700,
             "private Edge evidence", owner="azintake"),
    PathSpec("/var/lib/azazel/run/edge-intake", 0o2710,
             "receive-only socket reachable by Edge", owner="azintake", group="azedge"),
    PathSpec("/var/lib/azazel/run/edge-intake-status", 0o2750,
             "operator-readable intake liveness", owner="azintake", group="azazel-operator"),
    PathSpec(
        "/var/lib/azazel/run/edge-probe",
        0o2750,
        "Edge probe result leaf; the probe owns it so its temp-file rename "
        "stays inside it, and the operator group may read the result",
        owner="azprobe",
        group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/run/watchdog",
        0o2710,
        "watchdog socket leaf; daemon-owned with operator-group socket inheritance",
        owner="azwatch",
        group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/state",
        0o711,
        "service-state traversal only; each writer owns a private leaf",
    ),
    PathSpec(
        "/var/lib/azazel/state/audit",
        0o700,
        "auditd segmented hash chain",
        owner="azaudit",
        group="root",
    ),
    PathSpec(
        "/var/lib/azazel/state/auditd",
        0o700,
        "auditd refusal records, isolated from segmented chain inputs",
        owner="azaudit",
        group="root",
    ),
    PathSpec(
        "/var/lib/azazel/state/commission",
        0o700,
        "commissiond repin ledger, confirmation snapshots and refusal records",
        owner="azcommission",
        group="root",
    ),
    PathSpec(
        "/var/lib/azazel/state/watchdog",
        0o700,
        "watchdog fence and refusal records",
        owner="azwatch",
        group="root",
    ),
    PathSpec(
        "/var/lib/azazel/state/bootstrap",
        0o700,
        "root-private bootstrap deadlines, per-boot grant transactions and shared lock",
    ),
    PathSpec(
        "/var/lib/azazel/state/bootstrap-overlay",
        0o700,
        "isolated root-private journal for volatile helper unit overlays",
    ),
    PathSpec(
        "/var/lib/azazel/generations",
        0o700,
        "private staging trees; promoted, never edited in place",
    ),
    PathSpec(
        "/var/lib/azazel/bootstrap-generations", 0o700,
        "bootstrap-only trees, isolated from operational generation selection",
    ),
    PathSpec(
        "/var/lib/azazel/fetch",
        0o750,
        "the artifact fetcher's staging area, and the only path that service "
        "may write. Group-readable because what lands here is promoted by a "
        "different account: a fetcher that could also promote would be a "
        "fetcher whose output nothing else had to agree about",
        group="azfetch",
    ),
    PathSpec("/etc/azazel/model-admission", 0o750, "protected embedding approval store", group="azmio"),
    PathSpec("/etc/azazel/model-admission/evidence", 0o750, "attested combined campaign bundle", group="azmio"),
    PathSpec("/etc/azazel/model-admission/evidence/artifacts", 0o750, "attested campaign artifacts", group="azmio"),
    PathSpec("/var/lib/azazel/models", 0o750, "root importer model trees", group="azmio"),
    PathSpec("/var/lib/azazel/fetch/commission", 0o750, "root-written fetch commissioning", group="azfetch"),
    PathSpec("/var/lib/azazel/fetch/partial", 0o750, "fetch partials and refusal records", owner="azfetch", group="azfetch"),
    PathSpec("/var/lib/azazel/fetch/ready", 0o750, "complete unverified fetch handoffs", owner="azfetch", group="azfetch"),
    PathSpec("/var/lib/azazel/run/fetch", 0o2710, "fetch socket leaf with operator group inheritance", owner="azfetch", group="azazel-operator"),
    PathSpec("/var/lib/azazel/run/mio", 0o2710,
             "local model runtime host socket leaf; entryd reaches it through the operator group",
             owner="azmio", group="azazel-operator"),
    PathSpec("/var/lib/azazel/run/remote", 0o2710,
             "remote inference transport socket leaf; entryd reaches it through the operator group",
             owner="azremote", group="azazel-operator"),
    PathSpec("/var/lib/azazel/models/staging", 0o2750,
             "root-owned model staging; inherit the runtime read group", group="azmio"),
    PathSpec("/var/lib/azazel/models/store", 0o2750,
             "root-owned promoted weights; locald may read, never write", group="azmio"),
    PathSpec(
        "/var/lib/azazel/mio",
        0o750,
        "the local model runtime host's own directory: the models it may read "
        "and the only path it may write. Separate from the fetcher's staging "
        "because the account that may reach the network and the account that "
        "may run a program are not the same account, and a directory both "
        "could write is a path from a fetched byte to an executed one",
        owner="azmio", group="azmio",
    ),
    PathSpec(
        "/var/lib/azazel/remote",
        0o750,
        "the remote inference transport's own directory: the commissioned "
        "Provider Registry it reads and the only path it may write. Separate "
        "from the fetcher's and the local runtime's because the account that "
        "may push what this node observed is not the account that may pull a "
        "file, nor the one that may run a program",
        group="azremote",
    ),
    PathSpec(
        "/var/lib/azazel/lite-trust",
        0o2750,
        "commissioner-promoted public trust generations; Lite consumer reads only",
        owner="azcommission",
        group="azknowledge",
    ),
    PathSpec(
        "/var/lib/azazel/state/mio", 0o700,
        "M.I.O. entry route ledger and refusals", owner="azmioentry",
    ),
    PathSpec(
        "/var/lib/azazel/state/knowledge", 0o700,
        "Knowledge Lite daemon refusal records", owner="azknowledge",
    ),
    PathSpec(
        "/var/lib/azazel/run/mio-entry", 0o2710,
        "M.I.O. entry socket with operator group inheritance",
        owner="azmioentry", group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/run/mio-advise", 0o2710,
        "explainer's advice-only M.I.O. entry socket; no operator socket access",
        owner="azmioentry", group="azmio-advise",
    ),
    PathSpec(
        "/var/lib/azazel/run/knowledge", 0o2710,
        "Knowledge Lite socket with operator group inheritance",
        owner="azknowledge", group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/run/knowledge-read", 0o2710,
        "Knowledge Lite service client socket; no operator socket access",
        owner="azknowledge", group="azknowledge-read",
    ),
    PathSpec(
        "/var/lib/azazel/knowledge", 0o2750,
        "Knowledge Lite store with operator read access",
        owner="azknowledge", group="azazel-operator",
    ),
    PathSpec(
        "/var/lib/azazel/secrets",
        0o700,
        "root-only credential material; never readable by a daemon account",
    ),
)


def spec_for(path: str) -> Optional[PathSpec]:
    """The declaration for `path`, or `None` if the layout does not claim it."""

    for spec in LAYOUT:
        if spec.path == path:
            return spec
    return None


def create_layout(root: Path) -> tuple[Path, ...]:
    """Materialise the layout under `root`, modes included.

    Parents are created before children so that a child's mode is never
    inherited from an implicitly created parent -- `/var/lib/azazel/run` at
    `0711` under a `/var/lib/azazel` that `mkdir(parents=True)` created at the
    process umask would be a boundary set by whatever the shell happened to
    have configured.
    """

    created = []
    for spec in sorted(LAYOUT, key=lambda s: s.path.count("/")):
        target = root / spec.path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(spec.mode)
        created.append(target)
    return tuple(created)
