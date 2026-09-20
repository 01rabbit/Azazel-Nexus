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

*Modes are part of the declaration, not of the installer.* `run/` is `0750`
because a socket directory readable by everything on the host is the first
authorization boundary given away (§4). The installer copies these numbers; it
does not choose them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["LAYOUT", "PathSpec", "create_layout", "spec_for"]


@dataclass(frozen=True)
class PathSpec:
    """One directory the node requires, and why it has the mode it has."""

    path: str
    mode: int
    purpose: str

    def __post_init__(self) -> None:
        if not self.path.startswith("/"):
            raise ValueError(
                f"{self.path!r} is not absolute; the layout describes where a "
                "node keeps things on the host, which is not a relative question"
            )
        if not 0 <= self.mode <= 0o777:
            raise ValueError(f"{self.mode:o} is not a directory mode")
        if not self.purpose.strip():
            raise ValueError(
                f"{self.path!r} has no stated purpose; a directory nobody can "
                "say the reason for is a directory nobody can say the mode for"
            )


#: The CORE subset of `IMPLEMENTATION_SPEC.md` §3.
#:
#: Only the paths this slice actually writes to are here. The evidence store,
#: the mission volume and the optional components' state directories are not
#: omitted because they are optional -- they belong to slices that are not
#: built yet, and declaring a directory the node never creates would make this
#: table describe an intention instead of a host.
LAYOUT = (
    PathSpec("/etc/azazel", 0o755, "node configuration; world-readable by design"),
    PathSpec(
        "/etc/azazel/commissioning",
        0o755,
        "operator-confirmed role bindings and the read-only inventory",
    ),
    PathSpec(
        "/etc/azazel/systemd",
        0o755,
        "unit drop-ins installed by packages",
    ),
    PathSpec("/var/lib/azazel", 0o750, "small mutable state; not world-readable"),
    PathSpec(
        "/var/lib/azazel/run",
        0o750,
        "unix domain sockets; socket ACLs are the first authorization boundary",
    ),
    PathSpec("/var/lib/azazel/state", 0o750, "durable state machines"),
    PathSpec(
        "/var/lib/azazel/generations",
        0o700,
        "private staging trees; promoted, never edited in place",
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
    `0750` under a `/var/lib/azazel` that `mkdir(parents=True)` created at the
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
