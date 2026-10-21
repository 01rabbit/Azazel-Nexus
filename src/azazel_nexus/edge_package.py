"""Verify the local Edge Core package, and refuse to overstate the result (#44).

The Edge side is [Azazel-Edge#424](https://github.com/01rabbit/Azazel-Edge/issues/424),
whose contract this module consumes from `contract/azazel-edge-core/`. That
directory is a **copy** of what Azazel-Edge commits, and `PROVENANCE.md` there
says why the two repositories hold the tie with copies and tests rather than
with an import.

## Five checks, reported separately

`package_present`, `version_matches`, `digest_matches`,
`health_endpoint_healthy`, `running`. `activation.EdgeBaselineState` needs all
five for readiness; admission needs the first four. This module is the
**only producer of one in the package** -- the static scan in
`tests/unit/test_wizard_and_cli.py` keeps it that way.

They are separate because the operator's next action is different for each.
"Edge is not installed" is a deployment step. "Edge is installed and its
digest does not match what we pinned" is a **security finding**, and a display
that folded the two into "Edge: not ready" would send somebody to do the wrong
thing.

## Three-valued, because "nobody looked" is not "it failed"

A check is `passed`, `failed`, or `not-checked`. The third one is what an
absent probe produces, and it is kept apart from `failed` because a node that
reported a health failure it never attempted would have an operator chasing a
fault that does not exist. `not-checked` grants nothing either: unknown never
grants, and only `passed` counts towards ready.

## The digest is not signed, and a pass says so

`pin.json` carries `signed: false`. A matching digest establishes integrity
**against accidental change** -- a truncated copy, a half-written file, the
wrong build put in place. It does not establish integrity against an adversary
who can rewrite the package and its manifest together, because that adversary
rewrites the digest too.

So even a fully passing inspection carries that caveat, `as_event` carries it,
and the renderer prints it. A verification whose limits are recorded only in
the design document is a verification whose limits nobody reads.

A manifest that claims `signed: true` is **refused**, not believed: this node
can verify no signature, and a claim of authenticity it cannot check is worse
than an absent one, because it invites the reliance the absent one denies.

## What this module never does

It does not install, extract, configure a network, or start anything.
`tests/unit/test_boundary_static.py` forbids this package from importing
`subprocess`: Nexus's library half has not commissioned an operational
surface, and a status command that spawned the component it reports on would
be a status command with a side effect.

## Where health and running come from ([#72](https://github.com/01rabbit/Azazel-Nexus/issues/72))

From `az-edge-probed`, a **separate one-shot runtime service** in the runtime
distribution, which writes a bounded state file this module *reads*. `status`
stays read-only: it starts nothing, retries nothing and probes nothing.

The trust that places on the probe is deliberately small. **This module keeps
deriving `package_present`, `version_matches` and `digest_matches` itself**,
from the files on disk, on every read. Only `health_endpoint_healthy` and
`running` come from the probe, and a result is used only when it names the
same version and the same artifact digest this module just derived. A probe
that reports on a different package reports on nothing.

A result older than its own TTL is `not-checked` with a reason that says it
went stale. **Staleness never promotes**: there is no path by which an old
result, a mismatched result, or an unparseable one produces anything but
`not-checked`, and `edge-baseline-ready` needs all five checks `passed`.

## A result is bound to the boot it was observed in (#206, P5)

Probe contract v2 adds `boot_id`, the kernel's
`/proc/sys/kernel/random/boot_id` at the time of the probe. A reader uses a
result only when that equals the current boot's id, read by the same
protected reader (`read_current_boot_id`), **in addition to** the TTL: the
boot-time probe preflight runs moments before the activation pass, so a
result written just before a kernel reboot would otherwise still be inside its
TTL after it. A soft-reboot keeps the kernel and so the boot id: the boot id
does not tell its two userspaces apart, which is why `az-edge-probed` removes
the previous result before each run (#258 item 7). A result from another boot, a v1 result (which carries no boot and
so cannot be shown to be from this one), or any result when this boot's id
cannot be read is `not-checked` and says it is stale -- never `failed`.

The injected callables remain for tests and for a deployment that supplies
these another way. Passing both a probe result and a non-default callable is
refused: two sources for one finding is one source too many.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Sequence

from .activation import EDGE_CHECKS, EdgeBaselineState
from .integration import EdgePresence

__all__ = [
    "CHECKS",
    "DEFAULT_TTL_SECONDS",
    "EDGE_PACKAGE_ROOT",
    "EDGE_UNIT",
    "HEALTH_ARGV",
    "BOOT_ID_PATH",
    "PROBE_CONTRACT",
    "PROBE_CONTRACT_V1",
    "PROBE_MAX_BYTES",
    "PROBE_STATE_PATH",
    "ProbeResult",
    "load_probe_result",
    "parse_probe_result",
    "is_boot_id",
    "read_current_boot_id",
    "EdgeInspection",
    "EdgePin",
    "Evidence",
    "Finding",
    "HealthAnswer",
    "PIN",
    "UNSIGNED_CAVEAT",
    "BOUND_COMPONENTS",
    "bound_to_signed_package",
    "inspect",
    "installed_baseline_state",
    "installed_package_components",
    "installed_package_digest",
    "measure_extracted_components",
    "no_health_probe",
    "no_running_probe",
    "nothing_established",
    "presence_of",
]

#: Where the vendored Edge contract lives, relative to the repository root.
CONTRACT_DIR = Path(__file__).resolve().parents[2] / "contract" / "azazel-edge-core"

#: Where the Edge Core package is looked for. A **fixed** location, so that
#: "nothing is there" is a result rather than the absence of a question, and
#: so that neither this module nor the probe ever takes a path as input.
EDGE_PACKAGE_ROOT = Path("/opt/azazel/edge-core")

#: The systemd unit whose running state the probe reads. Fixed for the same
#: reason: a probe that accepted a unit name would be a probe that could be
#: pointed at any unit on the host.
EDGE_UNIT = "azazel-edge-core.service"

#: The health command, **fixed in code**. Edge's manifest declares the same
#: argv, and the probe checks that they agree -- but it runs this one. Running
#: the manifest's copy would be executing a command supplied as data, and a
#: manifest is exactly the file an adversary who can reach the package can
#: rewrite.
HEALTH_ARGV = ("bin/azazel-edge-core", "--health")

#: The state file the probe writes and this module reads.
#:
#: In a leaf of its own, `/var/lib/azazel/run/edge-probe`, which `layout.py`
#: declares `azprobe:azazel-operator 2750`: the probe's account owns the
#: directory, so it can create its temporary file there and rename it into
#: place, and nothing else under the traversal-only (`root 0711`) run root is
#: writable to it -- the leaf is the whole of the unit's `ReadWritePaths`.
#: The operator group may list and read the leaf, and the result itself is
#: `0644`, so the operator who runs `azazel-nexus status` (and root) reads it
#: by name. Durability across a reboot is not a problem the location has to
#: solve; the boot binding solves it (contract v2): a result from before a
#: reboot names another boot and is stale whatever its TTL says.
PROBE_STATE_PATH = Path("/var/lib/azazel/run/edge-probe/edge-probe.json")
PROBE_CLOCK_SKEW_SECONDS = 5
#: The contract the probe writes and readers use. v2 adds `boot_id`.
PROBE_CONTRACT = "azazel-nexus/edge-probe/v2"
#: The previous contract. Still parsed, so that `status` can say why it is not
#: used, and always stale: it names no boot, so it cannot be shown to be from
#: this one.
PROBE_CONTRACT_V1 = "azazel-nexus/edge-probe/v1"

#: The kernel's identifier for the current boot. Fixed, like every other path
#: here; tests inject another one.
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

#: The most this reads from the boot id file: 36 characters and a newline.
_BOOT_ID_MAX_BYTES = 64
_BOOT_ID_HEX = "0123456789abcdef"

#: A ceiling on what is read from the state file. A reader with no ceiling is
#: a reader whose memory is decided by whatever wrote the file.
PROBE_MAX_BYTES = 16384

#: How long a result may be used for, when it does not say. Short, because an
#: old answer about a running process is not a weak answer -- it is an answer
#: about a different moment.
DEFAULT_TTL_SECONDS = 300

#: The longest TTL a result may declare. A probe that could name its own
#: expiry without bound could name one that never arrives.
MAX_TTL_SECONDS = 3600

#: The five checks, in the order an operator reads them. A tuple rather than a
#: set: both a disappearance and a reordering should fail a test, because the
#: order is what the display walks.
CHECKS = EDGE_CHECKS

#: Printed beside every passing inspection. Not a footnote in a design
#: document: a limit recorded only there is a limit nobody reads.
UNSIGNED_CAVEAT = (
    "the Edge manifest is not signed, so a matching digest establishes "
    "integrity against accidental change and not authenticity; an adversary "
    "who can rewrite the package can rewrite the manifest with it"
)


class EdgePackageRefused(Exception):
    """An inspection that would mislead is not produced."""


class Evidence(str, Enum):
    """What happened to one check. `NOT_CHECKED` is not a failure."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_CHECKED = "not-checked"


@dataclass(frozen=True)
class EdgePin:
    """What this node fixes. Mirrors `contract/azazel-edge-core/pin.json`."""

    package: str
    version: str
    architecture: str
    manifest_contract: str
    health_contract: str
    signed: bool = False

    @property
    def manifest_name(self) -> str:
        return f"{self.package}-{self.version}-{self.architecture}.manifest.json"

    @property
    def artifact_name(self) -> str:
        return f"{self.package}-{self.version}-{self.architecture}.tar.gz"


#: The pinned Edge Core. Every field is asserted against the vendored
#: `pin.json` by `tests/unit/test_edge_package.py`, so a version bump in Edge
#: that is copied here without updating this constant fails the suite.
PIN = EdgePin(
    package="azazel-edge-core",
    version="0.1.0",
    architecture="x86_64",
    manifest_contract="azazel-edge-core/package-manifest/v1",
    health_contract="azazel-edge-core/health/v1",
    signed=False,
)

#: The manifest fields this node reads. A subset of the vendored schema, and a
#: test asserts it is a subset -- reading a field the producer does not
#: promise is how a consumer ends up verifying something nobody ships.
REQUIRED_MANIFEST_KEYS = (
    "architecture",
    "contract",
    "digest",
    "health.contract",
    "package",
    "posture.enforcement",
    "posture.observe_only",
    "signed",
    "version",
)

#: The same, for the health report.
REQUIRED_HEALTH_KEYS = ("contract", "status", "version")

#: The word the Edge health contract uses for a healthy report. Read from the
#: vendored schema by a test rather than trusted here.
HEALTHY_STATUS = "healthy"


@dataclass(frozen=True)
class Finding:
    """One check, its evidence, and why."""

    check: str
    evidence: Evidence
    reason: str
    #: True only for a failure that means somebody may have changed the
    #: package. A missing package is a deployment step; a digest that does not
    #: match is a finding.
    security: bool = False

    def __post_init__(self) -> None:
        if self.check not in CHECKS:
            raise EdgePackageRefused(f"{self.check!r} is not one of the five checks")
        if not self.reason.strip():
            raise EdgePackageRefused(
                f"the {self.check} finding has no reason; an unexplained state "
                "reads as agreement"
            )
        if self.security and self.evidence is not Evidence.FAILED:
            raise EdgePackageRefused(
                f"the {self.check} finding is marked a security finding while "
                f"its evidence is {self.evidence.value}; a check nobody ran "
                "has found nothing"
            )

    @property
    def held(self) -> bool:
        """Only `passed` counts. `not-checked` grants nothing."""

        return self.evidence is Evidence.PASSED

    def as_event(self) -> dict:
        return {
            "check": self.check,
            "evidence": self.evidence.value,
            "reason": self.reason,
            "security": self.security,
        }


@dataclass(frozen=True)
class HealthAnswer:
    """One run of the Edge health contract, as the probe observed it."""

    exit_code: Optional[int]
    stdout: str
    reason: str = ""


@dataclass(frozen=True)
class EdgeInspection:
    """The five findings together, and what may be concluded from them."""

    findings: tuple[Finding, ...]
    presence: EdgePresence
    caveats: tuple[str, ...] = ()
    root: str = ""
    probe: Optional["ProbeResult"] = None

    def __post_init__(self) -> None:
        seen = tuple(finding.check for finding in self.findings)
        if seen != CHECKS:
            raise EdgePackageRefused(
                f"an inspection reports {seen} and the five checks are {CHECKS}; "
                "a check nobody reports is a check nobody can act on"
            )
        if self.ready and self.presence is not EdgePresence.VERIFIED_READY:
            raise EdgePackageRefused(
                "every check passed and the displayed word is "
                f"{self.presence.value}; the display and the decision would "
                "disagree on the same node"
            )
        if self.presence is EdgePresence.VERIFIED_READY and not self.ready:
            raise EdgePackageRefused(
                "the display says verified-ready and not every check passed"
            )
        if not self.caveats:
            raise EdgePackageRefused(
                "an inspection carries no caveat; the unsigned manifest is a "
                "limit of every result this module produces, passing or not"
            )

    def finding(self, check: str) -> Finding:
        for candidate in self.findings:
            if candidate.check == check:
                return candidate
        raise EdgePackageRefused(f"no {check!r} finding")

    @property
    def ready(self) -> bool:
        return all(finding.held for finding in self.findings)

    @property
    def security_findings(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.security)

    @property
    def unchecked(self) -> tuple[str, ...]:
        return tuple(
            finding.check
            for finding in self.findings
            if finding.evidence is Evidence.NOT_CHECKED
        )

    def state(self) -> EdgeBaselineState:
        """The five booleans the activation decision consumes.

        `not-checked` becomes `False`. Unknown never grants, and the reason
        for the `False` stays in the finding rather than being flattened here.
        """

        return EdgeBaselineState(
            *(finding.held for finding in self.findings),
            observed_at=self.probe.observed_at if self.probe else None,
            package_version=self.probe.package_version if self.probe else None,
            package_digest=self.probe.package_digest if self.probe else None,
        )

    def as_event(self) -> dict:
        return {
            "event_type": "nexus.edge_package.inspection",
            "root": self.root,
            "presence": self.presence.value,
            "ready": self.ready,
            "caveats": list(self.caveats),
            "findings": [finding.as_event() for finding in self.findings],
        }


# -- the probe's result, which is read and never trusted further ----------


@dataclass(frozen=True)
class ProbeResult:
    """What `az-edge-probed` observed, as this module is willing to read it.

    It carries the version and artifact digest the probe saw. This module
    compares both against what it derived itself, and a result that names a
    different package supplies nothing -- which is what keeps the probe from
    being able to answer for a package that is not the one on disk.
    """

    contract: str
    observed_at: str
    ttl_seconds: int
    package_version: str
    package_digest: str
    health: Evidence
    health_reason: str
    running: Evidence
    running_reason: str
    #: True only when the probe found a healthy report from the wrong version.
    health_security: bool = False
    #: The boot the probe ran in (v2). `None` only on a v1 result, which is
    #: parsed so that a reader can say why it is not used, and never used.
    boot_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.contract == PROBE_CONTRACT:
            if not is_boot_id(self.boot_id):
                raise EdgePackageRefused(
                    f"a {PROBE_CONTRACT} result names the boot it was observed "
                    "in as a canonical boot id"
                )
        elif self.contract == PROBE_CONTRACT_V1:
            if self.boot_id is not None:
                raise EdgePackageRefused(
                    f"a {PROBE_CONTRACT_V1} result carries no boot_id; one that "
                    "does is neither contract"
                )
        else:
            raise EdgePackageRefused(
                f"the probe result declares contract {self.contract!r} and this "
                f"node reads {PROBE_CONTRACT!r}"
            )
        if not isinstance(self.ttl_seconds, int) or isinstance(self.ttl_seconds, bool):
            raise EdgePackageRefused("a TTL is a whole number of seconds")
        if not 0 < self.ttl_seconds <= MAX_TTL_SECONDS:
            raise EdgePackageRefused(
                f"a TTL of {self.ttl_seconds}s is outside 1-{MAX_TTL_SECONDS}s; "
                "an unbounded expiry is an expiry that never arrives"
            )
        for name in ("observed_at", "package_version"):
            if not str(getattr(self, name)).strip():
                raise EdgePackageRefused(f"a probe result states its {name}")
        # A probe that found no usable package checked nothing and claims no
        # package: it may leave the digest empty, but only when both checks are
        # not-checked. Any result that reports a checked outcome must name the
        # package it checked.
        checked_nothing = (self.health is Evidence.NOT_CHECKED
                           and self.running is Evidence.NOT_CHECKED)
        if not str(self.package_digest).strip() and not checked_nothing:
            raise EdgePackageRefused("a probe result states its package_digest")
        for name in ("health_reason", "running_reason"):
            if not str(getattr(self, name)).strip():
                raise EdgePackageRefused(
                    f"a probe result with no {name} reads as agreement"
                )
        if self.health_security and self.health is not Evidence.FAILED:
            raise EdgePackageRefused(
                "a probe result marks a security finding on a health check that "
                f"is {self.health.value}; a check nobody ran has found nothing"
            )
        _instant(self.observed_at)

    def expires_at(self) -> str:
        from datetime import timedelta

        moment = _instant(self.observed_at) + timedelta(seconds=self.ttl_seconds)
        return _zulu(moment.isoformat())

    def fresh_at(self, now: str) -> bool:
        return not self.future_at(now) and _instant(now) < _instant(self.expires_at())

    def future_at(self, now: str) -> bool:
        from datetime import timedelta

        return _instant(self.observed_at) > (
            _instant(now) + timedelta(seconds=PROBE_CLOCK_SKEW_SECONDS)
        )

    def from_boot(self, boot_id: Optional[str]) -> bool:
        """Whether this result was observed in the boot `boot_id` names.

        False for a v1 result, for an unknown current boot (`None`), and for
        any other boot. Only an exact match of two canonical ids is True.
        """

        return (
            self.contract == PROBE_CONTRACT
            and is_boot_id(boot_id)
            and self.boot_id == boot_id
        )

    def as_event(self) -> dict:
        document = {
            "contract": self.contract,
            "observed_at": self.observed_at,
            "ttl_seconds": self.ttl_seconds,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "health": self.health.value,
            "health_reason": self.health_reason,
            "health_security": self.health_security,
            "running": self.running.value,
            "running_reason": self.running_reason,
        }
        if self.boot_id is not None:
            document["boot_id"] = self.boot_id
        return document


def is_boot_id(value: object) -> bool:
    """A canonical lowercase UUID, as the kernel writes it. Nothing else."""

    if type(value) is not str or len(value) != 36:
        return False
    for index, char in enumerate(value):
        if index in (8, 13, 18, 23):
            if char != "-":
                return False
        elif char not in _BOOT_ID_HEX:
            return False
    return True


def read_current_boot_id(
    path: Path = BOOT_ID_PATH, *, owner_uid: Optional[int] = None,
) -> str:
    """This boot's id, read the protected way, or `EdgePackageRefused`.

    No symlink is followed, the file must be a regular one (procfs reports the
    sysctl as one) owned by root and writable by nobody else, the read is
    bounded, and the value must be a canonical lowercase UUID. Anything else
    refuses: the probe then writes nothing, and a reader treats every result
    as stale.

    `owner_uid` exists for unit tests of these checks against a file the test
    owns. No production caller passes it -- the probe, the activation pass
    and `status` all call this with no argument -- and no flag reaches it.
    """

    trusted = (0,) if owner_uid is None else (0, owner_uid)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in trusted
                    or info.st_mode & 0o022):
                raise EdgePackageRefused("the boot id has unsafe ownership or mode")
            raw = stream.read(_BOOT_ID_MAX_BYTES + 1)
    except OSError as exc:
        raise EdgePackageRefused(f"the boot id could not be read: {exc}") from exc
    if len(raw) > _BOOT_ID_MAX_BYTES:
        raise EdgePackageRefused("the boot id is longer than a boot id")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EdgePackageRefused("the boot id is not ASCII") from exc
    if text.endswith("\n"):
        text = text[:-1]
    if not is_boot_id(text):
        raise EdgePackageRefused("the boot id is not a canonical boot id")
    return text


def _optional_boot_id(path: Path) -> Optional[str]:
    try:
        return read_current_boot_id(path)
    except EdgePackageRefused:
        return None


def _zulu(isoformat: str) -> str:
    """`...+00:00` written as `...Z`.

    Written with a slice rather than `str.replace`, and `_offset` below for
    the same reason. The static scan in `tests/unit/test_edge_package.py`
    refuses the *name* `replace` anywhere in this module, because
    `Path.replace` and `os.replace` rename files and an AST scan cannot tell a
    `str` from a `Path`. This module must not be able to move a file it is
    verifying, so it gives up the string method rather than the guard -- the
    same exact-match precedent that keeps `capture_spool` while refusing
    `capture`.
    """

    tail = "+00:00"
    return isoformat[: -len(tail)] + "Z" if isoformat.endswith(tail) else isoformat


def _offset(text: str) -> str:
    """`...Z` written as `...+00:00`, which `fromisoformat` accepts on 3.10."""

    return text[:-1] + "+00:00" if text.endswith("Z") else text


def _instant(text: str):
    """One RFC3339 UTC instant. Nothing here reads a clock."""

    from datetime import datetime, timezone

    try:
        moment = datetime.fromisoformat(_offset(str(text)))
    except ValueError as exc:
        raise EdgePackageRefused(f"{text!r} is not an RFC3339 instant: {exc}") from exc
    if moment.tzinfo is None:
        raise EdgePackageRefused(
            f"{text!r} carries no time zone; an instant without one is an "
            "instant that means something different on every host"
        )
    return moment.astimezone(timezone.utc)


def parse_probe_result(text: str) -> ProbeResult:
    """Read one state file's contents. Refuses rather than repairing."""

    if len(text.encode("utf-8")) > PROBE_MAX_BYTES:
        raise EdgePackageRefused(
            f"the probe state is larger than {PROBE_MAX_BYTES} bytes; a reader "
            "with no ceiling has its memory decided by whatever wrote the file"
        )
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise EdgePackageRefused(f"the probe state is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise EdgePackageRefused("the probe state is JSON that is not an object")
    missing = [
        key
        for key in (
            "contract",
            "observed_at",
            "ttl_seconds",
            "package_version",
            "package_digest",
            "health",
            "health_reason",
            "running",
            "running_reason",
        )
        if key not in document
    ]
    if missing:
        raise EdgePackageRefused(f"the probe state is missing {missing}")
    try:
        health = Evidence(document["health"])
        running = Evidence(document["running"])
    except ValueError as exc:
        raise EdgePackageRefused(f"the probe state names an unknown evidence: {exc}") from exc
    if document["contract"] == PROBE_CONTRACT and "boot_id" not in document:
        raise EdgePackageRefused("the probe state is missing ['boot_id']")
    return ProbeResult(
        contract=document["contract"],
        observed_at=document["observed_at"],
        ttl_seconds=document["ttl_seconds"],
        package_version=document["package_version"],
        package_digest=document["package_digest"],
        health=health,
        health_reason=document["health_reason"],
        running=running,
        running_reason=document["running_reason"],
        health_security=bool(document.get("health_security", False)),
        boot_id=document.get("boot_id"),
    )


def _probe_owner_uid() -> int:
    try:
        return pwd.getpwnam("azprobe").pw_uid
    except KeyError:
        return 0  # An uninstalled account never trusts a local writer.


def load_probe_result(
    path: Path = PROBE_STATE_PATH, *, owner_uid: Optional[int] = None,
) -> Optional[ProbeResult]:
    """Read the state file, or `None` when there is nothing readable there.

    `None` for an absent file, because a node where the probe has never run is
    not a node with a broken probe. A file that exists and cannot be read as a
    result raises: something wrote it, and silently ignoring that would hide
    the one case where the probe is producing garbage. Only azprobe or root
    may own it, with no group/other write permission (layout.py's probe leaf).
    Tests may inject the writer UID; an unresolved azprobe trusts only root.
    """

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            if owner_uid is None:
                owner_uid = _probe_owner_uid()
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, owner_uid)
                    or info.st_mode & 0o022):
                raise EdgePackageRefused("the probe state has unsafe ownership or mode")
            text = stream.read(PROBE_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EdgePackageRefused(f"the probe state could not be read: {exc}") from exc
    return parse_probe_result(text)


def installed_baseline_state(
    *, now: str, package_root: Path = EDGE_PACKAGE_ROOT,
    probe_path: Path = PROBE_STATE_PATH, boot_id_path: Path = BOOT_ID_PATH,
) -> EdgeBaselineState:
    """Activation evidence from fixed installed paths, re-derived each pass.

    Only a fresh, package-bound probe from this boot supplies health or
    running. An unreadable probe supplies neither, and neither does any probe
    when this boot's id cannot be read; an inspection error establishes no
    checks at all. This reads files only and never invokes the binary or the
    service manager.
    """
    try:
        try:
            probe = load_probe_result(probe_path)
        except Exception:  # noqa: BLE001 - unreadable evidence never grants
            probe = None
        boot_id = _optional_boot_id(boot_id_path) if probe is not None else None
        return inspect(package_root, probe=probe, now=now, boot_id=boot_id).state()
    except Exception:  # noqa: BLE001 - inspection failure establishes nothing
        return nothing_established()


def nothing_established() -> EdgeBaselineState:
    """Every check False: what an absent, failed or unreadable reading establishes.

    The activation pass (#206 P5) hands this to the library when its own Edge
    reader failed, so that a lease-bearing pass never falls back to reading
    host paths it did not choose. It is not launchable and claims nothing.
    """

    return EdgeBaselineState(False, False, False, False, False)


def bound_to_signed_package(
    state: EdgeBaselineState, signed_package_digest: Optional[str],
) -> EdgeBaselineState:
    """`state`, with `digest_matches` False unless it describes the signed package.

    The activation pass (#206 P5) passes the observe-baseline generation's
    `edge_pin.package_digest` only after it has derived the same digest from
    the installed package (`installed_package_digest`) and the extracted
    components it runs (`measure_extracted_components`); otherwise None. The
    probe's package digest must be exactly that one: a state that names no
    probed package is never launchable here, whatever its other fields say.
    This only narrows: no field becomes True here.
    """

    if type(state) is not EdgeBaselineState:
        return nothing_established()
    if (type(signed_package_digest) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", signed_package_digest)
            and type(state.package_digest) is str
            and state.package_digest == signed_package_digest):
        return state
    return replace(state, digest_matches=False)


#: The extracted files `azazel-edge-core.service` actually uses: the binary it
#: executes and the redirect policy its observe-only `Environment=` names. The
#: archive digest says nothing about them once unpacked (#206 P5).
BOUND_COMPONENTS = ("bin/azazel-edge-core", "config/redirect_policy.yaml")
#: Ceilings for one extracted component, the archive and its member count.
_COMPONENT_MAX_BYTES = 256 << 20
_ARCHIVE_MAX_BYTES = 512 << 20
_ARCHIVE_MAX_MEMBERS = 4096
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _protected(fd: int, owner_uid: int, *, directory: bool) -> None:
    info = os.fstat(fd)
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not kind or info.st_uid != owner_uid or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise EdgePackageRefused("an extracted Edge component has unsafe type, ownership or mode")


def measure_extracted_components(
    *, package_root: Path = EDGE_PACKAGE_ROOT, owner_uid: int = 0,
) -> dict[str, str]:
    """SHA-256 of each `BOUND_COMPONENTS` file as unpacked under the package root.

    Each path component is opened without following links, and the root,
    every directory and the file must be owned by `owner_uid` (root in
    production) and not group or other writable; the file must be a regular
    file with a single link, at most 256 MiB. It returns what is there, equal
    to anything or not: comparing is the caller's job. Anything unreadable or
    unsafe raises `EdgePackageRefused`. Reads files only.
    """

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    result: dict[str, str] = {}
    try:
        root_fd = os.open(package_root, flags | os.O_DIRECTORY)
    except OSError as exc:
        raise EdgePackageRefused(f"the Edge package root could not be opened: {exc}") from exc
    try:
        _protected(root_fd, owner_uid, directory=True)
        for relative in BOUND_COMPONENTS:
            parent, name = relative.split("/")
            fds: list[int] = []
            try:
                fds.append(os.open(parent, flags | os.O_DIRECTORY, dir_fd=root_fd))
                _protected(fds[-1], owner_uid, directory=True)
                fds.append(os.open(name, flags | os.O_NONBLOCK, dir_fd=fds[0]))
                _protected(fds[-1], owner_uid, directory=False)
                digest, total = hashlib.sha256(), 0
                while chunk := os.read(fds[-1], 1 << 20):
                    total += len(chunk)
                    if total > _COMPONENT_MAX_BYTES:
                        raise EdgePackageRefused("an extracted Edge component is too large")
                    digest.update(chunk)
                result[relative] = "sha256:" + digest.hexdigest()
            except OSError as exc:
                raise EdgePackageRefused(
                    f"the extracted Edge component {relative} could not be read: {exc}"
                ) from exc
            finally:
                for fd in fds:
                    os.close(fd)
    finally:
        os.close(root_fd)
    return result


def _manifest_components(manifest: dict) -> dict[str, str]:
    declared: dict[str, str] = {}
    components = manifest.get("components")
    if type(components) is not list:
        raise EdgePackageRefused("the Edge manifest lists no components")
    for component in components:
        if type(component) is not dict:
            raise EdgePackageRefused("an Edge manifest component is not an object")
        path, digest = component.get("path"), component.get("digest")
        if path in BOUND_COMPONENTS:
            if path in declared or type(digest) is not str or not _DIGEST_PATTERN.match(digest):
                raise EdgePackageRefused("an Edge manifest component digest is refused")
            declared[path] = digest
    if set(declared) != set(BOUND_COMPONENTS):
        raise EdgePackageRefused("the Edge manifest does not record every bound component")
    return declared


def _archive_components(data: bytes) -> dict[str, str]:
    """The bound members of the verified archive bytes, hashed without extracting."""
    import io
    import tarfile

    found: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for count, member in enumerate(archive):
                if count >= _ARCHIVE_MAX_MEMBERS:
                    raise EdgePackageRefused("the Edge archive has too many members")
                name = member.name[2:] if member.name.startswith("./") else member.name
                if name not in BOUND_COMPONENTS:
                    continue
                if name in found or not member.isreg() or member.size > _COMPONENT_MAX_BYTES:
                    raise EdgePackageRefused("an Edge archive member is refused")
                stream = archive.extractfile(member)
                if stream is None:
                    raise EdgePackageRefused("an Edge archive member is unreadable")
                digest, total = hashlib.sha256(), 0
                while chunk := stream.read(1 << 20):
                    total += len(chunk)
                    if total > _COMPONENT_MAX_BYTES:
                        raise EdgePackageRefused("an Edge archive member is too large")
                    digest.update(chunk)
                found[name] = "sha256:" + digest.hexdigest()
    except EdgePackageRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - a malformed archive binds nothing
        raise EdgePackageRefused("the Edge archive could not be read") from exc
    if set(found) != set(BOUND_COMPONENTS):
        raise EdgePackageRefused("the Edge archive lacks a bound component")
    return found


def installed_package_components(
    *, package_root: Path = EDGE_PACKAGE_ROOT, pin: EdgePin = PIN, owner_uid: int = 0,
) -> tuple[str, dict[str, str]]:
    """The archive digest and the bound components, only when all three agree.

    For `az-activation generation-publish` (#206 P5): the package checks of
    `installed_package_digest`; then, for each of `BOUND_COMPONENTS`, the
    digest the manifest records, the digest of that member of the archive
    bytes just verified against the manifest (read bounded, never
    extracted) and the digest of the extracted file
    (`measure_extracted_components`) must be equal. The manifest is
    unsigned, so the equality is integrity at publication; the operator's
    signature over the generation is what binds the values afterwards.
    """

    digest = installed_package_digest(package_root=package_root, pin=pin)
    manifest_path = package_root / pin.manifest_name
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        fd = os.open(package_root / pin.artifact_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(_ARCHIVE_MAX_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise EdgePackageRefused("the installed Edge package could not be re-read") from exc
    if len(data) > _ARCHIVE_MAX_BYTES or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise EdgePackageRefused("the Edge archive changed or is too large")
    if type(manifest) is not dict or manifest.get("digest") != digest:
        raise EdgePackageRefused("the Edge manifest changed")
    declared = _manifest_components(manifest)
    archived = _archive_components(data)
    extracted = measure_extracted_components(package_root=package_root, owner_uid=owner_uid)
    if not declared == archived == extracted:
        raise EdgePackageRefused(
            "an extracted Edge component differs from its manifest or its archive member")
    return digest, dict(sorted(extracted.items()))


def installed_package_digest(
    *, package_root: Path = EDGE_PACKAGE_ROOT, pin: EdgePin = PIN,
) -> str:
    """The installed archive digest, only when the on-disk package checks pass.

    Runs the three checks `inspect` always derives itself -- `package_present`
    (observe-only posture, unsigned, pinned contracts), `version_matches` and
    `digest_matches` -- and returns the manifest's `digest`, which the artifact
    on disk was just re-derived to equal. Anything else refuses. No probe,
    binary or service manager is consulted, and health or running are not
    claimed. Integrity against accidental change, not authenticity
    (`UNSIGNED_CAVEAT`). The observe-baseline generation (#206) binds this
    value so an operator's signature names one specific Edge package.
    """

    manifest_path = package_root / pin.manifest_name
    artifact_path = package_root / pin.artifact_name
    _, package, manifest = _read_package(package_root, manifest_path, artifact_path, pin)
    if not package.held or manifest is None:
        raise EdgePackageRefused("the installed Edge package check did not pass")
    if (not _version_finding(manifest, pin).held
            or not _digest_finding(artifact_path, manifest).held):
        raise EdgePackageRefused("the installed Edge package differs from its pin or manifest")
    digest = manifest["digest"]
    if type(digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise EdgePackageRefused("the installed Edge package digest is malformed")
    return digest


# -- probes, whose defaults refuse ----------------------------------------


def no_health_probe() -> Optional[HealthAnswer]:
    """The default. Nothing ran, and that is reported as `not-checked`.

    Running the Edge binary is a decision a deployment makes, not something a
    status command does on its own: a status command that spawned the
    component it reports on would be a status command with a side effect.
    """

    return None


def no_running_probe() -> Optional[bool]:
    """The default. This build speaks to no service manager (HG-01)."""

    return None


# -- the inspection -------------------------------------------------------


def inspect(
    root: Optional[Path],
    *,
    pin: EdgePin = PIN,
    probe: Optional[ProbeResult] = None,
    now: str = "",
    boot_id: Optional[str] = None,
    health: Callable[[], Optional[HealthAnswer]] = no_health_probe,
    running: Callable[[], Optional[bool]] = no_running_probe,
) -> EdgeInspection:
    """Look at what is on disk and say what was established. Nothing more.

    `probe` is `az-edge-probed`'s last result. When it is given, it supplies
    `health_endpoint_healthy` and `running` -- and only when it names the same
    version and artifact digest derived here, only when it was observed in
    the boot `boot_id` names (the current one, read by the caller with
    `read_current_boot_id`; `None` when it could not be read, which makes
    every result stale), and only while it is fresh at `now`. Package, version
    and digest are always derived here regardless.

    `now` is passed in rather than read: a verifier that read a clock would
    give two different answers about one unchanged node.
    """

    if probe is not None:
        if health is not no_health_probe or running is not no_running_probe:
            raise EdgePackageRefused(
                "a probe result and a probe callable were both supplied; two "
                "sources for one finding is one source too many"
            )
        if not now.strip():
            raise EdgePackageRefused(
                "a probe result was supplied with no instant to judge its "
                "freshness against; an answer with no age is an answer that "
                "never goes stale"
            )
    caveats = (UNSIGNED_CAVEAT,)
    if root is None:
        return EdgeInspection(
            findings=tuple(
                Finding(
                    check=check,
                    evidence=Evidence.NOT_CHECKED,
                    reason=(
                        "no Edge package root is configured on this node, so "
                        "nothing was looked for. Not configured is not the "
                        "same fact as looked for and missing"
                    ),
                )
                for check in CHECKS
            ),
            presence=EdgePresence.UNKNOWN,
            caveats=caveats,
            root="",
        )

    manifest_path = root / pin.manifest_name
    artifact_path = root / pin.artifact_name
    presence, package, manifest = _read_package(root, manifest_path, artifact_path, pin)
    findings = [package]

    if not package.held:
        reason = (
            f"the package check reports {package.evidence.value}, so there was "
            "nothing to check this against"
        )
        findings.extend(
            Finding(check=check, evidence=Evidence.NOT_CHECKED, reason=reason)
            for check in CHECKS[1:]
        )
        return EdgeInspection(
            findings=tuple(findings),
            presence=presence,
            caveats=caveats,
            root=str(root),
        )

    assert manifest is not None  # _read_package holds this when the check passed
    version_finding = _version_finding(manifest, pin)
    digest_finding = _digest_finding(artifact_path, manifest)
    findings.append(version_finding)
    findings.append(digest_finding)
    if probe is None:
        findings.append(_health_finding(health(), pin))
        findings.append(_running_finding(running()))
    else:
        findings.extend(
            _probe_findings(
                probe,
                now=now,
                boot_id=boot_id,
                manifest_version=manifest["version"],
                artifact_digest=manifest["digest"],
                digest_held=digest_finding.held,
            )
        )
    ordered = tuple(findings)
    return EdgeInspection(
        findings=ordered,
        presence=presence_of(ordered),
        caveats=caveats,
        root=str(root),
        probe=probe,
    )


def _probe_findings(
    probe: ProbeResult,
    *,
    now: str,
    boot_id: Optional[str],
    manifest_version: str,
    artifact_digest: str,
    digest_held: bool,
) -> list[Finding]:
    """Health and running from the probe, or `not-checked` with the reason why.

    Three ways a result supplies nothing, and each says which:

    * it names a different package -- so it reports on something else;
    * the artifact on disk does not match its own manifest -- so "the same
      version and digest" is agreement between two things that are both
      suspect;
    * it is from another boot (or names none, or this boot is unknown), or it
      is older than its own TTL -- an old answer about a running process is
      not a weak answer, it is an answer about a different moment.

    None of the three is a failure of the Edge Core, and none of them may
    become one: an operator sent to restart a healthy Edge because a probe
    went stale is an operator doing harm on our word.
    """

    def unusable(reason: str) -> list[Finding]:
        return [
            Finding(check=check, evidence=Evidence.NOT_CHECKED, reason=reason)
            for check in ("health_endpoint_healthy", "running")
        ]

    if not digest_held:
        return unusable(
            "the artifact on disk does not match its own manifest, so a probe "
            "result agreeing with that manifest agrees with nothing this node "
            "can rely on"
        )
    if probe.package_version != manifest_version or probe.package_digest != artifact_digest:
        return unusable(
            f"the probe last observed {probe.package_version}/"
            f"{probe.package_digest}, and the package here is "
            f"{manifest_version}/{artifact_digest}. A result about a different "
            "package is a result about something else"
        )
    if probe.contract != PROBE_CONTRACT:
        return unusable(
            f"stale: the probe result is {probe.contract}, which names no boot, "
            "so it cannot be shown to be from this boot. It is not used, and it "
            "is not a failure of the Edge Core either"
        )
    if not is_boot_id(boot_id):
        return unusable(
            "stale: this boot's id could not be read, so no probe result can be "
            "shown to be from this boot. It is not used, and it is not a "
            "failure of the Edge Core either"
        )
    if not probe.from_boot(boot_id):
        return unusable(
            f"stale: from another boot. The probe result observed at "
            f"{probe.observed_at} names a boot other than this one, so it is "
            "not used whatever its TTL says, and it is not a failure of the "
            "Edge Core either"
        )
    if probe.future_at(now):
        return unusable("the probe observed_at is more than 5 seconds in the future; not checked")
    if not probe.fresh_at(now):
        return unusable(
            f"the probe result was observed at {probe.observed_at} and expired "
            f"at {probe.expires_at()}; it is stale at {now}. A stale result is "
            "not promoted, and it is not a failure of the Edge Core either"
        )
    return [
        Finding(
            check="health_endpoint_healthy",
            evidence=probe.health,
            reason=f"az-edge-probed at {probe.observed_at}: {probe.health_reason}",
            security=probe.health_security,
        ),
        Finding(
            check="running",
            evidence=probe.running,
            reason=f"az-edge-probed at {probe.observed_at}: {probe.running_reason}",
        ),
    ]


def presence_of(findings: Sequence[Finding]) -> EdgePresence:
    """The one word a display leads with, from the first check that did not pass.

    First in `CHECKS` order, so the word names the earliest thing that went
    wrong rather than the last. A digest mismatch reported as `not-running`
    because the payload also was not running would bury the finding under the
    consequence.
    """

    by_check = {finding.check: finding for finding in findings}
    for check in CHECKS:
        finding = by_check[check]
        if finding.held:
            continue
        if finding.evidence is Evidence.NOT_CHECKED:
            return EdgePresence.UNKNOWN
        return {
            "package_present": EdgePresence.ABSENT,
            "version_matches": EdgePresence.VERSION_MISMATCH,
            "digest_matches": EdgePresence.DIGEST_MISMATCH,
            "health_endpoint_healthy": EdgePresence.UNHEALTHY,
            "running": EdgePresence.NOT_RUNNING,
        }[check]
    return EdgePresence.VERIFIED_READY


def _read_package(
    root: Path, manifest_path: Path, artifact_path: Path, pin: EdgePin
) -> tuple[EdgePresence, Finding, Optional[dict]]:
    """Present, absent, or present and unusable -- which are three answers."""

    def refuse(presence: EdgePresence, reason: str, security: bool = False):
        return (
            presence,
            Finding(
                check="package_present",
                evidence=Evidence.FAILED,
                reason=reason,
                security=security,
            ),
            None,
        )

    if not manifest_path.exists() and not artifact_path.exists():
        return refuse(
            EdgePresence.ABSENT,
            f"no Edge package is installed at {root}: neither "
            f"{pin.manifest_name} nor {pin.artifact_name} is there. This is a "
            "deployment step and not a security finding",
        )
    if not manifest_path.exists():
        return refuse(
            EdgePresence.CORRUPT,
            f"{artifact_path.name} is at {root} with no manifest beside it. "
            "An artifact nobody can describe is not a package, and nothing "
            "about it can be verified",
        )
    if not artifact_path.exists():
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} is at {root} and the artifact it names, "
            f"{pin.artifact_name}, is not. A manifest alone verifies nothing",
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} could not be read as JSON ({exc}). A "
            "truncated copy and a rewritten one look the same from here, so "
            "this is reported rather than repaired",
        )
    if not isinstance(manifest, dict):
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} is valid JSON but not an object",
        )
    missing = [key for key in REQUIRED_MANIFEST_KEYS if _lookup(manifest, key) is None]
    if missing:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} is missing {missing}; it does not describe "
            f"a {pin.manifest_contract} package",
        )
    if manifest["contract"] != pin.manifest_contract:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} declares contract "
            f"{manifest['contract']!r} and this node verifies "
            f"{pin.manifest_contract!r}",
        )
    if manifest["package"] != pin.package or manifest["architecture"] != pin.architecture:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} describes "
            f"{manifest['package']}/{manifest['architecture']} and this node "
            f"pins {pin.package}/{pin.architecture}",
        )
    if _lookup(manifest, "health.contract") != pin.health_contract:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} declares health contract "
            f"{_lookup(manifest, 'health.contract')!r} and this node can only "
            f"read {pin.health_contract!r}",
        )
    if manifest["signed"] is not False:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} claims signed={manifest['signed']!r}. This "
            "node can verify no signature on an Edge package, and a claim of "
            "authenticity it cannot check invites the reliance an absent one "
            "denies. Refused rather than believed",
            security=True,
        )
    if _lookup(manifest, "posture.observe_only") is not True or _lookup(
        manifest, "posture.enforcement"
    ) is not False:
        return refuse(
            EdgePresence.CORRUPT,
            f"{manifest_path.name} declares a posture that is not observe-only "
            f"(observe_only={_lookup(manifest, 'posture.observe_only')!r}, "
            f"enforcement={_lookup(manifest, 'posture.enforcement')!r}). This "
            "node accepts no enforcing Edge package",
            security=True,
        )
    return (
        EdgePresence.VERIFIED_READY,
        Finding(
            check="package_present",
            evidence=Evidence.PASSED,
            reason=(
                f"{manifest_path.name} and {artifact_path.name} are both at "
                f"{root}, the manifest declares {pin.manifest_contract}, and "
                "its posture is observe-only"
            ),
        ),
        manifest,
    )


def _version_finding(manifest: dict, pin: EdgePin) -> Finding:
    found = manifest["version"]
    if found == pin.version:
        return Finding(
            check="version_matches",
            evidence=Evidence.PASSED,
            reason=f"the manifest declares {found}, which is the pinned version",
        )
    return Finding(
        check="version_matches",
        evidence=Evidence.FAILED,
        reason=(
            f"the manifest declares version {found!r} and this node pins "
            f"{pin.version!r}. A package that is not the pinned one has not "
            "been evaluated by anything this node was commissioned against"
        ),
    )


def _digest_finding(artifact_path: Path, manifest: dict) -> Finding:
    declared = manifest["digest"]
    try:
        actual = "sha256:" + hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    except OSError as exc:
        return Finding(
            check="digest_matches",
            evidence=Evidence.NOT_CHECKED,
            reason=f"{artifact_path.name} could not be read ({exc}), so no digest was derived",
        )
    if actual == declared:
        return Finding(
            check="digest_matches",
            evidence=Evidence.PASSED,
            reason=(
                f"re-derived {actual} from {artifact_path.name} and it matches "
                "the manifest. Integrity against accidental change; nothing "
                "here is signed, so this is not authenticity"
            ),
        )
    return Finding(
        check="digest_matches",
        evidence=Evidence.FAILED,
        reason=(
            f"the manifest declares {declared} and {artifact_path.name} "
            f"re-derives to {actual}. The artifact on disk is not the one the "
            "manifest describes. This is a security finding: report it, and do "
            "not repair it by rewriting either side"
        ),
        security=True,
    )


def _health_finding(answer: Optional[HealthAnswer], pin: EdgePin) -> Finding:
    """Four conditions, all of them, because a garbled stdout must not read as healthy."""

    if answer is None:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.NOT_CHECKED,
            reason=(
                "no health probe is configured on this node, so the Edge "
                "health contract was not run. Nobody looked, which is not the "
                "same fact as an unhealthy answer"
            ),
        )
    if answer.exit_code is None:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.NOT_CHECKED,
            reason=(
                "the health probe could not be run at all "
                f"({answer.reason or 'no reason given'}), so nothing was observed"
            ),
        )
    if answer.exit_code != 0:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason=f"the health contract exited {answer.exit_code}",
        )
    try:
        report = json.loads(answer.stdout)
    except ValueError as exc:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason=(
                f"the health contract exited 0 and its output is not JSON "
                f"({exc}). An exit code alone is not the contract"
            ),
        )
    if not isinstance(report, dict):
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason="the health contract printed JSON that is not an object",
        )
    missing = [key for key in REQUIRED_HEALTH_KEYS if _lookup(report, key) is None]
    if missing:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason=f"the health report is missing {missing}",
        )
    if report["contract"] != pin.health_contract:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason=(
                f"the health report declares contract {report['contract']!r} "
                f"and this node reads {pin.health_contract!r}; a report in an "
                "unknown dialect is not a healthy report"
            ),
        )
    if report["status"] != HEALTHY_STATUS:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason=f"the health report says status={report['status']!r}",
        )
    if report["version"] != pin.version:
        return Finding(
            check="health_endpoint_healthy",
            evidence=Evidence.FAILED,
            reason=(
                f"the health report is from version {report['version']!r} and "
                f"this node pins {pin.version!r}; the binary answering is not "
                "the one the manifest describes"
            ),
            security=True,
        )
    return Finding(
        check="health_endpoint_healthy",
        evidence=Evidence.PASSED,
        reason=(
            "the health contract exited 0, printed JSON, declared "
            f"{pin.health_contract} and reported status={HEALTHY_STATUS!r} at "
            f"version {pin.version}. All four conditions, so a truncated or "
            "garbled answer cannot read as healthy"
        ),
    )


def _running_finding(running: Optional[bool]) -> Finding:
    if running is None:
        return Finding(
            check="running",
            evidence=Evidence.NOT_CHECKED,
            reason=(
                "this build speaks to no service manager, so whether the Edge "
                "payload is running was not established "
                "(docs/hardware-gates.md HG-01). The Edge health contract is "
                "one-shot and says nothing about a daemon, so a healthy answer "
                "does not fill this in"
            ),
        )
    if running:
        return Finding(
            check="running",
            evidence=Evidence.PASSED,
            reason="the configured probe reports the Edge payload is running",
        )
    return Finding(
        check="running",
        evidence=Evidence.FAILED,
        reason="the configured probe reports the Edge payload is not running",
    )


def _lookup(document: dict, dotted: str):
    """Read a dotted path, or `None` if any step is absent."""

    current = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
