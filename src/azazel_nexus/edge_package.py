"""Verify the local Edge Core package, and refuse to overstate the result (#44).

The Edge side is [Azazel-Edge#424](https://github.com/01rabbit/Azazel-Edge/issues/424),
whose contract this module consumes from `contract/azazel-edge-core/`. That
directory is a **copy** of what Azazel-Edge commits, and `PROVENANCE.md` there
says why the two repositories hold the tie with copies and tests rather than
with an import.

## Five checks, reported separately

`package_present`, `version_matches`, `digest_matches`,
`health_endpoint_healthy`, `running`. `activation.EdgeBaselineState` needs all
five and this module is the **only producer of one in the package** -- the
static scan in `tests/unit/test_wizard_and_cli.py` keeps it that way.

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

It does not install, extract, configure a network, or start anything. Health
and running state arrive through **injected probes**, and the defaults refuse:
`no_health_probe` and `no_running_probe` report `not-checked` with the reason.

No runner is shipped with them, and that is a boundary rather than an
oversight. `tests/unit/test_boundary_static.py` forbids this package from
importing `subprocess` -- Nexus has not commissioned an operational surface,
and a status command that spawned the component it reports on would be a
status command with a side effect. Nothing here quietly acquires the authority
to run the Edge binary.

The consequence is stated rather than hidden: **on a node built from this
repository, `health_endpoint_healthy` and `running` are always `not-checked`**,
so `edge-baseline-ready` cannot be reached here even with a present, matched
package. Who runs the Edge health contract, and what establishes that the
payload is running, is a deployment decision that crosses that boundary, and
it is [Nexus#72](https://github.com/01rabbit/Azazel-Nexus/issues/72) rather
than something this module decided on its own. What this module does deliver
is the **parser** for both answers: all four health conditions, checked
independently and tested against the contract Edge ships.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Sequence

from .activation import EdgeBaselineState
from .integration import EdgePresence

__all__ = [
    "CHECKS",
    "EdgeInspection",
    "EdgePin",
    "Evidence",
    "Finding",
    "HealthAnswer",
    "PIN",
    "UNSIGNED_CAVEAT",
    "inspect",
    "no_health_probe",
    "no_running_probe",
    "presence_of",
]

#: Where the vendored Edge contract lives, relative to the repository root.
CONTRACT_DIR = Path(__file__).resolve().parents[2] / "contract" / "azazel-edge-core"

#: The five checks, in the order an operator reads them. A tuple rather than a
#: set: both a disappearance and a reordering should fail a test, because the
#: order is what the display walks.
CHECKS = (
    "package_present",
    "version_matches",
    "digest_matches",
    "health_endpoint_healthy",
    "running",
)

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

        return EdgeBaselineState(*(finding.held for finding in self.findings))

    def as_event(self) -> dict:
        return {
            "event_type": "nexus.edge_package.inspection",
            "root": self.root,
            "presence": self.presence.value,
            "ready": self.ready,
            "caveats": list(self.caveats),
            "findings": [finding.as_event() for finding in self.findings],
        }


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
    health: Callable[[], Optional[HealthAnswer]] = no_health_probe,
    running: Callable[[], Optional[bool]] = no_running_probe,
) -> EdgeInspection:
    """Look at what is on disk and say what was established. Nothing more."""

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
    findings.append(_version_finding(manifest, pin))
    findings.append(_digest_finding(artifact_path, manifest))
    findings.append(_health_finding(health(), pin))
    findings.append(_running_finding(running()))
    ordered = tuple(findings)
    return EdgeInspection(
        findings=ordered,
        presence=presence_of(ordered),
        caveats=caveats,
        root=str(root),
    )


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
