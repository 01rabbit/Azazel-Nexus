"""`azazel-nexus` -- the operator's five subcommands (#29).

Every one of them works with no network. That is not a convenience: a status
command that needs connectivity is unavailable exactly when an operator needs
it to explain why they have none. The package imports nothing that can open a
socket, and `tests/unit/test_boundary_static.py` enforces it against the
source, so this is structural rather than intended.

The rendering here is deliberately thin. `azazel_nexus.operator` holds the
refusals -- an enforcement-ready claim that cannot be set, a module state that
cannot be phrased as reassurance, a degradation view that cannot list losses
alone. This module turns a report into lines. If a prohibition were enforced
here instead, every other caller of the report would be outside it.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable, Optional, Sequence, TextIO

from .capability import CORE_CAPABILITIES
from .cognition import read_cognition
from .commissioning import CommissioningRefused, propose
from .compatibility import TestedTupleSet
from .decoy import IsolationCheck, evaluate as evaluate_decoy
from .integration import EdgePresence, IntegrationView, build_view
from .inventory import no_permanent_mac, read_interfaces
from .lite_service import KnowledgeLite
from .operator import (
    CapabilityReport,
    HealthReport,
    ModuleReport,
    ModuleState,
    OperatorReport,
    ProfileReport,
    build_report,
)
from .resource_profile import ResourceProfile, UsableMemoryUnavailable, take_reading
from .wizard import WizardAbandoned, commission, render_rows

__all__ = ["main"]

#: The external modules a CORE node may be asked about.
#:
#: Reported `ABSENT` with a reason rather than omitted. A module that is simply
#: missing from a status screen is a module an operator believes is fine.
EXTERNAL_MODULES = (
    ("AZ-04 Knowledge", "no module endpoint is configured on this node"),
    ("AZ-06 Deception", "no module endpoint is configured on this node"),
    ("Remote M.I.O.", "no remote cognition route is configured on this node"),
)

#: What this node can say about a local Edge Core: that it has not looked.
#:
#: `azazel_nexus.activation.EdgeBaselineState` holds the five checks the
#: decision needs, and **nothing in this repository produces one**. The
#: package those checks would run against is
#: [Azazel-Edge#424](https://github.com/01rabbit/Azazel-Edge/issues/424) and
#: it does not exist yet.
#:
#: So the row says the node is not configured for one, and says why. That is
#: not a placeholder for a check -- it is the accurate report of an absence,
#: and it is what keeps `edge-baseline-ready` from being a thing this node
#: has quietly stopped mentioning. A status screen that omitted Edge entirely
#: would read as a node with no Edge concern at all.
EDGE_BASELINE = (
    "Edge Core (local)",
    "no Edge package is configured on this node, and nothing here has "
    "looked for one: the x86_64 package Nexus would verify is not built yet "
    "(Azazel-Edge#424). edge-baseline-ready is not claimed",
)

#: Where the embedded stores live (`IMPLEMENTATION_SPEC.md` §3).
#:
#: Not in `layout.LAYOUT`: that declares `/etc/azazel` and `/var/lib/azazel`,
#: and `/data/azazel` is a tier whose volume, ownership and encryption are a
#: packaging decision this module does not make. Naming the paths here is safe
#: because **both services read an absent root correctly** -- Knowledge Lite
#: reports `unavailable` and the decoy runtime reports `disabled` -- so a node
#: without the tier gets the truth rather than an error.
KNOWLEDGE_LITE_ROOT = Path("/data/azazel/knowledge-lite")
DECEPTION_LITE_ROOT = Path("/data/azazel/deception-lite")


def _profile_report() -> ProfileReport:
    try:
        return ProfileReport(reading=take_reading())
    except (UsableMemoryUnavailable, OSError) as exc:
        return ProfileReport(reason=str(exc))


def _capability_report() -> CapabilityReport:
    """What a CORE node with no optional component has.

    Which is everything CORE is defined to be, and that is the expected state
    rather than a fault. The optional capabilities are listed as lost so the
    display has both halves to show.
    """

    return CapabilityReport(
        available=frozenset(CORE_CAPABILITIES),
        lost=(
            "extended_knowledge",
            "knowledge_lite",
            "full_host_redirect",
            "deception_lite",
            "local_cognition",
            "remote_cognition",
        ),
    )


def _module_reports() -> tuple[ModuleReport, ...]:
    return tuple(
        ModuleReport(name=name, state=ModuleState.ABSENT, reason=reason)
        for name, reason in (*EXTERNAL_MODULES, EDGE_BASELINE)
    )


def _health_reports(ledger_path: Optional[Path]) -> tuple[HealthReport, ...]:
    from .audit import AuditChainBroken, AuditLedger, AuditUnavailable

    checks = [
        HealthReport(
            subject="systemd units",
            healthy=None,
            detail=(
                "not established: this build ships no daemon and speaks to no "
                "service manager (docs/hardware-gates.md HG-01)"
            ),
        )
    ]
    if ledger_path is None or not ledger_path.exists():
        checks.append(
            HealthReport(
                subject="audit chain",
                healthy=None,
                detail="no ledger exists yet at the path given; nothing has "
                "been recorded on this node",
            )
        )
        return tuple(checks)
    try:
        AuditLedger(ledger_path).verify()
    except (AuditChainBroken, AuditUnavailable) as exc:
        checks.append(HealthReport("audit chain", False, str(exc)))
    else:
        checks.append(
            HealthReport(
                "audit chain", True, f"every link re-derived from {ledger_path}"
            )
        )
    return tuple(checks)


def _integration_view(
    report: OperatorReport,
    *,
    as_of: str,
    knowledge_root: Path,
) -> IntegrationView:
    """The six axes, from what this node has actually established.

    `as_of` is passed in rather than read here: a clock read inside a status
    builder makes two runs of the same node differ, and `docs/mio-runtime.md`
    §9 wants a decision replayable from its inputs. `main` reads the clock,
    because a command line is where a wall clock legitimately enters.

    Every argument below is a fact this node holds. Nothing is invented:
    `host=None` says the node has not been commissioned into a tested tuple,
    the decoy has no catalogue and no isolation result, and Edge is `absent`
    for exactly the reason `EDGE_BASELINE` gives.
    """

    profile = report.profile.profile or ResourceProfile.DIAGNOSTIC
    return build_view(
        capability=report.capabilities.state,
        knowledge=KnowledgeLite(
            root=knowledge_root,
            commissioning_digest=(
                report.record.digest if report.record is not None else ""
            ),
        ).read(as_of=as_of),
        cognition=read_cognition(
            [], profile=profile, tested=TestedTupleSet(), host=None
        ),
        decoy=evaluate_decoy(
            "deception-lite",
            catalogue=None,
            commissioning=None,
            isolation=IsolationCheck(passed=None),
        ),
        edge=EdgePresence.ABSENT,
    )


def _render_integration(view: IntegrationView, out: TextIO) -> None:
    """Print the six axes, and then what continues.

    What continues is printed **last and always**, not as a footnote that a
    long list of red pushes off the screen.
    """

    print("integration:", file=out)
    for row in view.rows:
        subject = f" [{row.subject}]" if row.subject else ""
        marker = "  DEFECT" if row.defect else ""
        print(f"    {row.axis}{subject}: {row.value}{marker}", file=out)
        print(f"        {row.reason}", file=out)
    print(file=out)
    print(f"enforcement capable: {'yes' if view.enforcement_capable else 'no'}", file=out)
    print(f"baseline ready: {'yes' if view.baseline_ready else 'no'}", file=out)
    print("continuing regardless: " + ", ".join(view.continues), file=out)


def _report(
    sysfs: Optional[Path],
    ledger: Optional[Path],
    permanent_mac_reader=no_permanent_mac,
) -> OperatorReport:
    return build_report(
        readouts=read_interfaces(sysfs, permanent_mac_reader=permanent_mac_reader),
        profile=_profile_report(),
        capabilities=_capability_report(),
        modules=_module_reports(),
        health=_health_reports(ledger),
    )


# -- rendering ----------------------------------------------------------


def _render_interfaces(report: OperatorReport, out: TextIO) -> None:
    if not report.interfaces:
        print("No interfaces were read from this host.", file=out)
        return
    for interface in report.interfaces:
        facts = ", ".join(f"{k}={v}" for k, v in sorted(interface.description.items()))
        state = interface.role or ("unassigned" if interface.commissionable else "not commissionable")
        print(f"{interface.handle}  {state}", file=out)
        print(f"    {facts}", file=out)
        for reason in interface.blocked_by:
            print(f"    blocked: {reason}", file=out)


def _render_profile(report: OperatorReport, out: TextIO) -> None:
    if report.profile.reading is None:
        print(f"resource profile: not measured -- {report.profile.reason}", file=out)
        return
    reading = report.profile.reading
    print(
        f"resource profile: {reading.profile.value} "
        f"(usable RAM {reading.usable_mib} MiB, as the OS reports it)",
        file=out,
    )
    print(
        "    a profile is an upper bound. It grants no NIC role, no capture, "
        "no enforcement and no external connection.",
        file=out,
    )


def _render_status(
    report: OperatorReport, out: TextIO, view: Optional[IntegrationView] = None
) -> None:
    _render_profile(report, out)
    print(file=out)
    print(f"capability state: {report.capabilities.state.value}", file=out)
    print("    continuing: " + ", ".join(report.capabilities.retained), file=out)
    if report.capabilities.lost:
        print("    not available: " + ", ".join(report.capabilities.lost), file=out)
    print(file=out)
    print(
        "enforcement ready: "
        + ("yes" if report.enforcement_ready else "no"),
        file=out,
    )
    # Printed as its own line rather than folded into the module list,
    # because it is a claim about this node and not about a peer. "No" here
    # means this node is not asserting a deterministic baseline; it does not
    # mean an Edge Core is broken, and the module row below says which.
    print("edge-baseline-ready: no", file=out)
    if not report.enforcement_ready:
        if report.record is None:
            print("    no commissioning record exists on this node", file=out)
        else:
            missing = report.record.missing_profiles
            if missing:
                print("    missing profiles: " + ", ".join(missing), file=out)
            if report.record.observe_only:
                print("    no interface carries a confirmed role", file=out)
    print(file=out)
    print("interfaces:", file=out)
    _render_interfaces(report, out)
    print(file=out)
    print("external modules:", file=out)
    for module in report.modules:
        print(f"    {module.name}: {module.state.value} -- {module.reason}", file=out)
    print(file=out)
    if view is not None:
        _render_integration(view, out)
        print(file=out)
    _render_health(report, out)
    print(file=out)
    print("next:", file=out)
    if not report.next_actions:
        print("    nothing is outstanding.", file=out)
    for action in report.next_actions:
        print(f"    {action.summary}", file=out)
        if action.command:
            print(f"        {action.command}", file=out)


def _render_health(report: OperatorReport, out: TextIO) -> None:
    print("health:", file=out)
    for check in report.health:
        mark = "unknown" if check.unknown else ("ok" if check.healthy else "FAILED")
        print(f"    {check.subject}: {mark} -- {check.detail}", file=out)


# -- commands -----------------------------------------------------------


def _cmd_commission(
    args: argparse.Namespace,
    out: TextIO,
    ask: Optional[Callable[[str, Sequence[str]], str]],
    confirm: Optional[Callable[[str], bool]],
    permanent_mac_reader=no_permanent_mac,
) -> int:
    proposal = propose(
        read_interfaces(args.sysfs, permanent_mac_reader=permanent_mac_reader)
    )
    for row in render_rows(proposal):
        facts = ", ".join(f"{k}={v}" for k, v in sorted(row["description"].items()))
        print(f"{row['handle']}  {facts}", file=out)
        for reason in row["blocked_by"]:
            print(f"    blocked: {reason}", file=out)
    print(file=out)

    if ask is None or confirm is None:
        print(
            "No operator prompt is available on this stream. Commissioning "
            "requires an explicit confirmation and will not proceed without "
            "one.",
            file=out,
        )
        return 2

    try:
        record = commission(
            proposal,
            ask=ask,
            confirm=confirm,
            operator=args.operator,
            at=args.at,
            profiles_present=args.profiles,
        )
    except WizardAbandoned as exc:
        print(f"abandoned: {exc}", file=out)
        return 2
    except CommissioningRefused as exc:
        print(f"refused: {exc}", file=out)
        return 1

    print(f"commissioning recorded: digest {record.digest()}", file=out)
    if record.observe_only:
        print(
            "    No interface carries a role. The node observes and enforces "
            "nothing, which is a completed commissioning, not an incomplete "
            "one.",
            file=out,
        )
    return 0


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    out: Optional[TextIO] = None,
    ask: Optional[Callable[[str, Sequence[str]], str]] = None,
    confirm: Optional[Callable[[str], bool]] = None,
    permanent_mac_reader=no_permanent_mac,
) -> int:
    import sys

    stream = out if out is not None else sys.stdout
    parser = argparse.ArgumentParser(
        prog="azazel-nexus",
        description="Read-only inventory, resource profile, commissioning, "
        "status and health. Every subcommand works with no network.",
    )
    parser.add_argument("--sysfs", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--ledger", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--knowledge-lite", type=Path, default=KNOWLEDGE_LITE_ROOT, help=argparse.SUPPRESS
    )
    parser.add_argument("--as-of", default=None, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("inventory", help="read-only hardware and interface list")
    sub.add_parser("profile", help="measured RAM and the profile it selects")
    sub.add_parser("status", help="everything above, as it currently stands")
    sub.add_parser("health", help="units and the audit chain")

    wizard = sub.add_parser("commission", help="assign roles, with confirmation")
    wizard.add_argument("--operator", required=True)
    wizard.add_argument("--at", required=True, help="RFC3339 timestamp")
    wizard.add_argument("--profiles", nargs="*", default=())

    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "commission":
        return _cmd_commission(
            args, stream, ask, confirm, permanent_mac_reader
        )

    report = _report(args.sysfs, args.ledger, permanent_mac_reader)
    if args.command == "inventory":
        _render_interfaces(report, stream)
    elif args.command == "profile":
        _render_profile(report, stream)
    elif args.command == "health":
        _render_health(report, stream)
    else:
        # The one place a wall clock legitimately enters: a command line is
        # where "now" comes from, and everything below it takes the instant as
        # an argument so that a status is replayable from its inputs.
        as_of = args.as_of or _now()
        _render_status(
            report,
            stream,
            _integration_view(
                report, as_of=as_of, knowledge_root=args.knowledge_lite
            ),
        )
    return 0


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
