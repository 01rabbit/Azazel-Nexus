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
from .commissioning import CommissioningRefused, propose
from .inventory import no_permanent_mac, read_interfaces
from .operator import (
    CapabilityReport,
    HealthReport,
    ModuleReport,
    ModuleState,
    OperatorReport,
    ProfileReport,
    build_report,
)
from .resource_profile import UsableMemoryUnavailable, take_reading
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
        for name, reason in EXTERNAL_MODULES
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


def _render_status(report: OperatorReport, out: TextIO) -> None:
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
        _render_status(report, stream)
    return 0
