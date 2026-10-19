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
import os
from pathlib import Path
from typing import Callable, Optional, Sequence, TextIO

from .capability import CORE_CAPABILITIES
from .cognition import read_cognition
from .commissioning import REQUIRED_PROFILES, CommissioningRefused, propose
from .commissioning_draft import (
    DraftRefused, export_draft, read_draft_review_inputs, verify_draft_review,
)
from .operator_store import load_operator_trust
from .operator_trust import ApprovalRefused
from .compatibility import TestedTupleSet
from .decoy import IsolationCheck, evaluate as evaluate_decoy
from .edge_package import (
    EDGE_PACKAGE_ROOT,
    PROBE_STATE_PATH,
    EdgeInspection,
    EdgePackageRefused,
    inspect as inspect_edge,
    load_probe_result,
)
from .audit import AuditLedger
from .hil_preflight import (
    BLOCKED,
    BOOT_ID_PATH,
    COMMISSIONING_DIR,
    PROTECTION_KEY,
    OPERATOR_SCREEN_FIELDS,
    OperatorDecisions,
    PreflightResult,
    PreflightRefused,
    Protection,
    audit_event,
    collect_readonly_inventory,
    describe_for_screen,
    evaluate as evaluate_preflight,
    local_principal,
    next_generation,
    node_clock,
    luks_backed,
    persist_commissioning_record,
    read_protection_key,
    tpm_present,
)
from .integration import IntegrationView, build_view
from .inventory import DEFAULT_SYSFS_NET, no_permanent_mac, read_interfaces
from .functional_readiness import readiness_for
from .lite_import import status_summary
from .lite_service import LiteReading, LiteState
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
from .wizard import Answer, WizardAbandoned, commission, render_rows

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

#: Where the embedded stores live (`IMPLEMENTATION_SPEC.md` §3).
#:
#: Not in `layout.LAYOUT`: that declares `/etc/azazel` and `/var/lib/azazel`,
#: and `/data/azazel` is a tier whose volume, ownership and encryption are a
#: packaging decision this module does not make. Naming the paths here is safe
#: because **both services read an absent root correctly** -- Knowledge Lite
#: reports `unavailable` and the decoy runtime reports `disabled` -- so a node
#: without the tier gets the truth rather than an error.
KNOWLEDGE_LITE_ROOT = Path("/var/lib/azazel/knowledge")
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
    """The **external** modules. The local Edge Core is not one of them.

    It used to be listed here, when all this node could say about it was that
    it had not looked. It has its own section now (`_render_edge`) because
    `ModuleState` has four words for a peer -- attested, unverified,
    unreachable, absent -- and #44 requires the local Edge Core to be
    distinguishable across eight: a missing package, a corrupt one, a version
    mismatch, a digest mismatch, an unhealthy answer, a payload that is not
    running, an unasked question, and verified-ready. Rendering that through a
    peer's vocabulary would lose the distinctions the issue exists to keep.
    """

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


def _knowledge_reading(root: Path, *, as_of: str) -> dict:
    """What Knowledge Lite currently is. **Reads; never imports.**

    `status` does not admit, quarantine, retry or fetch. It reads what a
    previous import left, and an audit ledger does not grow because somebody
    looked at a screen.
    """

    trust_root = Path(os.environ.get("AZAZEL_ROOT", "/")) / "var/lib/azazel/lite-trust"
    return status_summary(root=root, trust_root=trust_root, query_as_of=as_of)


def _as_lite_reading(reading: dict) -> LiteReading:
    """Carry the daemon's bounded status into the integration view."""
    return LiteReading(
        state=LiteState(reading["state"]),
        reason=f"{reading['reason_code']} | freshness: {reading['freshness']}",
        generation=reading["generation"],
    )


def _integration_view(
    report: OperatorReport,
    *,
    as_of: str,
    knowledge_root: Path,
    knowledge: dict,
    edge: EdgeInspection,
) -> IntegrationView:
    """The six axes, from what this node has actually established.

    `as_of` is passed in rather than read here: a clock read inside a status
    builder makes two runs of the same node differ, and `docs/mio-runtime.md`
    §9 wants a decision replayable from its inputs. `main` reads the clock,
    because a command line is where a wall clock legitimately enters.

    Every argument below is a fact this node holds. Nothing is invented:
    `host=None` says the node has not been commissioned into a tested tuple,
    the decoy has no catalogue and no isolation result, and the edge axis
    carries whatever `edge_package.inspect` established at the fixed package
    location -- one of eight words, not a placeholder.
    """

    profile = report.profile.profile or ResourceProfile.DIAGNOSTIC
    return build_view(
        capability=report.capabilities.state,
        knowledge=_as_lite_reading(knowledge),
        cognition=read_cognition(
            [], profile=profile, tested=TestedTupleSet(), host=None
        ),
        decoy=evaluate_decoy(
            "deception-lite",
            catalogue=None,
            commissioning=None,
            isolation=IsolationCheck(passed=None),
        ),
        edge=edge.presence,
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
    from .broker_cli import status_summary as broker_status
    broker = broker_status(now=_now())
    print("Integration broker (informational): " + broker["status_level"]
          + "; Core deterministic; transport unavailable: Fabric#25", file=out)


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
        facts = ", ".join(f"{k}={v}" for k, v in sorted(interface.description.items())
                          if k in OPERATOR_SCREEN_FIELDS)
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
    report: OperatorReport,
    out: TextIO,
    view: Optional[IntegrationView] = None,
    edge: Optional[EdgeInspection] = None,
    knowledge: Optional[dict] = None,
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
    # Printed as its own line rather than folded into a module list, because
    # it is a claim about this node and not about a peer. "No" here means this
    # node is not asserting a deterministic baseline; it does not mean an Edge
    # Core is broken, and the edge section below says which of the five checks
    # did not hold.
    ready = edge is not None and edge.ready
    print("edge-baseline-ready: " + ("yes" if ready else "no"), file=out)
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
    if knowledge is not None:
        _render_knowledge(knowledge, out)
        print(file=out)
    if edge is not None:
        _render_edge(edge, out)
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


def _probe_result(path: Path, out: TextIO):
    """`az-edge-probed`'s last result, or `None` when there is not a usable one.

    A state file that cannot be read as a result is **reported and then
    treated as absent**: something wrote it, and swallowing that would hide
    the one case where the probe is producing garbage. Reporting it costs
    nothing -- an unreadable result leaves health and running `not-checked`,
    which is where they start.
    """

    try:
        return load_probe_result(path)
    except EdgePackageRefused as exc:
        print(f"edge probe state at {path} was refused: {exc}", file=out)
        print(file=out)
        return None


def _render_knowledge(reading: dict, out: TextIO) -> None:
    """Render only facts returned by the commissioned trust status reader."""

    readiness = readiness_for("knowledge_lite")
    print(
        "Knowledge Lite: "
        + ("functional" if readiness.functional else readiness.value),
        file=out,
    )
    print(f"    state: {reading['state']}", file=out)
    print(f"    reason: {reading['reason_code']}", file=out)
    print(f"    generation: {reading['generation']}", file=out)
    print(f"    freshness: {reading['freshness']}", file=out)
    print(
        "    cryptographic implementation: not supported (Nexus#70 review pending)",
        file=out,
    )
    print(f"    functional means: {readiness.means}", file=out)
    for limit in readiness.does_not_mean:
        print(f"    it does not mean: {limit}", file=out)


def _render_edge(inspection: EdgeInspection, out: TextIO) -> None:
    """The local Edge Core: one word, then all five checks, then the limits.

    All five are printed whatever the leading word says. A screen that stopped
    at the first failure would leave an operator who fixed it guessing at what
    comes next, and -- worse -- would hide a digest mismatch behind a version
    mismatch found first.
    """

    where = inspection.root or "no package root configured"
    print(f"edge core (local): {inspection.presence.value}  [{where}]", file=out)
    for finding in inspection.findings:
        mark = "  SECURITY FINDING" if finding.security else ""
        print(f"    {finding.check}: {finding.evidence.value}{mark}", file=out)
        print(f"        {finding.reason}", file=out)
    for caveat in inspection.caveats:
        print(f"    caveat: {caveat}", file=out)


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
    proposal_reader=None,
) -> int:
    proposal = proposal_reader() if proposal_reader is not None else propose(
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

    if args.draft_output is not None:
        try:
            export_draft(record, args.draft_output)
        except DraftRefused:
            print("Draft export refused; inspect destination before retrying. Nothing was signed or activated.", file=out)
            return 1
        print("Unsigned private draft exported; not a persisted commissioning approval.", file=out)
    print("commissioning draft prepared; raw bindings and digest are not displayed", file=out)
    print(
        ("    This draft is in memory only: not signed, not persisted, and not "
         if args.draft_output is None else "    This exported draft is not signed and is not ") +
        "an activation approval. Profile names are operator assertions, not "
        "measured profile evidence.",
        file=out,
    )
    if record.observe_only:
        print(
            "    No interface carries a role in this draft. This records the "
            "operator's choice to assign none; it does not establish a running "
            "observation or enforcement service.",
            file=out,
        )
    return 0



def _cmd_commission_review(args, out, permanent_mac_reader, proposal_reader=None) -> int:
    """Verify a protected draft without importing, writing or activating it."""
    try:
        trust = load_operator_trust()
        payload, signature = read_draft_review_inputs()
        current = proposal_reader() if proposal_reader is not None else propose(
            read_interfaces(args.sysfs, permanent_mac_reader=permanent_mac_reader))
        verify_draft_review(payload=payload, signature=signature, operator=args.operator,
                            trust=trust, current=current)
    except (DraftRefused, ApprovalRefused, CommissioningRefused, OSError):
        print("Signed draft review refused. Check protected inputs, enrollment and current inventory locally.", file=out)
        return 1
    print(
        "Signed draft review: assigned bindings verified. This does not prove "
        "the entire inventory is unchanged or profiles are measured. Nothing "
        "was imported or activated.", file=out,
    )
    return 0


def _cmd_hil_preflight(
    args: argparse.Namespace,
    out: TextIO,
    ask: Optional[Callable[[str, Sequence[str]], str]],
    confirm: Optional[Callable[[str], bool]],
    text: Optional[Callable[[str], str]],
    permanent_mac_reader=no_permanent_mac,
) -> int:
    """One command, run on the target, answering one question.

    **It takes no operator, no timestamp and no identifier.** A command line
    is read by everyone on the host -- `ps`, `/proc/<pid>/cmdline`, the
    shell's history -- so a name passed as an argument is a name published to
    all of them. The operator is the local principal the kernel reports, the
    time is the node's own clock and boot, and the approval ID is asked for
    in the wizard, where the answer reaches the encrypted record and nothing
    else.

    It prints `HIL_PREFLIGHT_READY` or `HIL_PREFLIGHT_BLOCKED` and the fields
    `hil_preflight` allows for each. No raw identity, no operator identity and
    no raw instant is printed on either path.
    """

    readouts = read_interfaces(args.sysfs, permanent_mac_reader=permanent_mac_reader)
    proposal = propose(readouts)

    if ask is None or confirm is None or text is None:
        print(
            "No operator prompt is available on this stream. A preflight "
            "settles decisions only an operator may make and will not proceed "
            "without one.",
            file=out,
        )
        return 2

    answers: list[Answer] = []

    def recording_ask(handle: str, choices: Sequence[str]) -> str:
        answer = ask(handle, choices)
        answers.append(Answer(handle, None if answer == "skip" else answer))
        return answer

    # The narrower set: `describe_for_operator` carries the serial and the
    # device ids, and a terminal is not one of the two places raw identity
    # may go.
    for index, readout in enumerate(proposal.commissionable, start=1):
        facts = ", ".join(
            f"{k}={v}" for k, v in sorted(describe_for_screen(readout).items())
        )
        print(f"if-{index}  {facts}", file=out)
    for _, reasons in proposal.refused:
        print("-  this adapter was seen and cannot be commissioned", file=out)
        for reason in reasons:
            print(f"    blocked: {reason}", file=out)

    at, boot_id = node_clock(boot_id_path=args.boot_id)
    principal = local_principal()

    try:
        record = commission(
            proposal,
            ask=recording_ask,
            confirm=confirm,
            operator=principal,
            at=at,
            profiles_present=REQUIRED_PROFILES,
        )
    except (WizardAbandoned, CommissioningRefused):
        # The class name and nothing from the exception: a refusal's message
        # may quote what it refused.
        print(BLOCKED, file=out)
        print("missing: B-3", file=out)
        return 2

    decisions = OperatorDecisions(
        record=record,
        answers=tuple(answers),
        external_communication_forbidden=confirm(
            "forbid external communication for the duration of the campaign?"
        ),
        responsible=principal,
        at=at,
        host_label=text("anonymised host ID or asset ID"),
        approval_id=text("approval ID"),
        reboot_approved=confirm("approve measurements that require reboots?"),
        administrative_rights=confirm(
            "confirm administrative rights for units and read-only inventory?"
        ),
    )

    key = read_protection_key(args.key)
    protection = Protection(
        luks_backed=luks_backed(
            args.record_dir, sysfs_dev_block=args.sysfs_dev_block
        ),
        key_available=key is not None,
    )
    inventory = collect_readonly_inventory(
        interfaces=readouts,
        sysfs_net=args.sysfs or DEFAULT_SYSFS_NET,
        meminfo=args.meminfo,
        os_release=args.os_release,
        record_directory=args.record_dir,
        sysfs_dev_block=args.sysfs_dev_block,
        sysfs_tpm=args.sysfs_tpm,
    )
    generation = next_generation(args.record_dir)
    result = evaluate_preflight(
        inventory,
        decisions,
        protection=protection,
        generation=generation,
        key=key or b"",
        boot_id=boot_id,
        proposal=proposal,
    )

    if result.ready:
        # Written only here, and only once the storage that may hold it has
        # been established. A refusal writes nothing at all.
        try:
            persist_commissioning_record(
                record,
                directory=args.record_dir,
                protection=protection,
                generation=generation,
                boot_id=boot_id,
            )
        except PreflightRefused:
            for line in PreflightResult(
                outcome=BLOCKED, missing=("A-7", "A-8")
            ).lines():
                print(line, file=out)
            return 1

    if args.audit is not None:
        AuditLedger(args.audit).append(
            audit_event(result, approval_id=decisions.approval_id)
        )

    for line in result.lines():
        print(line, file=out)
    return 0 if result.ready else 1


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    out: Optional[TextIO] = None,
    err: Optional[TextIO] = None,
    ask: Optional[Callable[[str, Sequence[str]], str]] = None,
    confirm: Optional[Callable[[str], bool]] = None,
    text: Optional[Callable[[str], str]] = None,
    permanent_mac_reader=no_permanent_mac,
    commissioning_proposal_reader=None,
) -> int:
    import sys

    stream = out if out is not None else sys.stdout
    error_stream = err if err is not None else sys.stderr
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
    parser.add_argument(
        "--edge-root", type=Path, default=EDGE_PACKAGE_ROOT, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--edge-probe", type=Path, default=PROBE_STATE_PATH, help=argparse.SUPPRESS
    )
    sub = parser.add_subparsers(dest="command", required=True)

    from .mission_pack_cli import add_parser as add_pack_parser
    add_pack_parser(sub)

    from .operator_flow_cli import add_parser as add_setup_parser
    add_setup_parser(sub)

    from .broker_cli import add_parser as add_broker_parser
    add_broker_parser(sub)

    sub.add_parser("inventory", help="read-only hardware and interface list")
    sub.add_parser("profile", help="measured RAM and the profile it selects")
    sub.add_parser("status", help="everything above, as it currently stands")
    sub.add_parser("health", help="units and the audit chain")
    sub.add_parser(
        "bootstrap-deployment-preview",
        help="validate canonical administrator JSON from stdin; no installation or admission",
    )
    sub.add_parser(
        "bootstrap-admission-preview",
        help="validate canonical prestart admission policy JSON from stdin; no installation or admission",
    )
    sub.add_parser(
        "bootstrap-approval-policy-preview",
        help="validate canonical bootstrap approval policy JSON from stdin; no installation or enrollment",
    )
    sub.add_parser("bootstrap-deployment-initialize", help="interactive first declaration publication; no activation")
    sub.add_parser("bootstrap-deployment-recover", help="interactive completion of matching pending declaration; no repair")
    sub.add_parser("bootstrap-selection-initialize", help="interactive initial per-boot selection; no approval or activation")
    sub.add_parser("bootstrap-selection-recover", help="complete exact pending selection; no replacement or deadline reset")
    installed = sub.add_parser("installed-files-check", help="read-only pinned selected file comparison; not runtime admission")
    installed.add_argument("--manifest-digest", required=True, help="independently reviewed sha256:hex manifest pin")
    candidate_parser = sub.add_parser(
        "installed-files-candidate",
        help="emit a read-only selected-file candidate manifest; not admission",
    )
    candidate_parser.add_argument(
        "--directory", action="append", default=None,
        help=("explicit installed directory path (repeat in sorted unique order; "
              "does not discover directories)"),
    )
    candidate_parser.add_argument(
        "--link", action="append", default=None,
        help=("explicit installed symlink path (repeat in sorted unique order; "
              "does not discover links)"),
    )

    fetched = sub.add_parser("model-import-fetched", help="root verifies and promotes a completed fetch")
    fetched.add_argument("model_id")
    fetched.add_argument("--acknowledge-license", action="store_true")

    wizard = sub.add_parser("commission", help="assign roles, with confirmation")
    wizard.add_argument("--operator", required=True)
    wizard.add_argument("--at", required=True, help="RFC3339 timestamp")
    wizard.add_argument("--profiles", nargs="*", default=())
    wizard.add_argument("--draft-output", type=Path,
                        help="unsigned export to /etc/azazel/commissioning/commissioning-draft.json; requires encrypted protected storage; never activates")
    review = sub.add_parser("commission-review", help="verify protected signed draft against current inventory; no activation")
    review.add_argument("--operator", required=True, help="previously enrolled operator key label")

    preflight = sub.add_parser(
        "hil-preflight",
        help="may the 8 GiB HG-05 campaign start on this node? Takes no "
        "arguments, no sample, and reboots or activates nothing",
    )
    # **No operator, no timestamp, no identifier.** Every option below is a
    # path the node reads itself from, and every one is hidden: an operator
    # who had to name them could name one that describes a different machine,
    # and an option that took a name would put the name in `ps`.
    preflight.add_argument(
        "--record-dir", type=Path, default=COMMISSIONING_DIR, help=argparse.SUPPRESS
    )
    preflight.add_argument(
        "--key", type=Path, default=PROTECTION_KEY, help=argparse.SUPPRESS
    )
    preflight.add_argument("--audit", type=Path, default=None, help=argparse.SUPPRESS)
    preflight.add_argument(
        "--meminfo", type=Path, default=Path("/proc/meminfo"), help=argparse.SUPPRESS
    )
    preflight.add_argument(
        "--os-release", type=Path, default=Path("/etc/os-release"), help=argparse.SUPPRESS
    )
    preflight.add_argument(
        "--sysfs-dev-block",
        type=Path,
        default=Path("/sys/dev/block"),
        help=argparse.SUPPRESS,
    )
    preflight.add_argument(
        "--sysfs-tpm", type=Path, default=Path("/sys/class/tpm"), help=argparse.SUPPRESS
    )
    preflight.add_argument(
        "--boot-id", type=Path, default=BOOT_ID_PATH, help=argparse.SUPPRESS
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    from .lab_host import is_lab_host

    if is_lab_host():
        if args.command in {"status", "setup"}:
            print("LAB HOST", file=stream)
        if args.command in {"hil-preflight", "commission-review"}:
            print("refused: LAB_HOST_MARKER", file=error_stream)
            return 2

    if args.command == "broker":
        from .broker_cli import run as run_broker
        return run_broker(args, now=_now(), out=stream)

    if args.command == "setup":
        from .operator_flow_cli import run as run_setup
        return run_setup(args, now=_now(), out=stream)

    if args.command == "pack":
        from .mission_pack_cli import run as run_pack
        return run_pack(args, now=_now(), out=stream)

    if args.command == "model-import-fetched":
        from .model_fetched_cli import import_fetched
        return import_fetched(args.model_id, license_acknowledged=args.acknowledge_license,
                              now=_now(), out=stream)

    if args.command in {"bootstrap-selection-initialize", "bootstrap-selection-recover"}:
        from .bootstrap_selection_cli import run_publication
        return run_publication(source=sys.stdin, out=stream,
                               recovery=args.command == "bootstrap-selection-recover")

    if args.command == "installed-files-check":
        from .installed_files import measure_installed_files

        try:
            if sys.stdin.isatty():
                raise ApprovalRefused("bounded canonical manifest stdin required")
            raw = sys.stdin.buffer.read(1024 * 1024 + 1)
            result = measure_installed_files(raw, expected_digest=args.manifest_digest)
        except (ApprovalRefused, OSError, AttributeError, ValueError):
            print("Selected installed file inspection refused; no changes made.", file=stream)
            return 1
        print(f"Selected files matched: {result.file_count}; bytes: {result.total_bytes}", file=stream)
        directory_count = getattr(result, "directory_count", 0)
        if directory_count:
            print(f"Selected directories matched: {directory_count}", file=stream)
        link_count = getattr(result, "link_count", 0)
        if link_count:
            print(f"Selected links matched: {link_count}", file=stream)
        print("Manifest: " + result.manifest_digest, file=stream)
        print("NOT dependency closure, provenance, compatibility or runtime admission.", file=stream)
        return 0

    if args.command == "installed-files-candidate":
        import json

        print(
            "Candidate only: not dependency closure, approval, or admission.",
            file=error_stream,
        )
        try:
            if sys.stdin.isatty():
                raise ValueError("redirect bounded JSON into stdin")
            raw = sys.stdin.buffer.read((1 << 20) + 1)
            if type(raw) is not bytes or not 0 < len(raw) <= (1 << 20):
                raise ValueError("candidate input size refused")

            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate candidate JSON key")
                    result[key] = value
                return result

            document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            if type(document) is not dict or set(document) != {"paths"}:
                raise ValueError("candidate fields refused")
            selected = document["paths"]
            if type(selected) is not list or not 0 < len(selected) <= 4096:
                raise ValueError("candidate path list refused")
            paths = tuple(selected)
            if paths != tuple(sorted(set(paths))):
                raise ValueError("candidate paths must be sorted and unique")
            from .installed_manifest import _ROOTS_V4, _validate_path

            for path in paths:
                _validate_path(path, _ROOTS_V4)
            directories = tuple(args.directory or ())
            if len(directories) > 1024:
                raise ValueError("candidate directory count refused")
            if directories != tuple(sorted(set(directories))):
                raise ValueError("candidate directories must be sorted and unique")
            for directory in directories:
                _validate_path(directory, _ROOTS_V4)
            links = tuple(args.link or ())
            if len(links) > 1024:
                raise ValueError("candidate link count refused")
            if links != tuple(sorted(set(links))):
                raise ValueError("candidate links must be sorted and unique")
            for link in links:
                _validate_path(link, _ROOTS_V4)
            from .installed_candidate import generate_installed_candidate

            if args.directory is None and args.link is None:
                candidate = generate_installed_candidate(paths)
            elif args.link is None:
                candidate = generate_installed_candidate(
                    paths, directories=directories,
                )
            elif args.directory is None:
                candidate = generate_installed_candidate(paths, links=links)
            else:
                candidate = generate_installed_candidate(
                    paths, directories=directories, links=links,
                )
            if type(candidate) is not bytes or not candidate:
                raise ValueError("candidate manifest unavailable")
        except Exception:
            print("Installed files candidate refused; no changes made.", file=error_stream)
            return 1

        if out is None:
            sys.stdout.buffer.write(candidate)
            sys.stdout.buffer.flush()
        else:
            try:
                stream.write(candidate)
            except TypeError:
                stream.write(candidate.decode("utf-8"))
        return 0

    if args.command in {"bootstrap-deployment-initialize", "bootstrap-deployment-recover"}:
        from .bootstrap_deployment_cli import run_publication
        return run_publication(source=sys.stdin, out=stream,
                               recovery=args.command == "bootstrap-deployment-recover")

    if args.command == "bootstrap-deployment-preview":
        from hashlib import sha256
        from .bootstrap_deployment import decode_bootstrap_deployment

        try:
            if sys.stdin.isatty():
                raise ApprovalRefused("redirect canonical JSON into stdin")
            raw = sys.stdin.buffer.read(4097)
            decode_bootstrap_deployment(raw)
        except (ApprovalRefused, OSError, AttributeError, ValueError):
            print("Deployment preview refused; no changes made.", file=stream)
            return 1
        print("Declaration syntax valid; NOT installed, NOT admitted, NOT authorized.", file=stream)
        print("Declaration SHA-256: " + sha256(raw).hexdigest(), file=stream)
        print("Independent node, policy and fresh runtime checks remain required.", file=stream)
        return 0

    if args.command == "bootstrap-admission-preview":
        from hashlib import sha256
        from .bootstrap_prestart_policy import decode_pinned_prestart_policy

        try:
            if sys.stdin.isatty():
                raise ApprovalRefused("redirect canonical JSON into stdin")
            raw = sys.stdin.buffer.read(8193)
            if not raw or len(raw) > 8192:
                raise ApprovalRefused("policy size refused")
            digest = "sha256:" + sha256(raw).hexdigest()
            # Self-pinned: the pin is tautological (digest of the input itself).
            # The call is used only for its canonicality and type checks.
            policy = decode_pinned_prestart_policy(raw, expected_digest=digest)
        except (ApprovalRefused, OSError, AttributeError, ValueError, TypeError,
                RecursionError):
            print("Admission preview refused; no changes made.", file=stream)
            return 1
        print("Admission policy syntax valid; NOT installed, NOT admitted, NOT authorized.", file=stream)
        print("Admission policy SHA-256 (deployment policy_digest): " + digest, file=stream)
        if policy.loaded_policy_digest is None:
            print("Schema: v3", file=stream)
        elif policy.first_install_genesis is None:
            print("Schema: v4", file=stream)
            print("Loaded-units policy pin: " + policy.loaded_policy_digest, file=stream)
        else:
            print("Schema: v5", file=stream)
            print("Audit mode: first-install-genesis", file=stream)
            print("First-install genesis: accepted only while the audit ledger directory "
                  "exists, is correctly owned and is EMPTY; publish an existing-history "
                  "(v3/v4) admission after the first successful bootstrap.", file=stream)
            print("Genesis node digest: " + policy.first_install_genesis.node_digest, file=stream)
            print("Genesis provisioning_id (distinguishes this policy's digest; not checked "
                  "elsewhere): " + policy.first_install_genesis.provisioning_id, file=stream)
            print("Loaded-units policy pin: " + policy.loaded_policy_digest, file=stream)
        print("Independent package, closure, profile and fresh runtime checks remain required.", file=stream)
        return 0

    if args.command == "bootstrap-approval-policy-preview":
        # Private helper imported deliberately: it is the single canonical decoder
        # used by the protected store, so the preview cannot drift from it.
        from .bootstrap_store import _decode_policy

        try:
            if sys.stdin.isatty():
                raise ApprovalRefused("redirect canonical JSON into stdin")
            raw = sys.stdin.buffer.read(65537)
            if not raw or len(raw) > 65536:
                raise ApprovalRefused("policy size refused")
            policy = _decode_policy(raw)
        # RecursionError: deeply nested JSON reaches json.loads bare here, unlike
        # the protected reader whose caller fails closed on any exception.
        except (ApprovalRefused, OSError, AttributeError, ValueError, TypeError,
                RecursionError):
            print("Approval policy preview refused; no changes made.", file=stream)
            return 1
        print("Approval policy syntax valid; NOT installed, NOT enrolled, NOT authorized.", file=stream)
        print("Approval policy digest (deployment approval_policy_digest): " + policy.digest(), file=stream)
        print("Operator enrollment and signatures remain separate.", file=stream)
        return 0

    if args.command == "commission":
        return _cmd_commission(
            args, stream, ask, confirm, permanent_mac_reader, commissioning_proposal_reader
        )

    if args.command == "commission-review":
        return _cmd_commission_review(args, stream, permanent_mac_reader, commissioning_proposal_reader)

    if args.command == "hil-preflight":
        return _cmd_hil_preflight(
            args, stream, ask, confirm, text, permanent_mac_reader
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
        # Inspected once and passed to both the section and the axis, so the
        # two cannot describe different nodes on one screen.
        #
        # `status` never probes. It reads what `az-edge-probed` last
        # wrote (Nexus#72) and passes it in; package, version and digest
        # are still derived here, from the files, every time.
        edge = inspect_edge(
            args.edge_root, probe=_probe_result(args.edge_probe, stream), now=as_of
        )
        knowledge = _knowledge_reading(args.knowledge_lite, as_of=as_of)
        _render_status(
            report,
            stream,
            _integration_view(
                report,
                as_of=as_of,
                knowledge_root=args.knowledge_lite,
                knowledge=knowledge,
                edge=edge,
            ),
            edge,
            knowledge,
        )
    return 0


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
