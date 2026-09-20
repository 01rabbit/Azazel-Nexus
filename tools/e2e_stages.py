"""The stages the integration harness runs, in the order #43 lists them.

Each stage either executes and returns what it established, or raises
`NotExecuted` with the reason it could not run here. Neither is allowed to be
silent, and only the first counts as a pass.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.e2e_harness import Daemon, Harness, NotExecuted, request

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-20T12:00:00Z"
ACTOR = "e2e@harness"


def run_all(harness: Harness) -> None:
    harness.stage("install", lambda: _install(harness))
    harness.stage("units masked and disabled", lambda: _masked(harness))
    harness.stage("inventory", lambda: _inventory(harness))
    harness.stage("operator-confirmed commissioning", lambda: _commission(harness))
    harness.stage("verified generation", lambda: _generation(harness))
    harness.stage("activation", lambda: _activation(harness))
    harness.stage("health and status", lambda: _health(harness))
    harness.stage("daemon failure", lambda: _failure(harness))
    harness.stage("remask and rollback", lambda: _rollback(harness))
    harness.stage("audit chain", lambda: _audit(harness))


def _install(harness: Harness) -> str:
    """Run the real installer against a prefix, files and accounts only.

    The accounts are created on the host either way -- an installer that
    pretended to create them would be testing a different script.
    """

    libexec = harness.root / "usr/libexec/azazel"
    libexec.mkdir(parents=True, exist_ok=True)
    for name in ("az-activated", "az-commissiond", "az-auditd", "az-watchdog"):
        shim = libexec / name
        module = name.replace("az-", "")
        shim.write_text(
            "#!/bin/sh\n"
            f'exec "{sys.executable}" -m azazel_nexus_runtime.{module} "$@"\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)

    result = subprocess.run(
        ["sh", str(ROOT / "packaging" / "install.sh"), "--without-service-manager"],
        env={**harness.env, "DESTDIR": str(harness.root)},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"install.sh exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    if "SERVICE-MANAGER STAGE NOT EXECUTED" not in result.stdout:
        raise RuntimeError(
            "install.sh completed without saying the service-manager stage "
            "did not run; a silent skip is what this harness exists to refuse"
        )

    from azazel_nexus.layout import LAYOUT

    missing = [
        spec.path
        for spec in LAYOUT
        if not (harness.root / spec.path.lstrip("/")).is_dir()
    ]
    if missing:
        raise RuntimeError(f"the installer did not create {missing}")
    wrong = [
        spec.path
        for spec in LAYOUT
        if (harness.root / spec.path.lstrip("/")).stat().st_mode & 0o777 != spec.mode
    ]
    if wrong:
        raise RuntimeError(f"{wrong} were created with the wrong mode")
    return f"{len(LAYOUT)} directories at their declared modes; executables in place"


def _masked(harness: Harness) -> str:
    raise NotExecuted(
        "systemd is not running here (/run/systemd/system is absent), so no "
        "unit was masked and nothing established that one is. This is HG-01 "
        "in docs/hardware-gates.md and it stays open"
    )


def _inventory(harness: Harness) -> str:
    with Daemon(harness, "commissiond", "commission") as daemon:
        answer = request(
            daemon.path, {"verb": "commission.inventory", "arguments": {}}
        )
    if not answer.get("ok"):
        raise RuntimeError(f"the inventory was refused: {answer}")
    result = answer["result"]
    rows = result["interfaces"]
    for row in rows:
        for value in row["description"].values():
            if value in os.listdir("/sys/class/net"):
                raise RuntimeError(
                    "a kernel name reached the operator's rows, which is the "
                    "one thing commissioning.md 4 forbids showing"
                )
    return f"{len(rows)} interfaces, snapshot {result['snapshot'][:19]}..."


def _commission(harness: Harness) -> str:
    """A record written from a confirmed role, with no hand editing."""

    from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole

    record = CommissioningRecord(
        roles=(
            ConfirmedRole(
                composite=(("bus_path", "e2e-0"), ("permanent_mac", "aa:bb:cc:dd:ee:ff")),
                role="observation",
                confirmed_by=ACTOR,
                confirmed_at=NOW,
            ),
        ),
        profiles_present=("hardware", "resource", "topology"),
        created_at=NOW,
    )
    target = harness.root / "etc/azazel/commissioning/active.record"
    target.write_text(
        json.dumps({"digest": record.digest(), "created_at": record.created_at}),
        encoding="utf-8",
    )
    if not record.enforcement_ready:
        raise RuntimeError("the record is not enforcement-ready and should be")
    harness.record = record  # type: ignore[attr-defined]
    return f"record digest {record.digest()[:19]}..., enforcement ready"


def _generation(harness: Harness) -> str:
    from azazel_nexus.generation import GenerationStore

    store = GenerationStore(harness.root / "var/lib/azazel/generations")
    generation = store.create(
        {"suricata.yaml": b"role: observation\n"},
        created_at=NOW,
        commissioning_digest=harness.record.digest(),  # type: ignore[attr-defined]
    )
    verified = store.verify(generation.number)
    harness.store = store  # type: ignore[attr-defined]
    return f"generation {verified.number} verified, digest {verified.digest[:19]}..."


def _activation(harness: Harness) -> str:
    from azazel_nexus.activation import ActivationLease
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus_runtime.activated import ActivationDaemon
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager

    manager = RecordingUnitManager(UNIT_NAMES.values())
    daemon = ActivationDaemon(
        generations=harness.store,  # type: ignore[attr-defined]
        ledger=AuditLedger(harness.root / "var/lib/azazel/state/activation.jsonl"),
        manager=manager,
    )
    outcome = daemon.activate(
        now=NOW,
        actor=ACTOR,
        lease=ActivationLease(
            granted_by=ACTOR,
            granted_at="2026-09-19T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
            generation_digest=harness.store.current().digest,  # type: ignore[attr-defined]
        ),
        record=harness.record,  # type: ignore[attr-defined]
    )
    if len(outcome.granted) != len(UNIT_NAMES):
        raise RuntimeError(f"only {outcome.granted} were granted")
    if outcome.edge_baseline_ready:
        raise RuntimeError(
            "edge-baseline-ready was claimed with no Edge Core established"
        )
    harness.manager = manager  # type: ignore[attr-defined]
    return (
        f"{len(outcome.granted)} supporting units granted; "
        "edge-baseline-ready correctly withheld"
    )


def _health(harness: Harness) -> str:
    import io

    from azazel_nexus.cli import main as cli

    out = io.StringIO()
    code = cli(["--sysfs", "/sys/class/net", "status"], out=out)
    if code != 0:
        raise RuntimeError(f"status exited {code}")
    text = out.getvalue()
    for forbidden in ("enforcement ready: yes",):
        if forbidden in text:
            raise RuntimeError(f"status claimed {forbidden!r} on this node")
    if "systemd units: unknown" not in text:
        raise RuntimeError("status did not report the service manager as unknown")
    return "status answered with no network; units reported unknown, not healthy"


def _failure(harness: Harness) -> str:
    """Inject a daemon failure and confirm it is detected, not assumed away."""

    from azazel_nexus.audit import AuditLedger
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager
    from azazel_nexus_runtime.watchdog import FenceStore, WatchdogService

    ticks = iter([0, 10])
    service = WatchdogService(
        manager=RecordingUnitManager(UNIT_NAMES.values()),
        ledger=AuditLedger(harness.root / "var/lib/azazel/state/watchdog.jsonl"),
        fences=FenceStore(harness.root / "var/lib/azazel/state/fences.json"),
        clock=lambda: next(ticks),
    )
    healthy = service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    if healthy:
        raise RuntimeError("an unwell daemon was reported healthy")
    if service.fenced.get("azazel-auditd.service") != "unhealthy":
        raise RuntimeError(f"the fence is {service.fenced}")
    return "an unwell daemon was fenced and recorded as unhealthy"


def _rollback(harness: Harness) -> str:
    from azazel_nexus.activation import ActivationLease, UnitState
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus_runtime.activated import ActivationDaemon
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager

    manager = RecordingUnitManager(
        UNIT_NAMES.values(), fail_on="azazel-watchdog.service"
    )
    ledger = AuditLedger(harness.root / "var/lib/azazel/state/rollback.jsonl")
    daemon = ActivationDaemon(
        generations=harness.store,  # type: ignore[attr-defined]
        ledger=ledger,
        manager=manager,
    )
    daemon.activate(
        now=NOW,
        actor=ACTOR,
        lease=ActivationLease(
            granted_by=ACTOR,
            granted_at="2026-09-19T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
            generation_digest=harness.store.current().digest,  # type: ignore[attr-defined]
        ),
        record=harness.record,  # type: ignore[attr-defined]
    )
    left_open = [
        name for name in UNIT_NAMES.values() if manager.state(name) is not UnitState.MASKED
    ]
    if left_open:
        raise RuntimeError(f"{left_open} were left widened after a failed pass")
    events = [entry.event["event_type"] for entry in ledger]
    if "activation.rolled_back" not in events:
        raise RuntimeError("the rollback was not recorded")
    return "a failed pass took back every unit it had widened, and recorded it"


def _audit(harness: Harness) -> str:
    from azazel_nexus_runtime.auditd import SegmentedLedger

    root = harness.root / "var/lib/azazel/state/audit"
    root.mkdir(parents=True, exist_ok=True)
    ledger = SegmentedLedger(root)
    ledger.append(
        {
            "event_type": "activation.unit_granted",
            "unit": "auditd",
            "generation": 1,
            "digest": harness.store.current().digest,  # type: ignore[attr-defined]
            "occurred_at": NOW,
            "actor": ACTOR,
        },
        day=NOW[:10],
    )
    ledger.verify()
    sequence, _ = ledger.head()
    return f"{sequence} entries, chain verified across {len(ledger.segments())} segment(s)"
