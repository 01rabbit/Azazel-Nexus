"""The stages the integration harness runs, in the order #43 lists them.

Each stage either executes and returns what it established, or raises
`NotExecuted` with the reason it could not run here. Neither is allowed to be
silent, and only the first counts as a pass.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from tools.e2e_harness import Daemon, Harness, NotExecuted, request

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-20T12:00:00Z"
ACTOR = "e2e@harness"


#: Installation has three halves and they need different privileges.
#:
#: Files need write access to the prefix. Accounts and directory ownership
#: need root. Masking a unit needs a running systemd. A single `install`
#: stage would have to claim all three or none, and on a CI runner that is
#: neither root nor running systemd it would claim failure for something that
#: simply cannot be done there.
def run_all(harness: Harness) -> None:
    harness.stage("install files", lambda: _install_files(harness))
    harness.stage("install accounts", lambda: _install_accounts(harness))
    harness.stage("units masked and disabled", lambda: _masked(harness))
    harness.stage(
        "inventory",
        lambda: _inventory(harness),
        requires=("install accounts",),
    )
    harness.stage("operator-confirmed commissioning", lambda: _commission(harness),
                  requires=("install files",))
    harness.stage("verified generation", lambda: _generation(harness),
                  requires=("operator-confirmed commissioning",))
    harness.stage("activation", lambda: _activation(harness),
                  requires=("verified generation",))
    harness.stage("health and status", lambda: _health(harness))
    harness.stage("daemon failure", lambda: _failure(harness))
    harness.stage("remask and rollback", lambda: _rollback(harness),
                  requires=("verified generation",))
    harness.stage("audit chain", lambda: _audit(harness),
                  requires=("verified generation",))
    harness.stage("CORE + Lite configurations", lambda: _lite_matrix(harness))
    harness.stage("Edge package verification", lambda: _edge_package(harness))
    harness.stage("loopback decoy runtime", lambda: _loopback_decoys(harness))
    harness.stage("Edge probe to status", lambda: _edge_probe(harness))
    harness.stage("Knowledge Lite offline import", lambda: _lite_import(harness))
    harness.stage("M.I.O. entry handoff", lambda: _mio_entry(harness),
                  requires=("install files", "install accounts"))
    harness.stage("Knowledge Lite status", lambda: _knowledge_status(harness),
                  requires=("Knowledge Lite offline import", "install accounts"))
    harness.stage("Operator setup flow", lambda: _operator_setup(harness),
                  requires=("install files", "Knowledge Lite offline import"))
    harness.stage("Core reserve input path", lambda: _core_reserve_path(harness))
    harness.stage("Integration broker", lambda: _integration_broker(harness))
    harness.stage("integrated defensive loop", lambda: _integrated_loop(harness),
                  requires=("Knowledge Lite offline import", "install accounts"))
    # ADR 0008: the trust maintenance transactions with real accounts and
    # processes, on a root of their own (tools/e2e_lite_trust.py).
    from tools import e2e_lite_trust

    harness.stage("Knowledge Lite trust enrollment", lambda: e2e_lite_trust.enrollment(harness),
                  requires=("install accounts",))
    harness.stage("Knowledge Lite import, repin, revocation and audit stop",
                  lambda: e2e_lite_trust.operations(harness),
                  requires=("Knowledge Lite trust enrollment",))


def _install_files(harness: Harness) -> str:
    """Run the real installer against a prefix. Not a reimplementation of it.

    Without the account half, which needs root: the modes are applied and the
    ownership is not, and the installer says so.
    """

    _setup_snapshot(harness, "before-install")
    result = subprocess.run(
        [
            "sh",
            str(ROOT / "packaging" / "install.sh"),
            "--without-service-manager",
            "--without-accounts",
        ],
        env={**harness.env, "DESTDIR": str(harness.root), "PYTHON": sys.executable},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"install.sh exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    for marker in ("SERVICE-MANAGER STAGE NOT EXECUTED", "ACCOUNT STAGE NOT EXECUTED"):
        if marker not in result.stdout:
            raise RuntimeError(
                f"install.sh completed without printing {marker!r}; a silent "
                "skip is what this harness exists to refuse"
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
        if stat.S_IMODE((harness.root / spec.path.lstrip("/")).stat().st_mode) != spec.mode
    ]
    if wrong:
        raise RuntimeError(f"{wrong} were created with the wrong mode")
    _setup_snapshot(harness, "after-install")
    return (
        f"{len(LAYOUT)} directories at their declared modes; executables in "
        "place. Ownership was not applied -- that is the account stage"
    )


def _install_accounts(harness: Harness) -> str:
    """The half that needs root: system accounts and directory ownership."""

    if os.geteuid() != 0:
        raise NotExecuted(
            f"this process runs as uid {os.geteuid()} and creating a system "
            "account needs root, so no account exists and nothing established "
            "that the daemons could run as one"
        )
    result = subprocess.run(
        ["sh", str(ROOT / "packaging" / "install.sh"), "--without-service-manager"],
        env={**harness.env, "DESTDIR": str(harness.root), "PYTHON": sys.executable},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"install.sh exited {result.returncode}: {result.stderr.strip()[:400]}"
        )

    import grp
    import pwd

    from azazel_nexus_runtime.hardening import SYSTEM_ACCOUNTS

    for account in SYSTEM_ACCOUNTS:
        entry = pwd.getpwnam(account)
        if "nologin" not in entry.pw_shell and "false" not in entry.pw_shell:
            raise RuntimeError(f"{account} has a login shell: {entry.pw_shell}")
    for group in ("azazel-operator", "azknowledge-read", "azmission-read",
                  "azaudit-submit", "azmio-advise"):
        grp.getgrnam(group)
    return f"{len(SYSTEM_ACCOUNTS)} non-login accounts and operator/Knowledge/Mission Pack groups"


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
    from azazel_nexus_runtime.activated import ActivationDaemon
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager

    from azazel_nexus.activation import CORE_UNITS, ActivationLease, UnitTier
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.edge_package import installed_baseline_state

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
        edge=installed_baseline_state(
            now=NOW, package_root=harness.root / "empty-edge-package",
            probe_path=harness.root / "empty-edge-probe.json",
        ),
    )
    # Not "everything governed". A unit naming a capability this build does
    # not wire is withheld for that -- `azazel-model-fetchd.service` has no
    # transport here; locald has no admitted model provider. Granting either
    # would enable a unit that starts and
    # exits at the next boot. Checked as two statements rather than one count,
    # so that a pass which granted the wrong set cannot satisfy it.
    expected = {d.name for d in CORE_UNITS
                if d.wiring is None and d.tier is UnitTier.SUPPORTING}
    if set(outcome.granted) != expected:
        raise RuntimeError(
            f"granted {sorted(outcome.granted)}, expected {sorted(expected)}"
        )
    unwired = {d.name for d in CORE_UNITS if d.wiring is not None}
    if not unwired:
        raise RuntimeError(
            "no governed unit needs wiring, so the withholding below was not "
            "checked against anything"
        )
    for verdict in outcome.verdicts:
        if verdict.unit in unwired and not verdict.reason.startswith("wiring_absent"):
            raise RuntimeError(
                f"{verdict.unit} was withheld for {verdict.reason!r}, not for "
                "having nothing to serve"
            )
    edge_verdict = next(v for v in outcome.verdicts if v.unit == "azazel-edge-core.service")
    # A lease-bearing pass now reads the installed package (#198); the
    # harness installs none, so the package check itself must be what fails.
    if (edge_verdict.granted or not edge_verdict.reason.startswith("edge_not_ready:")
            or "package_present" not in edge_verdict.reason):
        raise RuntimeError("Edge Core must be withheld without an installed package")
    if outcome.edge_baseline_ready:
        raise RuntimeError(
            "edge-baseline-ready was claimed with no Edge Core established"
        )
    harness.manager = manager  # type: ignore[attr-defined]
    return (
        f"{len(outcome.granted)} supporting units granted; "
        f"{len(unwired)} withheld for having no provider or transport wired in this "
        "build; edge-baseline-ready correctly withheld"
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

    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager
    from azazel_nexus_runtime.watchdog import FenceStore, WatchdogService

    from azazel_nexus.audit import AuditLedger

    ticks = iter([0, 10, 20, 30])
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
    ledger = AuditLedger(harness.root / "var/lib/azazel/state/watchdog.jsonl")
    ledger.verify()
    entries = list(ledger)
    if len(entries) != 1:
        raise RuntimeError(f"expected one fence record, found {len(entries)}")
    event = entries[0].event
    expected = {
        "event_type": "watchdog.fenced",
        "unit": "azazel-auditd.service",
        "reason": "unhealthy",
        "previous_state": "in_service",
        "previous_reason": None,
        "state": "fenced",
    }
    if any(event.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"unexpected fence transition: {event}")
    service.probe("auditd", budget_ms=250, now=NOW, call=lambda: False)
    ledger.verify()
    if len(list(ledger)) != len(entries):
        raise RuntimeError("an identical observation appended another fence record")
    return "unhealthy fence reason and prior in_service state read from verified ledger; repeat deduplicated"


def _rollback(harness: Harness) -> str:
    from azazel_nexus_runtime.activated import ActivationDaemon
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager

    from azazel_nexus.activation import ActivationLease, UnitState
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.edge_package import installed_baseline_state

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


def _lite_matrix(harness: Harness) -> str:
    """Run the nine CORE + Lite configurations through the integration view.

    The assertions live in `tests/unit/test_core_lite_integration.py`; this
    stage exists so the matrix appears in the harness report alongside the
    install-to-status sequence, and so a run that could not execute it says
    so rather than leaving a silence a reader fills in.

    Deliberately not a subset of the unit test: it drives the *composed*
    path -- three features into one view -- and checks the two claims that
    must hold in all nine. If the composition raised, or a configuration
    claimed readiness, this stage fails and the report says which one.
    """

    from azazel_nexus.capability import CapabilityState
    from azazel_nexus.cognition import read_cognition
    from azazel_nexus.compatibility import TestedTupleSet
    from azazel_nexus.decoy import DecoyState, DecoyStatus, IsolationCheck, evaluate
    from azazel_nexus.integration import EdgePresence, build_view
    from azazel_nexus.lite_service import LiteReading, LiteState
    from azazel_nexus.resource_profile import ResourceProfile

    def reading(state):
        return LiteReading(state=state, reason=f"knowledge is {state.value}", generation=1)

    absent = evaluate(
        "decoy-a", catalogue=None, commissioning=None, isolation=IsolationCheck(passed=None)
    )
    exposed = DecoyStatus(decoy="decoy-a", state=DecoyState.EXPOSED, reason="exposed")
    held = DecoyStatus(decoy="decoy-a", state=DecoyState.QUARANTINED, reason="held")

    configurations = (
        ("knowledge only", reading(LiteState.AVAILABLE), absent),
        ("mio only", None, absent),
        ("deception only", None, exposed),
        ("all three", reading(LiteState.AVAILABLE), exposed),
        ("none present", reading(LiteState.UNAVAILABLE), absent),
        ("knowledge stale", reading(LiteState.STALE), absent),
        ("knowledge quarantined", reading(LiteState.QUARANTINED), absent),
        ("decoy quarantined", reading(LiteState.AVAILABLE), held),
        ("remote not permitted", reading(LiteState.AVAILABLE), absent),
    )

    cognition = read_cognition(
        [], profile=ResourceProfile.LITE, tested=TestedTupleSet(), host=None
    )
    composed = 0
    for name, knowledge, decoy in configurations:
        view = build_view(
            capability=CapabilityState.CORE,
            knowledge=knowledge,
            cognition=cognition,
            decoy=decoy,
            edge=EdgePresence.ABSENT,
        )
        if view.enforcement_capable or view.baseline_ready:
            raise RuntimeError(f"{name} claimed readiness with no Edge")
        if "Edge deterministic decisions" in view.continues:
            raise RuntimeError(f"{name} claimed Edge decisions continue with no Edge")
        if not view.continues:
            raise RuntimeError(f"{name} listed nothing that continues")
        composed += 1
    # Counted inside the loop, not taken from the table's length. A detail
    # line derived from what the stage *meant* to do rather than from what it
    # did is a stage that reports nine having composed none -- and the
    # mutation that made this a real check did exactly that.
    if composed != len(configurations):
        raise RuntimeError(
            f"{composed} of {len(configurations)} configurations were composed"
        )
    return (
        f"{composed} CORE + Lite configurations composed; none claimed "
        "enforcement or baseline readiness, and every one named what continues"
    )



def _synthetic_elf(architecture: str) -> bytes:
    """A 64-bit little-endian ELF executable header for `architecture`, not runnable.

    The Edge package checks read the CPU from the archived binary's ELF header
    (S-11); a stage that wrote any other payload would be refused before the
    check it means to exercise. `e_machine` from the System V ABI.
    """

    machine = {"x86_64": 62, "aarch64": 183}[architecture]
    return (b"\x7fELF\x02\x01\x01\x00" + bytes(8) + (3).to_bytes(2, "little")
            + machine.to_bytes(2, "little") + (1).to_bytes(4, "little") + bytes(40)
            + b"synthetic azazel-edge-core\n")


def _synthetic_edge_archive(binary: bytes) -> bytes:
    """The package archive as Edge's packager lays it out, around `binary`."""

    import gzip
    import io
    import tarfile

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in (("bin/azazel-edge-core", binary),
                           ("config/redirect_policy.yaml", b"redirect: none\n")):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755 if name.startswith("bin/") else 0o644
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def _edge_package(harness: Harness) -> str:
    """The five checks, each failed on its own, on packages written here (#44).

    Written and inspected rather than described: a stage that asserted the
    verifier's intentions would pass on a verifier that inspected nothing. Each
    row below breaks exactly one thing and expects exactly one word.
    """

    import hashlib
    import json

    from azazel_nexus.edge_package import PIN, Evidence, inspect
    from azazel_nexus.integration import EdgePresence

    root = harness.root / "edge-packages"
    payload = _synthetic_edge_archive(_synthetic_elf(PIN.architecture))
    good_digest = "sha256:" + hashlib.sha256(payload).hexdigest()

    def manifest(**overrides):
        document = {
            "contract": PIN.manifest_contract,
            "package": PIN.package,
            "version": PIN.version,
            "architecture": PIN.architecture,
            "artifact": PIN.artifact_name,
            "digest": good_digest,
            "signed": False,
            "health": {"contract": PIN.health_contract},
            "posture": {"observe_only": True, "enforcement": False},
        }
        document.update(overrides)
        return document

    def write(name, *, document=manifest(), artifact=payload):
        where = root / name
        where.mkdir(parents=True, exist_ok=True)
        if artifact is not None:
            (where / PIN.artifact_name).write_bytes(artifact)
        if document is not None:
            (where / PIN.manifest_name).write_text(json.dumps(document), encoding="utf-8")
        return where

    def health(status=None, version=None):
        report = {
            "contract": PIN.health_contract,
            "status": status or "healthy",
            "version": version or PIN.version,
        }
        from azazel_nexus.edge_package import HealthAnswer

        return lambda: HealthAnswer(exit_code=0, stdout=json.dumps(report))

    running = lambda: True  # noqa: E731

    cases = (
        ("absent", write("absent", document=None, artifact=None), EdgePresence.ABSENT, {}),
        ("corrupt", write("corrupt", artifact=None), EdgePresence.CORRUPT, {}),
        (
            "version mismatch",
            write("version", document=manifest(version="0.0.1")),
            EdgePresence.VERSION_MISMATCH,
            {"health": health(), "running": running},
        ),
        (
            "digest mismatch",
            write("digest", document=manifest(digest="sha256:" + "0" * 64)),
            EdgePresence.DIGEST_MISMATCH,
            {"health": health(), "running": running},
        ),
        (
            "unhealthy",
            write("unhealthy"),
            EdgePresence.UNHEALTHY,
            {"health": health(status="unhealthy"), "running": running},
        ),
        (
            "not running",
            write("stopped"),
            EdgePresence.NOT_RUNNING,
            {"health": health(), "running": lambda: False},
        ),
        (
            "verified ready",
            write("ready"),
            EdgePresence.VERIFIED_READY,
            {"health": health(), "running": running},
        ),
    )

    checked = 0
    for name, where, expected, probes in cases:
        inspection = inspect(where, **probes)
        if inspection.presence is not expected:
            raise RuntimeError(
                f"{name}: expected {expected.value}, read {inspection.presence.value}"
            )
        if inspection.ready is not (expected is EdgePresence.VERIFIED_READY):
            raise RuntimeError(f"{name}: ready disagreed with the displayed word")
        if not inspection.caveats:
            raise RuntimeError(f"{name}: a result carried no caveat")
        checked += 1

    # The default probes, which is the node this repository actually ships.
    shipped = inspect(root / "ready")
    if shipped.ready:
        raise RuntimeError(
            "a node with no health or running probe reached edge-baseline-ready"
        )
    if shipped.finding("health_endpoint_healthy").evidence is not Evidence.NOT_CHECKED:
        raise RuntimeError("an unrun health probe was reported as something other than not-checked")

    if checked != len(cases):
        raise RuntimeError(f"{checked} of {len(cases)} packages were inspected")
    return (
        f"{checked} packages inspected; each of the five checks failed on its "
        "own word, and the shipped node withheld readiness for want of a probe"
    )


def _loopback_decoys(harness: Harness) -> str:
    """Decoys that really bind, are really reached, and reach nothing (#69).

    Run against real sockets in the harness root. A stage that described the
    runtime's intentions would pass on a runtime that bound nothing, which is
    the state this issue exists to leave behind.
    """

    import socket

    from azazel_nexus_runtime.decoy_loopback import (
        LoopbackCatalogue,
        LoopbackDecoy,
        LoopbackRuntime,
        ResponderState,
    )

    from azazel_nexus.functional_readiness import LOOPBACK_ONLY, readiness_for

    generation = "sha256:" + "cd" * 32
    instants = iter(f"2026-09-21T01:00:{second:02d}Z" for second in range(60))
    catalogue = LoopbackCatalogue.of(
        [
            LoopbackDecoy(name="alpha", responder="ssh-banner"),
            LoopbackDecoy(name="bravo", responder="http-banner"),
        ]
    )
    runtime = LoopbackRuntime(
        harness.root / "decoys",
        catalogue=catalogue,
        generation_digest=generation,
        clock=lambda: next(instants),
    )
    try:
        listening = runtime.start()
        if listening != ("alpha", "bravo"):
            raise RuntimeError(f"expected both decoys listening, got {listening}")

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        try:
            client.connect(str(runtime.path_for("alpha")))
            client.sendall(b"password=hunter2")
            client.shutdown(socket.SHUT_WR)
            observation = runtime.serve_once("alpha")
            banner = client.recv(1024)
        finally:
            client.close()
        if observation is None:
            raise RuntimeError("a decoy was reached and nothing was observed")
        if banner != catalogue.entry("alpha").banner:
            raise RuntimeError("the decoy did not answer with its own responder")
        if observation.bytes_received != 16:
            raise RuntimeError(
                f"{observation.bytes_received} bytes observed, 16 were sent"
            )
        rendered = repr(observation) + repr(observation.as_event())
        if "hunter2" in rendered or "password" in rendered:
            raise RuntimeError("the observation kept what was sent to the decoy")

        # A crash takes one decoy and leaves the other.
        runtime.quarantine("alpha", "the responder fell over")
        if runtime.state("alpha") is not ResponderState.QUARANTINED:
            raise RuntimeError("a failed decoy was not quarantined")
        if runtime.listening() != ("bravo",):
            raise RuntimeError("a decoy failure took another decoy with it")
        if runtime.path_for("alpha").exists():
            raise RuntimeError("a quarantined decoy's socket was left in place")

        event = runtime.as_event()
        if event["externally_reachable"] or event["redirect_eligible"]:
            raise RuntimeError("the runtime claimed reach or redirect")
        readiness = readiness_for("deception_lite")
        if readiness.value != LOOPBACK_ONLY or readiness.functional:
            raise RuntimeError(
                "the display word does not match a runtime that reaches only "
                "this host"
            )
    finally:
        runtime.stop()

    return (
        "2 decoys bound on private Unix sockets; one was reached and observed "
        "without keeping what was sent, a crash quarantined it alone, and "
        "nothing claimed external reach or redirect"
    )


def _edge_probe(harness: Harness) -> str:
    """The probe writes, the library reads, and neither trusts the other (#72).

    Driven end to end against files: a package on disk, a probe run with a
    fake health command and a fake unit reader, the result written to a state
    file, and the library reading it back. The three ways a result supplies
    nothing are exercised here too, because each of them is a place a stale
    or mismatched answer could have been promoted.
    """

    import hashlib
    import json

    from azazel_nexus_runtime import edge_probed

    from azazel_nexus.edge_package import (
        PIN,
        Evidence,
        inspect,
        load_probe_result,
    )
    from azazel_nexus.integration import EdgePresence

    root = harness.root / "edge-core"
    (root / "bin").mkdir(parents=True, exist_ok=True)
    binary = _synthetic_elf(PIN.architecture)
    payload = _synthetic_edge_archive(binary)
    (root / PIN.artifact_name).write_bytes(payload)
    (root / "bin/azazel-edge-core").write_bytes(binary)
    manifest = {
        "contract": PIN.manifest_contract,
        "package": PIN.package,
        "version": PIN.version,
        "architecture": PIN.architecture,
        "artifact": PIN.artifact_name,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "signed": False,
        "health": {
            "contract": PIN.health_contract,
            "command": ["bin/azazel-edge-core", "--health"],
        },
        "posture": {"observe_only": True, "enforcement": False},
        "components": [
            {
                "path": "bin/azazel-edge-core",
                "digest": "sha256:" + hashlib.sha256(binary).hexdigest(),
                "size": len(binary),
            }
        ],
    }
    (root / PIN.manifest_name).write_text(json.dumps(manifest), encoding="utf-8")

    class _Completed:
        returncode = 0
        stdout = json.dumps(
            {"contract": PIN.health_contract, "status": "healthy", "version": PIN.version}
        )

    ran = []

    def runner(argv, cwd):
        # The descriptor is live only during this callback. Verify the fixed
        # arguments and the executable bytes here, not an installed pathname
        # that the probe deliberately no longer resolves at execution time.
        if (len(argv) != 2 or argv[1] != "--health" or cwd != root
                or not argv[0].startswith("/proc/self/fd/")
                or not argv[0].removeprefix("/proc/self/fd/").isdecimal()):
            raise RuntimeError(f"the probe supplied an unexpected health command: {argv}")
        if Path(argv[0]).read_bytes() != binary:
            raise RuntimeError("the probe's executable snapshot differs from the checked binary")
        ran.append(list(argv))
        return _Completed()

    def units(method, unit):
        return {"ActiveState": "active", "SubState": "running", "LoadState": "loaded"}

    # Probe contract v2 (#206 P5): the result names the boot it was observed
    # in, and a reader uses it only in that boot. A fixed id stands for this
    # harness's boot, another for the previous one.
    boot = "0f0e0d0c-0b0a-4908-8706-050403020100"
    previous_boot = "11111111-2222-4333-8444-555555555555"
    # The harness owns the package it wrote; on a node root owns it.
    owner = edge_probed.PACKAGE_OWNER_UID
    edge_probed.PACKAGE_OWNER_UID = os.geteuid()
    try:
        outcome = edge_probed.probe(
            root,
            clock=lambda: "2026-09-21T04:00:00Z",
            runner=runner,
            unit_reader=units,
            boot_id=boot,
        )
    finally:
        edge_probed.PACKAGE_OWNER_UID = owner
    if len(ran) != 1:
        raise RuntimeError(f"the probe supplied {len(ran)} health runs instead of one checked snapshot")

    state = harness.root / "run" / "edge-probe" / "edge-probe.json"
    edge_probed.write_result(outcome, state)
    # The harness plays azprobe: it wrote the file, so it is the writer the
    # reader is told to trust. An installed reader resolves the account.
    writer = os.geteuid()
    result = load_probe_result(state, owner_uid=writer)
    if result is None:
        raise RuntimeError("the state file the probe just wrote read back as absent")

    ready = inspect(root, probe=result, now="2026-09-21T04:01:00Z", boot_id=boot)
    if not ready.ready or ready.presence is not EdgePresence.VERIFIED_READY:
        raise RuntimeError(
            f"a verified package with a fresh probe read {ready.presence.value}"
        )

    # The three ways a result supplies nothing. Each must withhold, and none
    # may report a failure of the Edge Core.
    withheld = 0

    stale = inspect(root, probe=result, now="2026-09-21T04:10:00Z", boot_id=boot)
    if stale.ready:
        raise RuntimeError("a stale probe result was promoted to ready")
    if stale.finding("running").evidence is not Evidence.NOT_CHECKED:
        raise RuntimeError("a stale result was reported as a failure of Edge")
    withheld += 1

    # Inside its TTL, but from another boot: stale by the boot binding alone.
    rebooted = inspect(root, probe=result, now="2026-09-21T04:01:00Z",
                       boot_id=previous_boot)
    if rebooted.ready:
        raise RuntimeError("a probe result from another boot was promoted to ready")
    if rebooted.finding("running").evidence is not Evidence.NOT_CHECKED:
        raise RuntimeError("a result from another boot was reported as a failure of Edge")
    withheld += 1

    # A result about another package: the same file with the version changed,
    # written through the same writer so the shape is the one a probe emits.
    other = json.loads(state.read_text(encoding="utf-8"))
    other["package_version"] = "9.9.9"
    other_state = harness.root / "run" / "edge-probe-other.json"
    other_state.write_text(json.dumps(other), encoding="utf-8")
    mismatched_version = inspect(
        root, probe=load_probe_result(other_state, owner_uid=writer),
        now="2026-09-21T04:01:00Z", boot_id=boot,
    )
    if mismatched_version.ready:
        raise RuntimeError("a result about another version was promoted to ready")
    if mismatched_version.finding("health_endpoint_healthy").evidence is not Evidence.NOT_CHECKED:
        raise RuntimeError("a result about another version was read as a verdict")
    withheld += 1

    tampered = harness.root / "edge-tampered"
    (tampered / "bin").mkdir(parents=True, exist_ok=True)
    (tampered / PIN.artifact_name).write_bytes(b"swapped")
    (tampered / PIN.manifest_name).write_text(json.dumps(manifest), encoding="utf-8")
    mismatched = inspect(tampered, probe=result, now="2026-09-21T04:01:00Z",
                         boot_id=boot)
    if mismatched.presence is not EdgePresence.DIGEST_MISMATCH:
        raise RuntimeError("a tampered artifact with a passing probe was not a mismatch")
    if mismatched.ready:
        raise RuntimeError("a probe result made a tampered package ready")
    withheld += 1

    if withheld != 4:
        raise RuntimeError(f"{withheld} of 4 withholding cases were exercised")
    return (
        "the probe ran the command fixed in code, wrote a bounded result bound "
        "to its boot, and the library read it back to verified-ready; stale, "
        "other-boot, mismatched and tampered cases each withheld without "
        "reporting a failure"
    )


def _lite_import(harness: Harness) -> str:
    """Knowledge in through the inbox, and Edge unaffected by every outcome (#67).

    The producer's own pinned fixtures, driven end to end: enumerate the
    inbox, select by content id, verify, admit or quarantine, then serve. All
    six cases, in finite time, against real files.

    The two readable bundles are re-signed under a key made for this run and
    never written down: the producer's fixture key is published, and a
    commissioned anchor refuses it off a marked lab host (lab_keys). The
    content, expiry and the three broken archives are the producer's bytes.

    Edge readiness and action authority are read before and after each one
    and must be identical. Knowledge is advice; it does not move authority.
    """

    import shutil
    from pathlib import Path as _Path

    from azazel_nexus.edge_package import inspect as inspect_edge
    from azazel_nexus.lite_import import CommissionedLite, LiteImport

    contract = _Path(__file__).resolve().parents[1] / "contract" / "azazel-knowledge-lite"
    as_of = "2026-09-21T00:00:00Z"
    no_edge = harness.root / "no-edge-core"

    import io
    import tarfile

    from nacl.signing import SigningKey

    run_key = SigningKey.generate()
    key_id = "e2e-run-key"
    anchors_text = (f'threshold = 1\n[keys]\n"{key_id}" = '
                    f'"{run_key.verify_key.encode().hex()}"\n')

    def resigned(bundle: str) -> bytes:
        with tarfile.open(contract / bundle, "r:gz") as archive:
            members = {e.name: archive.extractfile(e).read() for e in archive if e.isfile()}
        signature = run_key.sign(members["manifest.json"]).signature.hex()
        members["manifest.sig"] = f"{key_id}:{signature}\n".encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for member, data in members.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return stream.getvalue()

    def edge_answer():
        answer = inspect_edge(no_edge)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    if baseline != (False, "absent", False):
        raise RuntimeError(f"the Edge baseline is {baseline}, not an absent Edge")

    cases = (
        ("valid", "lite.tar.gz", True, "available", "current", "available"),
        ("corrupt-signature", "negative/corrupt-signature.tar.gz", False, "quarantined", "absent", "absent"),
        ("corrupt-payload", "negative/corrupt-payload.tar.gz", False, "quarantined", "absent", "absent"),
        ("corrupt-truncated", "negative/corrupt-truncated.tar.gz", False, "quarantined", "absent", "absent"),
        ("expired", "negative/expired.tar.gz", True, "available", "stale", "available"),
        ("absent", None, False, "unavailable", "absent", "absent"),
    )

    _setup_snapshot(harness, "before-knowledge")
    checked = 0
    for name, bundle, admitted, overall, time_bound, static in cases:
        root = (harness.root / "var/lib/azazel/knowledge" if name == "valid"
                else harness.root / f"knowledge-lite-{name}")
        (root / "inbox").mkdir(parents=True, exist_ok=True)
        (root / "trust").mkdir(parents=True, exist_ok=True)
        (root / "trust" / "anchors.toml").write_text(anchors_text)
        if bundle is not None and name in ("valid", "expired"):
            (root / "inbox" / _Path(bundle).name).write_bytes(resigned(bundle))
        elif bundle is not None:
            shutil.copy(contract / bundle, root / "inbox" / _Path(bundle).name)

        transitions = []
        service = LiteImport(
            CommissionedLite(root=root),
            recorder=lambda transition, event: transitions.append(transition.value),
        )
        entries = service.list_inbox()
        if bundle is None:
            if entries:
                raise RuntimeError("the absent case found something in the inbox")
            reading = service.read(query_as_of=as_of)
            if transitions:
                raise RuntimeError("a node with no artifact wrote to the ledger")
        else:
            if len(entries) != 1:
                raise RuntimeError(f"{name}: {len(entries)} inbox entries, expected 1")
            outcome = service.import_entry(entries[0].entry_id, now=as_of)
            reading = outcome.reading
            if outcome.admitted is not admitted:
                raise RuntimeError(f"{name}: admitted={outcome.admitted}, expected {admitted}")

        if reading.overall != overall:
            raise RuntimeError(f"{name}: overall {reading.overall}, expected {overall}")
        if reading.time_bound.value != time_bound:
            raise RuntimeError(
                f"{name}: time-bound {reading.time_bound.value}, expected {time_bound}"
            )
        if reading.static_reference.value != static:
            raise RuntimeError(
                f"{name}: static reference {reading.static_reference.value}, expected {static}"
            )

        rows = list(service.serve(query_as_of=as_of))
        dated = [row for row in rows if "agg_next_expiry" in row]
        reference = [row for row in rows if "agg_next_expiry" not in row]
        if name == "valid" and not (dated and reference):
            raise RuntimeError("the valid bundle did not serve both kinds of claim")
        if name == "expired":
            if dated:
                raise RuntimeError("an expired indicator was served")
            if not reference:
                raise RuntimeError("the static reference was not served")
        if not admitted and rows:
            raise RuntimeError(f"{name}: a bundle that was not admitted served {len(rows)} rows")

        after = edge_answer()
        if after != baseline:
            raise RuntimeError(
                f"{name}: the Edge answer changed from {baseline} to {after}; "
                "Knowledge is advice and does not move authority"
            )
        checked += 1

    # The daemon and operator views use the same separate commissioned pin.
    from nacl.signing import SigningKey

    from azazel_nexus.lite_bundle import read_anchors
    from azazel_nexus.lite_trust import TrustStore
    from azazel_nexus.revocation_policy import (
        REVOCATION_SIGNING,
        RevocationPolicy,
        commission_policy,
    )

    trust = harness.root / "var/lib/azazel/lite-trust"
    (trust / "trust").mkdir(parents=True, exist_ok=True)
    (trust / "trust/anchors.toml").write_text(anchors_text)
    anchors = read_anchors(trust / "trust/anchors.toml")
    TrustStore(trust).pin([key.hex() for key in anchors.keys.values()],
                         commissioning_digest="sha256:" + "e" * 64,
                         pinned_at=NOW, actor=ACTOR)
    revoker = SigningKey.generate().verify_key.encode()
    commission_policy(
        trust, RevocationPolicy(keys={"fixture-revoker": revoker},
                                key_roles={"fixture-revoker": REVOCATION_SIGNING},
                                threshold=1, generation=1),
        commissioning_digest="sha256:" + "e" * 64,
        anchors_key_roles=anchors.key_roles, anchors_keys=anchors.keys,
    )
    _setup_snapshot(harness, "after-knowledge")
    if checked != len(cases):
        raise RuntimeError(f"{checked} of {len(cases)} cases were exercised")
    return (
        f"{checked} Knowledge Lite cases driven through the inbox; the valid "
        "bundle served both kinds of claim, the expired one withheld its "
        "indicators and still served reference material, three broken ones "
        "were quarantined and served nothing, and the Edge answer was "
        "identical throughout"
    )


def _core_reserve_path(harness: Harness) -> str:
    """The Core reserve input path, with no measurement on it (#68).

    `HG-05` is open: nobody has measured the Core reserve on target hardware,
    and this stage takes no measurement either. What it drives is the path a
    measurement would travel -- record, validation, reserve, admission gate --
    in the three states that matter, on the machine running this harness.

    The record it writes is **synthetic and says so**: its `harness_version`
    is not the real harness's, and this stage asserts that. A record that
    could be mistaken for a measurement is the one thing this must not leave
    behind.
    """

    import json
    from pathlib import Path as _Path

    from azazel_nexus_runtime.core_reserve_probe import HARNESS_VERSION

    from azazel_nexus.cognition import (
        AdmissionGate,
        ResourceEvidence,
        admit_local_model,
    )
    from azazel_nexus.compatibility import (
        ADMITTED_ARCHITECTURE,
        HostFacts,
        TestedTuple,
        TestedTupleSet,
    )
    from azazel_nexus.core_reserve import (
        MIN_SAMPLES,
        REQUIRED_SUBSYSTEMS,
        Provenance,
        Sample,
        build_record,
        load_reserve,
        record_as_document,
        reserve_from,
    )
    from azazel_nexus.resource_profile import ResourceProfile

    SYNTHETIC = "e2e-synthetic/0"
    if SYNTHETIC == HARNESS_VERSION:
        raise RuntimeError("the synthetic marker collided with the real harness's version")

    component = "sha256:" + "1" * 64
    digest = "sha256:" + "2" * 64
    host = HostFacts(
        os_abi="debian-13/linux-6.12",
        architecture=ADMITTED_ARCHITECTURE,
        cpu_features=frozenset({"avx2"}),
        fabric_version="v0.10.0",
        fabric_features=frozenset(),
        schema_features=frozenset(),
        profile=ResourceProfile.LITE,
        overlay_schema="3",
        security_epoch=4,
    )
    tested = TestedTupleSet.of(
        [
            TestedTuple(
                component_digest=component,
                model_role="embedding",
                adapter_digest=digest,
                renderer_digest=digest,
                toolchain_digest=digest,
                os_abi="debian-13/linux-6.12",
                architecture=ADMITTED_ARCHITECTURE,
                fabric_version="v0.10.0",
                profile=ResourceProfile.LITE,
                overlay_schema="3",
                security_epoch=4,
                max_rollback_version="0.9.0",
            )
        ]
    )
    # Ephemeral test evidence lives outside the shipped packages.
    import importlib.util
    from dataclasses import replace

    spec = importlib.util.spec_from_file_location("admission_test_evidence", ROOT / "tests/unit/admission_helpers.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)

    def evidenced(need=1000):
        provider = _reserve_provider(component, memory_need_mib=need)
        return replace(provider, evidence=helper.evidence(component=component, need=need))

    provider = evidenced()

    room = harness.root / "core-reserve"
    room.mkdir(parents=True, exist_ok=True)

    # 1. No record: every node in this build. The gate refuses for want of a
    #    measurement, and says so.
    absent = load_reserve(room / "core-reserve.json")
    if absent is not None:
        raise RuntimeError("a node with no record produced a reserve")
    unmeasured = admit_local_model(provider, host=host, tested=tested, resources=None)
    if unmeasured.failed_gate is not AdmissionGate.RESOURCE_TOPOLOGY:
        raise RuntimeError(f"with no reserve the gate was {unmeasured.failed_gate}")
    if "unmeasured" not in unmeasured.reason:
        raise RuntimeError("the refusal does not name the unmeasured reserve")

    samples = tuple(
        Sample(offset_seconds=i * 10, resident_mib=2000) for i in range(MIN_SAMPLES + 1)
    )
    from azazel_nexus.virtualization import SENSORS

    # core-reserve/4 (ADR-0003 R2): only a record that names the deployment
    # baseline's CPU and profile can yield a reserve; older versions are read
    # and refused. These values are this stage's, not an observation.
    common = {
        "profile": ResourceProfile.LITE,
        "host_digest": "hmac-sha256:" + "e" * 64,
        "harness_version": SYNTHETIC,
        "subsystems_active": REQUIRED_SUBSYSTEMS,
        "samples": samples,
        "boot_fingerprint": "hmac-sha256:" + "f" * 64,
        "run_sequence": 1,
        "build_commit": "0" * 40,
        "kernel_release": "e2e-synthetic",
        "virtualization_observations": dict.fromkeys(SENSORS, "clear"),
        "architecture": "amd64",
        "platform_profile_id": "debian-13-amd64-cp313",
    }

    # 2. A fixture record: refused for being one, and it reaches the disk
    #    first, so this is the reader and the validator and not a constructor.
    fixture_path = room / "fixture.json"
    fixture_path.write_text(
        json.dumps(record_as_document(build_record(provenance=Provenance.FIXTURE, **common))),
        encoding="utf-8",
    )
    if load_reserve(fixture_path) is not None:
        raise RuntimeError("a fixture record produced a reserve")

    # 3. A record shaped like a measurement: the reserve is derived, the
    #    resource gate decides, and the next gate refuses for having no
    #    implementation. One gate further, and no further.
    measured_path = room / "measured.json"
    record = build_record(provenance=Provenance.MEASURED, **common)
    measured_path.write_text(
        json.dumps(record_as_document(record)), encoding="utf-8"
    )
    reserve = load_reserve(measured_path)
    if reserve is None:
        raise RuntimeError("a record shaped like a measurement produced no reserve")
    if reserve.harness_version == HARNESS_VERSION:
        raise RuntimeError(
            "this stage's record claims the real harness produced it; it is "
            "synthetic and must never be mistakeable for a measurement"
        )
    if reserve.reserve_mib != 2000:
        raise RuntimeError(f"the reserve is {reserve.reserve_mib}, not the maximum observed")
    if reserve_from(record) != reserve:
        raise RuntimeError("the reserve differs between the file and the record")

    fits = admit_local_model(
        provider,
        host=host,
        tested=tested,
        resources=ResourceEvidence(reserve=reserve, envelope_mib=15000),
    )
    if fits.admitted or fits.failed_gate is not AdmissionGate.APPROVAL:
        raise RuntimeError(f"with a reserve the answer was {fits.failed_gate}, admitted={fits.admitted}")

    too_large = admit_local_model(
        evidenced(3000),
        host=host,
        tested=tested,
        resources=ResourceEvidence(reserve=reserve, envelope_mib=4500),
    )
    if too_large.failed_gate is not AdmissionGate.RESOURCE_TOPOLOGY:
        raise RuntimeError("an oversized provider was not refused by the resource gate")
    if reserve.fits(memory_need_mib=3000, envelope_mib=4500):
        raise RuntimeError("a provider larger than headroom fits the reserve")

    # And the node's own record path on this machine is still empty.
    from azazel_nexus.core_reserve import RESERVE_RECORD_PATH

    if RESERVE_RECORD_PATH.exists():
        raise RuntimeError(f"{RESERVE_RECORD_PATH} exists on this machine")

    return (
        "no measurement was taken: fixture reserve records refused, synthetic "
        "test-minted providers reached resource and approval gates. "
        "No provider was admitted"
    )


def _reserve_provider(component: str, memory_need_mib: int = 1000):
    from azazel_nexus.cognition import LocalModelProvider

    return LocalModelProvider(
        name="local-model",
        component_digest=component,
        declared_format="gguf",
        tokenizer_format="sentencepiece",
        runtime_version="1.4.0",
        quantization="q4_k_m",
        context_size=2048,
        memory_need_mib=memory_need_mib,
        evidence=None,
        role="embedding",
    )


def _cli(harness: Harness, arguments: list[str]) -> str:
    result = subprocess.run(
        [sys.executable, "-c",
         "from azazel_nexus.cli import main; raise SystemExit(main())", *arguments],
        env=harness.env, capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"operator CLI exited {result.returncode}: {result.stderr[:200]}")
    return result.stdout


def _setup_snapshot(harness: Harness, point: str) -> dict:
    document = json.loads(_cli(harness, ["setup", "--json"]))
    assert document["read_only"] is True
    assert document["hg05"] == "unmeasured"
    assert document["provider_admission"] == "blocked"
    steps = {step["name"]: step for step in document["steps"]}
    assert steps["provider-admission"]["status"] == "blocked"
    assert "unmeasured" in steps["provider-admission"]["reason"]
    if not hasattr(harness, "setup_snapshots"):
        harness.setup_snapshots = {}
    harness.setup_snapshots[point] = steps
    return steps


def _operator_setup(harness: Harness) -> str:
    snapshots = harness.setup_snapshots
    assert snapshots["before-install"]["installed-files"]["status"] == "needed"
    assert "missing:" in snapshots["before-install"]["installed-files"]["reason"]
    assert "entrypoints present" in snapshots["after-install"]["installed-files"]["reason"]
    assert snapshots["before-knowledge"]["knowledge-trust"]["status"] == "needed"
    after = _setup_snapshot(harness, "final")
    assert after["knowledge-trust"]["status"] == "done"
    assert after["knowledge-store"]["status"] == "done"
    return "read-only setup snapshots; entrypoint and Knowledge steps advanced; HG-05 unmeasured, provider admission blocked"


def _mio_entry(harness: Harness) -> str:
    from azazel_nexus.route_ledger import ROUTE_DIR, RouteChain
    from azazel_nexus.routing import Route

    absent = [harness.root / "var/lib/azazel/run" / leaf / f"{leaf}.sock"
              for leaf in ("mio", "remote")]
    assert all(not path.exists() for path in absent)
    with Daemon(harness, "mio_entryd", "mio-entry") as daemon:
        replies = [request(daemon.path, {"verb": "mio.route", "arguments": {
            "privacy_class": "P0-public", "deadline_ms": 1000,
        }}) for _ in range(2)]
    ledger = RouteChain(harness.root / ROUTE_DIR.lstrip("/"))
    ledger.verify()
    events = [entry.event for entry in ledger]
    for reply in replies:
        assert reply["ok"] is True
        assert reply["result"]["route"] == Route.DETERMINISTIC_HANDOFF.value
        assert reply["result"]["outcome"] == "refused"
        assert reply["result"]["reason"]
    assert {k: v for k, v in replies[0]["result"].items() if k != "ledger_seq"} == {
        k: v for k, v in replies[1]["result"].items() if k != "ledger_seq"}
    assert replies[1]["result"]["ledger_seq"] == len(events)
    selections = [e for e in events if e["event_type"] == "mio.route.selected"]
    terminals = [e for e in events if e["event_type"] == "mio.route.terminal"]
    assert len(selections) == len(terminals) == 2
    for reply, selected, terminal in zip(replies, selections, terminals, strict=True):
        assert selected["reason"] == reply["result"]["reason"]
        assert selected["route"] == terminal["route"] == reply["result"]["route"]
        assert terminal["outcome"] == reply["result"]["outcome"]
    availability = [e for e in events if e["event_type"] == "mio.entry.availability"]
    assert len(availability) == 2
    assert all(e["local"] == "local_unavailable" and e["remote"] == "remote_unavailable"
               and "unmeasured" in e["local_refusal"] for e in availability)
    assert not any(e["event_type"] in {"mio.local.readiness", "mio.remote.response"}
                   for e in events)
    assert all(not path.exists() for path in absent)
    return "two deterministic handoffs; reasons and route chain checked; absent local/remote sockets, no provider dispatch"


def _knowledge_status(harness: Harness) -> str:
    from datetime import UTC, datetime

    from azazel_nexus.lite_import import status_summary

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    root = harness.root / "var/lib/azazel/knowledge"
    expected = status_summary(root=root, trust_root=harness.root / "var/lib/azazel/lite-trust",
                              query_as_of=now)
    assert expected["state"] == "available"
    assert expected["generation"] is not None
    # The daemon keeps a wall-clock floor in its own state leaf, which the
    # installer gives to azknowledge (0700); it refuses a leaf another uid
    # owns. Run it as that service account, as the loop stage does.
    from tools.e2e_loop import prepare_accounts

    prepare_accounts(harness)
    with Daemon(harness, "knowledge_lited", "knowledge", account="azknowledge") as daemon:
        reply = request(daemon.path, {"verb": "knowledge.status", "arguments": {}})
    assert reply == {"ok": True, "result": expected}
    status = _cli(harness, ["--knowledge-lite", str(root), "--as-of", now, "status"])
    for key, label in (("state", "state"), ("reason_code", "reason"),
                       ("generation", "generation"), ("freshness", "freshness")):
        assert f"    {label}: {expected[key]}" in status
    setup = _setup_snapshot(harness, "daemon-knowledge")
    assert setup["knowledge-store"]["status"] == "done"
    assert f"reason: {expected['reason_code']}" in setup["knowledge-store"]["reason"]
    assert f"freshness: {expected['freshness']}" in setup["knowledge-store"]["reason"]
    return ("real Knowledge daemon (as azknowledge, with its clock floor) matches reconciled "
            "setup/status view with the offline import store and separate trust pin")


def _integration_broker(harness: Harness) -> str:
    """Signed test-only local assurance; deliberately no adapter transport."""
    from datetime import datetime, timedelta

    from nacl.signing import SigningKey

    from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole
    from azazel_nexus.integration_broker import (
        ADAPTER_MANIFEST_DOMAIN,
        AdapterCommissioning,
        Broker,
        CredentialRef,
        DispatchIntent,
        EdgeLease,
        ExposureChangeProposal,
        GateRefusal,
        ManagementFailsafe,
    )
    from azazel_nexus.integration_broker.routing import (
        EDGE_LEASE_DOMAIN,
        EDGE_LEASE_SCHEMA,
    )
    from azazel_nexus.knowledge_peer import canonical
    from azazel_nexus.sanitizer import SanitizerPolicy

    now = datetime.fromisoformat(NOW)
    expires = (now + timedelta(minutes=5)).isoformat()
    topology = CommissioningRecord(
        (ConfirmedRole((("serial", "fixture-nic"),), "deception_bridge", ACTOR, NOW),),
        ("hardware", "resource", "topology"), NOW)
    adapter_key, edge_key = SigningKey.generate(), SigningKey.generate()
    root = Path(harness.env["AZAZEL_ROOT"]) / "var/lib/azazel/integration-broker"
    broker = Broker(root, trusted_keys={"fixture-adapter": bytes(adapter_key.verify_key)}, topology=topology,
                    edge_keys={"fixture-edge": bytes(edge_key.verify_key)})
    fixture = root / "fixtures"
    fixture.mkdir(parents=True)
    for adapter, capability in (("fixture-telemetry", "telemetry_read"), ("fixture-exposure", "exposure_change")):
        document = {
            "schema": "azazel-nexus/adapter-manifest/1", "commissioning_digest": topology.digest(),
            "adapter_id": adapter, "kind": "ndr", "version": "1.0.0",
            "artifact_digest": "sha256:" + "b" * 64, "capability_set": [capability],
            "tenant": "fixture", "privacy_class": "P1-sanitized",
            "egress_allowlist": [{"address": "192.0.2.8", "port": 443}],
            "mtls_identity": "fixture-mtls", "credential_ref": "fixture-credential",
            "compatibility": ["azazel-nexus/1"],
        }
        payload = canonical(document)
        signed = adapter_key.sign(ADAPTER_MANIFEST_DOMAIN + payload).signature + payload
        manifest_file = fixture / (adapter + ".signed")
        manifest_file.write_bytes(signed)
        scope = AdapterCommissioning(
            adapter, None, "/etc/azazel/credentials/" + adapter,
            {document["artifact_digest"]: "/opt/azazel/adapters/" + adapter},
            CredentialRef(adapter, "fixture-credential", now + timedelta(hours=1)), now)
        unit = broker.admit(manifest_file.read_bytes(), commissioning=scope, now=NOW)
        assert "IPAddressDeny=any" in unit and "port 443" in unit
    policy = SanitizerPolicy.from_mapping({
        "version": "fixture-v1", "remote_default": "deny",
        "classes": {"P1-sanitized": {"remote": "allow", "fields": ["text"]}},
        "redactions": ["secret"], "limits": {"max_bytes": 4096}})
    record = broker.route("fixture-telemetry", {"text": "fixture observation", "secret": "discard"},
                          observed_at=NOW, expires_at=expires, now=NOW, policy=policy,
                          mission="fixture", alias_key=b"fixture-test-key")
    assert record.destination == "knowledge" and b"discard" not in record.frame
    assert broker.status_level(now=NOW) == "LITE"
    proposal = ExposureChangeProposal("fixture-exposure", b'{"fixture":"opaque data"}')
    context = {"failsafe": ManagementFailsafe(topology.digest(), "mgmt", "mgmt", NOW, True),
               "dry_run": True, "human_confirmed": True, "now": NOW}
    assert isinstance(broker.gate(proposal, edge_lease=None, **context), GateRefusal)
    payload = canonical({"schema": EDGE_LEASE_SCHEMA, "adapter_id": proposal.adapter_id,
                         "lease_id": "fixture-lease",
                         "manifest_digest": broker.status(now=NOW)["adapters"][0]["manifest_digest"],
                         "proposal_digest": proposal.digest, "commissioning_digest": topology.digest(),
                         "issued_at": NOW, "expires_at": expires})
    lease = EdgeLease(edge_key.sign(EDGE_LEASE_DOMAIN + payload).signature + payload)
    intent = broker.gate(proposal, edge_lease=lease, **context)
    assert isinstance(intent, DispatchIntent)
    assert broker.deliver(intent, now=NOW).reason == "transport unavailable: Fabric#25"
    broker.withdraw_all(reason="fixture_complete", now=NOW)
    assert broker.status_level(now=NOW) == "CORE"
    assert all(row["state"] == "disabled" for row in broker.status(now=NOW)["adapters"])
    broker.ledger.verify()
    return "signed telemetry admission, sanitized routing, lease-gated intent, transport refusal, withdrawal; audit verified; HIL not covered"


def _integrated_loop(harness: Harness) -> str:
    from tools.e2e_loop import integrated_loop

    return integrated_loop(harness)
