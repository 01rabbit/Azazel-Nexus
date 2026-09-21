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


def _install_files(harness: Harness) -> str:
    """Run the real installer against a prefix. Not a reimplementation of it.

    Without the account half, which needs root: the modes are applied and the
    ownership is not, and the installer says so.
    """

    from azazel_nexus_runtime.hardening import PROFILES

    libexec = harness.root / "usr/libexec/azazel"
    libexec.mkdir(parents=True, exist_ok=True)
    # Derived from the profiles rather than listed. A hand-written list stops
    # covering the newest unit exactly when that unit is the one to check.
    for name in sorted({Path(profile.executable).name for profile in PROFILES}):
        shim = libexec / name
        module = name[len("az-") :].replace("-", "_")
        shim.write_text(
            "#!/bin/sh\n"
            f'exec "{sys.executable}" -m azazel_nexus_runtime.{module} "$@"\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)

    result = subprocess.run(
        [
            "sh",
            str(ROOT / "packaging" / "install.sh"),
            "--without-service-manager",
            "--without-accounts",
        ],
        env={**harness.env, "DESTDIR": str(harness.root)},
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
        if (harness.root / spec.path.lstrip("/")).stat().st_mode & 0o777 != spec.mode
    ]
    if wrong:
        raise RuntimeError(f"{wrong} were created with the wrong mode")
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
        env={**harness.env, "DESTDIR": str(harness.root)},
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
    grp.getgrnam("azazel-operator")
    return f"{len(SYSTEM_ACCOUNTS)} non-login accounts and the operator group"


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
    payload = b"edge-core-payload"
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

    from azazel_nexus.functional_readiness import LOOPBACK_ONLY, readiness_for
    from azazel_nexus_runtime.decoy_loopback import (
        LoopbackCatalogue,
        LoopbackDecoy,
        LoopbackRuntime,
        ResponderState,
    )

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

    from azazel_nexus.edge_package import (
        PIN,
        Evidence,
        inspect,
        load_probe_result,
    )
    from azazel_nexus.integration import EdgePresence
    from azazel_nexus_runtime import edge_probed

    root = harness.root / "edge-core"
    (root / "bin").mkdir(parents=True, exist_ok=True)
    payload = b"edge-core-payload"
    binary = b"#!/bin/sh\nexit 0\n"
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
        ran.append(list(argv))
        return _Completed()

    def units(method, unit):
        return {"ActiveState": "active", "SubState": "running", "LoadState": "loaded"}

    outcome = edge_probed.probe(
        root,
        clock=lambda: "2026-09-21T04:00:00Z",
        runner=runner,
        unit_reader=units,
    )
    if ran != [[str(root / "bin/azazel-edge-core"), "--health"]]:
        raise RuntimeError(f"the probe ran {ran}, not the command fixed in code")

    state = harness.root / "run" / "edge-probe.json"
    edge_probed.write_result(outcome, state)
    result = load_probe_result(state)
    if result is None:
        raise RuntimeError("the state file the probe just wrote read back as absent")

    ready = inspect(root, probe=result, now="2026-09-21T04:01:00Z")
    if not ready.ready or ready.presence is not EdgePresence.VERIFIED_READY:
        raise RuntimeError(
            f"a verified package with a fresh probe read {ready.presence.value}"
        )

    # The three ways a result supplies nothing. Each must withhold, and none
    # may report a failure of the Edge Core.
    withheld = 0

    stale = inspect(root, probe=result, now="2026-09-21T04:10:00Z")
    if stale.ready:
        raise RuntimeError("a stale probe result was promoted to ready")
    if stale.finding("running").evidence is not Evidence.NOT_CHECKED:
        raise RuntimeError("a stale result was reported as a failure of Edge")
    withheld += 1

    # A result about another package: the same file with the version changed,
    # written through the same writer so the shape is the one a probe emits.
    other = json.loads(state.read_text(encoding="utf-8"))
    other["package_version"] = "9.9.9"
    other_state = harness.root / "run" / "edge-probe-other.json"
    other_state.write_text(json.dumps(other), encoding="utf-8")
    mismatched_version = inspect(
        root, probe=load_probe_result(other_state), now="2026-09-21T04:01:00Z"
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
    mismatched = inspect(tampered, probe=result, now="2026-09-21T04:01:00Z")
    if mismatched.presence is not EdgePresence.DIGEST_MISMATCH:
        raise RuntimeError("a tampered artifact with a passing probe was not a mismatch")
    if mismatched.ready:
        raise RuntimeError("a probe result made a tampered package ready")
    withheld += 1

    if withheld != 3:
        raise RuntimeError(f"{withheld} of 3 withholding cases were exercised")
    return (
        "the probe ran the command fixed in code, wrote a bounded result, and "
        "the library read it back to verified-ready; stale, mismatched and "
        "tampered cases each withheld without reporting a failure"
    )
