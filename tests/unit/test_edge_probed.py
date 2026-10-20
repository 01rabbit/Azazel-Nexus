"""`az-edge-probed`, and the narrowness of the one exemption it holds (#72).

This is the only module in the runtime distribution allowed to start a
process. `test_runtime_activated.py` grants that exemption by name and
asserts the module still needs it; the rules that apply *inside* it are here.

Everything the probe touches is fixed in code. There is no argument, no
environment variable and no file by which a caller can change the package
path, the health command, the unit read, or where the result is written --
and the tests below drive it against real files rather than describing it.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from azazel_nexus.edge_package import (
    EDGE_PACKAGE_ROOT,
    EDGE_UNIT,
    HEALTH_ARGV,
    PIN,
    PROBE_CONTRACT,
    PROBE_STATE_PATH,
    EdgePackageRefused,
    Evidence,
    parse_probe_result,
)
from azazel_nexus_runtime import edge_probed
from azazel_nexus_runtime.systemd_bus import (
    EdgeUnitStateReader,
    SystemdBusSession,
    _unit_object_path,
)
from azazel_nexus_runtime.units import UnitOperationFailed

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "edge_probed.py"

HEALTHY = json.dumps(
    {"contract": PIN.health_contract, "status": "healthy", "version": PIN.version}
)

BOOT = "0f0e0d0c-0b0a-4908-8706-050403020100"


class _Completed:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


def _clock(first="2026-09-21T03:00:00Z"):
    return lambda: first


def _package(tmp_path, *, payload=b"edge-core-payload", binary=b"#!/bin/sh\n", **overrides):
    """A package on disk: manifest, archive, and the unpacked binary."""

    root = tmp_path / "edge"
    (root / "bin").mkdir(parents=True, exist_ok=True)
    (root / PIN.artifact_name).write_bytes(payload)
    (root / HEALTH_ARGV[0]).write_bytes(binary)
    manifest = {
        "contract": PIN.manifest_contract,
        "package": PIN.package,
        "version": PIN.version,
        "architecture": PIN.architecture,
        "artifact": PIN.artifact_name,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "signed": False,
        "health": {"contract": PIN.health_contract, "command": list(HEALTH_ARGV)},
        "posture": {"observe_only": True, "enforcement": False},
        "components": [
            {
                "path": HEALTH_ARGV[0],
                "digest": "sha256:" + hashlib.sha256(binary).hexdigest(),
                "size": len(binary),
            }
        ],
    }
    manifest.update(overrides)
    (root / PIN.manifest_name).write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _runner(stdout=HEALTHY, returncode=0, log=None):
    def run(argv, cwd):
        if log is not None:
            log.append((list(argv), cwd))
        return _Completed(returncode, stdout)

    return run


def _units(active="active", sub="running", load="loaded", log=None):
    def read(method, unit):
        if log is not None:
            log.append((method, unit))
        return {"ActiveState": active, "SubState": sub, "LoadState": load}

    return read


# -- what it runs, and what it will not take from anyone -------------------


def test_it_runs_the_command_fixed_in_code(tmp_path):
    log = []
    root = _package(tmp_path)
    edge_probed.probe(root, clock=_clock(), runner=_runner(log=log), unit_reader=_units())
    argv, cwd = log[0]
    assert argv == [str(root / HEALTH_ARGV[0]), *HEALTH_ARGV[1:]]
    assert cwd == root


def test_a_manifest_declaring_another_command_is_not_obeyed(tmp_path):
    """A manifest is the file an adversary who can reach the package rewrites.

    Agreement with it is a verification. Taking the command from it would be
    executing something supplied as data.
    """

    log = []
    root = _package(tmp_path, health={"contract": PIN.health_contract, "command": ["/bin/sh", "-c", "id"]})
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(log=log), unit_reader=_units())
    assert log == [], "the probe ran something a manifest named"
    assert outcome.health is Evidence.NOT_CHECKED
    assert "supplied as data" in outcome.health_reason


def test_main_takes_nothing_that_could_redirect_it():
    """No path, no unit, no command, no argument but `--print`."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "main")
    flags = [
        node.args[0].value
        for node in ast.walk(main)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    ]
    assert flags == ["--print"]


def test_main_probes_the_fixed_root(tmp_path, monkeypatch):
    """It passes `probe()` the read-only reader and nothing else, so every
    other default -- root, runner, TTL -- is what is used (#195)."""

    seen = {}

    def fake_probe(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return edge_probed.ProbeOutcome(
            observed_at="2026-09-21T03:00:00Z",
            package_version=PIN.version,
            package_digest="sha256:" + "0" * 64,
            health=Evidence.NOT_CHECKED,
            health_reason="not run",
            running=Evidence.NOT_CHECKED,
            running_reason="not read",
        )

    monkeypatch.setattr(edge_probed, "probe", fake_probe)
    monkeypatch.setattr(edge_probed, "write_result", lambda outcome: tmp_path / "x")
    monkeypatch.setattr(edge_probed, "read_current_boot_id", lambda: BOOT)
    assert edge_probed.main([]) == 0
    assert seen["args"] == ()
    assert list(seen["kwargs"]) == ["unit_reader", "boot_id"]
    assert isinstance(seen["kwargs"]["unit_reader"], EdgeUnitStateReader)
    assert seen["kwargs"]["boot_id"] == BOOT


def test_main_reads_the_boot_id_from_the_fixed_path_only():
    """`read_current_boot_id()` with no argument: the kernel's path, nothing else."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "main")
    calls = [
        node for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "read_current_boot_id"
    ]
    assert len(calls) == 1
    assert calls[0].args == [] and calls[0].keywords == []


def test_main_with_an_unreadable_boot_id_probes_nothing_and_writes_nothing(
    tmp_path, monkeypatch, capsys,
):
    """Contract v2: a result that cannot name its boot is never written."""

    def unreadable():
        raise EdgePackageRefused("the boot id could not be read: denied")

    def must_not_run(*args, **kwargs):
        raise AssertionError("probed although the boot id was unreadable")

    monkeypatch.setattr(edge_probed, "read_current_boot_id", unreadable)
    monkeypatch.setattr(edge_probed, "probe", must_not_run)
    monkeypatch.setattr(edge_probed, "write_result", must_not_run)
    assert edge_probed.main([]) == 2
    assert "boot's id could not be read" in capsys.readouterr().err


# -- main reads running over the fixed, read-only system bus (#195) --------


class _Variant:
    def __init__(self, value, signature="s"):
        self.value = value
        self.signature = signature


class _ScriptedBus:
    """A system bus that answers the Edge unit's GetUnit and state reads."""

    def __init__(self, state=None):
        self.state = state
        self.messages = []
        self.disconnected = False

    async def call(self, message):
        from types import SimpleNamespace

        self.messages.append(message)
        if message.member == "GetUnit":
            if self.state is None:
                return SimpleNamespace(
                    message_type=3, error_name="org.freedesktop.systemd1.NoSuchUnit",
                    signature="s", body=["no unit"],
                )
            return SimpleNamespace(
                message_type=1, signature="o", body=[_unit_object_path(EDGE_UNIT)]
            )
        return SimpleNamespace(
            message_type=1, signature="v", body=[_Variant(self.state[message.body[1]])]
        )

    def disconnect(self):
        self.disconnected = True


def _session(bus):
    import asyncio
    from types import SimpleNamespace

    class Loop:
        def run_until_complete(self, awaitable):
            return asyncio.run(awaitable)

        def is_closed(self):
            return True

        def close(self):
            pass

    return SystemdBusSession(
        bus=bus, loop=Loop(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **values: SimpleNamespace(**values),
    )


def _main_against(tmp_path, monkeypatch, connect):
    """Run `main` for real except for the package root, runner and bus."""

    root = _package(tmp_path)
    real_probe = edge_probed.probe
    monkeypatch.setattr(
        edge_probed, "probe",
        lambda **kwargs: real_probe(root, clock=_clock(), runner=_runner(), **kwargs),
    )
    monkeypatch.setattr(SystemdBusSession, "connect", classmethod(lambda cls: connect()))
    monkeypatch.setattr(edge_probed, "read_current_boot_id", lambda: BOOT)
    written = {}
    monkeypatch.setattr(
        edge_probed, "write_result",
        lambda outcome: written.setdefault("outcome", outcome),
    )
    assert edge_probed.main([]) == 0
    assert written["outcome"].boot_id == BOOT
    return written["outcome"]


def test_main_reads_running_over_the_bus_and_closes_it(tmp_path, monkeypatch):
    bus = _ScriptedBus({"LoadState": "loaded", "ActiveState": "active", "SubState": "running"})
    outcome = _main_against(tmp_path, monkeypatch, lambda: _session(bus))
    assert outcome.health is Evidence.PASSED
    assert outcome.running is Evidence.PASSED, outcome.running_reason
    assert bus.disconnected is True
    assert [(m.member, m.body) for m in bus.messages] == [
        ("GetUnit", [EDGE_UNIT]),
        ("Get", ["org.freedesktop.systemd1.Unit", "LoadState"]),
        ("Get", ["org.freedesktop.systemd1.Unit", "ActiveState"]),
        ("Get", ["org.freedesktop.systemd1.Unit", "SubState"]),
    ]


def test_main_reports_an_inactive_unit_as_failed(tmp_path, monkeypatch):
    bus = _ScriptedBus({"LoadState": "masked", "ActiveState": "inactive", "SubState": "dead"})
    outcome = _main_against(tmp_path, monkeypatch, lambda: _session(bus))
    assert outcome.running is Evidence.FAILED
    assert "not running" in outcome.running_reason


def test_main_reports_no_unit_object_as_failed(tmp_path, monkeypatch):
    """`GetUnit` never loads a unit: NoSuchUnit means nothing is running it."""

    outcome = _main_against(tmp_path, monkeypatch, lambda: _session(_ScriptedBus(None)))
    assert outcome.running is Evidence.FAILED
    assert "no unit object" in outcome.running_reason


def test_main_without_a_bus_is_not_checked_and_health_still_runs(tmp_path, monkeypatch):
    """A container, a host with no systemd, a refusal: nobody looked."""

    def refuse():
        raise UnitOperationFailed("could not connect to the system D-Bus service manager")

    outcome = _main_against(tmp_path, monkeypatch, refuse)
    assert outcome.health is Evidence.PASSED
    assert outcome.running is Evidence.NOT_CHECKED
    assert "could not connect" in outcome.running_reason


def test_main_with_an_unreadable_bus_answer_is_not_checked(tmp_path, monkeypatch):
    bus = _ScriptedBus({"LoadState": "loaded", "ActiveState": "running?", "SubState": "x"})
    outcome = _main_against(tmp_path, monkeypatch, lambda: _session(bus))
    assert outcome.running is Evidence.NOT_CHECKED
    assert bus.disconnected is True


def test_the_probe_imports_only_the_read_only_view_of_the_bus():
    """Not the session, not the controller's calls: the one reader."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {
        (node.module, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and "systemd" in node.module
        for alias in node.names
    }
    assert imported == {("systemd_bus", "EdgeUnitStateReader")}


def test_the_only_spawn_uses_no_shell_a_fixed_environment_and_a_deadline():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    spawns = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and getattr(node.func.value, "id", "") == "subprocess"
    ]
    assert len(spawns) == 1, f"{len(spawns)} spawns; the exemption is for one"
    keywords = {kw.arg for kw in spawns[0].keywords}
    assert "shell" not in keywords
    assert {"timeout", "env"} <= keywords


def _code_strings(module: Path) -> set[str]:
    """Every string literal the module *evaluates*, docstrings excluded.

    The module's own prose names `StartUnit` in order to explain that it is
    absent, so a plain text search reads the explanation as the offence. What
    matters is whether a verb can be sent, and only a literal in the code can
    be.
    """

    tree = ast.parse(module.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    }


def test_no_systemd_verb_but_reading_can_be_sent():
    """`StartUnit` and its siblings are absent from the table, not by habit."""

    literals = _code_strings(MODULE)
    for verb in ("StartUnit", "StopUnit", "RestartUnit", "EnableUnitFiles", "MaskUnitFiles"):
        assert verb not in literals
    assert "GetUnitProperties" in literals, "a vacuous scan: no method is named at all"
    assert edge_probed.READ_ONLY_METHODS == ("GetUnit", "GetUnitProperties")


# -- it verifies before it runs --------------------------------------------


def test_an_absent_package_runs_nothing(tmp_path):
    log = []
    outcome = edge_probed.probe(
        tmp_path / "nothing", clock=_clock(), runner=_runner(log=log), unit_reader=_units()
    )
    assert log == []
    assert outcome.health is Evidence.NOT_CHECKED
    assert outcome.running is Evidence.NOT_CHECKED


def test_a_digest_mismatch_runs_nothing(tmp_path):
    """Running the payload anyway would be acting on the finding here."""

    log = []
    root = _package(tmp_path)
    (root / PIN.artifact_name).write_bytes(b"swapped")
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(log=log), unit_reader=_units())
    assert log == []
    assert outcome.health is Evidence.NOT_CHECKED
    assert "does not match the digest" in outcome.health_reason


def test_a_binary_that_is_not_the_one_the_manifest_records_runs_nothing(tmp_path):
    """An intact archive says nothing about the file next to it that runs."""

    log = []
    root = _package(tmp_path)
    (root / HEALTH_ARGV[0]).write_bytes(b"#!/bin/sh\nid\n")
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(log=log), unit_reader=_units())
    assert log == []
    assert outcome.health is Evidence.NOT_CHECKED
    assert "actually run" in outcome.health_reason


def test_an_unpacked_binary_that_is_absent_is_not_checked(tmp_path):
    root = _package(tmp_path)
    (root / HEALTH_ARGV[0]).unlink()
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(), unit_reader=_units())
    assert outcome.health is Evidence.NOT_CHECKED
    assert "not unpacked" in outcome.health_reason


def test_the_wrong_version_runs_nothing(tmp_path):
    log = []
    root = _package(tmp_path, version="9.9.9")
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(log=log), unit_reader=_units())
    assert log == []
    assert outcome.health is Evidence.NOT_CHECKED


def test_the_running_state_is_still_read_when_health_could_not_be(tmp_path):
    """They are separate findings, so one being unavailable is not both."""

    root = _package(tmp_path)
    (root / HEALTH_ARGV[0]).unlink()
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(), unit_reader=_units())
    assert outcome.health is Evidence.NOT_CHECKED
    assert outcome.running is Evidence.PASSED


# -- the health contract, all four conditions ------------------------------


def test_a_healthy_report_passes(tmp_path):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units(),
        boot_id=BOOT,
    )
    assert outcome.health is Evidence.PASSED
    assert outcome.health_security is False


@pytest.mark.parametrize(
    "stdout, returncode, fragment",
    [
        (HEALTHY, 3, "exited 3"),
        ("not json", 0, "not JSON"),
        ("[]", 0, "not an object"),
        (json.dumps({"contract": "x", "status": "healthy", "version": PIN.version}), 0, "declares contract"),
        (json.dumps({"contract": PIN.health_contract, "status": "unhealthy", "version": PIN.version}), 0, "status="),
    ],
)
def test_each_health_condition_fails_on_its_own(tmp_path, stdout, returncode, fragment):
    outcome = edge_probed.probe(
        _package(tmp_path),
        clock=_clock(),
        runner=_runner(stdout=stdout, returncode=returncode),
        unit_reader=_units(),
    )
    assert outcome.health is Evidence.FAILED
    assert fragment in outcome.health_reason


def test_a_healthy_report_from_another_version_is_a_security_finding(tmp_path):
    stdout = json.dumps(
        {"contract": PIN.health_contract, "status": "healthy", "version": "9.9.9"}
    )
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(stdout=stdout), unit_reader=_units()
    )
    assert outcome.health is Evidence.FAILED
    assert outcome.health_security is True


def test_a_health_command_that_cannot_be_run_is_not_checked(tmp_path):
    def explode(argv, cwd):
        raise OSError("no such file")

    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=explode, unit_reader=_units()
    )
    assert outcome.health is Evidence.NOT_CHECKED
    assert "nobody looked" in outcome.health_reason


# -- running state ---------------------------------------------------------


def test_the_unit_is_read_by_a_typed_method_and_a_fixed_name(tmp_path):
    log = []
    edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units(log=log)
    )
    assert log == [("GetUnitProperties", EDGE_UNIT)]


def test_no_service_manager_is_not_checked_rather_than_down(tmp_path):
    """A host with no systemd is not a host whose Edge Core is down."""

    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=edge_probed.no_unit_reader
    )
    assert outcome.running is Evidence.NOT_CHECKED
    assert "Nobody looked" in outcome.running_reason


def test_a_reader_that_raises_is_not_checked(tmp_path):
    def explode(method, unit):
        raise PermissionError("denied")

    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=explode
    )
    assert outcome.running is Evidence.NOT_CHECKED
    assert "nobody looked" in outcome.running_reason


@pytest.mark.parametrize(
    "active, sub, load, evidence",
    [
        ("active", "running", "loaded", Evidence.PASSED),
        ("inactive", "dead", "loaded", Evidence.FAILED),
        ("failed", "failed", "loaded", Evidence.FAILED),
        ("active", "exited", "loaded", Evidence.FAILED),
        ("inactive", "dead", "not-found", Evidence.FAILED),
    ],
)
def test_the_unit_state_maps_to_one_verdict(tmp_path, active, sub, load, evidence):
    outcome = edge_probed.probe(
        _package(tmp_path),
        clock=_clock(),
        runner=_runner(),
        unit_reader=_units(active=active, sub=sub, load=load),
    )
    assert outcome.running is evidence


def test_an_answer_this_node_cannot_read_is_not_checked(tmp_path):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=lambda m, u: "active"
    )
    assert outcome.running is Evidence.NOT_CHECKED


# -- the result ------------------------------------------------------------


def test_the_result_parses_as_what_the_reader_expects(tmp_path):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units(),
        boot_id=BOOT,
    )
    parsed = parse_probe_result(json.dumps(outcome.as_document()))
    assert parsed.contract == PROBE_CONTRACT == "azazel-nexus/edge-probe/v2"
    assert parsed.boot_id == BOOT
    assert parsed.from_boot(BOOT)
    assert parsed.health is Evidence.PASSED
    assert parsed.running is Evidence.PASSED
    assert parsed.package_version == PIN.version


def test_the_result_names_the_package_it_observed(tmp_path):
    """So a reader can tell whether it is about the package they are looking at."""

    root = _package(tmp_path, payload=b"a-particular-build")
    outcome = edge_probed.probe(root, clock=_clock(), runner=_runner(), unit_reader=_units())
    expected = "sha256:" + hashlib.sha256(b"a-particular-build").hexdigest()
    assert outcome.package_digest == expected


def test_the_result_is_written_atomically_and_leaves_no_debris(tmp_path):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units(),
        boot_id=BOOT,
    )
    target = tmp_path / "state" / "edge-probe.json"
    edge_probed.write_result(outcome, target)
    assert parse_probe_result(target.read_text(encoding="utf-8")).health is Evidence.PASSED
    assert sorted(p.name for p in target.parent.iterdir()) == ["edge-probe.json"]


def test_a_failed_write_leaves_no_partial_file(tmp_path, monkeypatch):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units(),
        boot_id=BOOT,
    )
    target = tmp_path / "state" / "edge-probe.json"
    target.parent.mkdir(parents=True)

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(edge_probed.os, "replace", explode)
    with pytest.raises(OSError):
        edge_probed.write_result(outcome, target)
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize("boot_id", ["", "not-a-boot", BOOT.upper()])
def test_an_outcome_naming_no_boot_is_never_written(tmp_path, boot_id):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units(),
        boot_id=boot_id,
    )
    target = tmp_path / "state" / "edge-probe.json"
    with pytest.raises(ValueError, match="names no boot"):
        edge_probed.write_result(outcome, target)
    assert not target.parent.exists()


def test_every_outcome_shape_carries_the_boot(tmp_path):
    """Absent package, refused command and a full run all record the boot."""

    absent = edge_probed.probe(tmp_path / "nothing", clock=_clock(), boot_id=BOOT)
    full = edge_probed.probe(_package(tmp_path), clock=_clock(), runner=_runner(),
                             unit_reader=_units(), boot_id=BOOT)
    for outcome in (absent, full):
        assert outcome.as_document()["boot_id"] == BOOT
        assert parse_probe_result(json.dumps(outcome.as_document())).boot_id == BOOT


def test_the_defaults_are_the_fixed_locations():
    assert edge_probed.probe.__defaults__[0] == EDGE_PACKAGE_ROOT
    assert PROBE_STATE_PATH == Path("/var/lib/azazel/run/edge-probe/edge-probe.json")
