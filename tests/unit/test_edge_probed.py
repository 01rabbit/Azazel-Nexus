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
    Evidence,
    parse_probe_result,
)
from azazel_nexus_runtime import edge_probed

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "edge_probed.py"

HEALTHY = json.dumps(
    {"contract": PIN.health_contract, "status": "healthy", "version": PIN.version}
)


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
    """It calls `probe()` with no argument, so the default is what is used."""

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
    assert edge_probed.main([]) == 0
    assert seen == {"args": (), "kwargs": {}}


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
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units()
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
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units()
    )
    parsed = parse_probe_result(json.dumps(outcome.as_document()))
    assert parsed.contract == PROBE_CONTRACT
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
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units()
    )
    target = tmp_path / "state" / "edge-probe.json"
    edge_probed.write_result(outcome, target)
    assert parse_probe_result(target.read_text(encoding="utf-8")).health is Evidence.PASSED
    assert sorted(p.name for p in target.parent.iterdir()) == ["edge-probe.json"]


def test_a_failed_write_leaves_no_partial_file(tmp_path, monkeypatch):
    outcome = edge_probed.probe(
        _package(tmp_path), clock=_clock(), runner=_runner(), unit_reader=_units()
    )
    target = tmp_path / "state" / "edge-probe.json"
    target.parent.mkdir(parents=True)

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(edge_probed.os, "replace", explode)
    with pytest.raises(OSError):
        edge_probed.write_result(outcome, target)
    assert list(target.parent.iterdir()) == []


def test_the_defaults_are_the_fixed_locations():
    assert edge_probed.probe.__defaults__[0] == EDGE_PACKAGE_ROOT
    assert PROBE_STATE_PATH == Path("/var/lib/azazel/run/edge-probe.json")
