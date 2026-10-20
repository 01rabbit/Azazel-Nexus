"""Activation node_health collector (#206 P2): injected probes, temp ledgers."""

import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation_policy import decode_activation_policy
from azazel_nexus.audit import AuditLedger
from azazel_nexus.operator_trust import OperatorTrust
from azazel_nexus_runtime import activation_health
from azazel_nexus_runtime.activation_health import (
    HEALTH_CHECKS,
    PRODUCTION_PROBES,
    NodeHealthProbes,
    collect_node_health,
    read_watchdog_fences,
)
from azazel_nexus_runtime.bootstrap_resources import (
    BootstrapResourceThresholds,
    require_bootstrap_resources,
)
from azazel_nexus_runtime.bootstrap_state_capacity import (
    BootstrapStateFloors,
    require_bootstrap_state_capacity,
)
from test_activation_policy import _raw

NOW = "2026-10-20T00:00:00Z"
POLICY = decode_activation_policy(_raw())
KEY = bytes(SigningKey.generate().verify_key)


def _probes(**changes):
    seen = SimpleNamespace(state=None, resources=None)

    def state(floors):
        seen.state = floors

    def resources(thresholds):
        seen.resources = thresholds

    fields = {
        "state_capacity": state,
        "resources": resources,
        "operator_trust": lambda: OperatorTrust({"operator-a": KEY}),
        "lab_host": lambda: False,
        "watchdog_fences": lambda: {},
    }
    fields.update(changes)
    return NodeHealthProbes(**fields), seen


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "activation.jsonl")


def _collect(ledger, probes, policy=POLICY, now=NOW):
    return collect_node_health(policy=policy, ledger=ledger, now=now, probes=probes)


def test_all_checks_pass_only_when_every_check_holds(ledger):
    probes, seen = _probes()
    healthy, findings = _collect(ledger, probes)
    assert healthy is True
    assert findings == tuple((name, "ok") for name in HEALTH_CHECKS)
    assert seen.state == BootstrapStateFloors(**POLICY.state_floor_values())
    assert seen.resources == BootstrapResourceThresholds(**POLICY.resource_floor_values())
    entries = list(ledger)
    assert [entry.event["event_type"] for entry in entries] == ["activation.health_ledger_probe"]
    ledger.verify()


def _raise(*args):
    raise RuntimeError("secret detail /etc/azazel")


@pytest.mark.parametrize("check, changes", [
    ("state_capacity", {"state_capacity": _raise}),
    ("resources", {"resources": _raise}),
    ("operator_trust", {"operator_trust": _raise}),
    ("operator_trust", {"operator_trust": lambda: OperatorTrust({"operator-a": KEY}, frozenset({"operator-a"}))}),
    ("operator_trust", {"operator_trust": lambda: OperatorTrust({})}),
    ("operator_trust", {"operator_trust": lambda: {"operator-a": KEY}}),
    ("lab_marker", {"lab_host": lambda: True}),
    ("lab_marker", {"lab_host": _raise}),
    ("lab_marker", {"lab_host": lambda: None}),
    ("lab_marker", {"lab_host": lambda: 0}),
    ("watchdog_fences", {"watchdog_fences": lambda: {"azazel-edge-probed.service": "unhealthy"}}),
    ("watchdog_fences", {"watchdog_fences": _raise}),
    ("watchdog_fences", {"watchdog_fences": lambda: None}),
    ("watchdog_fences", {"watchdog_fences": lambda: []}),
])
def test_each_failing_check_makes_the_node_unhealthy(ledger, check, changes):
    probes, _ = _probes(**changes)
    healthy, findings = _collect(ledger, probes)
    assert healthy is False
    assert dict(findings)[check] == "failed"
    assert [name for name, result in findings if result == "failed"] == [check]
    assert "secret" not in repr(findings)


def test_broken_ledger_chain_is_unhealthy(ledger):
    ledger.append({"event_type": "x"})
    ledger.append({"event_type": "y"})
    lines = ledger.path.read_text().splitlines()
    record = json.loads(lines[0])
    record["event"]["event_type"] = "edited"
    ledger.path.write_text("\n".join([json.dumps(record)] + lines[1:]) + "\n")
    probes, _ = _probes()
    healthy, findings = _collect(ledger, probes)
    assert healthy is False and dict(findings)["activation_ledger"] == "failed"
    assert len(ledger.path.read_text().splitlines()) == 2  # nothing appended


def test_unwritable_ledger_is_unhealthy(tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    probes, _ = _probes()
    healthy, findings = _collect(AuditLedger(blocker / "activation.jsonl"), probes)
    assert healthy is False and dict(findings)["activation_ledger"] == "failed"


@pytest.mark.parametrize("ledger_value", [None, "activation.jsonl", SimpleNamespace()])
def test_ledger_must_be_an_injected_audit_ledger(ledger_value):
    probes, _ = _probes()
    healthy, findings = _collect(ledger_value, probes)
    assert healthy is False and dict(findings)["activation_ledger"] == "failed"


@pytest.mark.parametrize("policy", [None, {}, POLICY.__dict__])
def test_absent_policy_means_no_floors_and_unhealthy(ledger, policy):
    probes, seen = _probes()
    healthy, findings = _collect(ledger, probes, policy=policy)
    assert healthy is False
    assert dict(findings)["state_capacity"] == "failed"
    assert dict(findings)["resources"] == "failed"
    assert seen.state is None and seen.resources is None


@pytest.mark.parametrize("now", [None, "", "2026-10-20 00:00:00", "2026-10-20T00:00:00.5Z"])
def test_invalid_time_is_unhealthy_without_touching_the_ledger(ledger, now):
    probes, _ = _probes()
    healthy, findings = _collect(ledger, probes, now=now)
    assert healthy is False
    assert all(result == "failed" for _, result in findings)
    assert not ledger.path.exists()


def test_probes_must_be_the_fixed_record(ledger):
    healthy, findings = collect_node_health(
        policy=POLICY, ledger=ledger, now=NOW, probes={"lab_host": lambda: False})
    assert healthy is False and all(result == "failed" for _, result in findings)


def test_every_check_runs_even_after_a_failure(ledger):
    calls = []
    probes, _ = _probes(
        state_capacity=lambda floors: (_ for _ in ()).throw(RuntimeError()),
        watchdog_fences=lambda: calls.append("fences") or {},
    )
    healthy, findings = _collect(ledger, probes)
    assert healthy is False and calls == ["fences"]
    assert [name for name, _ in findings] == list(HEALTH_CHECKS)


def test_production_probes_reuse_the_bootstrap_checks():
    assert PRODUCTION_PROBES.state_capacity is require_bootstrap_state_capacity
    assert PRODUCTION_PROBES.resources is require_bootstrap_resources
    assert PRODUCTION_PROBES.watchdog_fences is read_watchdog_fences
    assert PRODUCTION_PROBES.lab_host.__module__ == "azazel_nexus.lab_host"
    assert PRODUCTION_PROBES.operator_trust.__module__ == "azazel_nexus.operator_store"


def test_collector_consults_no_service_self_report():
    """Imports only the fixed local readers; nothing that talks to a daemon."""
    source = Path(activation_health.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add(("." * node.level) + (node.module or ""))
    assert modules == {
        "__future__", "dataclasses", "json", "os", "pwd", "stat", "typing",
        "azazel_nexus.activation_policy", "azazel_nexus.audit",
        "azazel_nexus.bootstrap_approval", "azazel_nexus.lab_host",
        "azazel_nexus.operator_store", "azazel_nexus.operator_trust",
        ".bootstrap_resources", ".bootstrap_state_capacity", ".runtime_paths",
    }
    code = source.split('"""', 2)[2]
    for word in ("socket", "status", "protocol", "systemd", "edge_loop", "probe_result"):
        assert word not in code, word


# -- watchdog fence store reader -------------------------------------------------


@pytest.fixture
def fences(tmp_path, monkeypatch):
    directory = tmp_path / "watchdog"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(activation_health, "watchdog_state_dir", lambda: directory)
    monkeypatch.setattr(activation_health.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=os.getuid()) if name == "azwatch"
                        else (_ for _ in ()).throw(KeyError(name)))
    return directory


def test_never_fenced_store_reads_empty(fences):
    assert read_watchdog_fences() == {}


def test_written_fences_are_returned_and_empty_object_is_empty(fences):
    (fences / "fences.json").write_text("{}\n")
    assert read_watchdog_fences() == {}
    (fences / "fences.json").write_text(json.dumps({"azazel-edge-probed.service": "unhealthy"}))
    assert read_watchdog_fences() == {"azazel-edge-probed.service": "unhealthy"}


@pytest.mark.parametrize("content", [b"", b"not json", b"[]", b"null", b"x" * 70000])
def test_unreadable_fence_store_raises(fences, content):
    (fences / "fences.json").write_bytes(content)
    with pytest.raises(Exception):
        read_watchdog_fences()


def test_missing_store_directory_raises(fences):
    fences.rmdir()
    with pytest.raises(OSError):
        read_watchdog_fences()


def test_symlinked_store_or_file_raises(fences, tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}")
    (fences / "fences.json").symlink_to(target)
    with pytest.raises(OSError):
        read_watchdog_fences()


def test_writable_by_others_or_foreign_owner_raises(fences, monkeypatch):
    (fences / "fences.json").write_text("{}")
    (fences / "fences.json").chmod(0o666)
    with pytest.raises(Exception):
        read_watchdog_fences()
    (fences / "fences.json").chmod(0o600)
    fences.chmod(0o777)
    with pytest.raises(Exception):
        read_watchdog_fences()
    fences.chmod(0o700)
    monkeypatch.setattr(activation_health.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=os.getuid() + 1))
    with pytest.raises(Exception):
        read_watchdog_fences()


def test_missing_watchdog_account_raises(fences, monkeypatch):
    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(activation_health.pwd, "getpwnam", missing)
    with pytest.raises(KeyError):
        read_watchdog_fences()


def test_fence_reader_failure_is_an_unhealthy_finding(fences, ledger):
    (fences / "fences.json").write_text("garbage")
    probes, _ = _probes(watchdog_fences=read_watchdog_fences)
    healthy, findings = _collect(ledger, probes)
    assert healthy is False and dict(findings)["watchdog_fences"] == "failed"
