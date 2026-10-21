"""Real composition path with synthetic readers and a recording unit manager."""

from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.generation import GenerationStore
from azazel_nexus.operator_trust import OperatorTrust
from azazel_nexus_runtime import activated
from azazel_nexus_runtime.node_config import DeclaredNode
from azazel_nexus_runtime.units import RecordingUnitManager

BOOT = "12345678-1234-1234-1234-123456789abc"
NOW = "2026-10-13T00:00:00Z"


@pytest.mark.parametrize("trust_state,boot", [
    ("active", BOOT), ("revoked", BOOT), ("empty", None),
    ("error", "private-invalid-boot"), ("active", "error"),
])
@pytest.mark.parametrize("generation_present", [False, True])
def test_actual_pass_narrows_before_collecting_and_never_grants(
    tmp_path, monkeypatch, trust_state, boot, generation_present,
):
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    for definition in CORE_UNITS:
        manager.unmask_and_enable(definition.name)
    manager.calls.clear()
    if generation_present:
        GenerationStore(tmp_path / "var/lib/azazel/generations").create(
            {"config": b"synthetic configuration"}, created_at=NOW,
            commissioning_digest="sha256:" + "a" * 64,
        )
    public = bytes(SigningKey.generate().verify_key)

    def trust_reader():
        assert {unit for action, unit in manager.calls if action == "mask"} == {
            d.name for d in CORE_UNITS
        }
        if trust_state == "error":
            raise RuntimeError("private reader detail")
        return OperatorTrust(
            {} if trust_state == "empty" else {"private-operator": public},
            frozenset({"private-operator"}) if trust_state == "revoked" else frozenset(),
        )

    def boot_reader():
        if boot == "error":
            raise OSError("private kernel detail")
        return boot

    monkeypatch.setattr(activated, "load_operator_trust", trust_reader)
    monkeypatch.setattr(activated, "read_boot_id", boot_reader)
    monkeypatch.setattr(activated, "load_declared_node", lambda: DeclaredNode("private-node"))
    collect = activated._collect_input_status
    monkeypatch.setattr(activated, "_collect_input_status", lambda root: collect(Path("/")))
    outcome = activated._run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert outcome.granted == ()
    assert all(manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    path = tmp_path / "var/lib/azazel/state/activation.jsonl"
    event = list(AuditLedger(path))[-1].event
    assert event["event_type"] == "activation.inputs_incomplete"
    assert "node_health" in event["missing_producers"]
    assert "operational_generation_publisher" in event["missing_producers"]
    assert event["observed_inputs"]["boot"] == ("observed" if boot == BOOT else "unavailable_or_invalid")
    expected = {"active": "active_keys_present", "revoked": "no_active_keys",
                "empty": "no_active_keys", "error": "unavailable_or_refused"}
    assert event["observed_inputs"]["operator_trust"] == expected[trust_state]
    assert event["observed_inputs"]["declared_node"] == "protected_declaration_only"
    assert "node_identity" in event["missing_producers"]
    audit_text = path.read_text()
    assert BOOT not in audit_text
    assert "private" not in audit_text
    assert public.hex() not in audit_text


def test_production_pass_still_supplies_no_lease_or_health(tmp_path, monkeypatch):
    """P1 adds a scoped lease to the library only; the pass stays lease-free (#206)."""
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    seen = []
    original = activated.ActivationDaemon.activate

    def spy(self, **kwargs):
        seen.append(kwargs)
        return original(self, **kwargs)

    monkeypatch.setattr(activated.ActivationDaemon, "activate", spy)
    outcome = activated._run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert outcome.granted == ()
    assert len(seen) == 1
    assert seen[0]["lease"] is None
    assert seen[0]["healthy"] is False


def test_staged_root_never_reads_host_inputs(tmp_path, monkeypatch):
    def forbidden():
        raise AssertionError("host input read")
    monkeypatch.setattr(activated, "load_operator_trust", forbidden)
    monkeypatch.setattr(activated, "read_boot_id", forbidden)
    monkeypatch.setattr(activated, "load_declared_node", forbidden)
    assert set(activated._collect_input_status(tmp_path).values()) == {"not_collected_staged_root"}


def test_diagnostic_audit_failure_leaves_units_masked(tmp_path, monkeypatch):
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    original = AuditLedger.append

    def append(ledger, event):
        if event["event_type"] == "activation.inputs_incomplete":
            raise AuditUnavailable("injected diagnostic append failure")
        return original(ledger, event)

    monkeypatch.setattr(AuditLedger, "append", append)
    # #251 L-2: the unrecorded pass is withdrawn (markers, remask), then fails.
    with pytest.raises(RuntimeError, match="pass record could not be appended") as raised:
        activated._run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert type(raised.value.__context__) is AuditUnavailable
    assert all(manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert all(action == "mask" for action, _ in manager.calls)


def test_missing_yaml_parser_cannot_skip_mandatory_narrowing(tmp_path, monkeypatch):
    import builtins
    from azazel_nexus_runtime import node_config

    original_import = builtins.__import__
    def importing(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("private-parser-detail")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", importing)
    monkeypatch.setattr(activated, "load_declared_node", lambda: node_config._decode(b"node_id: private-node"))
    monkeypatch.setattr(activated, "read_boot_id", lambda: None)
    monkeypatch.setattr(activated, "load_operator_trust", lambda: OperatorTrust({}))
    collect = activated._collect_input_status
    monkeypatch.setattr(activated, "_collect_input_status", lambda root: collect(Path("/")))
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    for definition in CORE_UNITS:
        manager.unmask_and_enable(definition.name)
    outcome = activated._run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert outcome.granted == ()
    assert all(manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    path = tmp_path / "var/lib/azazel/state/activation.jsonl"
    assert list(AuditLedger(path))[-1].event["observed_inputs"]["declared_node"] == "unavailable_or_refused"
    assert "private" not in path.read_text()


# -- the commissioning storage label (#242 §4 "Diagnostic only") ---------------


def _host_readers(monkeypatch):
    monkeypatch.setattr(activated, "load_operator_trust", lambda: OperatorTrust({}))
    monkeypatch.setattr(activated, "read_boot_id", lambda: BOOT)
    monkeypatch.setattr(activated, "load_declared_node", lambda: DeclaredNode("private-node"))


@pytest.mark.parametrize("backed,label", [(True, "luks_backed"), (False, "not_luks_backed")])
def test_storage_label_is_one_of_two_fixed_values_for_the_commissioning_dir(
        monkeypatch, backed, label):
    _host_readers(monkeypatch)
    seen = []
    monkeypatch.setattr(activated, "luks_backed", lambda path: seen.append(path) or backed)
    observed = activated._collect_input_status(Path("/"))
    assert seen == [Path("/etc/azazel/commissioning")]
    assert observed["commissioning_storage"] == label
    assert activated.COMMISSIONING_STORAGE_LABELS == ("luks_backed", "not_luks_backed")


@pytest.mark.parametrize("result", [
    RuntimeError("private /dev/dm-3 detail"), PermissionError("private"), None, "yes", 1,
], ids=["raises", "permission", "none", "text", "int"])
def test_storage_label_is_absent_rather_than_invented(monkeypatch, result):
    _host_readers(monkeypatch)

    def reader(_path):
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(activated, "luks_backed", reader)
    observed = activated._collect_input_status(Path("/"))
    assert "commissioning_storage" not in observed
    assert "private" not in repr(observed)


def test_staged_root_never_reads_the_storage(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("host storage read")
    monkeypatch.setattr(activated, "luks_backed", forbidden)
    assert "commissioning_storage" not in activated._collect_input_status(tmp_path)


@pytest.mark.parametrize("uuid,label", [
    ("CRYPT-LUKS2-0123456789abcdef0123456789abcdef-azn-commissioning", "luks_backed"),
    ("LVM-private-volume", "not_luks_backed"),
    (None, "not_luks_backed"),
])
def test_storage_label_from_the_real_reader_carries_no_device(tmp_path, monkeypatch, uuid, label):
    """The HIL preflight's own reader over a synthetic /sys/dev/block."""
    import os
    from types import SimpleNamespace

    from azazel_nexus import hil_preflight

    sysfs = tmp_path / "sys/dev/block"
    device = os.makedev(254, 3)
    if uuid is not None:
        (sysfs / "254:3/dm").mkdir(parents=True)
        (sysfs / "254:3/dm/uuid").write_text(uuid + "\n")
    monkeypatch.setattr(activated, "luks_backed", lambda path: hil_preflight.luks_backed(
        path, stat=lambda _p: SimpleNamespace(st_dev=device), sysfs_dev_block=sysfs))
    _host_readers(monkeypatch)
    collect = activated._collect_input_status
    monkeypatch.setattr(activated, "_collect_input_status", lambda root: collect(Path("/")))
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    outcome = activated._run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert outcome.granted == ()
    path = tmp_path / "var/lib/azazel/state/activation.jsonl"
    event = list(AuditLedger(path))[-1].event
    assert event["observed_inputs"]["commissioning_storage"] == label
    text = path.read_text()
    for leak in ("254:3", "CRYPT", "LUKS2", "azn-commissioning", "/etc/azazel", "/sys", "private"):
        assert leak not in text, leak
