"""Actual runtime-to-library CLI wiring with ephemeral signatures/observations."""

from dataclasses import replace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import cli
from azazel_nexus.commissioning import confirm_roles
from azazel_nexus.commissioning_draft import draft_bytes
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message
from azazel_nexus_runtime import commission_cli
from azazel_nexus_runtime.hardware_inventory import HardwareObservation
from azazel_nexus_runtime.netlink import LinkRecord


@pytest.fixture
def scope(monkeypatch):
    item = InterfaceReadout("synthetic0", dict(bus_path="pci/synthetic",
        permanent_mac="02:00:00:00:00:01", pci_id="8086:15b8", driver="synthetic"))
    observed = HardwareObservation("2026-10-13T00:00:00Z", (item,), {}, (),
        ("kernel-loopback-excluded",), 1)
    monkeypatch.setattr(commission_cli, "read_links", lambda: (LinkRecord(1, item.kernel_name, item.fields["permanent_mac"]),))
    monkeypatch.setattr(cli, "read_interfaces", lambda *a, **k: pytest.fail("unscoped collection"))
    return observed


def _collector(monkeypatch, before, after, *, change_link=False):
    observations = iter((before, after))
    calls = 0
    def collect(*, permanent_mac_reader):
        nonlocal calls
        calls += 1
        assert permanent_mac_reader("synthetic0") == "02:00:00:00:00:01"
        if change_link and calls == 2:
            monkeypatch.setattr(commission_cli, "read_links", lambda: (LinkRecord(2, "synthetic0", "02:00:00:00:00:02"),))
        return next(observations)
    monkeypatch.setattr(commission_cli, "collect_hardware_observations", collect)


@pytest.mark.parametrize("change", ["none", "platform", "storage", "exclusion", "interface", "netlink"])
def test_real_review_uses_scoped_proposal_and_rechecks_snapshot(scope, monkeypatch, capsys, change):
    key = SigningKey.generate()
    record = confirm_roles(scope.commissioning_proposal(), ((scope.interfaces[0], "observation"),),
                           operator="operator-a", at=scope.collected_at, profiles_present=())
    payload = draft_bytes(record)
    signature = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature
    monkeypatch.setattr(cli, "load_operator_trust", lambda: OperatorTrust({"operator-a": bytes(key.verify_key)}))
    monkeypatch.setattr(cli, "read_draft_review_inputs", lambda: (payload, signature))
    after = {
        "none": replace(scope, collected_at="2026-10-13T00:00:01Z"),
        "platform": replace(scope, platform={"vendor": "changed"}),
        "storage": replace(scope, storage_devices=({"changed": True},)),
        "exclusion": replace(scope, excluded_loopbacks=2),
        "interface": replace(scope, interfaces=(replace(scope.interfaces[0], driver_version="changed"),)),
        "netlink": scope,
    }[change]
    _collector(monkeypatch, scope, after, change_link=change == "netlink")
    assert commission_cli.main(["commission-review", "--operator", "operator-a"]) == (0 if change == "none" else 1)
    output = capsys.readouterr()
    assert ("assigned bindings verified" in output.out) is (change == "none")
    assert "02:00" not in output.out + output.err


@pytest.mark.parametrize("changed", [False, True, "netlink"])
def test_real_wizard_rechecks_scoped_inventory_before_export(scope, monkeypatch, capsys, changed):
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(commission_cli.sys.stdout, "isatty", lambda: True)
    answers = iter(("observation", "CONFIRM"))
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    _collector(monkeypatch, scope, replace(scope, excluded_loopbacks=2) if changed is True else scope,
               change_link=changed == "netlink")
    exports = []
    monkeypatch.setattr(cli, "export_draft", lambda record, destination: exports.append(record))
    result = commission_cli.main(["commission", "--operator", "operator-a", "--at", scope.collected_at,
        "--profiles", "hardware", "--draft-output", "/etc/azazel/commissioning/commissioning-draft.json"])
    assert result == (1 if changed else 0)
    assert len(exports) == (0 if changed else 1)
    assert ("draft prepared" in capsys.readouterr().out) is (not changed)
