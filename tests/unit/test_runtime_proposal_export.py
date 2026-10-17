"""Interactive proposal export wiring; all host observations are synthetic."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning import confirm_roles
from azazel_nexus.commissioning_draft import DraftRefused, draft_bytes
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message
from azazel_nexus_runtime import commission_cli, proposal_export, proposal_review
from azazel_nexus_runtime.hardware_inventory import HardwareObservation
from azazel_nexus_runtime.netlink import LinkRecord
from azazel_nexus_runtime.node_config import NodeConfigUnavailable

pytest.importorskip("azazel_fabric")


@pytest.fixture
def export_scope(monkeypatch):
    """Complete synthetic hardware/resource data and a real signed role draft."""
    readout = InterfaceReadout(
        "synthetic0",
        {
            "bus_path": "pci/synthetic",
            "permanent_mac": "02:00:00:00:00:01",
            "pci_id": "8086:15b8",
            "driver": "synthetic",
        },
    )
    hardware = HardwareObservation(
        collected_at="2026-10-13T00:00:00Z",
        interfaces=(readout,),
        platform={
            "vendor": None,
            "product_name": None,
            "board_serial": None,
            "firmware_vendor": None,
            "firmware_version": None,
        },
        storage_devices=(
            {
                "bus_path": "pci/storage",
                "size_bytes": 4096,
                "removable": False,
                "rotational": False,
                "model_name": None,
                "serial": None,
            },
        ),
        limitations=(
            "read-only-snapshot-not-authenticated",
            "snapshot-not-atomic",
            "platform-fields-unavailable",
            "storage-optional-identity-unavailable",
        ),
    )
    role_record = confirm_roles(
        hardware.commissioning_proposal(),
        ((readout, "observation"),),
        operator="operator-a",
        at="2026-10-13T00:00:00Z",
        profiles_present=(),
    )
    payload = draft_bytes(role_record)
    key = SigningKey.generate()
    signature = key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING, payload)
    ).signature
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)})
    resource_observation = {
        "schema": "azazel-nexus/resource-observation/v1",
        "observed_at": "2026-10-13T00:00:00Z",
        "architecture": "arm64",
        "measurements": {
            "usable_memory_mib": 16095,
            "online_logical_cpus": 4,
            "mission_available_mib": 10000,
        },
        "unavailable": [],
        "limitations": [
            "gpu-unmeasured",
            "throughput-unmeasured",
            "thermal-power-unmeasured",
            "cgroup-limits-unmeasured",
            "storage-trust-unverified",
        ],
        "admission": "not-evaluated",
    }

    # The runtime still constructs _PermanentAddresses and reads these actual
    # synthetic records. Repeated reads return the same snapshot by default.
    monkeypatch.setattr(
        commission_cli,
        "read_links",
        lambda: (LinkRecord(1, "synthetic0", "02:00:00:00:00:01"),),
    )
    monkeypatch.setattr(proposal_export, "load_declared_node", lambda: SimpleNamespace(node_id="node-synthetic"))
    monkeypatch.setattr(proposal_export, "load_operator_trust", lambda: trust)
    monkeypatch.setattr(proposal_export, "read_draft_review_inputs", lambda: (payload, signature))
    monkeypatch.setattr(
        proposal_export,
        "collect_hardware_observations",
        lambda *, permanent_mac_reader: (
            pytest.fail("collector must be configured for each test")
        ),
    )
    monkeypatch.setattr(proposal_export, "assess_resources", lambda: resource_observation)
    monkeypatch.setattr(proposal_export, "_now", lambda: "2026-10-13T00:00:00Z")
    answers = iter(("EXPORT",))
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    def collector(observations=(hardware, hardware)):
        remaining = iter(observations)

        def collect(*, permanent_mac_reader):
            assert permanent_mac_reader("synthetic0") == "02:00:00:00:00:01"
            return next(remaining)

        monkeypatch.setattr(proposal_export, "collect_hardware_observations", collect)

    writes = []
    def retain_context(**context):
        writes.append(commissioning_proposal_payload(**context))

    monkeypatch.setattr(proposal_export, "retain_proposal_context", retain_context)
    collector()
    return SimpleNamespace(
        hardware=hardware,
        resource_observation=resource_observation,
        trust=trust,
        key=key,
        payload=payload,
        signature=signature,
        collector=collector,
        writes=writes,
        readout=readout,
    )


def _set_interactive(monkeypatch):
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(commission_cli.sys.stdout, "isatty", lambda: True)


def test_proposal_export_cli_saves_full_linked_unsigned_record(export_scope, monkeypatch, capsys):
    _set_interactive(monkeypatch)
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0

    output = capsys.readouterr()
    assert len(export_scope.writes) == 1
    document = json.loads(export_scope.writes[0])
    assert document["schema"] == "azazel-nexus/commissioning-proposal/v1"
    assert document["status"] == "unsigned-proposal"
    assert document["confirmation_is"] == "proposed-until-full-signature-verified"
    assert document["inventory"]["node_id"] == "node-synthetic"
    assert document["inventory"]["storage_devices"][0]["size_bytes"] == 4096
    assert document["resource"]["node_id"] == document["inventory"]["node_id"]
    assert document["resource"]["hardware_inventory_digest"] == document["inventory"]["inventory_digest"]
    assert document["resource"]["usable_memory_mib"] == 16095
    assert document["topology"]["node_id"] == document["inventory"]["node_id"]
    assert document["topology"]["hardware_inventory_digest"] == document["inventory"]["inventory_digest"]
    assert document["topology"]["commissioned_assignments"][0]["role"] == "observation"
    assert document["record"]["node_id"] == document["inventory"]["node_id"]
    assert document["record"]["hardware_inventory_digest"] == document["inventory"]["inventory_digest"]
    assert document["record"]["resource_profile_digest"]
    assert document["record"]["topology_profile_digest"]
    assert document["record"]["authority"] == "descriptive_only"
    assert "unsigned-proposal-pending-full-operator-signature" in document["record"]["limitations"]
    assert "02:00:00:00:00:01" not in output.out + output.err
    assert "synthetic0" not in output.out + output.err
    assert "Unsigned full proposal saved" in output.out


def test_cli_exports_to_real_private_fixed_file_and_refuses_overwrite(
    export_scope, monkeypatch, capsys, tmp_path
):
    _set_interactive(monkeypatch)
    monkeypatch.setattr(commission_cli.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        commissioning_draft, "read_protection_key", lambda _path: b"synthetic-protection-key"
    )
    monkeypatch.setattr(
        proposal_export, "retain_proposal_context", commissioning_draft.retain_proposal_context
    )

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    expected = tmp_path / "commissioning-proposal.expected.json"
    saved = tmp_path / "commissioning-proposal.json"
    expected_bytes = expected.read_bytes()
    original = saved.read_bytes()
    assert original == expected_bytes
    document = json.loads(original)
    assert document["schema"] == "azazel-nexus/commissioning-proposal/v1"
    assert document["status"] == "unsigned-proposal"
    assert document["inventory"]["node_id"] == "node-synthetic"
    assert document["resource"]["hardware_inventory_digest"] == document["inventory"]["inventory_digest"]
    assert document["topology"]["hardware_inventory_digest"] == document["inventory"]["inventory_digest"]
    assert document["record"]["authority"] == "descriptive_only"
    assert saved.stat().st_mode & 0o777 == 0o600
    assert expected.stat().st_mode & 0o777 == 0o600
    assert {path.name for path in tmp_path.iterdir()} == {
        "commissioning-proposal.expected.json",
        "commissioning-proposal.json",
    }

    # Repeat the complete CLI path with fresh synthetic collection values.
    export_scope.collector()
    monkeypatch.setattr("builtins.input", lambda _prompt: "EXPORT")
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert saved.read_bytes() == original
    assert expected.read_bytes() == expected_bytes
    assert {path.name for path in tmp_path.iterdir()} == {
        "commissioning-proposal.expected.json",
        "commissioning-proposal.json",
    }
    output = capsys.readouterr()
    assert "02:00:00:00:00:01" not in output.out + output.err


def test_real_proposal_export_can_be_signed_and_reviewed_historically(
    export_scope, monkeypatch, capsys, tmp_path
):
    _set_interactive(monkeypatch)
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        commissioning_draft, "read_protection_key", lambda _path: b"synthetic-protection-key"
    )
    monkeypatch.setattr(
        proposal_export,
        "retain_proposal_context",
        commissioning_draft.retain_proposal_context,
    )
    node = SimpleNamespace(node_id="node-synthetic")
    monkeypatch.setattr(proposal_export, "load_declared_node", lambda: node)
    monkeypatch.setattr(proposal_review, "load_declared_node", lambda: node)
    monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: export_scope.trust)

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    export_output = capsys.readouterr()
    expected = tmp_path / "commissioning-proposal.expected.json"
    proposal = tmp_path / "commissioning-proposal.json"
    assert expected.read_bytes() == proposal.read_bytes()
    saved_payload = proposal.read_bytes()
    signature = export_scope.key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, saved_payload)
    ).signature
    signature_path = tmp_path / "commissioning-proposal.sig"
    signature_path.write_bytes(signature)
    signature_path.chmod(0o600)

    assert commission_cli.main(["proposal-review", "--operator", "operator-a"]) == 0
    review_output = capsys.readouterr()
    monkeypatch.setattr(
        proposal_review,
        "collect_hardware_observations",
        lambda *, permanent_mac_reader: (
            permanent_mac_reader("synthetic0"), export_scope.hardware
        )[1],
    )
    assert commission_cli.main(
        ["proposal-review", "--operator", "operator-a", "--check-current-hardware"]
    ) == 0
    current_output = capsys.readouterr()
    combined_output = export_output.out + export_output.err + review_output.out + review_output.err
    combined_output += current_output.out + current_output.err
    assert "Historical approval only" in review_output.out
    assert "current hardware fields match retained evidence" in current_output.out
    assert len(signature_path.read_bytes()) == 64
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (expected, proposal, signature_path))

    document = json.loads(saved_payload)
    private_values = (
        document["inventory"]["node_id"],
        "pci/synthetic",
        "02:00:00:00:00:01",
        document["inventory"]["inventory_digest"],
    )
    assert all(value not in combined_output for value in private_values)


@pytest.fixture
def signed_real_proposal(export_scope, monkeypatch, tmp_path):
    """A real exported proposal, signed ephemerally and retained privately."""
    _set_interactive(monkeypatch)
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        commissioning_draft, "read_protection_key", lambda _path: b"synthetic-protection-key"
    )
    monkeypatch.setattr(
        proposal_export,
        "retain_proposal_context",
        commissioning_draft.retain_proposal_context,
    )
    node = SimpleNamespace(node_id="node-synthetic")
    monkeypatch.setattr(proposal_export, "load_declared_node", lambda: node)
    monkeypatch.setattr(proposal_review, "load_declared_node", lambda: node)
    monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: export_scope.trust)

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    proposal_path = tmp_path / "commissioning-proposal.json"
    signature = export_scope.key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, proposal_path.read_bytes())
    ).signature
    signature_path = tmp_path / "commissioning-proposal.sig"
    signature_path.write_bytes(signature)
    signature_path.chmod(0o600)
    return SimpleNamespace(signature_path=signature_path)


@pytest.mark.parametrize(
    "changed",
    ["platform", "storage", "interface", "limitations", "scope", "clock"],
)
def test_current_hardware_review_rejects_changed_synthetic_observation(
    export_scope, signed_real_proposal, monkeypatch, capsys, changed
):
    hardware = export_scope.hardware
    if changed == "platform":
        current = replace(hardware, platform={**hardware.platform, "vendor": "synthetic-other"})
    elif changed == "storage":
        storage = (dict(hardware.storage_devices[0], size_bytes=8192),)
        current = replace(hardware, storage_devices=storage)
    elif changed == "interface":
        readout = replace(
            hardware.interfaces[0],
            fields={**hardware.interfaces[0].fields, "pci_id": "1234:5678"},
        )
        current = replace(hardware, interfaces=(readout,))
    elif changed == "limitations":
        current = replace(
            hardware,
            limitations=hardware.limitations + ("virtual-storage-and-partitions-excluded",),
        )
    elif changed == "scope":
        additional = replace(
            hardware.interfaces[0],
            kernel_name="synthetic1",
            fields={
                **hardware.interfaces[0].fields,
                "bus_path": "pci/synthetic-secondary",
                "permanent_mac": "02:00:00:00:00:02",
            },
        )
        current = replace(hardware, interfaces=hardware.interfaces + (additional,))
    else:
        current = replace(hardware, collected_at="2026-10-12T00:00:00Z")

    observations = iter((current, current))

    def collect(*, permanent_mac_reader):
        assert permanent_mac_reader("synthetic0") == "02:00:00:00:00:01"
        return next(observations)

    monkeypatch.setattr(proposal_review, "collect_hardware_observations", collect)
    assert commission_cli.main(
        ["proposal-review", "--operator", "operator-a", "--check-current-hardware"]
    ) == 1
    output = capsys.readouterr()
    assert "nothing activated" in output.err
    assert "02:00:00:00:00:01" not in output.out + output.err
    assert "synthetic0" not in output.out + output.err


def test_current_hardware_review_refuses_netlink_change_during_second_collection(
    export_scope, signed_real_proposal, monkeypatch, capsys
):
    reads = iter(
        (
            (LinkRecord(1, "synthetic0", "02:00:00:00:00:01"),),
            (LinkRecord(1, "synthetic0", "02:00:00:00:00:01"),),
            (LinkRecord(2, "synthetic0", "02:00:00:00:00:02"),),
        )
    )
    monkeypatch.setattr(commission_cli, "read_links", lambda: next(reads))
    calls = 0

    def collect(*, permanent_mac_reader):
        nonlocal calls
        calls += 1
        assert permanent_mac_reader("synthetic0") == "02:00:00:00:00:01"
        return export_scope.hardware

    monkeypatch.setattr(proposal_review, "collect_hardware_observations", collect)
    assert commission_cli.main(
        ["proposal-review", "--operator", "operator-a", "--check-current-hardware"]
    ) == 1
    output = capsys.readouterr()
    assert calls == 2
    assert "nothing activated" in output.err
    assert "02:00:00:00:00:01" not in output.out + output.err
    assert "synthetic0" not in output.out + output.err


def test_current_hardware_review_refuses_hardware_change_during_second_collection(
    export_scope, signed_real_proposal, monkeypatch, capsys
):
    observations = iter(
        (
            export_scope.hardware,
            replace(
                export_scope.hardware,
                platform={**export_scope.hardware.platform, "vendor": "synthetic-other"},
            ),
        )
    )
    calls = 0

    def collect(*, permanent_mac_reader):
        nonlocal calls
        calls += 1
        assert permanent_mac_reader("synthetic0") == "02:00:00:00:00:01"
        return next(observations)

    monkeypatch.setattr(proposal_review, "collect_hardware_observations", collect)
    assert commission_cli.main(
        ["proposal-review", "--operator", "operator-a", "--check-current-hardware"]
    ) == 1
    output = capsys.readouterr()
    assert calls == 2
    assert "nothing activated" in output.err
    assert "02:00:00:00:00:01" not in output.out + output.err
    assert "synthetic0" not in output.out + output.err


@pytest.mark.parametrize(
    ("missing", "error"),
    [
        ("node", NodeConfigUnavailable),
        ("trust", ApprovalRefused),
        ("draft", DraftRefused),
    ],
)
def test_missing_protected_input_refuses_export(export_scope, monkeypatch, capsys, missing, error):
    _set_interactive(monkeypatch)
    seams = {
        "node": "load_declared_node",
        "trust": "load_operator_trust",
        "draft": "read_draft_review_inputs",
    }

    def unavailable(*_args, **_kwargs):
        raise error("synthetic protected input unavailable")

    monkeypatch.setattr(proposal_export, seams[missing], unavailable)
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert export_scope.writes == []
    output = capsys.readouterr()
    assert "synthetic protected" not in output.out + output.err
    assert "02:00:00:00:00:01" not in output.out + output.err


@pytest.mark.parametrize("protection", ["luks", "key"])
def test_protected_storage_failure_does_not_create_proposal(
    export_scope, monkeypatch, capsys, tmp_path, protection
):
    _set_interactive(monkeypatch)
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(
        proposal_export, "retain_proposal_context", commissioning_draft.retain_proposal_context
    )
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *args, **kwargs: protection != "luks")
    monkeypatch.setattr(
        commissioning_draft,
        "read_protection_key",
        lambda _path: None if protection == "key" else b"synthetic-protection-key",
    )

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert list(tmp_path.iterdir()) == []
    assert export_scope.writes == []
    output = capsys.readouterr()
    assert "synthetic-protection" not in output.out + output.err


def test_netlink_change_during_second_collection_prevents_export(
    export_scope, monkeypatch, capsys
):
    _set_interactive(monkeypatch)
    link_reads = iter(
        (
            (LinkRecord(1, "synthetic0", "02:00:00:00:00:01"),),
            (LinkRecord(1, "synthetic0", "02:00:00:00:00:01"),),
            (LinkRecord(2, "synthetic0", "02:00:00:00:00:02"),),
        )
    )
    monkeypatch.setattr(commission_cli, "read_links", lambda: next(link_reads))

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert export_scope.writes == []
    output = capsys.readouterr()
    assert "02:00:00:00:00:01" not in output.out + output.err


@pytest.mark.parametrize("changed", ["node", "trust", "draft", "hardware", "netlink"])
def test_changed_protected_or_hardware_input_after_confirmation_prevents_write(
    export_scope, monkeypatch, capsys, changed
):
    _set_interactive(monkeypatch)
    if changed == "node":
        nodes = iter((SimpleNamespace(node_id="node-synthetic"), SimpleNamespace(node_id="node-changed")))
        monkeypatch.setattr(proposal_export, "load_declared_node", lambda: next(nodes))
    elif changed == "trust":
        trusts = iter((export_scope.trust, OperatorTrust({}, frozenset({"operator-a"}))))
        monkeypatch.setattr(proposal_export, "load_operator_trust", lambda: next(trusts))
    elif changed == "draft":
        drafts = iter(
            (
                (export_scope.payload, export_scope.signature),
                (export_scope.payload, b"x" * 64),
            )
        )
        monkeypatch.setattr(proposal_export, "read_draft_review_inputs", lambda: next(drafts))
    elif changed == "hardware":
        export_scope.collector(
            (
                export_scope.hardware,
                replace(export_scope.hardware, platform={"vendor": "changed"}),
            )
        )
    else:
        reads = iter(
            (
                (LinkRecord(1, "synthetic0", "02:00:00:00:00:01"),),
                (LinkRecord(2, "synthetic0", "02:00:00:00:00:02"),),
            )
        )
        monkeypatch.setattr(commission_cli, "read_links", lambda: next(reads))

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    output = capsys.readouterr()
    assert export_scope.writes == []
    assert "private" not in output.out + output.err
    assert "02:00:00:00:00:01" not in output.out + output.err


def test_declined_confirmation_does_not_write(export_scope, monkeypatch, capsys):
    _set_interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert export_scope.writes == []
    assert "export declined" not in capsys.readouterr().out


def test_missing_resource_measurement_does_not_write(export_scope, monkeypatch, capsys):
    _set_interactive(monkeypatch)
    observation = dict(export_scope.resource_observation)
    observation["measurements"] = dict(observation["measurements"], usable_memory_mib=None)
    observation["unavailable"] = ["usable_memory_mib"]
    monkeypatch.setattr(proposal_export, "assess_resources", lambda: observation)

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert export_scope.writes == []
    output = capsys.readouterr()
    assert "16095" not in output.out + output.err


def test_non_tty_proposal_export_does_not_collect_or_write(export_scope, monkeypatch, capsys):
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: False)

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert export_scope.writes == []
    output = capsys.readouterr()
    assert "requires a local interactive terminal" in output.err


@pytest.mark.parametrize(
    "argv",
    [
        ["proposal-export"],
        ["proposal-export", "operator-a"],
        ["proposal-export", "--operator", "operator-a", "--output", "/tmp/proposal.json"],
        ["proposal-export", "--path", "/tmp/proposal.json", "--operator", "operator-a"],
    ],
)
def test_wrong_proposal_export_arguments_are_rejected(export_scope, capsys, argv):
    assert commission_cli.main(argv) == 2
    assert export_scope.writes == []
    assert "path overrides" in capsys.readouterr().err
