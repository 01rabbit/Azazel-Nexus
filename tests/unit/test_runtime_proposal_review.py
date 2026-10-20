"""Runtime CLI review of historical proposals using synthetic protected state."""

from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message
from azazel_nexus_runtime import commission_cli, proposal_review

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import (  # noqa: E402
    HardwareInventory,
    ResourceProfile,
    TopologyProfile,
)
from azazel_fabric.testing.provisioning import (  # noqa: E402
    golden_hardware_inventory,
    golden_resource_profile,
    golden_topology_profile,
)


@pytest.fixture
def retained_proposal(monkeypatch, tmp_path):
    context = {
        "inventory": HardwareInventory.model_validate(golden_hardware_inventory()),
        "resource_profile": ResourceProfile.model_validate(golden_resource_profile()),
        "topology_profile": TopologyProfile.model_validate(golden_topology_profile()),
        "record_id": "record-synthetic",
        "operator": "operator-a",
        "confirmed_at": "2026-10-13T00:00:00Z",
    }
    key = SigningKey.generate()
    payload = commissioning_proposal_payload(**context)
    signature = key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)
    ).signature
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)})

    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    profile_dir = tmp_path.parent / (tmp_path.name + "-mio-profile")
    profile_dir.mkdir(mode=0o700)
    monkeypatch.setattr(commissioning_draft, "MIO_PROFILE_DIR", profile_dir)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        commissioning_draft, "read_protection_key", lambda _path: b"synthetic-protection-key"
    )
    commissioning_draft.retain_proposal_context(**context)
    signature_path = tmp_path / "commissioning-proposal.sig"
    signature_path.write_bytes(signature)
    signature_path.chmod(0o600)

    node_id = context["inventory"].node_id
    monkeypatch.setattr(
        proposal_review,
        "load_declared_node",
        lambda: SimpleNamespace(node_id=node_id),
    )
    monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: trust)
    return SimpleNamespace(
        context=context,
        key=key,
        trust=trust,
        payload=payload,
        signature=signature,
        node_id=node_id,
        directory=tmp_path,
    )


def _names(directory):
    return {path.name for path in directory.iterdir()}


def test_proposal_review_cli_accepts_retained_historical_signature_without_activation(
    retained_proposal, capsys
):
    assert commission_cli.main(["proposal-review", "--operator", "operator-a"]) == 0

    expected = retained_proposal.directory / "commissioning-proposal.expected.json"
    proposal = retained_proposal.directory / "commissioning-proposal.json"
    signature = retained_proposal.directory / "commissioning-proposal.sig"
    assert expected.read_bytes() == retained_proposal.payload
    assert proposal.read_bytes() == retained_proposal.payload
    assert signature.read_bytes() == retained_proposal.signature
    assert len(signature.read_bytes()) == 64
    # Only the signature leaves encrypted storage; the proposal bytes never do (#244).
    assert _names(commissioning_draft.MIO_PROFILE_DIR) == {"commissioning-proposal.sig"}
    assert (commissioning_draft.MIO_PROFILE_DIR / "commissioning-proposal.sig").read_bytes() == (
        retained_proposal.signature)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (expected, proposal, signature))
    assert _names(retained_proposal.directory) == {
        "commissioning-proposal.expected.json",
        "commissioning-proposal.json",
        "commissioning-proposal.sig",
    }
    output = capsys.readouterr()
    assert "Historical approval only" in output.out
    assert "activated" not in output.out.lower()
    assert "activated" not in output.err.lower()


@pytest.mark.parametrize("failure", ["wrong-key", "wrong-purpose", "wrong-node", "revoked", "mismatched-payload"])
def test_proposal_review_cli_rejects_invalid_historical_approval(
    retained_proposal, monkeypatch, capsys, failure
):
    if failure == "wrong-key":
        retained_proposal.directory.joinpath("commissioning-proposal.sig").write_bytes(
            SigningKey.generate()
            .sign(approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, retained_proposal.payload))
            .signature
        )
    elif failure == "wrong-purpose":
        retained_proposal.directory.joinpath("commissioning-proposal.sig").write_bytes(
            retained_proposal.key.sign(
                approval_message(ApprovalPurpose.COMMISSIONING, retained_proposal.payload)
            ).signature
        )
    elif failure == "wrong-node":
        monkeypatch.setattr(
            proposal_review,
            "load_declared_node",
            lambda: SimpleNamespace(node_id="node-other"),
        )
    elif failure == "revoked":
        revoked = OperatorTrust(
            {"operator-a": bytes(retained_proposal.key.verify_key)}, frozenset({"operator-a"})
        )
        monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: revoked)
    else:
        retained_proposal.directory.joinpath("commissioning-proposal.json").write_bytes(
            retained_proposal.payload + b" "
        )

    assert commission_cli.main(["proposal-review", "--operator", "operator-a"]) == 1
    output = capsys.readouterr()
    assert "verified" not in output.out.lower()
    assert "nothing activated" in output.err


def test_proposal_review_cli_rejects_missing_retained_expectation(retained_proposal, capsys):
    (retained_proposal.directory / "commissioning-proposal.expected.json").unlink()

    assert commission_cli.main(["proposal-review", "--operator", "operator-a"]) == 1
    assert "nothing activated" in capsys.readouterr().err


@pytest.mark.parametrize("changed", ["node", "trust", "inputs"])
def test_proposal_review_cli_refuses_protected_state_changed_during_recheck(
    retained_proposal, monkeypatch, capsys, changed
):
    if changed == "node":
        nodes = iter(
            (
                SimpleNamespace(node_id=retained_proposal.node_id),
                SimpleNamespace(node_id="node-changed"),
            )
        )
        monkeypatch.setattr(proposal_review, "load_declared_node", lambda: next(nodes))
    elif changed == "trust":
        revoked = OperatorTrust(
            {"operator-a": bytes(retained_proposal.key.verify_key)}, frozenset({"operator-a"})
        )
        trusts = iter((retained_proposal.trust, revoked))
        monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: next(trusts))
    else:
        read_actual = commissioning_draft.read_proposal_review_inputs
        # Use a counter to change only the reread after cryptographic verification.
        calls = 0

        def read_then_change_on_second_call():
            nonlocal calls
            calls += 1
            values = read_actual()
            if calls == 2:
                return values[0] + b" ", values[1], values[2]
            return values

        monkeypatch.setattr(proposal_review, "read_proposal_review_inputs", read_then_change_on_second_call)

    assert commission_cli.main(["proposal-review", "--operator", "operator-a"]) == 1
    output = capsys.readouterr()
    assert "verified" not in output.out.lower()
    assert "nothing activated" in output.err


@pytest.mark.parametrize(
    "argv",
    [
        ["proposal-review"],
        ["proposal-review", "operator-a"],
        ["proposal-review", "--operator", "operator-a", "--path", "/tmp/proposal.json"],
    ],
)
def test_proposal_review_cli_rejects_bad_arguments(capsys, argv):
    assert commission_cli.main(argv) == 2
    assert "path overrides" in capsys.readouterr().err
