"""`proposal-export` with the Deception Lite exposure scope (#196 grant §4.1 S1, G6).

Only a signed draft that assigns `deception_bridge` is asked for the
approved IPv4 source prefixes; empty keeps v2 exactly; a scope is decoded
whole, printed, and needs `EXPOSE` before `EXPORT`; the v3 proposal is then
reviewed with the same separate full-proposal signature and is what the
activation pass's P6 restores. All host observations are synthetic.
"""

import json

import pytest

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning import confirm_roles
from azazel_nexus.commissioning_draft import draft_bytes
from azazel_nexus.decoy_scope import BRIDGE_PREFIX
from azazel_nexus.operator_trust import ApprovalPurpose, approval_message
from azazel_nexus_runtime import commission_cli, proposal_export, proposal_review

from test_runtime_proposal_export import _set_interactive, export_scope  # noqa: F401

pytest.importorskip("azazel_fabric")


@pytest.fixture
def bridge_scope(export_scope, monkeypatch):  # noqa: F811
    """The same node, its one interface confirmed `deception_bridge`."""
    hardware = export_scope.hardware
    record = confirm_roles(hardware.commissioning_proposal(),
                           ((export_scope.readout, "deception_bridge"),),
                           operator="operator-a", at="2026-10-13T00:00:00Z",
                           profiles_present=())
    payload = draft_bytes(record)
    signature = export_scope.key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature
    monkeypatch.setattr(proposal_export, "read_draft_review_inputs",
                        lambda: (payload, signature))
    return export_scope


def _answers(monkeypatch, *answers):
    asked = []
    remaining = iter(answers)

    def answer(prompt):
        asked.append(prompt)
        return next(remaining)

    monkeypatch.setattr("builtins.input", answer)
    return asked


def test_a_bridge_role_and_prefixes_export_a_v3_proposal(bridge_scope, monkeypatch, capsys):
    _set_interactive(monkeypatch)
    asked = _answers(monkeypatch, "LITE", "10.20.0.0/24, 192.168.10.0/24", "EXPOSE", "EXPORT")
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    assert asked[1] == proposal_export.SCOPE_PROMPT and asked[2] == proposal_export.EXPOSE_PROMPT
    assert "Deception Lite exposure scope" in asked[3]
    document = json.loads(bridge_scope.writes[0])
    assert document["schema"] == "azazel-nexus/commissioning-proposal/v3"
    assert document["deception_scope"] == {
        "approved_v4": ["10.20.0.0/24", "192.168.10.0/24"],
        "bridge_prefix": BRIDGE_PREFIX, "ingress_role": "deception_bridge"}
    out = capsys.readouterr().out
    assert f"Decoy bridge prefix (fixed, confirmed): {BRIDGE_PREFIX}" in out
    assert "Approved IPv4 source prefixes: 10.20.0.0/24, 192.168.10.0/24" in out
    assert "Ingress interfaces (role deception_bridge): 1" in out
    assert "synthetic0" not in out and "02:00:00:00:00:01" not in out


def test_empty_keeps_the_v2_proposal_exactly(bridge_scope, monkeypatch):
    _set_interactive(monkeypatch)
    asked = _answers(monkeypatch, "LITE", "", "EXPORT")
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    assert asked[1] == proposal_export.SCOPE_PROMPT and len(asked) == 3
    document = json.loads(bridge_scope.writes[0])
    assert document["schema"] == "azazel-nexus/commissioning-proposal/v2"
    assert "deception_scope" not in document


@pytest.mark.parametrize("prefixes", [
    "8.8.8.0/24",                      # not RFC 1918
    "192.168.10.0/24,10.20.0.0/24",    # not sorted
    "10.20.0.1/24",                    # not a strict network
    "10.255.196.0/28",                 # the decoy network's block
    "10.20.0.0/24,10.20.0.0/24",       # a duplicate
    "nonsense",
])
def test_a_scope_out_of_its_rules_refuses_the_whole_export(bridge_scope, monkeypatch, capsys,
                                                           prefixes):
    _set_interactive(monkeypatch)
    asked = _answers(monkeypatch, "LITE", prefixes, "EXPOSE", "EXPORT")
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert bridge_scope.writes == []
    assert proposal_export.EXPOSE_PROMPT not in asked
    assert "Deception Lite exposure scope refused" in capsys.readouterr().err


def test_without_expose_nothing_is_exported(bridge_scope, monkeypatch):
    _set_interactive(monkeypatch)
    _answers(monkeypatch, "LITE", "10.20.0.0/24", "expose", "EXPORT")
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 1
    assert bridge_scope.writes == []


def test_a_draft_without_the_bridge_role_is_never_asked(export_scope, monkeypatch):  # noqa: F811
    _set_interactive(monkeypatch)
    asked = _answers(monkeypatch, "LITE", "EXPORT")
    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    assert proposal_export.SCOPE_PROMPT not in asked
    assert json.loads(export_scope.writes[0])["schema"] == (
        "azazel-nexus/commissioning-proposal/v2")


def test_the_v3_proposal_is_retained_reviewed_and_restored_for_p6(bridge_scope, monkeypatch,
                                                                  capsys, tmp_path):
    from types import SimpleNamespace

    from azazel_nexus.fabric_boundary import restore_commissioning_inputs
    from azazel_nexus_runtime.exposure_pass import resolve_exposure_scope

    _set_interactive(monkeypatch)
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    profile_dir = tmp_path.parent / (tmp_path.name + "-mio-profile")
    profile_dir.mkdir(mode=0o700)
    monkeypatch.setattr(commissioning_draft, "MIO_PROFILE_DIR", profile_dir)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *_a, **_k: True)
    monkeypatch.setattr(commissioning_draft, "read_protection_key",
                        lambda _path: b"synthetic-protection-key")
    monkeypatch.setattr(proposal_export, "retain_proposal_context",
                        commissioning_draft.retain_proposal_context)
    node = SimpleNamespace(node_id="node-synthetic")
    monkeypatch.setattr(proposal_export, "load_declared_node", lambda: node)
    monkeypatch.setattr(proposal_review, "load_declared_node", lambda: node)
    monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: bridge_scope.trust)
    _answers(monkeypatch, "FULL", "10.20.0.0/24", "EXPOSE", "EXPORT")

    assert commission_cli.main(["proposal-export", "--operator", "operator-a"]) == 0
    saved = (tmp_path / "commissioning-proposal.json").read_bytes()
    assert saved == (tmp_path / "commissioning-proposal.expected.json").read_bytes()
    assert json.loads(saved)["schema"] == "azazel-nexus/commissioning-proposal/v3"
    signature = bridge_scope.key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, saved)).signature
    (tmp_path / "commissioning-proposal.sig").write_bytes(signature)
    (tmp_path / "commissioning-proposal.sig").chmod(0o600)
    assert commission_cli.main(["proposal-review", "--operator", "operator-a"]) == 0
    assert "Historical approval only" in capsys.readouterr().out

    # What the pass's P6 restores from the evidence's payload.
    context = restore_commissioning_inputs(json.loads(saved))
    assert context["deception_scope"]["approved_v4"] == ["10.20.0.0/24"]
    current = context["inventory"]
    evidence = SimpleNamespace(payload=saved, current_inventory=json.dumps(
        current.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8"))
    scope, roles = resolve_exposure_scope(evidence)
    assert [str(n) for n in scope.approved_v4] == ["10.20.0.0/24"]
    assert len(roles.ingress) == 1
