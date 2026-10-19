"""Export failures before optional Fabric projection; synthetic inputs only."""

import sys
from types import SimpleNamespace

import pytest

from azazel_nexus import commissioning_draft as draft
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import proposal_export as export


@pytest.mark.parametrize("case,expected", [
    ("missing", "no signed draft present"),
    ("unreadable", "signed draft unreadable"),
    ("signature", "draft signature refused"),
    ("verification", "signed draft signature or current binding refused"),
])
def test_specific_refusal_without_writes_or_secret_output(tmp_path, monkeypatch, capsys, case, expected):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(export, "load_declared_node", lambda: SimpleNamespace(node_id="synthetic"))
    monkeypatch.setattr(export, "load_operator_trust", lambda: object())
    monkeypatch.setattr(draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(draft, "_check_protection", lambda fd: None)
    def read(fd, name, *, maximum):
        if case == "missing":
            raise FileNotFoundError("secret identity")
        if case == "unreadable":
            raise PermissionError("secret identity")
        return b"bad" if case == "signature" else b"x" * 64
    monkeypatch.setattr(draft, "_read_private", read)
    monkeypatch.setattr(export, "read_draft_review_inputs", draft.read_draft_review_inputs)
    observed = SimpleNamespace(interfaces=(), platform={}, storage_devices=(), limitations=(),
                               collected_at="2026-10-19T00:00:00Z", commissioning_proposal=lambda: None)
    monkeypatch.setattr(export, "collect_hardware_observations", lambda **kw: observed)
    monkeypatch.setattr(export, "project_hardware_inventory", lambda **kw: None)
    monkeypatch.setattr(export, "assess_resources", lambda: None)
    monkeypatch.setattr(export, "project_resource_profile", lambda **kw: None)
    def refused(**kw):
        raise ApprovalRefused("secret identity")
    monkeypatch.setattr(export, "project_reviewed_topology", refused)
    assert export.run("synthetic", None) == 1
    output = capsys.readouterr()
    assert expected in output.err
    assert "No activation attempted" in output.err
    assert "secret identity" not in output.out + output.err
    assert list(tmp_path.iterdir()) == []
