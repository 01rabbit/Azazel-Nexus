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


@pytest.mark.parametrize("case,expected", [
    ("owner", "draft directory ownership or access refused"),
    ("mode", "draft directory ownership or access refused"),
    ("luks", "encrypted commissioning storage is required"),
    ("key", "commissioning protection key is unavailable"),
])
def test_protection_refusals_precede_missing_draft(tmp_path, monkeypatch, private_os, capsys, case, expected):
    # Exercise the real protection check against synthetic directory metadata.
    # No real protected files or key material are read.
    import stat
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(export, "load_declared_node", lambda: SimpleNamespace(node_id="synthetic"))
    monkeypatch.setattr(export, "load_operator_trust", lambda: object())
    monkeypatch.setattr(draft, "COMMISSIONING_DIR", tmp_path)
    private_os(draft)
    monkeypatch.setattr(draft.os, "fstat", lambda fd: SimpleNamespace(
        st_mode=stat.S_IFDIR | (0o777 if case == "mode" else 0o700),
        st_uid=-1 if case == "owner" else draft.os.geteuid()))
    monkeypatch.setattr(draft, "luks_backed", lambda *a, **kw: case == "key")
    key_checks = []
    def key_unavailable(path):
        key_checks.append(True)
        return None
    monkeypatch.setattr(draft, "read_protection_key", key_unavailable)
    monkeypatch.setattr(draft, "_read_private", lambda *a, **kw: pytest.fail("draft read before protection"))
    monkeypatch.setattr(export, "read_draft_review_inputs", draft.read_draft_review_inputs)
    monkeypatch.setattr(export, "collect_hardware_observations", lambda **kw: pytest.fail("inventory read"))
    monkeypatch.setattr(export, "retain_proposal_context", lambda **kw: pytest.fail("write attempted"))
    assert export.run("private-identity-sentinel", None) == 1
    output = capsys.readouterr()
    assert output.err == f"Proposal export refused: {expected}. No activation attempted.\n"
    assert output.out == ""
    assert key_checks == ([True] if case == "key" else [])
    assert list(tmp_path.iterdir()) == []


def test_draft_input_reasons_are_closed():
    with pytest.raises(ValueError, match="unreviewed draft input reason"):
        draft.DraftInputRefused("private-identity-sentinel")
