from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_generation import VerifiedBootstrapGeneration
from azazel_nexus.installed_files import SelectedInstalledFiles
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.debian_packages import parse_package_output
from azazel_nexus_runtime import bootstrap_inputs as inputs
from test_bootstrap_generation import NOW, _context


@pytest.fixture(autouse=True)
def installed_file_measurement(monkeypatch):
    monkeypatch.setattr(
        inputs,
        "measure_bootstrap_installed_files",
        lambda context: SelectedInstalledFiles(context.unit_closure_digest, 2, 128),
    )


def _package_context():
    package = parse_package_output(b"dpkg\t1.22.22\tamd64\tii \n")
    return replace(_context(), package_digest=package.digest), package


def test_reads_protected_generation_before_and_after_semantic_admission(monkeypatch):
    context, package = _package_context()
    verified = VerifiedBootstrapGeneration(context.generation, context.generation_digest, NOW)
    calls = []
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: package)

    def reader(*, expected):
        assert expected is context
        calls.append("read")
        return verified

    def admit(expected, observed):
        assert expected is context and observed is verified
        calls.append("admit")

    monkeypatch.setattr(inputs, "load_bootstrap_generation", reader)
    assert inputs.ProtectedBootstrapGenerationAdmission(admit)(context) is verified
    assert calls == ["read", "admit", "read"]


@pytest.mark.parametrize("result", [True, False, 1, "admitted", {}, object()])
def test_truthy_or_falsey_permission_flags_are_not_semantic_admission(monkeypatch, result):
    context, package = _package_context()
    verified = VerifiedBootstrapGeneration(context.generation, context.generation_digest, NOW)
    monkeypatch.setattr(inputs, "load_bootstrap_generation", lambda **_: verified)
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: package)
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapGenerationAdmission(lambda *_: result)(context)


@pytest.mark.parametrize("stage", ["read-before", "admit", "read-after", "changed-after"])
def test_any_read_or_admission_failure_refuses_without_success(monkeypatch, stage):
    context, package = _package_context()
    verified = VerifiedBootstrapGeneration(context.generation, context.generation_digest, NOW)
    calls = []
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: package)

    def read(**_):
        calls.append("read")
        if stage == "read-before" or (stage == "read-after" and len(calls) == 3):
            raise RuntimeError("private detail")
        if stage == "changed-after" and len(calls) == 3:
            return replace(verified, created_at="2026-10-14T00:00:00Z")
        return verified

    def admit(*_):
        calls.append("admit")
        if stage == "admit":
            raise RuntimeError("private detail")

    monkeypatch.setattr(inputs, "load_bootstrap_generation", read)
    with pytest.raises(ApprovalRefused) as error:
        inputs.ProtectedBootstrapGenerationAdmission(admit)(context)
    assert "private detail" not in str(error.value)
    assert calls == (["read"] if stage == "read-before" else
                     ["read", "admit"] if stage == "admit" else ["read", "admit", "read"])


def test_missing_semantic_checker_has_no_default():
    with pytest.raises(TypeError):
        inputs.ProtectedBootstrapGenerationAdmission()
    with pytest.raises(ValueError):
        inputs.ProtectedBootstrapGenerationAdmission(None)


@pytest.mark.parametrize("change_during_admission", [False, True])
def test_adapter_uses_real_protected_reader_on_ordinary_files(
    tmp_path, monkeypatch, change_during_admission
):
    from test_bootstrap_generation_store import _public_reader, _store

    _, package = _package_context()
    root, context, _ = _store(tmp_path, package_digest=package.digest)
    _public_reader(monkeypatch, root)
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: package)
    admitted = []

    def admit(expected, observed):
        admitted.append((expected, observed))
        if change_during_admission:
            (root / "7/tree/bootstrap.json").write_bytes(b"{}")

    adapter = inputs.ProtectedBootstrapGenerationAdmission(admit)
    if change_during_admission:
        with pytest.raises(ApprovalRefused):
            adapter(context)
    else:
        result = adapter(context)
        assert result == admitted[0][1]
    assert len(admitted) == 1 and admitted[0][0] == context


def test_package_snapshot_must_match_protected_context_before_semantic_check(monkeypatch):
    context, package = _package_context()
    verified = VerifiedBootstrapGeneration(context.generation, context.generation_digest, NOW)
    monkeypatch.setattr(inputs, "load_bootstrap_generation", lambda **_: verified)
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: replace(
        package, digest="sha256:" + "9" * 64
    ))
    called = []
    adapter = inputs.ProtectedBootstrapGenerationAdmission(lambda *_: called.append(True))
    with pytest.raises(ApprovalRefused):
        adapter(context)
    assert called == []


def test_package_snapshot_is_remeasured_after_semantic_check(monkeypatch):
    context, package = _package_context()
    verified = VerifiedBootstrapGeneration(context.generation, context.generation_digest, NOW)
    changed = parse_package_output(b"dpkg\t1.22.22\tarm64\tii \n")
    snapshots = iter((package, changed))
    monkeypatch.setattr(inputs, "load_bootstrap_generation", lambda **_: verified)
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: next(snapshots))
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapGenerationAdmission(lambda *_: None)(context)
