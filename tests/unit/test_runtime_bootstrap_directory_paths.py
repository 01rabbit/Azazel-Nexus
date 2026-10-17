"""Retained fixed bootstrap directory observations on private test trees."""

from contextlib import contextmanager
import os
import operator
from pathlib import Path
import stat

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_directory_paths as paths


def _private(path):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _tree(tmp_path, relative):
    root = _private(tmp_path.resolve())
    current = root
    for part in Path(relative).parts[:-1]:
        current = _private(current / part)
    return root, current


def test_present_and_missing_optional_leaf_have_retained_observations(tmp_path):
    root, parent = _tree(tmp_path, "a/leaf")
    leaf = _private(parent / "leaf")
    with paths._directory_under(root, "a/leaf", owner_uid=os.getuid(), optional=True) as (retained, fd):
        assert type(fd) is paths.PresentBootstrapDirectory
        assert stat.S_ISDIR(os.fstat(fd).st_mode)
        assert retained.path == leaf
        retained.check()

    (parent / "leaf").rmdir()
    with paths._directory_under(root, "a/leaf", owner_uid=os.getuid(), optional=True) as (retained, witness):
        assert type(witness) is paths.AbsentBootstrapDirectory
        with pytest.raises(TypeError):
            operator.index(witness)
        assert witness.stamp(os.getuid())[0] == "absent"
        witness.bind(leaf)
        retained.check()


@pytest.mark.parametrize("relative,optional", [("missing", False), ("missing/leaf", True)])
def test_missing_mandatory_or_intermediate_directory_refuses(tmp_path, relative, optional):
    root = _private(tmp_path.resolve())
    with pytest.raises(ApprovalRefused):
        with paths._directory_under(root, relative, owner_uid=os.getuid(), optional=optional):
            pass


@pytest.mark.parametrize("where", ["final", "intermediate"])
def test_symlink_component_refuses(tmp_path, where):
    root = _private(tmp_path.resolve())
    target = _private(root / "target")
    if where == "final":
        (root / "leaf").symlink_to(target, target_is_directory=True)
        relative = "leaf"
    else:
        (root / "link").symlink_to(target, target_is_directory=True)
        relative = "link/leaf"
    with pytest.raises(ApprovalRefused):
        with paths._directory_under(root, relative, owner_uid=os.getuid(), optional=True):
            pass


@pytest.mark.parametrize("mode", [0o777, 0o720, 0o700])
def test_unsafe_mode_or_owner_refuses(tmp_path, mode):
    root, parent = _tree(tmp_path, "leaf")
    leaf = _private(parent / "leaf")
    leaf.chmod(mode)
    uid = os.getuid()
    expected_uid = uid + 1 if mode == 0o700 else uid
    with pytest.raises(ApprovalRefused):
        with paths._directory_under(root, "leaf", owner_uid=expected_uid, optional=False):
            pass


@pytest.mark.parametrize("kind", ["directory", "file", "dangling_symlink"])
def test_appearance_of_optional_leaf_invalidates_witness(tmp_path, kind):
    root, parent = _tree(tmp_path, "leaf")
    leaf = parent / "leaf"
    with paths._directory_under(root, "leaf", owner_uid=os.getuid(), optional=True) as (_retained, witness):
        if kind == "directory":
            _private(leaf)
        elif kind == "file":
            leaf.write_text("x")
        else:
            leaf.symlink_to(parent / "absent")
        with pytest.raises(ApprovalRefused):
            witness.stamp(os.getuid())


@pytest.mark.parametrize("replacement", [False, True])
def test_renamed_or_replaced_ancestor_invalidates_retained_path(tmp_path, replacement):
    root, parent = _tree(tmp_path, "ancestor/leaf")
    _private(parent / "leaf")
    with paths._directory_under(root, "ancestor/leaf", owner_uid=os.getuid(), optional=False) as (retained, _fd):
        ancestor = root / "ancestor"
        saved = root / "saved"
        ancestor.rename(saved)
        if replacement:
            _private(ancestor)
            _private(ancestor / "leaf")
        with pytest.raises(ApprovalRefused):
            retained.check()


def test_fd_use_rechecks_renamed_ancestor(tmp_path):
    root, parent = _tree(tmp_path, "ancestor/leaf")
    _private(parent / "leaf")
    with paths._directory_under(root, "ancestor/leaf", owner_uid=os.getuid(), optional=False) as (_retained, handle):
        (root / "ancestor").rename(root / "saved")
        with pytest.raises(ApprovalRefused):
            os.fstat(handle)


def test_context_exit_invalidates_observation_and_closes_descriptor(tmp_path):
    root, parent = _tree(tmp_path, "leaf")
    _private(parent / "leaf")
    with paths._directory_under(root, "leaf", owner_uid=os.getuid(), optional=False) as (retained, handle):
        fd = operator.index(handle)
        retained.check()
    with pytest.raises(ApprovalRefused):
        retained.check()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_absence_witness_refuses_different_path(tmp_path):
    root, _parent = _tree(tmp_path, "leaf")
    with paths._directory_under(root, "leaf", owner_uid=os.getuid(), optional=True) as (_retained, witness):
        with pytest.raises(ApprovalRefused):
            witness.bind(root / "other")


def test_fixed_wrapper_groups_checks_and_uses_declared_paths(tmp_path, monkeypatch):
    observed = []
    root = _private(tmp_path.resolve())
    for relative in ("run", "run/systemd", "run/systemd/system.control",
                     "etc", "etc/systemd", "etc/systemd/system"):
        _private(root / relative)
    for relative in ("etc/systemd/system.control", "run/systemd/transient",
                     "run/systemd/generator.early"):
        _private(root / relative)
    open_overlay = paths._overlay_directories_under

    @contextmanager
    def fixed_overlay(root, *, owner_uid):
        observed.append((root, owner_uid))
        with open_overlay(tmp_path.resolve(), owner_uid=os.getuid()) as directories:
            yield directories

    monkeypatch.setattr(paths, "_overlay_directories_under", fixed_overlay)
    with paths.open_bootstrap_overlay_directories() as result:
        assert result.owner_uid == os.getuid()
        assert type(result.arguments["transient_fd"]) is paths.PresentBootstrapDirectory
        assert stat.S_ISDIR(os.fstat(result.arguments["transient_fd"]).st_mode)
        assert all(len(result.arguments[key + "_fd"]._checks) == 5 for key in paths._PATHS)
        result.check()
        competitor = root / "run/systemd/transient/azazel-auditd.service.d"
        competitor.mkdir()
        with pytest.raises(ApprovalRefused):
            os.fstat(result.arguments["overlay_fd"])
    assert observed == [(Path("/"), 0)]


@pytest.mark.parametrize("directory", ["etc/systemd/system.control", "run/systemd/transient",
                                        "run/systemd/generator.early"])
@pytest.mark.parametrize("name", ["azazel-auditd.service", "azazel-commissiond.service.d"])
def test_fixed_wrapper_rejects_preexisting_optional_competitor(tmp_path, monkeypatch, directory, name):
    root = _private(tmp_path.resolve())
    for relative in ("run", "run/systemd", "run/systemd/system.control",
                     "etc", "etc/systemd", "etc/systemd/system"):
        _private(root / relative)
    for relative in ("etc/systemd/system.control", "run/systemd/transient",
                     "run/systemd/generator.early"):
        _private(root / relative)
    conflict = root / directory / name
    if name.endswith(".d"):
        conflict.mkdir()
    else:
        conflict.write_text("conflict")
    open_overlay = paths._overlay_directories_under

    @contextmanager
    def fixed_overlay(_root, *, owner_uid):
        with open_overlay(root, owner_uid=os.getuid()) as directories:
            yield directories

    monkeypatch.setattr(paths, "_overlay_directories_under", fixed_overlay)
    with pytest.raises(ApprovalRefused):
        with paths.open_bootstrap_overlay_directories():
            pass
