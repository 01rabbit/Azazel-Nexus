"""Protected-tree tests for the fixed CPython startup-override absence set."""

import errno
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import python_startup
from azazel_nexus_runtime.python_startup import (
    StartupAbsence,
    _observe_at,
    observe_python_startup_absence,
    startup_absence_paths,
)


INTERPRETER = "/opt/env/bin/python"
EXPECTED_PATHS = (
    "opt/env/bin/python._pth",
    "usr/bin/Modules/Setup.local",
    "usr/bin/pybuilddir.txt",
    "usr/bin/python3.13._pth",
    "usr/lib/python313.zip",
)


def _absence(interpreter="/opt/env/bin/python"):
    paths = startup_absence_paths(interpreter)
    placeholder = tuple((path, 0, ()) for path in paths)
    return StartupAbsence(paths, placeholder)


def _mkdir(path, *, root):
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while True:
        current.chmod(0o755)
        if current == root:
            break
        current = current.parent


def _open_root(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def test_fixed_absence_paths_are_exact_and_sorted():
    assert startup_absence_paths(INTERPRETER) == EXPECTED_PATHS
    assert startup_absence_paths(INTERPRETER) == tuple(sorted(EXPECTED_PATHS))


@pytest.mark.parametrize("interpreter", [
    None,
    b"/opt/env/bin/python",
    "/usr/bin/python3.13",
    "/opt/env/bin/python3.12",
    "/opt/env/../evil/bin/python",
])
def test_absence_paths_refuse_unsupported_interpreter_layout(interpreter):
    with pytest.raises((ApprovalRefused, ValueError)):
        startup_absence_paths(interpreter)


def test_fixture_helper_returns_immutable_placeholder_for_mocked_consumers():
    absence = _absence()
    assert type(absence) is StartupAbsence
    assert absence.paths == EXPECTED_PATHS
    assert type(absence.paths) is tuple
    assert type(absence.observations) is tuple
    assert len(absence.observations) == len(EXPECTED_PATHS)
    assert _absence("/opt/other/bin/python3.13").paths != absence.paths


@pytest.mark.parametrize("existing", ["empty-file", "file", "directory", "symlink", "dangling"])
def test_any_present_leaf_refuses_even_if_empty_or_unreadable(tmp_path, existing):
    leaf = tmp_path / EXPECTED_PATHS[0]
    _mkdir(leaf.parent, root=tmp_path)
    if existing == "empty-file":
        leaf.write_bytes(b"")
    elif existing == "file":
        leaf.write_bytes(b"synthetic override")
    elif existing == "directory":
        _mkdir(leaf, root=tmp_path)
    elif existing == "symlink":
        leaf.symlink_to("target")
    else:
        leaf.symlink_to("missing-target")

    root_fd = _open_root(tmp_path)
    try:
        with pytest.raises(ApprovalRefused):
            _observe_at(root_fd, INTERPRETER, owner=os.getuid())
    finally:
        os.close(root_fd)


@pytest.mark.parametrize("layout", ["empty-root", "missing-intermediate", "partial"])
def test_protected_tree_with_missing_leaf_and_intermediate_is_absent(tmp_path, layout):
    if layout == "missing-intermediate":
        _mkdir(tmp_path / "opt", root=tmp_path)
    elif layout == "partial":
        for relative in ("opt/env/bin", "usr/bin/Modules", "usr/lib"):
            _mkdir(tmp_path / relative, root=tmp_path)

    root_fd = _open_root(tmp_path)
    try:
        absence = _observe_at(root_fd, INTERPRETER, owner=os.getuid())
    finally:
        os.close(root_fd)

    assert absence.paths == EXPECTED_PATHS
    assert len(absence.observations) == 5
    assert all(item[0] in EXPECTED_PATHS for item in absence.observations)


@pytest.mark.parametrize("unsafe", ["writable-mode", "symlink", "wrong-owner"])
def test_unsafe_root_or_ancestor_refuses_absence(tmp_path, unsafe):
    if unsafe == "writable-mode":
        ancestor = tmp_path / "opt"
        _mkdir(ancestor, root=tmp_path)
        ancestor.chmod(0o775)
    elif unsafe == "symlink":
        target = tmp_path / "safe-target"
        _mkdir(target, root=tmp_path)
        (tmp_path / "opt").symlink_to(target, target_is_directory=True)

    root_fd = _open_root(tmp_path)
    owner = os.getuid() + 1 if unsafe == "wrong-owner" else os.getuid()
    try:
        with pytest.raises(ApprovalRefused):
            _observe_at(root_fd, INTERPRETER, owner=owner)
    finally:
        os.close(root_fd)


@pytest.mark.parametrize("error_number", [errno.EACCES, errno.EIO])
def test_permission_and_io_errors_are_not_treated_as_absence(tmp_path, monkeypatch, error_number):
    root_fd = _open_root(tmp_path)
    actual_stat = os.stat

    def fail_lookup(path, *args, **kwargs):
        if path == "opt" and kwargs.get("dir_fd") is not None:
            raise OSError(error_number, "synthetic lookup failure")
        return actual_stat(path, *args, **kwargs)

    monkeypatch.setattr(python_startup.os, "stat", fail_lookup)
    try:
        with pytest.raises(OSError) as raised:
            _observe_at(root_fd, INTERPRETER, owner=os.getuid())
    finally:
        os.close(root_fd)
    assert raised.value.errno == error_number


def test_enotdir_during_component_walk_is_not_treated_as_absence(tmp_path, monkeypatch):
    _mkdir(tmp_path / "opt", root=tmp_path)
    root_fd = _open_root(tmp_path)
    actual_stat = os.stat

    def fail_nested_lookup(path, *args, **kwargs):
        if path == "env":
            raise OSError(errno.ENOTDIR, "synthetic non-directory ancestor")
        return actual_stat(path, *args, **kwargs)

    monkeypatch.setattr(python_startup.os, "stat", fail_nested_lookup)
    try:
        with pytest.raises(OSError) as raised:
            _observe_at(root_fd, INTERPRETER, owner=os.getuid())
    finally:
        os.close(root_fd)
    assert raised.value.errno == errno.ENOTDIR


def test_ancestor_identity_replacement_between_snapshots_refuses(tmp_path, monkeypatch):
    _mkdir(tmp_path / "opt", root=tmp_path)
    original_snapshot = python_startup._snapshot_at
    calls = 0

    def replace_ancestor(root_fd, paths, *, owner):
        nonlocal calls
        result = original_snapshot(root_fd, paths, owner=owner)
        calls += 1
        if calls == 1:
            (tmp_path / "opt").rename(tmp_path / "opt-old")
            _mkdir(tmp_path / "opt", root=tmp_path)
        return result

    monkeypatch.setattr(python_startup, "_snapshot_at", replace_ancestor)
    root_fd = _open_root(tmp_path)
    try:
        with pytest.raises(ApprovalRefused):
            _observe_at(root_fd, INTERPRETER, owner=os.getuid())
    finally:
        os.close(root_fd)
    assert calls == 2


def test_missing_component_appearing_between_snapshots_refuses(tmp_path, monkeypatch):
    original_snapshot = python_startup._snapshot_at
    calls = 0

    def add_component(root_fd, paths, *, owner):
        nonlocal calls
        result = original_snapshot(root_fd, paths, owner=owner)
        calls += 1
        if calls == 1:
            _mkdir(tmp_path / "opt", root=tmp_path)
        return result

    monkeypatch.setattr(python_startup, "_snapshot_at", add_component)
    root_fd = _open_root(tmp_path)
    try:
        with pytest.raises(ApprovalRefused):
            _observe_at(root_fd, INTERPRETER, owner=os.getuid())
    finally:
        os.close(root_fd)
    assert calls == 2


@pytest.mark.parametrize("refuse", [False, True])
def test_public_observer_uses_fixed_root_and_redacts_refusal(monkeypatch, refuse):
    opened = []
    closed = []
    real_open, real_close, real_stat, real_fstat = os.open, os.close, os.stat, os.fstat

    def fixed_root(path, flags, *args, **kwargs):
        opened.append(path)
        if path != "/":
            raise AssertionError("observer attempted a non-fixed root")
        return 91

    monkeypatch.setattr(python_startup.os, "open", fixed_root)
    monkeypatch.setattr(python_startup.os, "close", closed.append)
    monkeypatch.setattr(python_startup.os, "fstat", lambda fd: (
        SimpleNamespace() if fd == 91 else real_fstat(fd)
    ))
    monkeypatch.setattr(python_startup.os, "stat", lambda path, *args, **kwargs: (
        SimpleNamespace() if path == "/" else real_stat(path, *args, **kwargs)
    ))
    monkeypatch.setattr(python_startup, "_stamp", lambda *_args, **_kwargs: (1,))
    def observe(root_fd, interpreter, *, owner):
        assert root_fd == 91 and owner == 0
        if refuse:
            raise OSError("synthetic sensitive detail must not escape")
        return _absence(interpreter)

    monkeypatch.setattr(python_startup, "_observe_at", observe)

    if refuse:
        with pytest.raises(ApprovalRefused, match="^protected Python startup absence refused$"):
            observe_python_startup_absence(INTERPRETER)
    else:
        result = observe_python_startup_absence(INTERPRETER)
        assert result == _absence(INTERPRETER)
    assert opened == ["/"]
    assert closed == [91]
    assert real_open and real_close
