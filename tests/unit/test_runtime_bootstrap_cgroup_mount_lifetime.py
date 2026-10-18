"""Synthetic lifecycle and kernel-source tests for cgroup mount admission.

No test here opens /proc or /sys, consults a service manager, or mounts a
filesystem. The fixed-root and mount-identity observations are replaced with
controlled test seams; procfs reads use temporary ordinary files.
"""

import os
import stat

import pytest

from azazel_nexus_runtime import bootstrap_cgroup_mount as cgroup_mount
from azazel_nexus_runtime import bootstrap_manager
from azazel_nexus_runtime.units import UnitOperationFailed


def _directory_fd(tmp_path):
    root = tmp_path / "synthetic-cgroup-root"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def _snapshot_for_fd(fd):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, 17, ("cgroup:[1]", "cgroup:[1]"))


def _install_synthetic_opener(monkeypatch, fd, snapshot=None):
    monkeypatch.setattr(cgroup_mount, "_open_fixed_root", lambda: fd)
    monkeypatch.setattr(cgroup_mount, "_snapshot", snapshot or _snapshot_for_fd)


def _is_open(fd):
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True


def test_context_closes_root_after_successful_body(tmp_path, monkeypatch):
    fd = _directory_fd(tmp_path)
    _install_synthetic_opener(monkeypatch, fd)

    with cgroup_mount.open_bootstrap_cgroup_mount() as handle:
        assert handle.fileno() == fd
        handle.check()

    assert not _is_open(fd)


def test_context_closes_root_when_body_raises(tmp_path, monkeypatch):
    fd = _directory_fd(tmp_path)
    _install_synthetic_opener(monkeypatch, fd)
    marker = RuntimeError("body failed")

    with pytest.raises(RuntimeError) as raised:
        with cgroup_mount.open_bootstrap_cgroup_mount():
            raise marker

    assert raised.value is marker
    assert not _is_open(fd)


def test_context_closes_root_when_initial_admission_fails(tmp_path, monkeypatch):
    fd = _directory_fd(tmp_path)
    _install_synthetic_opener(
        monkeypatch, fd,
        snapshot=lambda _fd: (_ for _ in ()).throw(
            UnitOperationFailed("synthetic admission failure")
        ),
    )

    with pytest.raises(UnitOperationFailed, match="synthetic admission failure"):
        with cgroup_mount.open_bootstrap_cgroup_mount():
            pytest.fail("body must not run when initial admission fails")

    assert not _is_open(fd)


def test_handle_check_rejects_stale_mount_identity(tmp_path, monkeypatch):
    fd = _directory_fd(tmp_path)
    snapshots = iter((
        _snapshot_for_fd(fd),
        _snapshot_for_fd(fd),
        (1, 2, 18, ("cgroup:[1]", "cgroup:[1]")),
    ))
    _install_synthetic_opener(monkeypatch, fd, snapshot=lambda _fd: next(snapshots))

    with pytest.raises(UnitOperationFailed, match="identity changed"):
        with cgroup_mount.open_bootstrap_cgroup_mount() as handle:
            handle.check()

    assert not _is_open(fd)


def test_handle_rejects_use_after_context_close(tmp_path, monkeypatch):
    fd = _directory_fd(tmp_path)
    _install_synthetic_opener(monkeypatch, fd)

    with cgroup_mount.open_bootstrap_cgroup_mount() as handle:
        pass

    with pytest.raises(UnitOperationFailed):
        handle.check()
    with pytest.raises(UnitOperationFailed):
        handle.fileno()
    assert not _is_open(fd)


def test_fixed_root_opener_failure_does_not_leak_descriptor(tmp_path, monkeypatch):
    fd = _directory_fd(tmp_path)

    def fail_open():
        raise OSError("synthetic fixed-root failure")

    monkeypatch.setattr(cgroup_mount, "_open_fixed_root", fail_open)
    with pytest.raises(UnitOperationFailed, match="admission unavailable"):
        with cgroup_mount.open_bootstrap_cgroup_mount():
            pytest.fail("body must not run when opening fails")
    assert _is_open(fd)  # The unrelated fixture descriptor remains caller-owned.
    os.close(fd)


def test_kernel_source_reader_is_path_fixed_by_caller_and_bounded(tmp_path, monkeypatch):
    source = tmp_path / "synthetic-proc-source"
    source.write_bytes(b"kernel-owned fixture\n")
    opened = []
    real_open = os.open

    def tracked_open(path, flags, *args, **kwargs):
        opened.append(path)
        return real_open(source, flags, *args, **kwargs)

    monkeypatch.setattr(cgroup_mount.os, "open", tracked_open)
    monkeypatch.setattr(cgroup_mount, "_filesystem_type", lambda _fd: cgroup_mount._PROC_MAGIC)

    assert cgroup_mount._read_proc("synthetic-kernel-source", 64) == b"kernel-owned fixture\n"
    assert opened == ["synthetic-kernel-source"]

    source.write_bytes(b"x" * 65)
    with pytest.raises(UnitOperationFailed, match="exceeds bound"):
        cgroup_mount._read_proc("synthetic-kernel-source", 64)


def test_kernel_source_reader_rejects_wrong_filesystem_and_closes_fd(tmp_path, monkeypatch):
    source = tmp_path / "synthetic-not-proc"
    source.write_bytes(b"not procfs")
    opened = []
    closed = []
    real_open = os.open
    real_close = os.close

    def tracked_open(path, flags, *args, **kwargs):
        fd = real_open(source, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(cgroup_mount.os, "open", tracked_open)
    monkeypatch.setattr(cgroup_mount.os, "close", tracked_close)
    monkeypatch.setattr(cgroup_mount, "_filesystem_type", lambda _fd: 0x12345678)

    with pytest.raises(UnitOperationFailed, match="kernel procfs source required"):
        cgroup_mount._read_proc("synthetic-kernel-source", 64)

    assert len(opened) == 1
    assert closed == opened
    assert not _is_open(opened[0])


def _namespace_fixtures(tmp_path):
    target_a = tmp_path / "namespace-target-a"
    target_a.write_text("synthetic namespace target")
    parents = {}
    for process, target in (("self", target_a),):
        parent = tmp_path / f"proc-{process}" / "ns"
        parent.mkdir(parents=True)
        (parent / "cgroup").symlink_to(target)
        parents[f"/proc/{process}/ns"] = parent
    return parents


def _redirect_namespace_opens(monkeypatch, parents):
    opened = []
    real_open = os.open

    def redirected_open(path, flags, *args, **kwargs):
        if type(path) is str and path.startswith("/proc/"):
            opened.append(path)
            assert path in parents, "unexpected absolute proc access"
            path = parents[path]
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(cgroup_mount.os, "open", redirected_open)
    return opened


def test_namespace_reader_rejects_ordinary_parent_directory(tmp_path, monkeypatch):
    parents = _namespace_fixtures(tmp_path)
    opened = _redirect_namespace_opens(monkeypatch, parents)
    monkeypatch.setattr(cgroup_mount, "_filesystem_type", lambda _fd: 0x1234)

    with pytest.raises(UnitOperationFailed, match="kernel namespace source required"):
        cgroup_mount._namespaces()

    assert opened == ["/proc/self/ns"]


def test_namespace_reader_rejects_ordinary_target_file(tmp_path, monkeypatch):
    parents = _namespace_fixtures(tmp_path)
    opened = _redirect_namespace_opens(monkeypatch, parents)
    # fd links are intentionally not consulted: distinguish the synthetic
    # parent directories from target files by their descriptor mode.
    monkeypatch.setattr(
        cgroup_mount,
        "_filesystem_type",
        lambda fd: cgroup_mount._PROC_MAGIC if stat.S_ISDIR(os.fstat(fd).st_mode) else 0x1234,
    )

    with pytest.raises(UnitOperationFailed, match="kernel namespace descriptor required"):
        cgroup_mount._namespaces()

    assert opened == ["/proc/self/ns"]


def _manager_with_mount(handle, session_factory):
    return bootstrap_manager.BootstrapNarrowingManager(
        job_timeout_seconds=5.0,
        session_factory=session_factory,
        cgroup_mount=handle,
    )


def test_manager_closed_mount_refuses_empty_confirmation_before_bus(
    tmp_path, monkeypatch
):
    fd = _directory_fd(tmp_path)
    _install_synthetic_opener(monkeypatch, fd)
    # Deliberately model a synthetic caller-owned directory as root-owned;
    # this test is about handle lifetime, not filesystem ownership policy.
    monkeypatch.setattr(
        bootstrap_manager, "validate_cgroup_root", lambda descriptor, _owner: os.fstat(descriptor)
    )
    sessions = []

    def factory():
        sessions.append("opened")
        raise AssertionError("closed mount must refuse before bus session")

    with cgroup_mount.open_bootstrap_cgroup_mount() as handle:
        manager = _manager_with_mount(handle, factory)

    assert not _is_open(fd)
    with pytest.raises(UnitOperationFailed):
        manager.confirm_empty_pair()
    assert sessions == []


def test_manager_replaced_mount_identity_refuses_empty_confirmation_before_bus(
    tmp_path, monkeypatch
):
    fd = _directory_fd(tmp_path)
    state = {"changed": False}

    def snapshot(descriptor):
        identity = _snapshot_for_fd(descriptor)
        if state["changed"]:
            return (*identity[:2], identity[2] + 1, identity[3])
        return identity

    _install_synthetic_opener(monkeypatch, fd, snapshot=snapshot)
    monkeypatch.setattr(
        bootstrap_manager, "validate_cgroup_root", lambda descriptor, _owner: os.fstat(descriptor)
    )
    sessions = []

    def factory():
        sessions.append("opened")
        raise AssertionError("replaced mount must refuse before bus session")

    try:
        with cgroup_mount.open_bootstrap_cgroup_mount() as handle:
            manager = _manager_with_mount(handle, factory)
            state["changed"] = True
            with pytest.raises(UnitOperationFailed, match="identity changed"):
                manager.confirm_empty_pair()
            assert sessions == []
    finally:
        assert not _is_open(fd)
