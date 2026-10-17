"""Durable one-shot marker tests for the private controller start gate."""

import os
import stat

import pytest

from azazel_nexus import bootstrap_controller_once as controller_once
from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.operator_trust import ApprovalRefused


_NAME = "controller-used"
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@pytest.fixture
def protected_directory(tmp_path):
    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    fd = os.open(directory, _FLAGS)

    def reopen():
        return os.open(directory, _FLAGS)

    guard = BootstrapTransactionGuard(lambda: None)
    try:
        yield directory, fd, reopen, guard
    finally:
        os.close(fd)


def _enter(directory_fd, reopen, guard, *, owner=None):
    return controller_once._controller_once_at(
        directory_fd,
        owner=os.getuid() if owner is None else owner,
        reopen=reopen,
        guard=guard,
    )


def test_first_entry_creates_durable_private_empty_marker_and_guard(
    protected_directory,
):
    directory, fd, reopen, guard = protected_directory

    with _enter(fd, reopen, guard) as retained:
        assert type(retained) is BootstrapTransactionGuard
        retained()

    marker = directory / _NAME
    info = marker.stat(follow_symlinks=False)
    assert stat.S_ISREG(info.st_mode)
    assert info.st_nlink == 1
    assert info.st_uid == os.getuid()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert marker.read_bytes() == b""


def test_second_entry_refuses_and_never_removes_existing_marker(protected_directory):
    directory, fd, reopen, guard = protected_directory
    with _enter(fd, reopen, guard):
        pass
    marker = directory / _NAME
    original = marker.stat()

    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard):
            pytest.fail("one-shot context must not be entered twice")

    current = marker.stat(follow_symlinks=False)
    assert marker.read_bytes() == b""
    assert (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)


def test_preexisting_marker_is_not_overwritten_or_removed(protected_directory):
    directory, fd, reopen, guard = protected_directory
    marker = directory / _NAME
    marker.write_bytes(b"existing evidence")

    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard):
            pytest.fail("preexisting marker must refuse")

    assert marker.read_bytes() == b"existing evidence"


@pytest.mark.parametrize("bad", [None, object(), lambda: False])
def test_guard_must_be_exact_bootstrap_transaction_guard(protected_directory, bad):
    _directory, fd, reopen, _guard = protected_directory
    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, bad):
            pytest.fail("invalid guard must refuse before entry")


@pytest.mark.parametrize("change", ["replace", "mode", "content", "symlink"])
def test_retained_guard_refuses_marker_replacement_or_mutation(
    protected_directory, change,
):
    directory, fd, reopen, guard = protected_directory
    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard) as retained:
            marker = directory / _NAME
            if change == "replace":
                marker.rename(directory / "old-marker")
                marker.write_bytes(b"")
                marker.chmod(0o600)
            elif change == "mode":
                marker.chmod(0o640)
            elif change == "content":
                marker.write_bytes(b"not empty")
            else:
                marker.unlink()
                marker.symlink_to(directory / "target")
            retained()

    # The original marker is one-shot evidence: no failure path cleans it up.
    if change == "replace":
        assert (directory / "old-marker").exists()


def test_retained_guard_refuses_reopened_directory_replacement(protected_directory):
    directory, fd, reopen, guard = protected_directory
    moved = directory.with_name("bootstrap-old")
    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard) as retained:
            directory.rename(moved)
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            retained()

    assert (moved / _NAME).read_bytes() == b""
    assert not (directory / _NAME).exists()


@pytest.mark.parametrize("change", ["mode", "owner"])
def test_protected_directory_requirements_refuse_before_marker(
    protected_directory, change,
):
    directory, fd, reopen, guard = protected_directory
    if change == "mode":
        directory.chmod(0o750)
        owner = os.getuid()
    else:
        owner = os.getuid() + 1

    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard, owner=owner):
            pytest.fail("unprotected directory must refuse")
    assert not (directory / _NAME).exists()


@pytest.mark.parametrize("failure", ["file-fsync", "directory-fsync"])
def test_creation_fsync_failure_leaves_marker_for_fail_closed_retry(
    protected_directory, monkeypatch, failure,
):
    directory, fd, reopen, guard = protected_directory
    original_fsync = controller_once.os.fsync

    def fail_selected(descriptor):
        info = os.fstat(descriptor)
        selected = (stat.S_ISREG(info.st_mode) if failure == "file-fsync"
                    else stat.S_ISDIR(info.st_mode))
        if selected:
            raise OSError("injected marker durability failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(controller_once.os, "fsync", fail_selected)
    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard):
            pytest.fail("failed fsync must refuse")

    marker = directory / _NAME
    assert marker.exists() and marker.read_bytes() == b""
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    monkeypatch.setattr(controller_once.os, "fsync", original_fsync)
    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard):
            pytest.fail("uncertain marker must keep future entry refused")


def test_invalidated_enclosing_guard_refuses_entry_without_marker(protected_directory):
    directory, fd, reopen, _guard = protected_directory
    valid = True

    def check():
        if not valid:
            raise ApprovalRefused("transaction ended")

    guard = BootstrapTransactionGuard(check)
    valid = False
    with pytest.raises(ApprovalRefused):
        with _enter(fd, reopen, guard):
            pytest.fail("invalid enclosing transaction must refuse")
    assert not (directory / _NAME).exists()
