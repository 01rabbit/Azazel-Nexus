"""Descriptor and flock behavior for the protected bootstrap transaction."""

from contextlib import contextmanager
import inspect
import multiprocessing
import os
import stat

import pytest

from azazel_nexus import bootstrap_lock
from azazel_nexus.operator_trust import ApprovalRefused


@contextmanager
def _directory_fd(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        yield fd
    finally:
        os.close(fd)


def _reopen_path(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def _spawn_contender(path, ready, result):
    """Independent spawned process: flock is associated with its open FD."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    ready.set()
    try:
        try:
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid(), reopen=lambda: _reopen_path(path)
            ):
                result.put("acquired")
        except (ApprovalRefused, BlockingIOError):
            result.put("refused")
    finally:
        os.close(fd)


@pytest.fixture
def private_dir(tmp_path):
    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _enter(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    return fd, bootstrap_lock._transaction_at(
        fd, owner=os.getuid(), reopen=lambda: _reopen_path(path)
    )


def test_transaction_acquires_and_retains_lock_inode(private_dir):
    fd, transaction = _enter(private_dir)
    try:
        with transaction as check:
            check()
            info = os.stat("supervisor.lock", dir_fd=fd, follow_symlinks=False)
            assert stat.S_ISREG(info.st_mode)
            assert info.st_mode & 0o777 == 0o600
            identity = info.st_dev, info.st_ino
        after = os.stat("supervisor.lock", dir_fd=fd, follow_symlinks=False)
        assert (after.st_dev, after.st_ino) == identity
    finally:
        os.close(fd)


def test_separate_descriptor_in_same_process_contends_and_reacquires(private_dir):
    with (
        _directory_fd(private_dir) as first_fd,
        _directory_fd(private_dir) as second_fd,
    ):
        with bootstrap_lock._transaction_at(
            first_fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
        ):
            with pytest.raises((ApprovalRefused, BlockingIOError)):
                with bootstrap_lock._transaction_at(
                    second_fd,
                    owner=os.getuid(),
                    reopen=lambda: _reopen_path(private_dir),
                ):
                    pytest.fail("contending transaction yielded")
        with bootstrap_lock._transaction_at(
            second_fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
        ) as check:
            check()


@pytest.mark.real_process
def test_spawned_process_cannot_enter_while_lock_is_held(private_dir):
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    result = context.Queue()
    process = None
    with _directory_fd(private_dir) as fd:
        try:
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
            ):
                process = context.Process(
                    target=_spawn_contender, args=(str(private_dir), ready, result)
                )
                process.start()
                assert ready.wait(5), "spawned contender did not start"
                process.join(5)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
                    pytest.fail("spawned contender did not finish within timeout")
                assert process.exitcode == 0
                assert result.get(timeout=2) == "refused"
        finally:
            if process is not None and process.is_alive():
                process.terminate()
                process.join(5)
            result.close()
            result.join_thread()


def test_replacement_between_acquisition_and_validation_never_yields(
    private_dir, monkeypatch
):
    flock = bootstrap_lock.fcntl.flock

    def raced(fd, operation):
        flock(fd, operation)
        (private_dir / "supervisor.lock").rename(private_dir / "old.lock")
        (private_dir / "supervisor.lock").touch(mode=0o600)

    monkeypatch.setattr(bootstrap_lock.fcntl, "flock", raced)
    with _directory_fd(private_dir) as fd:
        with pytest.raises(ApprovalRefused):
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
            ):
                pytest.fail("raced acquisition must not yield")
    assert (private_dir / "old.lock").exists()
    assert (private_dir / "supervisor.lock").exists()


def test_directory_replacement_is_refused(private_dir, tmp_path):
    moved = tmp_path / "moved"
    replacement = private_dir
    fd = os.open(private_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(ApprovalRefused):
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid(), reopen=lambda: _reopen_path(replacement)
            ) as check:
                os.rename(private_dir, moved)
                replacement.mkdir(mode=0o700)
                replacement.chmod(0o700)
                check()
    finally:
        os.close(fd)


@pytest.mark.parametrize("replacement_kind", ["regular", "symlink", "hardlink"])
def test_lock_file_replacement_is_refused(private_dir, tmp_path, replacement_kind):
    fd, transaction = _enter(private_dir)
    try:
        with pytest.raises(ApprovalRefused):
            with transaction as check:
                lock_path = private_dir / "supervisor.lock"
                original = tmp_path / "original-lock"
                os.rename(lock_path, original)
                if replacement_kind == "regular":
                    lock_path.touch(mode=0o600)
                elif replacement_kind == "symlink":
                    lock_path.symlink_to(original)
                else:
                    os.link(original, lock_path)
                check()
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "case", ["symlink", "hardlink", "nonprivate", "nonempty", "wrongowner"]
)
def test_invalid_existing_lock_is_refused(private_dir, case):
    lock_path = private_dir / "supervisor.lock"
    if case == "symlink":
        target = private_dir / "target"
        target.touch(mode=0o600)
        lock_path.symlink_to(target)
    elif case == "hardlink":
        target = private_dir / "target"
        target.touch(mode=0o600)
        os.link(target, lock_path)
    elif case == "nonprivate":
        lock_path.touch(mode=0o600)
        lock_path.chmod(0o640)
    elif case == "nonempty":
        lock_path.write_text("occupied")
        lock_path.chmod(0o600)
    else:
        lock_path.touch(mode=0o600)
    with _directory_fd(private_dir) as fd:
        owner = os.getuid() + 1 if case == "wrongowner" else os.getuid()
        with pytest.raises((ApprovalRefused, OSError)):
            with bootstrap_lock._transaction_at(
                fd, owner=owner, reopen=lambda: _reopen_path(private_dir)
            ):
                pytest.fail("invalid lock yielded")


def test_nonprivate_directory_and_wrong_directory_owner_are_refused(private_dir):
    with _directory_fd(private_dir) as fd:
        private_dir.chmod(0o750)
        with pytest.raises(ApprovalRefused):
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
            ):
                pytest.fail("nonprivate directory yielded")
        private_dir.chmod(0o700)
        with pytest.raises(ApprovalRefused):
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid() + 1, reopen=lambda: _reopen_path(private_dir)
            ):
                pytest.fail("wrong-owner directory yielded")


def test_validation_after_release_is_refused(private_dir):
    fd, transaction = _enter(private_dir)
    try:
        with transaction as check:
            pass
        with pytest.raises(ApprovalRefused):
            check()
    finally:
        os.close(fd)


def test_released_callback_stays_invalid_during_next_reacquisition(private_dir):
    with _directory_fd(private_dir) as fd:
        with bootstrap_lock._transaction_at(
            fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
        ) as stale_check:
            stale_check()
        with bootstrap_lock._transaction_at(
            fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
        ) as current_check:
            current_check()
            with pytest.raises(ApprovalRefused):
                stale_check()


def test_path_replacement_does_not_override_inflight_exception(private_dir, tmp_path):
    moved = tmp_path / "moved-for-exception"
    fd = os.open(private_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(RuntimeError, match="containment failure"):
            with bootstrap_lock._transaction_at(
                fd, owner=os.getuid(), reopen=lambda: _reopen_path(private_dir)
            ):
                os.rename(private_dir, moved)
                private_dir.mkdir(mode=0o700)
                private_dir.chmod(0o700)
                raise RuntimeError("containment failure")
    finally:
        os.close(fd)


def test_public_api_uses_fixed_owner_and_no_overrides(monkeypatch, private_dir):
    opened = []

    def open_fixture():
        fd = os.open(private_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        opened.append(fd)
        return fd

    monkeypatch.setattr(bootstrap_lock, "_open_directory", open_fixture)
    original_transaction = bootstrap_lock._transaction_at

    @contextmanager
    def fixed_owner_transaction(fd, *, owner, reopen):
        assert owner == 0
        with original_transaction(fd, owner=os.getuid(), reopen=reopen) as check:
            yield check

    monkeypatch.setattr(bootstrap_lock, "_transaction_at", fixed_owner_transaction)
    with bootstrap_lock.bootstrap_transaction() as check:
        check()
    assert len(opened) >= 1
    assert _is_closed(opened[0])
    assert not inspect.signature(bootstrap_lock.bootstrap_transaction).parameters


def _is_closed(fd):
    try:
        os.fstat(fd)
    except OSError:
        return True
    return False
