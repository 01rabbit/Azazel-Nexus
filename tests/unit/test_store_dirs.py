"""fsync_directory: the durability step store writers take after a rename.

A missing directory fsync changes nothing a test can read back, so these tests
watch the call itself: the directory's own descriptor is synced, a failure
reaches the caller, and a symlink is not followed.
"""

import os
import stat

import pytest

from azazel_nexus import store_dirs


def _tracked(monkeypatch, module_os, *, fail=False):
    opened, closed, synced = [], [], []
    real_open, real_close, real_fsync = os.open, os.close, os.fsync

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    def tracking_close(fd):
        closed.append(fd)
        real_close(fd)

    def tracking_fsync(fd):
        info = os.fstat(fd)
        synced.append((info.st_dev, info.st_ino, stat.S_ISDIR(info.st_mode)))
        if fail:
            raise OSError("synthetic directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(module_os, "open", tracking_open)
    monkeypatch.setattr(module_os, "close", tracking_close)
    monkeypatch.setattr(module_os, "fsync", tracking_fsync)
    return opened, closed, synced


def test_fsync_directory_syncs_that_directory_once_and_closes_it(
    tmp_path, monkeypatch, private_os,
):
    opened, closed, synced = _tracked(monkeypatch, private_os(store_dirs))

    store_dirs.fsync_directory(tmp_path)

    target = os.stat(tmp_path)
    assert synced == [(target.st_dev, target.st_ino, True)]
    assert len(opened) == 1 and closed == opened


def test_fsync_directory_failure_reaches_the_caller_and_still_closes(
    tmp_path, monkeypatch, private_os,
):
    # Callers report uncertain durability from this error; it must not vanish.
    opened, closed, synced = _tracked(monkeypatch, private_os(store_dirs), fail=True)

    with pytest.raises(OSError, match="synthetic directory fsync failure"):
        store_dirs.fsync_directory(tmp_path)

    assert len(synced) == 1
    assert len(opened) == 1 and closed == opened


def test_fsync_directory_does_not_follow_a_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(OSError):
        store_dirs.fsync_directory(link)
