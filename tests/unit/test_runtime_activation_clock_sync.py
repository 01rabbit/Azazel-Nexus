"""The read-only clock-synchronization reader of the pass (#251 M-1).

`docs/activation-observe-baseline.md` §10.1. Temporary files stand in for
`/run/systemd/timesync/synchronized`; the tmp root is resolved first because
the reader follows no symbolic link at any component.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from azazel_nexus_runtime import activation_clock_sync
from azazel_nexus_runtime.activation_clock_sync import (
    TIMESYNC_SYNCHRONIZED,
    ClockNotSynchronized,
    require_clock_synchronized,
)

MODULE = Path(activation_clock_sync.__file__)


@pytest.fixture
def timesync(tmp_path):
    directory = Path(os.path.realpath(tmp_path)) / "run/systemd/timesync"
    directory.mkdir(parents=True, mode=0o755)
    directory.chmod(0o755)
    return directory


def _marker(directory: Path, mode=0o644) -> str:
    marker = directory / "synchronized"
    marker.write_bytes(b"")
    marker.chmod(mode)
    return str(marker)


def test_the_path_is_timesyncds_fixed_marker():
    assert TIMESYNC_SYNCHRONIZED == "/run/systemd/timesync/synchronized"


def test_a_regular_marker_proves_synchronization(timesync):
    assert require_clock_synchronized(_marker(timesync)) is True


def test_a_non_empty_marker_still_counts(timesync):
    path = _marker(timesync)
    Path(path).write_bytes(b"x")
    assert require_clock_synchronized(path) is True


def _refused(path):
    with pytest.raises(ClockNotSynchronized) as error:
        require_clock_synchronized(path)
    assert str(error.value) == "clock synchronization not proven"


def test_absent_marker_refuses(timesync):
    _refused(str(timesync / "synchronized"))


def test_absent_directory_refuses(timesync):
    _refused(str(timesync / "missing" / "synchronized"))


def test_marker_symlink_refuses(timesync):
    real = _marker(timesync)
    os.rename(real, timesync / "real")
    os.symlink(timesync / "real", timesync / "synchronized")
    _refused(str(timesync / "synchronized"))


def test_directory_symlink_refuses(timesync):
    _marker(timesync)
    link = timesync.parent / "linked"
    os.symlink(timesync, link)
    _refused(str(link / "synchronized"))


def test_marker_that_is_a_directory_refuses(timesync):
    (timesync / "synchronized").mkdir()
    _refused(str(timesync / "synchronized"))


def test_world_writable_marker_refuses(timesync):
    _refused(_marker(timesync, mode=0o666))


def test_world_writable_directory_refuses(timesync):
    path = _marker(timesync)
    timesync.chmod(0o777)
    _refused(path)


@pytest.mark.parametrize("path", [
    "", "relative/synchronized", "/", "/synchronized/", "/run//synchronized",
    "/run/./synchronized", "/run/../synchronized", None, b"/run/synchronized",
])
def test_malformed_paths_refuse(path):
    _refused(path)


def test_the_reader_opens_nothing_for_writing_and_takes_no_environment():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not {"O_WRONLY", "O_RDWR", "O_CREAT", "environ", "getenv", "argv"} & names
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "open" not in calls
