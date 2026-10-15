"""Synthetic parser tests for fixed-path cgroup2 mount admission."""

import pytest

from azazel_nexus_runtime.bootstrap_cgroup_mount import _mount_record
from azazel_nexus_runtime.units import UnitOperationFailed


DEVICE = 0
INODE = 987654
MOUNT_ID = 35
_UNSET = object()


def _mount(
    *,
    mount_id=MOUNT_ID,
    device="0:0",
    root="/",
    mountpoint="/sys/fs/cgroup",
    options="rw",
    filesystem="cgroup2",
    source="cgroup2",
):
    return (
        f"{mount_id} 26 {device} {root} {mountpoint} {options} "
        f"- {filesystem} {source} rw\n"
    ).encode("ascii")


def _fdinfo(*, mount_id=MOUNT_ID, inode=INODE):
    return f"pos:\t0\nflags:\t0400000\nmnt_id:\t{mount_id}\nino:\t{inode}\n".encode(
        "ascii"
    )


def _parse(mountinfo=_UNSET, fdinfo=_UNSET, *, device=DEVICE, inode=INODE):
    return _mount_record(
        _mount() if mountinfo is _UNSET else mountinfo,
        _fdinfo() if fdinfo is _UNSET else fdinfo,
        device,
        inode,
    )


def test_accepts_exact_cgroup2_mount_bound_to_fd_identity():
    assert _parse() == MOUNT_ID


def test_accepts_read_only_mount():
    assert _parse(mountinfo=_mount(options="ro,nosuid,nodev")) == MOUNT_ID


@pytest.mark.parametrize(
    "mountinfo",
    [
        b"",
        _mount(root="/nested"),
        _mount(mountpoint="/sys/fs/cgroup/child"),
        _mount(mountpoint="/sys/fs/cgroup-old"),
        _mount(filesystem="cgroup"),
        _mount(device="0:31"),
        b"35 26 0:30 / /sys/fs/cgroup rw cgroup2 cgroup2 rw\n",
        _mount() + _mount(mount_id=36),
        _mount(mount_id=36) + _mount(mount_id=36, mountpoint="/other"),
        _mount() + _mount(mount_id=36, mountpoint="/sys/fs/cgroup/child"),
        _mount() + _mount(mount_id=36),
        _mount()[:-3],
        _mount() + b"\xff\n",
        b"x" * (1024 * 1024 + 1),
    ],
)
def test_rejects_invalid_ambiguous_or_oversized_mountinfo(mountinfo):
    with pytest.raises(UnitOperationFailed):
        _parse(mountinfo=mountinfo)


@pytest.mark.parametrize(
    "fdinfo",
    [
        b"",
        b"pos:\t0\n",
        b"mnt_id: 35\nino: 1\nino: 1\n",
        b"mnt_id: 35\nmnt_id: 35\nino: 987654\n",
        b"mnt_id: 35\nino: 987655\n",
        b"mnt_id: 0\nino: 987654\n",
        b"mnt_id: -1\nino: 987654\n",
        b"mnt_id: 123456789012345678901\nino: 987654\n",
        b"mnt_id: 35\nino: nope\n",
        b"mnt_id 35\nino: 987654\n",
        b"mnt_id: 35\nino: 987654\n\xff",
        b"x" * 4097,
    ],
)
def test_rejects_malformed_duplicate_mismatched_or_oversized_fdinfo(fdinfo):
    with pytest.raises(UnitOperationFailed):
        _parse(fdinfo=fdinfo)


def test_fd_mount_id_must_select_the_exact_mount():
    with pytest.raises(UnitOperationFailed):
        _parse(fdinfo=_fdinfo(mount_id=MOUNT_ID + 1))


def test_inode_argument_must_match_fdinfo():
    with pytest.raises(UnitOperationFailed):
        _parse(inode=INODE + 1)


@pytest.mark.parametrize("raw", [bytearray(b"x"), "text", None])
def test_rejects_non_bytes_inputs(raw):
    with pytest.raises(UnitOperationFailed):
        _parse(mountinfo=raw)


def test_rejects_empty_or_nonpositive_input_bounds():
    for mountinfo, fdinfo in ((b"", _fdinfo()), (_mount(), b"")):
        with pytest.raises(UnitOperationFailed):
            _parse(mountinfo=mountinfo, fdinfo=fdinfo)
