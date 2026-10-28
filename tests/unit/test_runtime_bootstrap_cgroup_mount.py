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


# --- _namespaces: self-only cgroup namespace admission (synthetic data) ---

import os
import stat

from azazel_nexus_runtime import bootstrap_cgroup_mount as cgroup_mount

GOOD_CGROUP = b"0::/system.slice/azazel-activated.service\n"


def _ns_setup(tmp_path, monkeypatch, *, cgroup=GOOD_CGROUP, magic=None, swap=None):
    target = tmp_path / "ns-target"
    target.write_text("synthetic")
    other = tmp_path / "ns-other"
    other.write_text("synthetic other")
    parent = tmp_path / "self-ns"
    parent.mkdir()
    link = parent / "cgroup"
    link.symlink_to(target)
    opened, reads = [], []
    real_open = os.open
    real_stat = os.stat

    def fake_open(path, flags, *args, **kwargs):
        if type(path) is str and path.startswith("/proc/"):
            opened.append(path)
            assert path == "/proc/self/ns", "unexpected proc access"
            path = parent
        return real_open(path, flags, *args, **kwargs)

    def fake_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if swap is not None and path == "cgroup" and kwargs.get("follow_symlinks") is False:
            reads.append("stat")
            if len(reads) >= swap:
                # Linux (ext4/tmpfs) immediately reuses a freed inode number, so
                # unlink()+symlink_to() can yield the same (st_dev, st_ino).
                # Create the replacement first (old inode still allocated, so the
                # new one must differ) and atomically rename it over the link.
                tmp = parent / "cgroup.new"
                tmp.symlink_to(other)
                os.replace(tmp, link)
        return result

    def fake_read(path, limit):
        reads.append(path)
        assert path == "/proc/self/cgroup" and limit == 4096
        return cgroup

    def fs_type(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            return cgroup_mount._PROC_MAGIC
        return cgroup_mount._NSFS_MAGIC if magic is None else magic

    monkeypatch.setattr(cgroup_mount.os, "open", fake_open)
    monkeypatch.setattr(cgroup_mount.os, "stat", fake_stat)
    monkeypatch.setattr(cgroup_mount, "_read_proc", fake_read)
    monkeypatch.setattr(cgroup_mount, "_filesystem_type", fs_type)
    return target, opened


def test_namespaces_accepts_exact_controller_line_and_is_deterministic(tmp_path, monkeypatch, private_os):
    private_os(cgroup_mount)
    target, opened = _ns_setup(tmp_path, monkeypatch)
    first = cgroup_mount._namespaces()
    info = os.stat(target)
    assert first == ((info.st_dev, info.st_ino),)
    assert cgroup_mount._namespaces() == first
    hash(first)
    assert opened == ["/proc/self/ns"] * 2
    assert not any("/proc/1" in path for path in opened)


@pytest.mark.parametrize(
    "content",
    [
        b"0::/system.slice/other.service\n",
        b"0::/\n",
        GOOD_CGROUP + b"1:name=systemd:/x\n",
        b"1:name=systemd:/system.slice/azazel-activated.service\n",
        b"12:cpu:/\n" + GOOD_CGROUP,
        GOOD_CGROUP[:-1],
        b"0::/system.slice/azazel-activated.service/child\n",
        b"0::/../system.slice/azazel-activated.service\n",
    ],
)
def test_namespaces_refuses_other_cgroup_content(tmp_path, monkeypatch, content, private_os):
    private_os(cgroup_mount)
    _ns_setup(tmp_path, monkeypatch, cgroup=content)
    with pytest.raises(UnitOperationFailed):
        cgroup_mount._namespaces()


def test_namespaces_refuses_wrong_nsfs_magic(tmp_path, monkeypatch, private_os):
    private_os(cgroup_mount)
    _ns_setup(tmp_path, monkeypatch, magic=0x1234)
    with pytest.raises(UnitOperationFailed, match="kernel namespace descriptor required"):
        cgroup_mount._namespaces()


@pytest.mark.parametrize("swap", [1, 2])
def test_namespaces_refuses_link_changed_between_reads(tmp_path, monkeypatch, swap, private_os):
    # swap=1: link replaced right after the initial lstat; swap=2: replaced
    # around the /proc/self/cgroup read (recheck after the read must catch it).
    private_os(cgroup_mount)
    _ns_setup(tmp_path, monkeypatch, swap=swap)
    with pytest.raises(UnitOperationFailed, match="namespace link changed"):
        cgroup_mount._namespaces()


def test_namespaces_never_opens_pid1(tmp_path, monkeypatch, private_os):
    private_os(cgroup_mount)
    _, opened = _ns_setup(tmp_path, monkeypatch)
    cgroup_mount._namespaces()
    assert opened == ["/proc/self/ns"]
