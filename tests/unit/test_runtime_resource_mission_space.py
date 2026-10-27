"""Superblock rule for a read-only /data mount; synthetic mountinfo only."""

from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import resource_assessment as resources

DEV = resources.os.makedev(8, 1)
RO = resources.os.ST_RDONLY


def line(majmin="8:1", mountpoint="/data", sb="rw,errors=remount-ro", mountopts="ro,relatime"):
    return f"40 30 {majmin} / {mountpoint} {mountopts} shared:2 - ext4 /dev/sda1 {sb}"


@pytest.fixture
def setup(monkeypatch, private_os):
    private_os(resources)
    state = {"flag": RO, "dev": DEV, "root": 1, "mountinfo": line()}
    closed = []
    monkeypatch.setattr(resources.os, "open", lambda path, flags: 123)
    monkeypatch.setattr(resources.os, "close", closed.append)
    monkeypatch.setattr(resources.os, "fstat", lambda fd: SimpleNamespace(st_dev=state["dev"]))
    real_stat = resources.os.stat
    monkeypatch.setattr(resources.os, "stat", lambda path, *a, **k: SimpleNamespace(
        st_dev=state["root"]) if path == "/" else real_stat(path, *a, **k))
    monkeypatch.setattr(resources.os, "fstatvfs", lambda fd: SimpleNamespace(
        f_frsize=4096, f_bavail=512, f_bfree=768, f_blocks=1024, f_flag=state["flag"]))
    monkeypatch.setattr(resources, "_read_mountinfo", lambda: state["mountinfo"] + "\n")
    return state


def test_sandbox_ro_bind_over_rw_superblock_accepted(setup):
    assert resources._mission_space() == 2


def test_rw_path_unchanged_and_ignores_mountinfo(setup, monkeypatch):
    setup["flag"] = 0
    monkeypatch.setattr(resources, "_read_mountinfo", lambda: pytest.fail("mountinfo read"))
    assert resources._mission_space() == 2


@pytest.mark.parametrize("sb", ["ro", "ro,errors=remount-ro", "rw,ro", "errors=continue", ""])
def test_ro_or_unknown_superblock_refused(setup, sb):
    setup["mountinfo"] = line(sb=sb)
    with pytest.raises(ValueError):
        resources._mission_space()


@pytest.mark.parametrize("text", [
    "",
    line(mountpoint="/other"),
    line(mountpoint="/data/sub"),
    line(majmin="8:2"),
])
def test_no_matching_entry_refused(setup, text):
    setup["mountinfo"] = text
    with pytest.raises(ValueError):
        resources._mission_space()


def test_duplicate_entries_refused(setup):
    setup["mountinfo"] = line() + "\n" + line(sb="rw")
    with pytest.raises(ValueError):
        resources._mission_space()


def test_stacked_rw_over_ro_refused(setup):
    setup["mountinfo"] = line(sb="ro") + "\n" + line(sb="rw")
    with pytest.raises(ValueError):
        resources._mission_space()


@pytest.mark.parametrize("bad", [
    "garbage",
    "40 30 8:1 / /data ro - ext4 /dev/sda1 rw",  # separator too early
    "40 30 8:1 / /data ro,relatime shared:2 ext4 /dev/sda1 rw",  # no separator
    "40 30 8:1 / /data ro - ext4 /dev/sda1",  # missing super options
    "x 30 8:1 / /data ro rel - ext4 /dev/sda1 rw",
    "40 30 81 / /data ro rel - ext4 /dev/sda1 rw",
    "40 30 8:1 / data ro rel - ext4 /dev/sda1 rw",
    "40 30 8:1 / /data ro rel - ext4 /dev/sda1 rw extra",
])
def test_malformed_lines_refused(setup, bad):
    setup["mountinfo"] = line() + "\n" + bad
    with pytest.raises(ValueError):
        resources._mission_space()


def test_device_mismatch_refused(setup):
    setup["dev"] = resources.os.makedev(8, 2)
    with pytest.raises(ValueError):
        resources._mission_space()


def test_same_device_as_root_refused(setup, monkeypatch):
    setup["root"] = DEV
    monkeypatch.setattr(resources, "_read_mountinfo", lambda: pytest.fail("mountinfo read"))
    with pytest.raises(ValueError):
        resources._mission_space()


def test_invalid_statvfs_refused_even_with_rw_superblock(setup, monkeypatch):
    monkeypatch.setattr(resources.os, "fstatvfs", lambda fd: SimpleNamespace(
        f_frsize=4096, f_bavail=900, f_bfree=768, f_blocks=1024, f_flag=RO))
    with pytest.raises(ValueError):
        resources._mission_space()


def test_oversized_mountinfo_refused(monkeypatch, private_os):
    private_os(resources)
    reads = iter([b"x" * 65536] * 20)
    monkeypatch.setattr(resources.os, "open", lambda p, f: 9)
    monkeypatch.setattr(resources.os, "close", lambda fd: None)
    monkeypatch.setattr(resources.os, "read", lambda fd, n: next(reads))
    with pytest.raises(ValueError):
        resources._read_mountinfo()


VM_SANDBOX_LINE = ("573 515 0:49 / /data ro,nosuid,nodev,noexec,relatime shared:499 master:210"
                   " - tmpfs tmpfs rw,size=524288k,mode=755,inode64")


def test_verbatim_debian_vm_sandbox_line_accepted(setup):
    # Captured inside a ProtectSystem=strict unit on the Debian 13 ARM64 VM.
    setup["dev"] = resources.os.makedev(0, 49)
    setup["mountinfo"] = "24 1 259:3 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p3 rw\n" + VM_SANDBOX_LINE
    assert resources._mission_space() == 2


def test_verbatim_debian_vm_line_with_ro_superblock_refused(setup):
    setup["dev"] = resources.os.makedev(0, 49)
    setup["mountinfo"] = VM_SANDBOX_LINE.replace("tmpfs rw,", "tmpfs ro,")
    with pytest.raises(ValueError):
        resources._mission_space()


@pytest.mark.parametrize("unrelated", [
    "90 30 0:77 / /mnt/share rw,relatime - fuse.x my src rw,user=a b",  # spaces in super options
    "91 30 0:78 / /srv/odd rw - weird",                                  # truncated, but not /data
])
def test_unrelated_exotic_mount_does_not_refuse(setup, unrelated):
    setup["mountinfo"] = unrelated + "\n" + line()
    assert resources._mission_space() == 2


def test_candidate_line_with_extra_super_option_fields_refused(setup):
    setup["mountinfo"] = line(sb="rw extra")
    with pytest.raises(ValueError):
        resources._mission_space()


def test_mountinfo_decode_tolerates_non_utf8_mount_points(monkeypatch, private_os):
    private_os(resources)
    data = (b"90 30 0:77 / /mnt/\xff rw - tmpfs tmpfs rw\n"
            + VM_SANDBOX_LINE.encode() + b"\n")
    reads = iter([data, b""])
    monkeypatch.setattr(resources.os, "open", lambda path, flags: 7)
    monkeypatch.setattr(resources.os, "read", lambda fd, size: next(reads))
    monkeypatch.setattr(resources.os, "close", lambda fd: None)
    text = resources._read_mountinfo()
    assert VM_SANDBOX_LINE in text
