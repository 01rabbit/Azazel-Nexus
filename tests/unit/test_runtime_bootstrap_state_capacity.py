"""Synthetic bootstrap state capacity policy and sampling checks."""

from types import SimpleNamespace
import os

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_state_capacity as capacity

OWNER = 991


@pytest.fixture
def floors():
    return capacity.BootstrapStateFloors(100, 10, 200, 20)


@pytest.fixture
def account(monkeypatch):
    monkeypatch.setattr(capacity.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=OWNER))


def stats(*, frsize=1, bavail=1000, bfree=1000, blocks=1000,
          favail=100, ffree=100, files=100, flag=0):
    return SimpleNamespace(
        f_frsize=frsize, f_bavail=bavail, f_bfree=bfree, f_blocks=blocks,
        f_favail=favail, f_ffree=ffree, f_files=files, f_flag=flag,
    )


@pytest.mark.parametrize("values", [
    (0, 1, 1, 1), (-1, 1, 1, 1), (True, 1, 1, 1),
    (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0),
    (1, 1.5, 1, 1), (1, 1, "1", 1),
])
def test_every_state_floor_requires_positive_exact_integer_values(values):
    with pytest.raises(ApprovalRefused):
        capacity.BootstrapStateFloors(*values)


def test_distinct_devices_apply_each_floor_to_its_own_capacity(monkeypatch, floors, account):
    samples = iter([(1, 100, 10), (2, 200, 20)])
    calls = []

    def sample(kind, owner):
        calls.append((kind, owner))
        return next(samples)

    monkeypatch.setattr(capacity, "_sample", sample)

    assert capacity.require_bootstrap_state_capacity(floors) is None
    assert calls == [("bootstrap", 0), ("audit", OWNER)]


@pytest.mark.parametrize(("bootstrap", "audit"), [
    ((1, 299, 30), (1, 1000, 100)),
    ((1, 1000, 100), (1, 299, 30)),
    ((1, 1000, 29), (1, 1000, 100)),
    ((1, 1000, 100), (1, 1000, 29)),
])
def test_shared_device_requires_sum_of_both_byte_and_inode_floors(
    monkeypatch, floors, account, bootstrap, audit,
):
    values = iter([bootstrap, audit])
    monkeypatch.setattr(capacity, "_sample", lambda _kind, _owner: next(values))

    with pytest.raises(ApprovalRefused):
        capacity.require_bootstrap_state_capacity(floors)


def test_shared_device_succeeds_at_combined_capacity_floor(monkeypatch, floors, account):
    values = iter([(7, 300, 30), (7, 900, 90)])
    monkeypatch.setattr(capacity, "_sample", lambda _kind, _owner: next(values))

    assert capacity.require_bootstrap_state_capacity(floors) is None


def test_capacity_has_no_default_floor_values():
    with pytest.raises(TypeError):
        capacity.BootstrapStateFloors()


@pytest.mark.parametrize("uid", [0, True, -1, None])
def test_invalid_audit_owner_refuses_before_sampling(monkeypatch, floors, uid):
    monkeypatch.setattr(capacity.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=uid))
    monkeypatch.setattr(capacity, "_sample", lambda *_args: pytest.fail("must not sample"))

    with pytest.raises(ApprovalRefused):
        capacity.require_bootstrap_state_capacity(floors)


@pytest.fixture
def sample_dirs(tmp_path):
    paths = []
    fds = []
    for name in ("first", "replacement"):
        path = tmp_path / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        paths.append(path)
        fds.append(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    try:
        yield paths, fds
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


def _assert_closed(fd):
    with pytest.raises(OSError):
        os.fstat(fd)


def test_sample_reads_fstatvfs_and_closes_original_and_identity_fds(monkeypatch, sample_dirs, private_os):
    private_os(capacity)
    _, fds = sample_dirs
    opened = []

    def open_dir(_kind, _owner):
        source = fds[0]
        fd = os.dup(source)
        opened.append(fd)
        return fd

    monkeypatch.setattr(capacity, "_open", open_dir)
    monkeypatch.setattr(capacity.os, "fstatvfs", lambda _fd: stats(frsize=4096, bavail=12, favail=8))

    assert capacity._sample("bootstrap", 0) == (os.fstat(fds[0]).st_dev, 12 * 4096, 8)
    assert len(opened) == 2
    for fd in opened:
        _assert_closed(fd)


@pytest.mark.parametrize("change", [
    {"frsize": 0}, {"frsize": -1}, {"bavail": -1}, {"bfree": -1},
    {"blocks": -1}, {"favail": -1}, {"ffree": -1}, {"files": -1},
    {"flag": os.ST_RDONLY}, {"bavail": 5, "bfree": 4},
    {"bfree": 1001, "blocks": 1000}, {"favail": 5, "ffree": 4},
    {"ffree": 101, "files": 100}, {"frsize": True},
])
def test_sample_rejects_readonly_or_invalid_filesystem_capacity(
    monkeypatch, sample_dirs, change, private_os,
):
    private_os(capacity)
    _, fds = sample_dirs
    opened = []

    def open_dir(_kind, _owner):
        fd = os.dup(fds[0])
        opened.append(fd)
        return fd

    monkeypatch.setattr(capacity, "_open", open_dir)
    monkeypatch.setattr(capacity.os, "fstatvfs", lambda _fd: stats(**change))

    with pytest.raises(ApprovalRefused):
        capacity._sample("bootstrap", 0)
    assert len(opened) == 1
    _assert_closed(opened[0])


def test_sample_rechecks_directory_identity_and_closes_both_fds(monkeypatch, sample_dirs, private_os):
    private_os(capacity)
    _, fds = sample_dirs
    opened = []

    def open_dir(_kind, _owner):
        source = fds[len(opened)]
        fd = os.dup(source)
        opened.append(fd)
        return fd

    monkeypatch.setattr(capacity, "_open", open_dir)
    monkeypatch.setattr(capacity.os, "fstatvfs", lambda _fd: stats())

    with pytest.raises(ApprovalRefused):
        capacity._sample("audit", OWNER)
    assert len(opened) == 2
    for fd in opened:
        _assert_closed(fd)


@pytest.mark.parametrize("kind, owner", [("bootstrap", 0), ("audit", OWNER)])
def test_fixed_traversal_checks_root_parents_and_actual_leaf_owner(tmp_path, monkeypatch, kind, owner, private_os):
    private_os(capacity)
    root = tmp_path / "root"
    leaf = root / "var/lib/azazel/state" / kind
    leaf.mkdir(parents=True)
    leaf.chmod(0o700)
    original_open = os.open
    owners, paths = [], []

    def open_local(path, flags, **kwargs):
        paths.append(path)
        assert flags & os.O_NOFOLLOW
        assert not flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR)
        return original_open(root if path == "/" else path, flags, **kwargs)

    def inspect(fd, *, owner, directory):
        owners.append(owner)
        assert directory is True
        return os.fstat(fd)

    monkeypatch.setattr(capacity.os, "open", open_local)
    monkeypatch.setattr(capacity, "_protected", inspect)
    fd = capacity._open(kind, owner)
    try:
        assert os.fstat(fd).st_ino == leaf.stat().st_ino
    finally:
        os.close(fd)
    assert owners == [0, 0, 0, 0, 0, owner]
    assert paths == ["/", "var", "lib", "azazel", "state", kind]
