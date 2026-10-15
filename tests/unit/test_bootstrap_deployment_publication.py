"""Publication transaction tests use only an ordinary private temporary directory."""

from contextlib import contextmanager
import hashlib
import fcntl
import os

import pytest

from azazel_nexus import bootstrap_deployment_store as store
from azazel_nexus.bootstrap_deployment import decode_bootstrap_deployment, encode_bootstrap_deployment
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_deployment_store import declaration


@pytest.fixture
def publication_dir(tmp_path):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)

    @contextmanager
    def opened():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    with opened() as fd:
        yield root, fd, os.getuid()


@pytest.fixture
def record():
    return encode_bootstrap_deployment(declaration())


def initialize(fd, raw, *, owner, confirmation=None, digest=None):
    store._initialize_at(
        fd, raw, owner=owner,
        confirmed_sha256=hashlib.sha256(raw).hexdigest() if digest is None else digest,
        confirmed_initialize=True if confirmation is None else confirmation,
    )


def test_initialize_publishes_canonical_record_and_reader_loads_it(publication_dir, record):
    root, fd, owner = publication_dir

    initialize(fd, record, owner=owner)

    path = root / "deployment.json"
    assert path.read_bytes() == record
    assert path.stat().st_mode & 0o777 == 0o600
    assert not (root / "deployment.pending").exists()
    assert store._read_at(fd, owner=owner) == record
    assert decode_bootstrap_deployment(store._read_at(fd, owner=owner)) == declaration()


@pytest.mark.parametrize("existing", ["deployment.json", "deployment.pending"])
def test_initialize_refuses_existing_file_without_modifying_it(publication_dir, record, existing):
    root, fd, owner = publication_dir
    path = root / existing
    path.write_bytes(b"existing state")
    path.chmod(0o600)

    with pytest.raises(ApprovalRefused):
        initialize(fd, record, owner=owner)

    assert path.read_bytes() == b"existing state"
    assert sorted(item.name for item in root.iterdir()) == [existing]


@pytest.mark.parametrize("pending", ["file", "dangling-symlink"])
def test_pending_marker_including_dangling_symlink_blocks_reader_and_initializer(
    publication_dir, record, pending,
):
    root, fd, owner = publication_dir
    marker = root / "deployment.pending"
    if pending == "file":
        marker.write_bytes(b"pending review")
        marker.chmod(0o600)
    else:
        marker.symlink_to(root / "missing-target")

    with pytest.raises(ApprovalRefused):
        store._read_at(fd, owner=owner)
    with pytest.raises(ApprovalRefused):
        initialize(fd, record, owner=owner)
    assert marker.is_symlink() if pending == "dangling-symlink" else marker.read_bytes() == b"pending review"
    assert not (root / "deployment.json").exists()


@pytest.mark.parametrize(("digest", "confirmation"), [
    ("0" * 64, True),
    (None, 1),
    (None, "yes"),
])
def test_invalid_digest_or_non_true_confirmation_refuses_without_writes(
    publication_dir, record, digest, confirmation,
):
    root, fd, owner = publication_dir

    with pytest.raises(ApprovalRefused):
        initialize(fd, record, owner=owner, digest=digest, confirmation=confirmation)

    assert list(root.iterdir()) == []


def test_write_failure_after_pending_retains_marker_blocks_read_and_retry(
    publication_dir, record, monkeypatch,
):
    root, fd, owner = publication_dir
    original = store._write_new

    def fail_declaration_write(directory_fd, name, raw):
        if name == "deployment.json":
            raise OSError("injected declaration write failure")
        return original(directory_fd, name, raw)

    monkeypatch.setattr(store, "_write_new", fail_declaration_write)
    with pytest.raises(OSError, match="injected"):
        initialize(fd, record, owner=owner)

    marker = root / "deployment.pending"
    assert marker.read_bytes() == b"administrator deployment publication pending\n"
    with pytest.raises(ApprovalRefused):
        store._read_at(fd, owner=owner)
    with pytest.raises(ApprovalRefused):
        initialize(fd, record, owner=owner)
    assert not (root / "deployment.json").exists()


@pytest.mark.parametrize("fail_at", [1, 2, 3, 4, 5])
def test_each_fsync_failure_reports_failure_without_automatic_cleanup(
    publication_dir, record, monkeypatch, fail_at,
):
    root, fd, owner = publication_dir
    original = store.os.fsync
    calls = 0

    def fail_once(target):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError("injected fsync failure")
        original(target)

    monkeypatch.setattr(store.os, "fsync", fail_once)
    expected = OSError if fail_at < 5 else store.DeploymentDurabilityUncertain
    with pytest.raises(expected):
        initialize(fd, record, owner=owner)
    if fail_at < 5:
        assert (root / "deployment.pending").exists()
        with pytest.raises(ApprovalRefused):
            store._read_at(fd, owner=owner)
    else:
        # Publication may be readable, but durability was not established.
        assert store._read_at(fd, owner=owner) == record
    with pytest.raises(ApprovalRefused):
        initialize(fd, record, owner=owner)


def test_existing_reader_lock_prevents_publication(publication_dir, record):
    root, fd, owner = publication_dir
    reader = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            initialize(fd, record, owner=owner)
        assert list(root.iterdir()) == []
    finally:
        os.close(reader)
