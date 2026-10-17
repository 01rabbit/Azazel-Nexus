"""Protected selection reader: synthetic records and private ordinary files."""

from contextlib import contextmanager
from dataclasses import replace
import fcntl
from hashlib import sha256
import os

import pytest

from azazel_nexus import bootstrap_selection_store as store
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from azazel_nexus.bootstrap_selection import BootstrapSelection, encode_bootstrap_selection
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_deployment_store import declaration
from test_bootstrap_generation import _context


@pytest.fixture
def selected(tmp_path, monkeypatch):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    deployment = declaration()
    context = _context()
    selection = BootstrapSelection(
        "sha256:" + sha256(encode_bootstrap_deployment(deployment)).hexdigest(),
        context.boot_id, context.approval_id, context.generation, context.generation_digest,
    )
    path = root / "selection.json"
    path.write_bytes(encode_bootstrap_selection(selection))
    path.chmod(0o600)

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    original = store._read_at
    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    monkeypatch.setattr(store, "_read_at", lambda fd, *, owner: original(fd, owner=os.getuid()))
    monkeypatch.setattr(store, "load_bootstrap_deployment", lambda: deployment)
    monkeypatch.setattr(store, "read_boot_id", lambda: context.boot_id)
    return root, path, deployment, selection


def test_exact_protected_selection_binds_current_boot_and_deployment(selected):
    assert store.load_bootstrap_selection() == selected[3]


@pytest.mark.parametrize("case", ["missing", "mode", "symlink", "hardlink", "pending", "pending-symlink", "old-boot", "old-deployment"])
def test_unsafe_or_stale_selection_refuses(selected, monkeypatch, case):
    root, path, deployment, selection = selected
    if case == "missing":
        path.unlink()
    elif case == "mode":
        path.chmod(0o644)
    elif case == "symlink":
        path.unlink()
        path.symlink_to(root / "absent")
    elif case == "hardlink":
        os.link(path, root / "alias")
    elif case == "pending":
        (root / "selection.pending").write_bytes(b"unfinished")
    elif case == "pending-symlink":
        (root / "selection.pending").symlink_to(root / "absent")
    elif case == "old-boot":
        monkeypatch.setattr(store, "read_boot_id", lambda: "00000000-0000-0000-0000-000000000000")
    else:
        monkeypatch.setattr(store, "load_bootstrap_deployment", lambda: replace(deployment, security_epoch=4))
    with pytest.raises(ApprovalRefused):
        store.load_bootstrap_selection()


@pytest.mark.parametrize("source", ["record", "deployment", "boot"])
def test_changed_source_during_observation_refuses(selected, monkeypatch, source):
    _root, path, deployment, selection = selected
    if source == "record":
        original = store._read_at
        calls = []

        def read(fd, *, owner):
            raw = original(fd, owner=owner)
            calls.append(None)
            if len(calls) == 1:
                path.write_bytes(encode_bootstrap_selection(replace(selection, generation=99)))
            return raw

        monkeypatch.setattr(store, "_read_at", read)
    elif source == "deployment":
        values = iter((deployment, replace(deployment, security_epoch=4)))
        monkeypatch.setattr(store, "load_bootstrap_deployment", lambda: next(values))
    else:
        values = iter((selection.boot_id, "00000000-0000-0000-0000-000000000000"))
        monkeypatch.setattr(store, "read_boot_id", lambda: next(values))
    with pytest.raises(ApprovalRefused):
        store.load_bootstrap_selection()
