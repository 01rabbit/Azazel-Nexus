"""Protected per-boot selection publication using ordinary temporary files."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import fcntl
import os

import pytest

from azazel_nexus import bootstrap_selection_store as store
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from azazel_nexus.bootstrap_selection import BootstrapSelection, encode_bootstrap_selection
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_deployment_store import declaration
from test_bootstrap_generation import _context

_PENDING = b"administrator bootstrap selection publication pending\n"


@pytest.fixture
def protected(tmp_path, monkeypatch):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    deployment = declaration()
    context = _context()
    selection = BootstrapSelection(
        "sha256:" + sha256(encode_bootstrap_deployment(deployment)).hexdigest(),
        context.boot_id, context.approval_id, context.generation, context.generation_digest,
    )
    raw = encode_bootstrap_selection(selection)
    uid = os.getuid()

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    read_file = store._read_file_at

    def read_file_for_test(fd, name, *, owner, limit):
        return read_file(fd, name, owner=uid, limit=limit)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    monkeypatch.setattr(store, "_read_file_at", read_file_for_test)
    monkeypatch.setattr(store, "load_bootstrap_deployment", lambda: deployment)
    monkeypatch.setattr(store, "read_boot_id", lambda: context.boot_id)
    publish_at = store._publish_at

    def publish_at_for_test(fd, raw, *, owner, **kwargs):
        return publish_at(fd, raw, owner=uid, **kwargs)

    monkeypatch.setattr(store, "_publish_at", publish_at_for_test)
    return root, deployment, selection, raw, context, uid


def _confirm(raw):
    return sha256(raw).hexdigest()


def test_public_initialize_then_protected_reader_returns_selection(protected):
    root, _deployment, selection, raw, _context, _uid = protected

    assert store.initialize_bootstrap_selection(
        raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True,
    ) is None
    assert store.load_bootstrap_selection() == selection
    assert (root / "selection.json").read_bytes() == raw
    assert not (root / "selection.pending").exists()


def test_recovery_completes_only_exact_retained_pending_bytes(protected):
    root, _deployment, selection, raw, _context, _uid = protected
    pending = root / "selection.pending"
    pending.write_bytes(_PENDING)
    pending.chmod(0o600)
    (root / "selection.json").write_bytes(raw)
    (root / "selection.json").chmod(0o600)

    assert store.recover_bootstrap_selection(
        raw, confirmed_sha256=_confirm(raw), confirmed_recovery=True,
    ) is None
    assert not pending.exists()
    assert store.load_bootstrap_selection() == selection


def test_existing_selection_is_not_overwritten(protected):
    root, _deployment, selection, raw, _context, _uid = protected
    store.initialize_bootstrap_selection(
        raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True,
    )

    replacement = encode_bootstrap_selection(replace(selection, generation=selection.generation + 1))
    with pytest.raises(ApprovalRefused):
        store.initialize_bootstrap_selection(
            replacement, confirmed_sha256=_confirm(replacement), confirmed_initialize=True,
        )
    assert (root / "selection.json").read_bytes() == raw
    assert not (root / "selection.pending").exists()


@pytest.mark.parametrize("case", ["boot", "deployment"])
def test_wrong_boot_or_deployment_refuses_before_any_write(protected, monkeypatch, case):
    root, deployment, _selection, raw, context, _uid = protected
    if case == "boot":
        monkeypatch.setattr(store, "read_boot_id", lambda: "00000000-0000-4000-8000-000000000000")
    else:
        monkeypatch.setattr(
            store, "load_bootstrap_deployment",
            lambda: replace(deployment, security_epoch=deployment.security_epoch + 1),
        )

    with pytest.raises(ApprovalRefused):
        store.initialize_bootstrap_selection(
            raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True,
        )
    assert list(root.iterdir()) == []
    assert context.generation == 7


@pytest.mark.parametrize("confirmation", ["wrong-digest", "truthy"])
def test_wrong_digest_or_nontrue_confirmation_refuses_without_writes(protected, confirmation):
    root, _deployment, _selection, raw, _context, _uid = protected
    digest = "0" * 64 if confirmation == "wrong-digest" else _confirm(raw)
    accepted = True if confirmation == "wrong-digest" else 1

    with pytest.raises(ApprovalRefused):
        store.initialize_bootstrap_selection(
            raw, confirmed_sha256=digest, confirmed_initialize=accepted,
        )
    assert list(root.iterdir()) == []


def test_changed_deployment_on_second_source_check_retains_pending_and_reader_refuses(
    protected, monkeypatch,
):
    root, deployment, _selection, raw, _context, _uid = protected
    values = iter((deployment, deployment, replace(deployment, security_epoch=4)))
    monkeypatch.setattr(store, "load_bootstrap_deployment", lambda: next(values))

    with pytest.raises(ApprovalRefused):
        store.initialize_bootstrap_selection(
            raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True,
        )
    assert (root / "selection.pending").read_bytes() == _PENDING
    monkeypatch.setattr(store, "load_bootstrap_deployment", lambda: deployment)
    with pytest.raises(ApprovalRefused):
        store.load_bootstrap_selection()


@pytest.mark.parametrize("case", ["unknown-marker", "truncated", "missing-record", "different-boot"])
def test_recovery_refuses_incomplete_or_stale_state_without_repair(protected, monkeypatch, case):
    root, _deployment, _selection, raw, _context, _uid = protected
    marker = b"unknown" if case == "unknown-marker" else _PENDING
    (root / "selection.pending").write_bytes(marker)
    (root / "selection.pending").chmod(0o600)
    retained = raw[:-1] if case == "truncated" else raw
    if case != "missing-record":
        (root / "selection.json").write_bytes(retained)
        (root / "selection.json").chmod(0o600)
    if case == "different-boot":
        monkeypatch.setattr(store, "read_boot_id", lambda: "00000000-0000-0000-0000-000000000000")
    with pytest.raises(ApprovalRefused):
        store.recover_bootstrap_selection(raw, confirmed_sha256=_confirm(raw), confirmed_recovery=True)
    assert (root / "selection.pending").read_bytes() == marker
    if case == "missing-record":
        assert not (root / "selection.json").exists()
    else:
        assert (root / "selection.json").read_bytes() == retained


@pytest.mark.parametrize("recovery", [False, True])
def test_actual_cli_to_public_store_and_reader_on_ordinary_files(protected, monkeypatch, recovery):
    import io
    import sys
    from azazel_nexus import cli
    from test_bootstrap_selection_cli import Terminal

    root, _deployment, selection, raw, _context, _uid = protected
    if recovery:
        (root / "selection.pending").write_bytes(_PENDING)
        (root / "selection.pending").chmod(0o600)
        (root / "selection.json").write_bytes(raw)
        (root / "selection.json").chmod(0o600)
    operation = b"RECOVER" if recovery else b"INITIALIZE"
    monkeypatch.setattr(sys, "stdin", Terminal(raw + b"\n" + _confirm(raw).encode() + b"\n" + operation + b"\n"))
    name = "bootstrap-selection-recover" if recovery else "bootstrap-selection-initialize"
    output = io.StringIO()
    assert cli.main([name], out=output) == 0
    assert store.load_bootstrap_selection() == selection
    assert "NOT approval, admission or activation" in output.getvalue()


def test_fsync_failure_before_unlink_keeps_pending_marker_and_blocks_reader(
    protected, monkeypatch,
):
    import azazel_nexus.bootstrap_selection_store as selection_store

    root, _deployment, _selection, raw, _context, _uid = protected
    original_fsync = selection_store.os.fsync
    count = 0

    def fail_directory_sync(fd):
        nonlocal count
        count += 1
        if count == 2:  # pending file sync succeeded; fail directory sync
            raise OSError("injected pre-unlink sync failure")
        return original_fsync(fd)

    monkeypatch.setattr(selection_store.os, "fsync", fail_directory_sync)
    with pytest.raises(ApprovalRefused, match="selection publication refused"):
        store.initialize_bootstrap_selection(
            raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True,
        )
    assert (root / "selection.pending").exists()
    with pytest.raises(ApprovalRefused):
        store.load_bootstrap_selection()


@pytest.mark.parametrize("recovery", [False, True])
def test_final_fsync_after_unlink_reports_uncertainty_but_selection_reads(
    protected, monkeypatch, recovery,
):
    import azazel_nexus.bootstrap_selection_store as selection_store

    root, _deployment, selection, raw, _context, _uid = protected
    original_fsync = selection_store.os.fsync
    root_identity = root.stat()
    directory_syncs = 0
    if recovery:
        (root / "selection.pending").write_bytes(_PENDING)
        (root / "selection.pending").chmod(0o600)
        (root / "selection.json").write_bytes(raw)
        (root / "selection.json").chmod(0o600)

    def fail_final_sync(fd):
        nonlocal directory_syncs
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (root_identity.st_dev, root_identity.st_ino):
            directory_syncs += 1
            if directory_syncs == (2 if recovery else 3):
                raise OSError("injected final sync failure")
        return original_fsync(fd)

    monkeypatch.setattr(selection_store.os, "fsync", fail_final_sync)
    with pytest.raises(store.SelectionDurabilityUncertain):
        if recovery:
            store.recover_bootstrap_selection(raw, confirmed_sha256=_confirm(raw), confirmed_recovery=True)
        else:
            store.initialize_bootstrap_selection(raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True)
    assert not (root / "selection.pending").exists()
    assert store.load_bootstrap_selection() == selection


@pytest.mark.parametrize("recovery", [False, True])
def test_contending_shared_holder_refuses_exclusive_upgrade_without_mutation(protected, recovery):
    root, _deployment, _selection, raw, _context, _uid = protected
    if recovery:
        (root / "selection.pending").write_bytes(_PENDING)
        (root / "selection.pending").chmod(0o600)
        (root / "selection.json").write_bytes(raw)
        (root / "selection.json").chmod(0o600)
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    other = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(other, fcntl.LOCK_SH | fcntl.LOCK_NB)
        with pytest.raises(ApprovalRefused):
            if recovery:
                store.recover_bootstrap_selection(raw, confirmed_sha256=_confirm(raw), confirmed_recovery=True)
            else:
                store.initialize_bootstrap_selection(raw, confirmed_sha256=_confirm(raw), confirmed_initialize=True)
    finally:
        os.close(other)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
