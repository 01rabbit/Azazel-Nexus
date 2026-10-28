"""Post-withdraw file observation and journal finalization tests."""

import os
from dataclasses import replace

import pytest

import azazel_nexus.bootstrap_overlay_journal as overlay_journal
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_restore_files import BootstrapRestoredOverlayFiles
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap_overlay_withdraw import (
    PAIR,
    _close,
    _withdraw,
    _withdraw_environment,
)
from test_bootstrap_overlay_journal import good_evidence


def _restored(env):
    return BootstrapRestoredOverlayFiles(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        transient_fd=env["transient_fd"],
        generator_early_fd=env["generator_early_fd"],
        overlay_path=env["overlay_path"],
        masks_path=env["masks_path"],
        higher_priority_path=env["higher_path"],
        transient_path=env["transient_path"],
        generator_early_path=env["generator_early_path"],
        journal_store=env["store"],
        guard=env["guard"],
        owner_uid=os.getuid(),
    )


def _withdrawn(env):
    _close(env)
    return _withdraw(env)


def test_check_returns_exact_persistent_mask_fragment_paths(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _withdrawn(env)

        assert _restored(env).check() == (
            (UnitKey.AUDITD, str(env["masks_path"] / PAIR[0])),
            (UnitKey.COMMISSIOND, str(env["masks_path"] / PAIR[1])),
        )


def test_check_refuses_remaining_overlay_entry(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _withdrawn(env)
        files = _restored(env)
        foreign = env["overlay_path"] / PAIR[0]
        foreign.write_bytes(b"synthetic remaining entry")

        with pytest.raises(ApprovalRefused):
            files.check()


def test_constructor_refuses_closing_journal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)

        with pytest.raises(ApprovalRefused):
            _restored(env)


def test_check_refuses_changed_withdrawal_journal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        withdrawing = _withdrawn(env)
        files = _restored(env)
        changed = replace(
            withdrawing,
            intent=replace(withdrawing.intent, grant_id="e" * 32),
        )
        env["store"].replace(withdrawing, changed)

        with pytest.raises(ApprovalRefused):
            files.check()


def test_check_refuses_changed_persistent_mask(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _withdrawn(env)
        files = _restored(env)
        mask = env["masks_path"] / PAIR[0]
        mask.unlink()
        mask.symlink_to("/tmp/not-the-persistent-mask")

        with pytest.raises(ApprovalRefused):
            files.check()


def test_check_refuses_replaced_directory_binding(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _withdrawn(env)
        files = _restored(env)
        moved = env["overlay_path"].with_name("system.control.old")
        env["overlay_path"].rename(moved)
        env["overlay_path"].mkdir(mode=0o700)

        with pytest.raises(ApprovalRefused):
            files.check()


def test_finalize_records_closed_only_after_valid_evidence(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        withdrawing = _withdrawn(env)
        files = _restored(env)

        assert files.finalize(good_evidence()) is None
        closed = env["store"].load()
        assert closed.phase == "closed"
        assert closed.intent == withdrawing.intent
        assert closed.owned_files == ()
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)
        assert files.check() == (
            (UnitKey.AUDITD, str(env["masks_path"] / PAIR[0])),
            (UnitKey.COMMISSIOND, str(env["masks_path"] / PAIR[1])),
        )


def test_finalize_refuses_invalid_evidence(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _withdrawn(env)
        files = _restored(env)

        with pytest.raises(ApprovalRefused):
            files.finalize(None)
        assert env["store"].load().phase == "withdrawing"


def test_visible_closed_directory_fsync_failure_reaffirms_on_recovery(
    tmp_path, monkeypatch, private_os
):
    private_os(overlay_journal)
    with _withdraw_environment(tmp_path) as env:
        withdrawing = _withdrawn(env)
        files = _restored(env)
        real_fsync = overlay_journal.os.fsync
        journal_path_identity = env["journal_path"].stat()
        failed = False

        def fail_journal_directory_sync(fd):
            nonlocal failed
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino)
                    == (journal_path_identity.st_dev, journal_path_identity.st_ino)
                    and not failed):
                failed = True
                raise OSError("injected final journal directory fsync failure")
            return real_fsync(fd)

        monkeypatch.setattr(overlay_journal.os, "fsync", fail_journal_directory_sync)
        with pytest.raises(ApprovalRefused):
            files.finalize(good_evidence())
        assert failed
        closed = env["store"].load()
        assert closed.phase == "closed"
        assert closed.intent == withdrawing.intent
        assert closed.owned_files == ()

        reaffirmations = []
        replace_journal = env["store"].replace

        def record_replace(expected, updated):
            if expected == updated:
                reaffirmations.append((expected, updated))
            return replace_journal(expected, updated)

        monkeypatch.setattr(env["store"], "replace", record_replace)
        recovered = _restored(env)
        def fail_reaffirmation(expected, updated):
            assert expected == updated == closed
            raise ApprovalRefused("injected closed journal reaffirmation failure")

        monkeypatch.setattr(env["store"], "replace", fail_reaffirmation)
        with pytest.raises(ApprovalRefused):
            recovered.finalize(good_evidence())
        assert env["store"].load() == closed

        monkeypatch.setattr(env["store"], "replace", record_replace)
        assert recovered.finalize(good_evidence()) is None
        assert reaffirmations == [(closed, closed)]
        assert env["store"].load() == closed
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)
        assert all(os.readlink(env["masks_path"] / unit) == "/dev/null" for unit in PAIR)
