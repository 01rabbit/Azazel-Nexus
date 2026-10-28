"""Recoverable withdrawal of journal-owned empty overlay masks."""

import os
from contextlib import contextmanager

import pytest

from azazel_nexus.bootstrap_overlay_journal import OverlayJournalDurabilityUncertain
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_overlay_files
from azazel_nexus_runtime import bootstrap_withdraw_files as withdraw
from azazel_nexus_runtime.bootstrap_overlay_files import _close_candidates_at
from test_runtime_bootstrap_overlay_files import PAIR, _environment, _publish


@contextmanager
def _withdraw_environment(tmp_path):
    with _environment(tmp_path) as env:
        for name in ("transient", "generator_early"):
            path = tmp_path / name
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            env[name + "_path"] = path
            env[name + "_fd"] = os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        try:
            yield env
        finally:
            os.close(env["generator_early_fd"])
            os.close(env["transient_fd"])


def _close(env):
    _publish(env)
    return _close_candidates_at(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        journal_store=env["store"],
        guard=env["guard"],
        owner_uid=os.getuid(),
    )


def _withdraw(env, check_contained=lambda: None):
    return withdraw._withdraw_candidates_at(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        transient_fd=env["transient_fd"],
        generator_early_fd=env["generator_early_fd"],
        journal_store=env["store"],
        guard=env["guard"],
        owner_uid=os.getuid(),
        check_contained=check_contained,
    )


def test_withdraw_removes_owned_masks_and_retains_withdrawing_journal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        checks = []

        def fresh_containment_check():
            checks.append(None)
            return None

        result = _withdraw(env, fresh_containment_check)

        assert result.phase == "withdrawing"
        assert result.owned_files == closing.owned_files
        assert env["store"].load() == result
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)
        assert len(checks) > 1


def test_durable_withdrawing_intent_precedes_first_unlink(tmp_path, monkeypatch, private_os):
    private_os(withdraw)
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        events = []
        replace = env["store"].replace
        real_unlink = os.unlink

        def record_replace(expected, updated):
            result = replace(expected, updated)
            events.append(("journal", updated.phase))
            return result

        def record_unlink(name, *, dir_fd=None):
            if dir_fd == env["overlay_fd"]:
                events.append(("unlink", name, env["store"].load().phase))
            return real_unlink(name, dir_fd=dir_fd)

        monkeypatch.setattr(env["store"], "replace", record_replace)
        monkeypatch.setattr(withdraw.os, "unlink", record_unlink)
        result = _withdraw(env)

        assert result.phase == "withdrawing"
        first_unlink = next(i for i, event in enumerate(events) if event[0] == "unlink")
        assert events[:first_unlink] == [("journal", "withdrawing")]
        assert all(event[2] == "withdrawing" for event in events if event[0] == "unlink")


def test_partial_unlink_failure_recovers_with_intent_reaffirmed(tmp_path, monkeypatch, private_os):
    private_os(withdraw)
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        real_unlink = os.unlink
        unlink_calls = 0

        def fail_once(name, *, dir_fd=None):
            nonlocal unlink_calls
            if dir_fd == env["overlay_fd"]:
                unlink_calls += 1
                if unlink_calls == 2:
                    raise OSError("injected second unlink failure")
            return real_unlink(name, dir_fd=dir_fd)

        monkeypatch.setattr(withdraw.os, "unlink", fail_once)
        with pytest.raises(withdraw.OverlayWithdrawalUncertain):
            _withdraw(env)
        retained = env["store"].load()
        assert retained.phase == "withdrawing"
        assert retained.owned_files
        assert not (env["overlay_path"] / PAIR[1]).exists()
        assert (env["overlay_path"] / PAIR[0]).exists()

        reaffirmed = []
        replace = env["store"].replace

        def record_replace(expected, updated):
            if expected == updated:
                reaffirmed.append(updated)
            return replace(expected, updated)

        monkeypatch.setattr(env["store"], "replace", record_replace)
        result = _withdraw(env)
        assert result.phase == "withdrawing"
        assert result.owned_files == retained.owned_files
        assert reaffirmed == [retained]
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)


def test_visible_intent_replace_uncertainty_reaffirmation_failure_does_not_unlink(
    tmp_path, monkeypatch, private_os
):
    private_os(withdraw)
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        real_replace = env["store"].replace
        real_unlink = os.unlink
        unlink_calls = []
        replace_calls = 0

        def uncertain_replace(expected, updated):
            nonlocal replace_calls
            replace_calls += 1
            if replace_calls == 1:
                real_replace(expected, updated)
                raise OverlayJournalDurabilityUncertain("injected visible replace uncertainty")
            if replace_calls == 2:
                raise OverlayJournalDurabilityUncertain("injected reaffirmation failure")
            return real_replace(expected, updated)

        def count_unlink(name, *, dir_fd=None):
            if dir_fd == env["overlay_fd"]:
                unlink_calls.append(name)
            return real_unlink(name, dir_fd=dir_fd)

        monkeypatch.setattr(env["store"], "replace", uncertain_replace)
        monkeypatch.setattr(withdraw.os, "unlink", count_unlink)
        with pytest.raises(withdraw.OverlayWithdrawalUncertain):
            _withdraw(env)
        assert env["store"].load().phase == "withdrawing"
        assert unlink_calls == []

        with pytest.raises(withdraw.OverlayWithdrawalUncertain):
            _withdraw(env)
        assert unlink_calls == []
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)

        monkeypatch.setattr(env["store"], "replace", real_replace)
        result = _withdraw(env)
        assert result.phase == "withdrawing"
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)


def test_directory_fsync_failure_recovers_after_visible_unlink(tmp_path, monkeypatch, private_os):
    private_os(withdraw)
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        real_fsync = os.fsync
        failed = False

        def fail_overlay_fsync(fd):
            nonlocal failed
            if fd == env["overlay_fd"] and not failed:
                failed = True
                raise OSError("injected overlay directory fsync failure")
            return real_fsync(fd)

        monkeypatch.setattr(withdraw.os, "fsync", fail_overlay_fsync)
        with pytest.raises(withdraw.OverlayWithdrawalUncertain):
            _withdraw(env)
        retained = env["store"].load()
        assert retained.phase == "withdrawing"
        assert not (env["overlay_path"] / PAIR[1]).exists()
        assert (env["overlay_path"] / PAIR[0]).exists()

        result = _withdraw(env)
        assert result == retained
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)


def test_withdraw_refuses_replaced_owned_inode(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        target = env["overlay_path"] / PAIR[0]
        retained = env["overlay_path"] / (PAIR[0] + ".retained")
        original_identity = (target.stat().st_dev, target.stat().st_ino)
        target.rename(retained)
        target.write_bytes(b"")
        target.chmod(0o644)
        replacement_identity = (target.stat().st_dev, target.stat().st_ino)
        assert replacement_identity != original_identity
        with pytest.raises(ApprovalRefused):
            _withdraw(env)
        assert env["store"].load().phase == "closing"
        assert target.read_bytes() == b""
        assert (retained.stat().st_dev, retained.stat().st_ino) == original_identity


def test_withdraw_refuses_nonempty_owned_mask(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        (env["overlay_path"] / PAIR[0]).write_bytes(b"unexpected")
        with pytest.raises(ApprovalRefused):
            _withdraw(env)
        assert env["store"].load().phase == "closing"


def test_withdraw_refuses_unowned_candidate_and_preserves_it(tmp_path, monkeypatch, private_os):
    private_os(bootstrap_overlay_files)
    with _withdraw_environment(tmp_path) as env:
        real_open = os.open

        def fail_second_create(name, flags, mode=0o777, *, dir_fd=None):
            if name == PAIR[1] and dir_fd == env["overlay_fd"] and flags & os.O_CREAT:
                raise OSError("injected second candidate create failure")
            if dir_fd is None:
                return real_open(name, flags, mode)
            return real_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr("azazel_nexus_runtime.bootstrap_overlay_files.os.open", fail_second_create)
        with pytest.raises(ApprovalRefused):
            _publish(env)
        monkeypatch.undo()
        _close_candidates_at(
            overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
            higher_priority_fd=env["higher_fd"], journal_store=env["store"],
            guard=env["guard"], owner_uid=os.getuid(),
        )
        foreign = env["overlay_path"] / PAIR[1]
        foreign.write_bytes(b"unowned")
        with pytest.raises(ApprovalRefused):
            _withdraw(env)
        assert foreign.read_bytes() == b"unowned"
        assert env["store"].load().phase == "closing"


def test_withdraw_refuses_containment_callback_refusal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)

        def refuse():
            raise ApprovalRefused("synthetic containment refusal")

        with pytest.raises(ApprovalRefused):
            _withdraw(env, refuse)
        assert env["store"].load().phase == "closing"
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)


def test_withdraw_normalizes_containment_callback_exception(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)

        def fail():
            raise RuntimeError("synthetic check failure")

        with pytest.raises(ApprovalRefused):
            _withdraw(env, fail)
        assert env["store"].load().phase == "closing"


def test_withdraw_refuses_missing_owned_candidate_before_intent(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        (env["overlay_path"] / PAIR[0]).unlink()
        with pytest.raises(ApprovalRefused):
            _withdraw(env)
        assert env["store"].load().phase == "closing"


@pytest.mark.parametrize("directory", ["transient", "generator_early"])
@pytest.mark.parametrize("entry", [PAIR[0], PAIR[1] + ".d"])
def test_withdraw_refuses_higher_precedence_conflicts(tmp_path, directory, entry):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        conflict = env[directory + "_path"] / entry
        if entry.endswith(".d"):
            conflict.mkdir(mode=0o700)
        else:
            conflict.write_bytes(b"foreign")
        with pytest.raises(ApprovalRefused):
            _withdraw(env)
        assert env["store"].load().phase == "closing"
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)


def test_withdraw_refuses_changed_persistent_mask(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        mask = env["masks_path"] / PAIR[0]
        mask.unlink()
        mask.symlink_to("/tmp/not-the-mask")
        with pytest.raises(ApprovalRefused):
            _withdraw(env)
        assert env["store"].load().phase == "closing"


@pytest.mark.parametrize("aliased", ["overlay_fd", "masks_fd", "higher_fd", "transient_fd"])
def test_withdraw_refuses_aliased_directory_descriptors(tmp_path, aliased):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        original = env["generator_early_fd"]
        env["generator_early_fd"] = env[aliased]
        try:
            with pytest.raises(ApprovalRefused):
                _withdraw(env)
            assert env["store"].load().phase == "closing"
        finally:
            env["generator_early_fd"] = original


@pytest.mark.parametrize("directory", ["transient", "generator_early"])
def test_competitor_appearing_after_intent_blocks_unlink(tmp_path, monkeypatch, directory):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        replace = env["store"].replace
        conflict = env[directory + "_path"] / PAIR[0]

        def publish_then_compete(expected, updated):
            result = replace(expected, updated)
            if updated.phase == "withdrawing":
                conflict.write_bytes(b"late competitor")
            return result

        monkeypatch.setattr(env["store"], "replace", publish_then_compete)
        with pytest.raises(withdraw.OverlayWithdrawalUncertain):
            _withdraw(env)
        assert env["store"].load().phase == "withdrawing"
        assert conflict.read_bytes() == b"late competitor"
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)


def test_persistent_mask_change_after_intent_blocks_unlink(tmp_path, monkeypatch):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        replace = env["store"].replace
        mask = env["masks_path"] / PAIR[0]

        def publish_then_change_mask(expected, updated):
            result = replace(expected, updated)
            if updated.phase == "withdrawing":
                mask.unlink()
                mask.symlink_to("/tmp/late-mask-change")
            return result

        monkeypatch.setattr(env["store"], "replace", publish_then_change_mask)
        with pytest.raises(withdraw.OverlayWithdrawalUncertain):
            _withdraw(env)
        assert env["store"].load().phase == "withdrawing"
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)


def test_withdraw_requires_containment_callback_to_return_none(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        calls = 0

        def stale():
            nonlocal calls
            calls += 1
            return "synthetic live check result"

        with pytest.raises(ApprovalRefused):
            _withdraw(env, stale)
        assert calls == 1
        assert env["store"].load().phase == "closing"
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)
