"""Reboot-reset of an overlay journal abandoned in published/closing/withdrawing.

Owner decision on Nexus#324 (Option 2 of
docs/evidence/bootstrap-design-journal-lifecycle-2026-10-16.md): a journal
left by an earlier boot (for example after a watchdog SIGKILL) is fenced by
the persistent masks in this boot's containment, then reset to closed and
retired at publication, only when its boot id differs from the current boot,
no pair entry exists in the overlay and the persistent mask stamps are
unchanged. Everything else refuses exactly as before.

Real BootstrapNarrowingManager, overlay file objects, journal store and guard
over a temporary tree; only the system bus and cgroup tree are synthetic.
"""

from contextlib import contextmanager
from dataclasses import replace
import os

import pytest

from azazel_nexus.bootstrap_overlay_journal import (
    OverlayJournal,
    OverlayJournalDurabilityUncertain,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_journal_retire import NEW_BOOT, OLD_BOOT, _drop_pair, _stage
from test_runtime_bootstrap_journal_retire_callsite import _abandoned_grant
from test_runtime_bootstrap_manager_stopped import _cgroup_root
from test_runtime_bootstrap_overlay_withdraw import PAIR, _withdraw_environment
from test_runtime_bootstrap_unpublished_withdrawal import _real_manager
from test_runtime_bootstrap_unpublished_withdrawal import _transaction as _grant
from test_runtime_bootstrap_withdrawal_binding import _withdrawal

ABANDONED = ("published", "closing", "withdrawing")
WRITES = ("create", "replace", "remove")


def _spy(env):
    calls = []
    for name in WRITES:
        real = getattr(env["store"], name)

        def spy(*args, _real=real, _name=name, **kwargs):
            calls.append(_name)
            return _real(*args, **kwargs)

        setattr(env["store"], name, spy)
    return calls


def _current_grant():
    """This boot's grant after open_pair failed before its journal create."""
    return replace(_grant("pair_grant_intent"), boot_id=NEW_BOOT)


@contextmanager
def _host(tmp_path, phase, *, boot=NEW_BOOT, files_absent=True, grant_phase=None):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase, files_absent=files_absent)
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            manager = _real_manager(env, root_fd, [])
            manager._boot_id_reader = lambda: boot
            prior = _abandoned_grant(journal, grant_phase or "commissiond_ready")

            class Grants:
                def load(self, *, boot_id):
                    if boot_id != OLD_BOOT:
                        raise ApprovalRefused("bootstrap transaction unavailable")
                    return prior

            @contextmanager
            def opener(guard):
                assert guard is env["guard"]
                yield Grants()

            manager._grant_store_opener = opener
            manager.records = []
            manager._retirement_record = manager.records.append
            yield env, manager, journal
        finally:
            os.close(root_fd)


def _retire(env, manager):
    manager._retire_prior_boot_journal(env["store"], env["guard"])


def _overlay(env):
    return sorted(path.name for path in env["overlay_path"].iterdir())


# -- withdrawal files: the prior-boot fence itself ------------------------


@pytest.mark.parametrize("phase", ["published", "closing"])
def test_prior_boot_fence_binds_without_any_write(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        files = _withdrawal(env)
        calls = _spy(env)
        assert files.resume_closure(boot_id_reader=lambda: NEW_BOOT) is True
        fragments = files.check()
        assert files.close() is None
        assert [path for _key, path in fragments] == [
            str(env["masks_path"] / unit) for unit in PAIR]
        assert calls == []
        assert env["store"].load() == journal


@pytest.mark.parametrize("phase", ["published", "closing"])
@pytest.mark.parametrize("reader", [
    None,
    lambda: OLD_BOOT,  # same boot: never the reboot path
    lambda: NEW_BOOT.upper(),
    lambda: "not-a-uuid",
    lambda: (_ for _ in ()).throw(OSError("no /proc")),
])
def test_prior_boot_fence_not_proven_keeps_existing_path(tmp_path, phase, reader):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        files = _withdrawal(env)
        assert files.resume_closure(boot_id_reader=reader) is False
        assert files._prior_boot is None and files._intent is None
        assert env["store"].load() == journal


@pytest.mark.parametrize("phase", ["published", "closing"])
def test_prior_boot_fence_refused_with_any_overlay_entry(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        (env["overlay_path"] / PAIR[1]).write_bytes(b"")
        files = _withdrawal(env)
        assert files.resume_closure(boot_id_reader=lambda: NEW_BOOT) is False
        assert env["store"].load() == journal


@pytest.mark.parametrize("phase", ["intent", "partial"])
def test_prior_boot_fence_not_offered_for_unpublished_phases(tmp_path, phase):
    from azazel_nexus.bootstrap_overlay_journal import advance_overlay
    from test_runtime_bootstrap_overlay_files import _intent

    with _withdraw_environment(tmp_path) as env:
        journal = OverlayJournal(_intent(), "intent")
        env["store"].create(journal)
        if phase == "partial":
            partial = advance_overlay(journal, "create-file", unit=PAIR[1], device=1, inode=7)
            env["store"].replace(journal, partial)
        assert _withdrawal(env).resume_closure(boot_id_reader=lambda: NEW_BOOT) is False


@pytest.mark.parametrize("change", ["entry", "journal", "mask"])
def test_prior_boot_fence_check_refuses_after_change(tmp_path, change):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "published")
        files = _withdrawal(env)
        assert files.resume_closure(boot_id_reader=lambda: NEW_BOOT) is True
        if change == "entry":
            (env["overlay_path"] / PAIR[0]).write_bytes(b"")
        elif change == "journal":
            env["store"].replace(journal, OverlayJournal(journal.intent, "closed"))
        else:
            mask = env["masks_path"] / PAIR[0]
            mask.unlink()
            mask.symlink_to("/dev/null")
        with pytest.raises(ApprovalRefused):
            files.check()


@pytest.mark.parametrize("phase", ABANDONED)
def test_retire_refuses_abandoned_journal_not_bound_in_this_boot(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        audit = []
        with pytest.raises(ApprovalRefused, match="not bound"):
            _withdrawal(env).retire_prior_boot(journal, NEW_BOOT, audit.append)
        assert audit == []
        assert env["store"].load() == journal


def test_retire_refuses_when_fenced_journal_was_replaced(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "published")
        files = _withdrawal(env)
        assert files.resume_closure(boot_id_reader=lambda: NEW_BOOT) is True
        from azazel_nexus.bootstrap_overlay_journal import advance_overlay
        closing = advance_overlay(journal, "close-starts")
        env["store"].replace(journal, closing)
        audit = []
        with pytest.raises(ApprovalRefused, match="not bound"):
            files.retire_prior_boot(closing, NEW_BOOT, audit.append)
        assert audit == [] and env["store"].load() == closing


def test_withdraw_refused_while_only_prior_boot_fence_is_bound(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _stage(env, "published")
        files = _withdrawal(env)
        assert files.resume_closure(boot_id_reader=lambda: NEW_BOOT) is True
        files._selected_transaction = _current_grant()  # never set by bind here
        with pytest.raises(ApprovalRefused, match="explicit grant selection"):
            files.withdraw(lambda: None)


# -- real manager: containment, retirement and the crash points ------------


@pytest.mark.parametrize("phase", ABANDONED)
def test_rebooted_journal_is_fenced_then_retired_then_baseline_closes(tmp_path, phase):
    with _host(tmp_path, phase) as (env, manager, journal):
        calls = _spy(env)
        assert manager.close_starts() is None
        assert manager._containment_files is manager._withdrawal_files
        assert manager.confirm_empty_pair() is None
        assert calls == []  # containment alone never writes the journal

        _retire(env, manager)
        assert calls == ["replace", "remove"]
        assert env["store"].load_optional() is None
        assert list(env["journal_path"].iterdir()) == []
        files = manager._withdrawal_files
        assert (files._prior_boot, files._intent, files._owned, files._stamps) == (
            None, None, None, None)
        (event,) = manager.records
        assert (event["phase"], event["boot_id"], event["grant_id"]) == (
            phase, OLD_BOOT, journal.intent.grant_id)

        # Publication then fails before its journal create: the next
        # containment of this process takes the initial-baseline branch.
        assert manager.close_starts() is None
        assert manager._containment_files is manager._closed_overlay_files
        assert manager.withdraw_pair(_current_grant()) is None
        assert manager.withdrawal_kind == "unpublished-baseline"
        assert manager.confirm_empty_pair() is None
        assert _overlay(env) == []
        assert calls == ["replace", "remove"]


@pytest.mark.parametrize("phase", ["published", "closing"])
def test_same_boot_abandoned_journal_still_refuses_containment(tmp_path, phase):
    with _host(tmp_path, phase, boot=OLD_BOOT) as (env, manager, journal):
        calls = _spy(env)
        with pytest.raises(Exception):
            manager.close_starts()
        assert calls == [] and env["store"].load() == journal
        assert manager.records == []


def test_same_boot_withdrawing_journal_is_never_retired(tmp_path):
    with _host(tmp_path, "withdrawing", boot=OLD_BOOT) as (env, manager, journal):
        assert manager.close_starts() is None
        calls = _spy(env)
        _retire(env, manager)  # same boot: no-op, the later create refuses
        assert calls == [] and manager.records == []
        assert env["store"].load() == journal


def test_overlay_files_present_refuse_retirement(tmp_path):
    with _host(tmp_path, "published", files_absent=False) as (env, manager, journal):
        # Existing path: the close truncates the owned files it can prove.
        assert manager.close_starts() is None
        assert manager._containment_files is manager._closed_overlay_files
        with pytest.raises(UnitOperationFailed, match="not this boot's fence"):
            _retire(env, manager)
        assert env["store"].load().intent == journal.intent
        assert _overlay(env) == sorted(PAIR)
        assert manager.records == []


def test_unowned_overlay_entry_refuses_containment_and_is_untouched(tmp_path):
    with _host(tmp_path, "published") as (env, manager, journal):
        (env["overlay_path"] / PAIR[0]).write_bytes(b"foreign")
        with pytest.raises(Exception):
            manager.close_starts()
        assert (env["overlay_path"] / PAIR[0]).read_bytes() == b"foreign"
        assert env["store"].load() == journal and manager.records == []


def test_mask_changed_after_containment_refuses_retirement(tmp_path):
    with _host(tmp_path, "published") as (env, manager, journal):
        assert manager.close_starts() is None
        mask = env["masks_path"] / PAIR[1]
        mask.unlink()
        mask.symlink_to("/dev/null")
        calls = _spy(env)
        with pytest.raises(ApprovalRefused, match="masks changed"):
            _retire(env, manager)
        assert calls == [] and manager.records == []
        assert env["store"].load() == journal


def test_crash_at_reset_replace_keeps_old_phase_and_refuses_withdrawal(tmp_path):
    with _host(tmp_path, "published") as (env, manager, journal):
        assert manager.close_starts() is None

        def uncertain(_expected, _next):
            raise OverlayJournalDurabilityUncertain("injected")

        env["store"].replace = uncertain
        with pytest.raises(OverlayJournalDurabilityUncertain):
            _retire(env, manager)
        del env["store"].replace
        assert env["store"].load() == journal and len(manager.records) == 1
        # Finish path: containment re-fences, withdrawal of this boot's grant
        # refuses (the supervisor then records recovery_required).
        assert manager.close_starts() is None
        with pytest.raises(UnitOperationFailed):
            manager.withdraw_pair(_current_grant())
        assert env["store"].load() == journal and _overlay(env) == []


def test_crash_after_reset_before_unlink_leaves_closed_and_refuses(tmp_path):
    with _host(tmp_path, "closing") as (env, manager, journal):
        assert manager.close_starts() is None

        def uncertain(_expected):
            raise OverlayJournalDurabilityUncertain("injected")

        env["store"].remove = uncertain
        with pytest.raises(OverlayJournalDurabilityUncertain):
            _retire(env, manager)
        del env["store"].remove
        closed = OverlayJournal(journal.intent, "closed")
        assert env["store"].load() == closed
        assert manager.close_starts() is None
        with pytest.raises(UnitOperationFailed):
            manager.withdraw_pair(_current_grant())
        assert env["store"].load() == closed and _overlay(env) == []


def test_closed_by_reset_with_unfinished_prior_grant_keeps_manual_review(tmp_path):
    # A later boot sees the reset-closed journal; the closed rule (prior grant
    # closed) is unchanged, so it is not retired automatically.
    with _host(tmp_path, "published") as (env, manager, journal):
        closed = OverlayJournal(journal.intent, "closed")
        env["store"].replace(journal, closed)
        assert manager.close_starts() is None
        calls = _spy(env)
        with pytest.raises(ApprovalRefused, match="audit record refused"):
            _retire(env, manager)
        assert calls == [] and env["store"].load() == closed


def test_crash_after_unlink_before_directory_fsync_takes_baseline(tmp_path):
    with _host(tmp_path, "withdrawing") as (env, manager, journal):
        assert manager.close_starts() is None
        real_remove = env["store"].remove

        def unlinked_then_uncertain(expected):
            real_remove(expected)
            raise OverlayJournalDurabilityUncertain("injected")

        env["store"].remove = unlinked_then_uncertain
        with pytest.raises(OverlayJournalDurabilityUncertain):
            _retire(env, manager)
        assert env["store"].load_optional() is None
        assert manager.close_starts() is None
        assert manager.withdraw_pair(_current_grant()) is None
        assert manager.withdrawal_kind == "unpublished-baseline"


def test_record_failure_in_real_manager_leaves_everything(tmp_path):
    with _host(tmp_path, "published") as (env, manager, journal):
        assert manager.close_starts() is None

        def unwritable(_event):
            raise OSError("ledger unwritable")

        manager._retirement_record = unwritable
        calls = _spy(env)
        with pytest.raises(ApprovalRefused, match="audit record refused"):
            _retire(env, manager)
        assert calls == [] and env["store"].load() == journal


def test_reboot_after_retire_needs_no_journal_files(tmp_path):
    """Directory contents after each outcome: only the journal or nothing."""
    with _host(tmp_path, "published") as (env, manager, _journal):
        assert sorted(p.name for p in env["journal_path"].iterdir()) == [
            "overlay-journal.json"]
        assert manager.close_starts() is None
        _retire(env, manager)
        assert list(env["journal_path"].iterdir()) == []
        _drop_pair(env)  # idempotent: nothing to drop
        assert _overlay(env) == []
