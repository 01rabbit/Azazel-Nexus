"""Retirement of a moot overlay journal left by an earlier boot."""

import os

import pytest

from azazel_nexus.bootstrap_overlay_journal import (
    OverlayJournal,
    OverlayJournalDurabilityUncertain,
    advance_overlay,
)
from azazel_nexus.operator_trust import ApprovalRefused
from test_runtime_bootstrap_overlay_files import _intent, _publish, _replace_mask
from test_runtime_bootstrap_overlay_withdraw import PAIR, _withdraw_environment
from test_runtime_bootstrap_withdrawal_binding import _transaction, _withdrawal

OLD_BOOT = _intent().boot_id
NEW_BOOT = "cccccccc-cccc-cccc-cccc-cccccccccccc"


def _drop_pair(env):
    for unit in PAIR:
        path = env["overlay_path"] / unit
        if path.exists():
            path.unlink()
    os.fsync(env["overlay_fd"])


def _stage(env, phase, *, files_absent=True):
    """Persist a journal of `phase` from OLD_BOOT, optionally without its files."""
    journal = _publish(env)
    if phase == "closed":
        _drop_pair(env)
        closed = OverlayJournal(journal.intent, "closed")
        env["store"].replace(journal, closed)
        return closed
    if phase in {"closing", "withdrawing"}:
        closing = advance_overlay(journal, "close-starts")
        env["store"].replace(journal, closing)
        journal = closing
    if phase == "withdrawing":
        withdrawing = advance_overlay(journal, "begin-withdrawal")
        env["store"].replace(journal, withdrawing)
        journal = withdrawing
    if files_absent:
        _drop_pair(env)
    return journal


class Audit:
    def __init__(self, fail=None, before=None):
        self.calls, self.fail, self.before = [], fail, before

    def __call__(self, summary):
        self.calls.append(summary)
        if self.before:
            self.before()
        if self.fail:
            raise self.fail


def _bound(env, boot=NEW_BOOT):
    """This boot's containment fence over the abandoned journal (close_starts)."""
    files = _withdrawal(env)
    assert files.resume_closure(boot_id_reader=lambda: boot) is True
    return files


def _entries(env):
    return sorted(path.name for path in env["journal_path"].iterdir())


def _assert_untouched(env, journal):
    assert env["store"].load() == journal
    assert _entries(env) == ["overlay-journal.json"]


def test_closed_foreign_boot_journal_is_retired_and_audited_first(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        seen = []

        def audit(summary):
            seen.append((summary, env["store"].load_optional()))

        _withdrawal(env).retire_prior_boot(closed, NEW_BOOT, audit)

        (summary, still_there), = seen
        assert still_there == closed
        assert summary["event"] == "retiring"
        assert summary["phase"] == "closed"
        assert summary["boot_id"] == OLD_BOOT
        assert summary["grant_id"] == closed.intent.grant_id
        assert set(summary) == {"event", "phase", "boot_id", "grant_id", "context_digest",
                                "journal_sha256"}
        assert env["store"].load_optional() is None
        assert _entries(env) == []
        # A new publication can create its journal afterwards.
        env["store"].create(OverlayJournal(closed.intent, "intent"))


@pytest.mark.parametrize("phase", ["published", "closing", "withdrawing"])
def test_abandoned_phase_is_reset_then_retired_when_files_absent(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        assert journal.phase == phase
        audit = Audit()
        replaced = []
        real_replace = env["store"].replace

        def spy(expected, next_journal):
            replaced.append((expected, next_journal))
            return real_replace(expected, next_journal)

        files = _bound(env)
        env["store"].replace = spy
        files.retire_prior_boot(journal, NEW_BOOT, audit)

        assert replaced == [(journal, OverlayJournal(journal.intent, "closed"))]
        assert audit.calls[0]["phase"] == phase
        assert env["store"].load_optional() is None
        assert _entries(env) == []


@pytest.mark.parametrize("phase", ["published", "closing", "withdrawing"])
def test_pair_files_present_refuse_without_unlink_or_audit(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase, files_absent=False)
        audit = Audit()
        before = {unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR
                  if (env["overlay_path"] / unit).exists()}
        files = _withdrawal(env)
        try:
            # No fence over a journal whose files are still in the overlay.
            assert files.resume_closure(boot_id_reader=lambda: NEW_BOOT) is False
        except ApprovalRefused:
            pass  # withdrawing with non-empty owned files refuses at binding

        with pytest.raises(ApprovalRefused, match="not bound|pair entry present"):
            files.retire_prior_boot(journal, NEW_BOOT, audit)

        assert audit.calls == []
        assert {unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR
                if (env["overlay_path"] / unit).exists()} == before
        assert before
        _assert_untouched(env, journal)


def test_foreign_file_in_closed_overlay_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        (env["overlay_path"] / PAIR[0]).write_bytes(b"foreign")

        with pytest.raises(ApprovalRefused, match="pair entry present"):
            _withdrawal(env).retire_prior_boot(closed, NEW_BOOT, Audit())

        assert (env["overlay_path"] / PAIR[0]).read_bytes() == b"foreign"
        _assert_untouched(env, closed)


@pytest.mark.parametrize("phase", ["closed", "published"])
def test_same_boot_journal_is_never_retired(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        audit = Audit()

        with pytest.raises(ApprovalRefused, match="belongs to current boot"):
            _withdrawal(env).retire_prior_boot(journal, OLD_BOOT, audit)

        assert audit.calls == []
        _assert_untouched(env, journal)


@pytest.mark.parametrize("phase", ["intent", "partial"])
def test_unpublished_phases_are_not_retired(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        intent = _intent()
        journal = OverlayJournal(intent, "intent")
        env["store"].create(journal)
        if phase == "partial":
            partial = advance_overlay(journal, "create-file", unit=PAIR[1],
                                      device=1, inode=7)
            env["store"].replace(journal, partial)
            journal = partial

        audit = Audit()
        with pytest.raises(ApprovalRefused, match="phase refused"):
            _withdrawal(env).retire_prior_boot(journal, NEW_BOOT, audit)

        assert audit.calls == []
        _assert_untouched(env, journal)


def test_stale_expected_journal_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "withdrawing")
        stale = OverlayJournal(journal.intent, "closed")

        with pytest.raises(ApprovalRefused, match="differs from expected"):
            _withdrawal(env).retire_prior_boot(stale, NEW_BOOT, Audit())

        _assert_untouched(env, journal)


def test_mask_changed_after_binding_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        files = _withdrawal(env)
        files.bind(_transaction(closed.intent))
        _replace_mask(env["masks_path"] / PAIR[0])
        audit = Audit()

        with pytest.raises(ApprovalRefused, match="masks changed"):
            files.retire_prior_boot(closed, NEW_BOOT, audit)

        assert audit.calls == []
        _assert_untouched(env, closed)


@pytest.mark.parametrize("target, refusal", [
    ("/dev/null", "retirement masks changed"),       # same content: the stamp moved
    ("/dev/zero", "persistent helper mask changed"),  # no longer a mask: content check
])
def test_mask_changed_during_audit_refuses_before_any_mutation(tmp_path, target, refusal):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "published")

        def swap_mask():
            _replace_mask(env["masks_path"] / PAIR[1], target)

        files = _bound(env)
        with pytest.raises(ApprovalRefused, match=refusal):
            files.retire_prior_boot(journal, NEW_BOOT, Audit(before=swap_mask))

        _assert_untouched(env, journal)


@pytest.mark.parametrize("failure", [RuntimeError("ledger down"), OSError("disk full"),
                                     KeyboardInterrupt])
def test_audit_failure_leaves_journal_untouched(tmp_path, failure):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "withdrawing")
        audit = Audit(fail=failure)
        files = _bound(env)

        if failure is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt):
                files.retire_prior_boot(journal, NEW_BOOT, audit)
        else:
            with pytest.raises(ApprovalRefused, match="audit record refused"):
                files.retire_prior_boot(journal, NEW_BOOT, audit)

        assert len(audit.calls) == 1
        _assert_untouched(env, journal)


@pytest.mark.parametrize("audit", [None, "not callable", 0])
def test_missing_audit_callable_refuses(tmp_path, audit):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")

        with pytest.raises(ApprovalRefused, match="arguments refused"):
            _withdrawal(env).retire_prior_boot(closed, NEW_BOOT, audit)

        _assert_untouched(env, closed)


@pytest.mark.parametrize("boot", [None, "", "not-a-uuid", NEW_BOOT.upper(),
                                  NEW_BOOT.replace("-", ""), "{" + NEW_BOOT + "}"])
def test_non_canonical_current_boot_refuses(tmp_path, boot):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        audit = Audit()

        with pytest.raises(ApprovalRefused, match="current boot id refused"):
            _withdrawal(env).retire_prior_boot(closed, boot, audit)

        assert audit.calls == []

        _assert_untouched(env, closed)


def test_reset_replace_failure_keeps_old_phase_and_no_removal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "closing")
        removed = []
        files = _bound(env)

        def fail_replace(_expected, _next):
            raise OverlayJournalDurabilityUncertain("injected")

        env["store"].replace = fail_replace
        env["store"].remove = lambda expected: removed.append(expected)

        with pytest.raises(OverlayJournalDurabilityUncertain, match="injected"):
            files.retire_prior_boot(journal, NEW_BOOT, Audit())

        assert removed == []
        del env["store"].replace
        _assert_untouched(env, journal)
        assert not any((env["overlay_path"] / unit).exists() for unit in PAIR)


def test_unlink_failure_surfaces_and_is_retired_on_rerun(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "published")
        real_remove = env["store"].remove

        def uncertain(_expected):
            raise OverlayJournalDurabilityUncertain("injected")

        files = _bound(env)
        env["store"].remove = uncertain
        with pytest.raises(OverlayJournalDurabilityUncertain, match="injected"):
            files.retire_prior_boot(journal, NEW_BOOT, Audit())

        closed = OverlayJournal(journal.intent, "closed")
        assert env["store"].load() == closed
        assert not any((env["overlay_path"] / unit).exists() for unit in PAIR)

        env["store"].remove = real_remove
        _withdrawal(env).retire_prior_boot(closed, NEW_BOOT, Audit())
        assert env["store"].load_optional() is None


def test_retire_resets_bound_state_so_resume_closure_does_not_raise(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        files = _withdrawal(env)
        files.bind(_transaction(closed.intent))

        files.retire_prior_boot(closed, NEW_BOOT, Audit())

        assert files._intent is None and files._owned is None and files._stamps is None
        assert files.resume_closure() is False


def test_journal_changed_during_audit_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "published")
        closed = OverlayJournal(journal.intent, "closed")

        def change():
            env["store"].replace(journal, closed)

        files = _bound(env)
        with pytest.raises(ApprovalRefused, match="changed during retirement"):
            files.retire_prior_boot(journal, NEW_BOOT, Audit(before=change))

        assert env["store"].load() == closed


def test_pair_file_appearing_during_audit_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "closing")

        def appear():
            (env["overlay_path"] / PAIR[1]).write_bytes(b"")

        files = _bound(env)
        with pytest.raises(ApprovalRefused, match="pair entry present"):
            files.retire_prior_boot(journal, NEW_BOOT, Audit(before=appear))

        _assert_untouched(env, journal)


def test_foreign_entry_on_second_unit_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        (env["overlay_path"] / PAIR[1]).write_bytes(b"foreign")

        with pytest.raises(ApprovalRefused, match="pair entry present"):
            _withdrawal(env).retire_prior_boot(closed, NEW_BOOT, Audit())

        _assert_untouched(env, closed)


@pytest.mark.parametrize("where", ["transient", "generator_early"])
def test_higher_priority_dropin_refuses(tmp_path, where):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        (env[where + "_path"] / (PAIR[0] + ".d")).mkdir()
        audit = Audit()

        with pytest.raises(ApprovalRefused, match="higher-priority competitor"):
            _withdrawal(env).retire_prior_boot(closed, NEW_BOOT, audit)

        assert audit.calls == []
        _assert_untouched(env, closed)


def test_remove_failure_leaves_no_stale_binding(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        files = _withdrawal(env)
        files.bind(_transaction(closed.intent))

        def uncertain(_expected):
            raise OverlayJournalDurabilityUncertain("injected")

        env["store"].remove = uncertain
        with pytest.raises(OverlayJournalDurabilityUncertain, match="injected"):
            files.retire_prior_boot(closed, NEW_BOOT, Audit())

        assert files._intent is None and files._owned is None and files._stamps is None


def test_finalize_never_deletes_the_journal():
    from pathlib import Path

    source = (Path(__file__).parents[2] / "runtime/src/azazel_nexus_runtime"
              / "bootstrap_restore_files.py").read_text()
    assert ".remove(" not in source
    assert "retire_prior_boot" not in source
