"""Prior-boot journal retirement call site in publication (read-only identity proof)."""

from contextlib import contextmanager
from dataclasses import replace
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_overlay_journal import OverlayJournal
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_manager as module
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_masked import MaskedBootstrapPair
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_journal_retire import NEW_BOOT, OLD_BOOT, _entries, _stage
from test_runtime_bootstrap_overlay_withdraw import _withdraw_environment
from test_runtime_bootstrap_withdrawal_binding import _transaction, _withdrawal

STORE_WRITES = ("create", "replace", "remove")


class Reached(Exception):
    pass


class _Approval:
    context = None


def journal_intent(env):
    return env["store"].load().intent


class GrantStore:
    def __init__(self, grants):
        self.grants, self.loads = grants, []

    def load(self, *, boot_id):
        self.loads.append(boot_id)
        if boot_id not in self.grants:
            raise ApprovalRefused("bootstrap transaction unavailable")
        return self.grants[boot_id]

    def __getattr__(self, name):
        raise AssertionError(f"grant store write/other access: {name}")


def _manager(env, grants, boot=NEW_BOOT, monkeypatch=None):
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, withdrawal_files=_withdrawal(env),
    )
    manager._boot_id_reader = lambda: boot
    store = GrantStore(grants)

    @contextmanager
    def opener(guard):
        assert guard is env["guard"]
        yield store

    manager._grant_store_opener = opener
    return manager, store


def _spy_writes(env):
    calls = []
    for name in STORE_WRITES:
        real = getattr(env["store"], name)

        def spy(*args, _real=real, _name=name, **kwargs):
            calls.append(_name)
            return _real(*args, **kwargs)

        setattr(env["store"], name, spy)
    return calls


def _grant_for(journal, **changes):
    if changes.setdefault("phase", "closed") == "closed":
        changes.setdefault("close_intent_digest", "sha256:" + "c" * 64)
        changes.setdefault("close_evidence_digest", "sha256:" + "d" * 64)
    return replace(_transaction(journal.intent), **changes)


def test_foreign_closed_journal_with_matching_prior_grant_is_retired(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, grants = _manager(env, {OLD_BOOT: _grant_for(closed)})
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert env["store"].load_optional() is None
        assert _entries(env) == []
        assert grants.loads == [OLD_BOOT]


def test_published_foreign_journal_without_files_is_reset_and_retired(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, "published")
        assert journal.phase == "published"
        manager, _ = _manager(env, {OLD_BOOT: _grant_for(journal)})
        calls = _spy_writes(env)
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == ["replace", "remove"]
        assert env["store"].load_optional() is None


@pytest.mark.parametrize(
    "case", ["missing", "grant_id", "context", "boot", "recovery", "intent", "payload"])
def test_missing_or_mismatched_prior_grant_refuses_without_removal(tmp_path, case):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        grant = _grant_for(closed)
        grants = {
            "missing": {},
            "grant_id": {OLD_BOOT: _grant_for(closed, grant_id="1" * 32)},
            "context": {OLD_BOOT: _grant_for(closed, context_digest="sha256:" + "9" * 64)},
            "boot": {OLD_BOOT: _grant_for(closed, boot_id=NEW_BOOT)},
            "recovery": {OLD_BOOT: _grant_for(
                closed, phase="recovery_required",
                recovery_evidence_digest="sha256:" + "a" * 64)},
            "intent": {OLD_BOOT: _grant_for(closed, phase="pair_grant_intent")},
            "payload": {OLD_BOOT: _grant_for(closed, unit_payload_digests=tuple(
                (unit, "0" * 64) for unit, _ in closed.intent.payload_digests))},
        }[case]
        manager, _ = _manager(env, grants)
        calls = _spy_writes(env)
        with pytest.raises(ApprovalRefused):
            manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == []
        assert env["store"].load() == closed
        assert _entries(env) == ["overlay-journal.json"]
        assert grant.grant_id == closed.intent.grant_id


def test_same_boot_journal_is_never_retired(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, grants = _manager(env, {OLD_BOOT: _grant_for(closed)}, boot=OLD_BOOT)
        calls = _spy_writes(env)
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == [] and grants.loads == []
        assert env["store"].load() == closed


def test_no_journal_changes_nothing(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        manager, grants = _manager(env, {})
        calls = _spy_writes(env)
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == [] and grants.loads == []


def test_non_canonical_current_boot_id_refuses(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, _ = _manager(env, {OLD_BOOT: _grant_for(closed)}, boot=NEW_BOOT.upper())
        calls = _spy_writes(env)
        with pytest.raises(UnitOperationFailed):
            manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == [] and env["store"].load() == closed


def test_prior_grant_verification_never_writes_grant_store(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, grants = _manager(env, {OLD_BOOT: _grant_for(closed)})
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        # GrantStore raises on any attribute other than load().
        assert grants.loads == [OLD_BOOT]


def _publication_manager(env, monkeypatch, grants, boot=NEW_BOOT):
    manager, _ = _manager(env, grants, boot=boot)
    closed = MaskedBootstrapPair(owner=":1.5", fragments=(), fingerprint="f")
    manager._closed_observation = closed
    directories = SimpleNamespace(
        arguments={"overlay_fd": env["overlay_fd"], "masks_fd": env["masks_fd"],
                   "higher_priority_fd": env["higher_fd"]},
        owner_uid=0, check=lambda: None,
    )
    manager._publication_inputs = (directories, env["store"], env["guard"])
    manager._check_cgroup_mount = lambda: None
    manager.confirm_empty_pair = lambda: None
    monkeypatch.setattr(module, "current_bootstrap_controller_identity", lambda: None)
    monkeypatch.setattr(module, "load_loaded_bootstrap_policy", lambda expected: None)
    monkeypatch.setattr(module, "_mask_paths", lambda **kw: {})
    approval = _Approval()
    monkeypatch.setattr(module, "VerifiedBootstrapApproval", _Approval)
    seen = {}

    def publish(**kw):
        seen["journal"] = env["store"].load_optional()
        seen["observation"] = manager._closed_observation
        raise Reached

    monkeypatch.setattr(module, "_publish_verified_approval_at", publish)
    transaction = replace(_transaction(journal_intent(env)), phase="pair_grant_intent")
    return manager, transaction, approval, seen


def test_publication_proceeds_after_retirement_and_not_before_it(tmp_path, monkeypatch):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, tx, approval, seen = _publication_manager(
            env, monkeypatch, {OLD_BOOT: _grant_for(closed)})
        with pytest.raises(Reached):
            manager._publish_and_inspect_pair(
                tx, approval=approval, check_publish=lambda: None)
        assert seen["journal"] is None  # retired before publication began
        assert seen["observation"] is None


def test_publication_refused_and_journal_intact_without_prior_grant(tmp_path, monkeypatch):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, tx, approval, seen = _publication_manager(env, monkeypatch, {})
        with pytest.raises(ApprovalRefused):
            manager._publish_and_inspect_pair(
                tx, approval=approval, check_publish=lambda: None)
        assert seen == {}
        assert env["store"].load() == closed
        assert isinstance(closed, OverlayJournal)


@pytest.mark.parametrize("phase", ["recovery_required", "pair_grant_intent"])
def test_publication_refused_for_unfinished_prior_grant(tmp_path, monkeypatch, phase):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        extra = ({"recovery_evidence_digest": "sha256:" + "a" * 64}
                 if phase == "recovery_required" else {})
        manager, tx, approval, seen = _publication_manager(
            env, monkeypatch, {OLD_BOOT: _grant_for(closed, phase=phase, **extra)})
        with pytest.raises(ApprovalRefused):
            manager._publish_and_inspect_pair(
                tx, approval=approval, check_publish=lambda: None)
        assert seen == {}
        assert env["store"].load() == closed


def test_missing_withdrawal_files_refuses_foreign_journal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, _ = _manager(env, {OLD_BOOT: _grant_for(closed)})
        manager._withdrawal_files = None
        with pytest.raises(UnitOperationFailed):
            manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert env["store"].load() == closed


def test_real_grant_store_pending_marker_refuses(tmp_path):
    from azazel_nexus.bootstrap_grant_store import GrantTransactionStore
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        state = tmp_path / "grants"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            grants = GrantTransactionStore(
                fd, owner_uid=os.getuid(),
                reopen=lambda: os.open(state, os.O_RDONLY | os.O_DIRECTORY))
            grants.create(_grant_for(closed, phase="prepared"))
            (state / f".grant-{OLD_BOOT}.json.pending").write_bytes(b"x")
            manager, _ = _manager(env, {})

            @contextmanager
            def opener(guard):
                yield grants

            manager._grant_store_opener = opener
            with pytest.raises(ApprovalRefused, match="unfinished"):
                grants.load(boot_id=OLD_BOOT)
            with pytest.raises(ApprovalRefused):
                manager._retire_prior_boot_journal(env["store"], env["guard"])
            assert env["store"].load() == closed
            grants.close()
        finally:
            os.close(fd)


def test_after_retirement_resume_closure_is_false_and_baseline_close_passes(tmp_path):
    from azazel_nexus_runtime.bootstrap_close_files import BootstrapClosedOverlayFiles
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, _ = _manager(env, {OLD_BOOT: _grant_for(closed)})
        # The first containment of this process already bound the closed journal.
        assert manager._withdrawal_files.resume_closure() is True
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert manager._withdrawal_files.resume_closure() is False
        files = BootstrapClosedOverlayFiles(
            overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
            higher_priority_fd=env["higher_fd"], overlay_path=env["overlay_path"],
            masks_path=env["masks_path"], higher_priority_path=env["higher_path"],
            journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
        )
        files.close()
        assert files.initial_baseline() is True
