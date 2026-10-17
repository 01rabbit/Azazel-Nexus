"""Publication must consume the grant identity persisted before publication."""

from dataclasses import asdict, replace
from contextlib import contextmanager
from hashlib import sha256
import json
import os

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_grant_store import GrantTransactionStore
from azazel_nexus.bootstrap_overlay_journal import OverlayIntent
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_overlay_files as writer
from test_runtime_bootstrap_overlay_files import PAIR, _approval, _environment
from test_runtime_bootstrap_overlay_withdraw import _withdraw_environment
from test_runtime_bootstrap_withdrawal_binding import _withdrawal


@contextmanager
def _persisted_grant(root, transaction):
    directory = root / "grant"
    directory.mkdir(mode=0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    def reopen():
        return os.open(directory, flags)
    fd = reopen()
    store = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=reopen)
    os.close(fd)
    try:
        prepared = replace(transaction, phase="prepared")
        store.create(prepared)
        store.advance(prepared, "pair_grant_intent")
        def check():
            if store.load(boot_id=transaction.boot_id) != transaction:
                raise ApprovalRefused("retained grant changed")
        yield check
    finally:
        store.close()


def _transaction(approval, *, grant_id="0123456789abcdef0123456789abcdef",
                phase="pair_grant_intent"):
    payloads = writer._fixed_payloads()
    context_raw = json.dumps(asdict(approval.context), sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    return GrantTransaction(
        boot_id=approval.context.boot_id,
        context_digest="sha256:" + sha256(context_raw).hexdigest(),
        approval_digest=approval.payload_digest,
        generation=approval.context.generation,
        generation_digest=approval.context.generation_digest,
        grant_id=grant_id,
        unit_payload_digests=tuple(
            (unit, sha256(payloads[unit]).hexdigest()) for unit in PAIR
        ),
        phase=phase,
        close_intent_digest="sha256:" + "a" * 64 if phase == "closed" else None,
        close_evidence_digest="sha256:" + "b" * 64 if phase == "closed" else None,
    )


def _publish(env, approval, transaction, check_publish=lambda: None):
    return writer._publish_verified_approval_at(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        journal_store=env["store"],
        guard=env["guard"],
        approval=approval,
        transaction=transaction,
        check_publish=check_publish,
        owner_uid=os.getuid(),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
        {"context_digest": "sha256:" + "0" * 64},
        {"approval_digest": "sha256:" + "0" * 64},
        {"generation": 2},
        {"generation_digest": "sha256:" + "0" * 64},
        {"unit_payload_digests": ((PAIR[0], "0" * 64), (PAIR[1], "1" * 64))},
    ],
)
def test_mismatched_retained_transaction_refuses_before_writes(tmp_path, changes):
    approval = _approval()
    transaction = replace(_transaction(approval), **changes)
    with _environment(tmp_path) as env:
        with pytest.raises(ApprovalRefused):
            _publish(env, approval, transaction)
        assert list(env["overlay_path"].iterdir()) == []
        assert list(env["journal_path"].iterdir()) == []


@pytest.mark.parametrize("phase", ["prepared", "pair_grant_opened", "closed"])
def test_non_intent_transaction_phase_refuses_before_writes(tmp_path, phase):
    approval = _approval()
    transaction = _transaction(approval, phase=phase)
    with _environment(tmp_path) as env:
        with pytest.raises(ApprovalRefused):
            _publish(env, approval, transaction)
        assert list(env["overlay_path"].iterdir()) == []
        assert list(env["journal_path"].iterdir()) == []


def test_publication_uses_persisted_grant_id_and_retains_withdrawal_identity(tmp_path):
    approval = _approval()
    transaction = _transaction(approval)
    with _withdraw_environment(tmp_path) as env, _persisted_grant(tmp_path, transaction) as check:
        published = _publish(env, approval, transaction, check)

        assert published.phase == "published"
        assert published.intent == OverlayIntent(
            boot_id=transaction.boot_id,
            context_digest=transaction.context_digest.removeprefix("sha256:"),
            grant_id=transaction.grant_id,
            payload_digests=transaction.unit_payload_digests,
        )
        assert published.intent.grant_id == transaction.grant_id

        closing = writer._close_candidates_at(
            overlay_fd=env["overlay_fd"],
            masks_fd=env["masks_fd"],
            higher_priority_fd=env["higher_fd"],
            journal_store=env["store"],
            guard=env["guard"],
            owner_uid=os.getuid(),
        )
        assert closing.phase == "closing"
        assert closing.intent == published.intent
        assert closing.intent.grant_id == transaction.grant_id
        withdrawal = _withdrawal(env)
        withdrawal.bind(transaction)
        restored = withdrawal.withdraw(lambda: None)
        assert len(restored.check()) == 2
        assert env["store"].load().phase == "withdrawing"


def test_false_publication_checkpoint_refuses_before_journal_or_files(tmp_path):
    approval = _approval()
    transaction = _transaction(approval)
    checks = []

    def reject_publication():
        checks.append(True)
        return False

    with _environment(tmp_path) as env:
        with pytest.raises(ApprovalRefused):
            _publish(env, approval, transaction, reject_publication)
        assert checks
        assert list(env["overlay_path"].iterdir()) == []
        assert list(env["journal_path"].iterdir()) == []


@pytest.mark.parametrize("stop_at, expected_phase, owned, present", [
    # Full-check positions after redundant-checkpoint removal (READY budget):
    # 1 before journal create, 2 top of unit 0, 3 before unit-0 replace,
    # 4 top of unit 1, 5 before unit-1 replace. No check after the final
    # replace (the manager's checkpoint before Reload covers it).
    (2, "intent", 0, 0),
    (3, "intent", 0, 1),
    (4, "partial", 1, 1),
    (5, "partial", 1, 2),
])
def test_checkpoint_rejection_preserves_partial_publication_evidence(
    tmp_path, stop_at, expected_phase, owned, present,
):
    approval = _approval()
    transaction = _transaction(approval)
    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1
        if calls == stop_at:
            raise ApprovalRefused("synthetic admission loss")

    with _environment(tmp_path) as env:
        with pytest.raises(ApprovalRefused):
            _publish(env, approval, transaction, checkpoint)
        journal = env["store"].load()
        assert journal.intent.grant_id == transaction.grant_id
        assert journal.phase == expected_phase
        assert len(journal.owned_files) == owned
        assert len(list(env["overlay_path"].iterdir())) == present
        # No restart/retry or unowned-file cleanup is inferred from failure.
        assert all((env["masks_path"] / name).is_symlink() for name in PAIR)


def test_no_full_check_after_final_journal_replace_in_publication(tmp_path):
    approval = _approval()
    transaction = _transaction(approval)
    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1

    with _environment(tmp_path) as env:
        _publish(env, approval, transaction, checkpoint)
        assert env["store"].load().phase == "published"
    assert calls == 5


@pytest.mark.parametrize("checkpoint", [None, False, "allow"])
def test_missing_or_noncallable_admission_is_not_a_default_permission(tmp_path, checkpoint):
    approval = _approval()
    with _environment(tmp_path) as env:
        with pytest.raises(ApprovalRefused):
            _publish(env, approval, _transaction(approval), checkpoint)
        assert list(env["journal_path"].iterdir()) == []
        assert list(env["overlay_path"].iterdir()) == []
