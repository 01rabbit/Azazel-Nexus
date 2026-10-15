"""Grant binding and retained ownership checks for file withdrawal."""

import os
from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_overlay_journal import (
    OverlayJournal,
    OverlayStopEvidence,
    advance_overlay,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_withdrawal import BootstrapWithdrawalFiles
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap_overlay_withdraw import (
    PAIR,
    _close,
    _withdraw,
    _withdraw_environment,
)


def _transaction(intent):
    return GrantTransaction(
        boot_id=intent.boot_id,
        context_digest="sha256:" + intent.context_digest,
        approval_digest="sha256:" + "e" * 64,
        generation=1,
        generation_digest="sha256:" + "f" * 64,
        grant_id=intent.grant_id,
        unit_payload_digests=intent.payload_digests,
    )


def _withdrawal(env):
    return BootstrapWithdrawalFiles(
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


@pytest.mark.parametrize(
    "field, value",
    [
        ("boot_id", "cccccccc-cccc-cccc-cccc-cccccccccccc"),
        ("context_digest", "sha256:" + "a" * 64),
        ("grant_id", "1" * 32),
        ("unit_payload_digests", ((PAIR[0], "1" * 64), (PAIR[1], "2" * 64))),
    ],
)
def test_bind_refuses_each_intent_mismatch_before_mutation(tmp_path, field, value):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        before = tuple((env["overlay_path"] / unit).read_bytes() for unit in PAIR)
        transaction = replace(_transaction(closing.intent), **{field: value})

        with pytest.raises(ApprovalRefused):
            _withdrawal(env).bind(transaction)

        assert env["store"].load() == closing
        assert tuple((env["overlay_path"] / unit).read_bytes() for unit in PAIR) == before


@pytest.mark.parametrize("phase", ["closing", "withdrawing", "closed"])
def test_bind_accepts_only_matching_retained_withdrawal_phases(tmp_path, phase):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        current = closing
        if phase == "withdrawing":
            current = advance_overlay(closing, "begin-withdrawal")
            env["store"].replace(closing, current)
            (env["overlay_path"] / PAIR[1]).unlink()
            os.fsync(env["overlay_fd"])
        elif phase == "closed":
            _withdraw(env)
            withdrawing = env["store"].load()
            for unit in PAIR:
                path = env["overlay_path"] / unit
                if path.exists():
                    path.unlink()
            os.fsync(env["overlay_fd"])
            current = OverlayJournal(closing.intent, "closed")
            env["store"].replace(withdrawing, current)

        bound = _withdrawal(env)
        bound.bind(_transaction(current.intent))
        assert bound.check() == tuple(zip(
            (UnitKey.AUDITD, UnitKey.COMMISSIOND),
            (str((env["overlay_path"] if (env["overlay_path"] / unit).exists()
                  else env["masks_path"]) / unit) for unit in PAIR),
            strict=True,
        ))


def test_bind_refuses_unknown_and_replaced_overlay_entries(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        unknown = env["overlay_path"] / PAIR[1]
        first_owned = closing.owned_files[:1]
        partial_closing = OverlayJournal(closing.intent, "closing", first_owned)
        env["store"].replace(closing, partial_closing)
        unknown.unlink()
        unknown.write_bytes(b"foreign")
        with pytest.raises(ApprovalRefused):
            _withdrawal(env).bind(_transaction(partial_closing.intent))
        unknown.unlink()

        target = env["overlay_path"] / PAIR[0]
        retained = env["overlay_path"] / (PAIR[0] + ".retained")
        target.rename(retained)
        target.write_bytes(b"")
        target.chmod(0o600)
        with pytest.raises(ApprovalRefused):
            _withdrawal(env).bind(_transaction(partial_closing.intent))
        assert retained.is_file()
        assert target.read_bytes() == b""
        assert env["store"].load() == partial_closing


def test_resumed_closure_checks_masks_but_cannot_unlink_without_bind(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        withdrawal = _withdrawal(env)
        current = advance_overlay(closing, "begin-withdrawal")
        env["store"].replace(closing, current)
        before = {unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR}

        assert withdrawal.resume_closure() is True
        withdrawal.close()
        assert all(not contents for contents in before.values())
        assert all((env["masks_path"] / unit).is_symlink() for unit in PAIR)
        with pytest.raises(ApprovalRefused, match="explicit grant selection"):
            withdrawal.withdraw(lambda: None)

        assert env["store"].load() == current
        assert {unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR} == before


def test_failed_bind_revokes_previous_grant_selection(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        withdrawal = _withdrawal(env)
        withdrawal.bind(_transaction(closing.intent))
        wrong = replace(_transaction(closing.intent), grant_id="1" * 32)

        with pytest.raises(ApprovalRefused):
            withdrawal.bind(wrong)
        with pytest.raises(ApprovalRefused, match="explicit grant selection"):
            withdrawal.withdraw(lambda: None)

        assert env["store"].load() == closing
        assert all((env["overlay_path"] / unit).read_bytes() == b""
                   for unit in PAIR)


def test_withdraw_returns_restored_observer_after_callback_confirmed_removal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closing = _close(env)
        withdrawal = _withdrawal(env)
        withdrawal.bind(_transaction(closing.intent))
        checks = []

        def check_contained():
            checks.append(True)
            return None

        restored = withdrawal.withdraw(check_contained)

        assert checks
        assert env["store"].load().phase == "withdrawing"
        assert all(not (env["overlay_path"] / unit).exists() for unit in PAIR)
        assert restored.check() == tuple(
            (key, str(env["masks_path"] / unit))
            for key, unit in zip(
                (UnitKey.AUDITD, UnitKey.COMMISSIOND), PAIR, strict=True
            )
        )
        evidence = OverlayStopEvidence(
            start_fence_closed=True,
            stopped_pair=PAIR,
            inactive_pair=PAIR,
            withdrawn_pair=PAIR,
            persistent_masks_restored=True,
            loaded_masks_confirmed=True,
        )
        restored.finalize(evidence)
        assert env["store"].load().phase == "closed"
