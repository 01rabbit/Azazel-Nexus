import os
from contextlib import contextmanager
from hashlib import sha256

import pytest
from azazel_nexus_runtime import bootstrap_overlay_files as writer

from azazel_nexus import bootstrap_lock
from azazel_nexus.bootstrap_approval import BootstrapContext, VerifiedBootstrapApproval
from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_overlay_journal import (
    OverlayIntent,
    OverlayJournalStore,
)
from azazel_nexus.operator_trust import ApprovalRefused

PAIR = ("azazel-auditd.service", "azazel-commissiond.service")


def _mkdir_private(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _replace_mask(mask, target="/dev/null"):
    """Replace a mask symlink and make the replacement visible in its stamp.

    The writer stamps a mask by (dev, inode, uid, mode, mtime, ctime) and
    separately requires an owned symlink to /dev/null on every read. A
    recreated link with the same target can come back with the same inode and
    the same timestamps (ext4 reuses the freed inode within one timestamp
    tick), so the stamp alone may not change. Moving the link's mtime
    explicitly makes the change certain on any filesystem; a different target
    is a replacement the content check must refuse whatever the stamp.
    """
    before = os.lstat(mask)
    mask.unlink()
    mask.symlink_to(target)
    os.utime(mask, ns=(before.st_atime_ns, before.st_mtime_ns - 1_000_000_000),
             follow_symlinks=False)
    assert os.lstat(mask).st_mtime_ns != before.st_mtime_ns


@contextmanager
def _environment(tmp_path):
    lock_path = tmp_path / "lock"
    journal_path = tmp_path / "journal"
    overlay_path = tmp_path / "system.control"
    masks_path = tmp_path / "persistent"
    higher_path = tmp_path / "higher-priority"
    for path in (lock_path, journal_path, overlay_path, masks_path, higher_path):
        _mkdir_private(path)
    for unit in PAIR:
        (masks_path / unit).symlink_to("/dev/null")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    lock_fd = os.open(lock_path, flags)
    journal_fd = os.open(journal_path, flags)
    overlay_fd = os.open(overlay_path, flags)
    masks_fd = os.open(masks_path, flags)
    higher_fd = os.open(higher_path, flags)

    def reopen_lock():
        return os.open(lock_path, flags)

    def reopen_journal():
        return os.open(journal_path, flags)

    try:
        with bootstrap_lock._transaction_at(
            lock_fd, owner=os.getuid(), reopen=reopen_lock
        ) as guard:
            store = OverlayJournalStore(
                journal_fd, owner_uid=os.getuid(), reopen=reopen_journal
            )
            try:
                yield {
                    "guard": guard,
                    "store": store,
                    "overlay_fd": overlay_fd,
                    "masks_fd": masks_fd,
                    "higher_fd": higher_fd,
                    "overlay_path": overlay_path,
                    "journal_path": journal_path,
                    "masks_path": masks_path,
                    "higher_path": higher_path,
                }
            finally:
                store.close()
    finally:
        for fd in (higher_fd, masks_fd, overlay_fd, journal_fd, lock_fd):
            os.close(fd)


def _approval():
    digest = "sha256:" + "c" * 64
    context = BootstrapContext(
        approval_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        node_digest=digest,
        boot_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        generation=1,
        generation_digest=digest,
        package_digest=digest,
        unit_closure_digest=digest,
        policy_digest=digest,
        approval_policy_digest=digest,
        security_epoch=1,
        revocation_digest=digest,
    )
    return VerifiedBootstrapApproval(
        context=context,
        operator="test-operator",
        granted_at="2026-10-14T00:00:00Z",
        expires_at="2026-10-14T01:00:00Z",
        payload_digest=digest,
    )


def _intent():
    return writer.new_overlay_intent(_approval())


def _publish(environment, *, intent=None):
    return writer._publish_candidates_at(
        overlay_fd=environment["overlay_fd"],
        masks_fd=environment["masks_fd"],
        higher_priority_fd=environment["higher_fd"],
        journal_store=environment["store"],
        guard=environment["guard"],
        intent=_intent() if intent is None else intent,
        owner_uid=os.getuid(),
    )


def _publish_approval(environment, approval=None):
    bound = _approval()
    intent = writer.new_overlay_intent(bound)
    transaction = GrantTransaction(
        boot_id=bound.context.boot_id,
        context_digest="sha256:" + intent.context_digest,
        approval_digest=bound.payload_digest,
        generation=bound.context.generation,
        generation_digest=bound.context.generation_digest,
        grant_id=intent.grant_id,
        unit_payload_digests=intent.payload_digests,
        phase="pair_grant_intent",
    )
    return writer._publish_verified_approval_at(
        overlay_fd=environment["overlay_fd"],
        masks_fd=environment["masks_fd"],
        higher_priority_fd=environment["higher_fd"],
        journal_store=environment["store"],
        guard=environment["guard"],
        approval=_approval() if approval is None else approval,
        transaction=transaction,
        check_publish=lambda: None,
        owner_uid=os.getuid(),
    )


def test_fixed_payloads_bind_exact_profiles_and_ordered_digests():
    payloads = writer._fixed_payloads()
    assert tuple(payloads) == PAIR
    intent = _intent()
    assert intent.payload_digests == tuple(
        (unit, sha256(payloads[unit]).hexdigest()) for unit in PAIR
    )
    assert intent.boot_id == _approval().context.boot_id
    assert len(intent.context_digest) == 64
    assert len(intent.grant_id) == 32


def test_overlay_intent_rejects_untyped_approval_context():
    malformed = VerifiedBootstrapApproval(
        context=None,
        operator="test-operator",
        granted_at="2026-10-14T00:00:00Z",
        expires_at="2026-10-14T01:00:00Z",
        payload_digest="sha256:" + "c" * 64,
    )
    with pytest.raises(ApprovalRefused):
        writer.new_overlay_intent(malformed)


def test_candidate_publication_fsyncs_and_journals_exact_pair(tmp_path):
    with _environment(tmp_path) as env:
        result = _publish(env)
        assert result.phase == "published"
        assert tuple(row[0] for row in result.owned_files) == PAIR
        assert env["store"].load() == result
        for unit in PAIR:
            payload = writer._fixed_payloads()[unit]
            path = env["overlay_path"] / unit
            assert path.read_bytes() == payload
            info = path.stat(follow_symlinks=False)
            recorded = next(row for row in result.owned_files if row[0] == unit)
            assert (info.st_dev, info.st_ino) == (recorded[1], recorded[2])
            assert info.st_nlink == 1


def test_approval_composition_derives_intent_and_publishes_fixed_pair(tmp_path):
    with _environment(tmp_path) as env:
        approval = _approval()
        result = _publish_approval(env, approval)
        assert result.phase == "published"
        assert result.intent.boot_id == approval.context.boot_id
        assert result.intent.payload_digests == tuple(
            (unit, sha256(writer._fixed_payloads()[unit]).hexdigest())
            for unit in PAIR
        )
        assert env["store"].load() == result


def test_approval_composition_rejects_untyped_or_malformed_input(tmp_path):
    malformed = VerifiedBootstrapApproval(
        context=None,
        operator="test-operator",
        granted_at="2026-10-14T00:00:00Z",
        expires_at="2026-10-14T01:00:00Z",
        payload_digest="sha256:" + "c" * 64,
    )
    with _environment(tmp_path) as env:
        with pytest.raises(ApprovalRefused):
            _publish_approval(env, malformed)
        assert list(env["overlay_path"].iterdir()) == []
        assert list(env["journal_path"].iterdir()) == []


def test_wrong_intent_digest_refuses_before_journal_or_candidate_creation(tmp_path):
    with _environment(tmp_path) as env:
        bad = OverlayIntent(
            boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            context_digest="c" * 64,
            grant_id="d" * 32,
            payload_digests=tuple((unit, "0" * 64) for unit in PAIR),
        )
        with pytest.raises(ApprovalRefused):
            _publish(env, intent=bad)
        assert list(env["overlay_path"].iterdir()) == []
        assert list(env["journal_path"].iterdir()) == []


@pytest.mark.parametrize("conflict", ["higher", "dropin", "mask"])
def test_preexisting_conflicts_refuse_without_changing_them(tmp_path, conflict):
    with _environment(tmp_path) as env:
        if conflict == "higher":
            foreign = env["higher_path"] / PAIR[0]
            foreign.write_bytes(b"keep\n")
        elif conflict == "dropin":
            foreign = env["overlay_path"] / f"{PAIR[0]}.d"
            foreign.mkdir(mode=0o700)
        else:
            foreign = env["masks_path"] / PAIR[0]
            foreign.unlink()
            foreign.symlink_to("/tmp/not-the-mask")
        with pytest.raises(ApprovalRefused):
            _publish(env)
        assert list(env["overlay_path"].iterdir()) == (
            [foreign] if conflict == "dropin" else []
        )
        assert list(env["journal_path"].iterdir()) == []
        if conflict == "higher":
            assert foreign.read_bytes() == b"keep\n"
        if conflict == "mask":
            assert foreign.is_symlink()


def test_second_create_failure_retains_durable_partial_journal_and_first_file(
    tmp_path, monkeypatch, private_os
):
    private_os(writer)
    with _environment(tmp_path) as env:
        real_open = os.open

        def fail_commissiond(name, flags, mode=0o777, *, dir_fd=None):
            if name == PAIR[1] and dir_fd == env["overlay_fd"] and flags & os.O_CREAT:
                raise OSError("injected second candidate open failure")
            if dir_fd is None:
                return real_open(name, flags, mode)
            return real_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(writer.os, "open", fail_commissiond)
        with pytest.raises(ApprovalRefused):
            _publish(env)
        monkeypatch.setattr(writer.os, "open", real_open)

        retained = env["store"].load()
        assert retained.phase == "partial"
        assert tuple(row[0] for row in retained.owned_files) == (PAIR[0],)
        assert (env["overlay_path"] / PAIR[0]).read_bytes() == writer._fixed_payloads()[PAIR[0]]
        assert not (env["overlay_path"] / PAIR[1]).exists()
        with pytest.raises(ApprovalRefused):
            _publish(env)
        assert env["store"].load() == retained


def test_second_journal_update_failure_keeps_unrecorded_second_file_unadopted(
    tmp_path, monkeypatch
):
    with _environment(tmp_path) as env:
        real_replace = env["store"].replace
        calls = 0

        def fail_second_update(expected, updated):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ApprovalRefused("injected publication journal failure")
            return real_replace(expected, updated)

        monkeypatch.setattr(env["store"], "replace", fail_second_update)
        with pytest.raises(writer.OverlayPublicationUncertain):
            _publish(env)
        monkeypatch.setattr(env["store"], "replace", real_replace)

        retained = env["store"].load()
        assert retained.phase == "partial"
        assert tuple(row[0] for row in retained.owned_files) == (PAIR[0],)
        for unit in PAIR:
            assert ((env["overlay_path"] / unit).read_bytes()
                    == writer._fixed_payloads()[unit])
        with pytest.raises(ApprovalRefused):
            _publish(env)
        assert env["store"].load() == retained


def test_replaced_first_candidate_inode_blocks_second_publication(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        real_replace = env["store"].replace
        updated_once = False

        def replace_then_swap(expected, updated):
            nonlocal updated_once
            result = real_replace(expected, updated)
            if not updated_once:
                updated_once = True
                candidate = env["overlay_path"] / PAIR[0]
                replacement = env["overlay_path"] / "replacement.tmp"
                replacement.write_bytes(candidate.read_bytes())
                replacement.chmod(0o644)
                replacement.replace(candidate)
            return result

        monkeypatch.setattr(env["store"], "replace", replace_then_swap)
        with pytest.raises(ApprovalRefused):
            _publish(env)
        monkeypatch.setattr(env["store"], "replace", real_replace)
        retained = env["store"].load()
        assert retained.phase == "partial"
        assert tuple(row[0] for row in retained.owned_files) == (PAIR[0],)
        assert (env["overlay_path"] / PAIR[0]).read_bytes() == writer._fixed_payloads()[PAIR[0]]
        assert not (env["overlay_path"] / PAIR[1]).exists()


def test_crash_gap_after_candidate_fsync_before_journal_identity_is_not_adopted(
    tmp_path, monkeypatch
):
    with _environment(tmp_path) as env:
        original_replace = env["store"].replace

        def fail_record(_expected, _next):
            raise ApprovalRefused("injected journal update failure")

        monkeypatch.setattr(env["store"], "replace", fail_record)
        with pytest.raises(writer.OverlayPublicationUncertain):
            _publish(env)
        monkeypatch.setattr(env["store"], "replace", original_replace)

        retained = env["store"].load()
        assert retained.phase == "intent"
        assert retained.owned_files == ()
        first = env["overlay_path"] / PAIR[0]
        assert first.read_bytes() == writer._fixed_payloads()[PAIR[0]]
        with pytest.raises(ApprovalRefused):
            _publish(env)
        assert env["store"].load() == retained
        assert first.read_bytes() == writer._fixed_payloads()[PAIR[0]]


def test_invalid_or_expired_transaction_guard_refuses_before_write(tmp_path):
    with _environment(tmp_path) as env:
        env["guard"]._check()
        # A different, constructible Python callback is not accepted as the
        # typed trusted-composition guard.
        with pytest.raises(ApprovalRefused):
            writer._publish_candidates_at(
                overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
                higher_priority_fd=env["higher_fd"],
                journal_store=env["store"], guard=lambda: None,
                intent=_intent(), owner_uid=os.getuid(),
            )
        assert list(env["overlay_path"].iterdir()) == []
