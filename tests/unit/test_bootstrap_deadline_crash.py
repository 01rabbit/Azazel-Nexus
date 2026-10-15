"""Abrupt worker exit against ordinary files, not power loss or service HIL."""

import multiprocessing
import os

import pytest
from nacl.signing import SigningKey

from azazel_nexus import bootstrap_deadline_store as store
from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy, BootstrapContext, bootstrap_payload, verify_bootstrap_approval,
)
from azazel_nexus.bootstrap_deadline import begin_deadline
from azazel_nexus.operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message

START = "2026-10-13T00:00:00Z"
BOOT = "11111111-1111-1111-1111-111111111111"


def _crash_after_sync(directory, state, phase):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    original = store._write_new

    def crash_write(target_fd, name, raw):
        original(target_fd, name, raw)
        if name == ("initial.json" if phase == "initial" else "checkpoint.next"):
            os._exit(73)

    store._write_new = crash_write
    try:
        if phase == "initial":
            store._retain_initial_at(fd, state, owner=os.getuid())
        else:
            store._advance_at(fd, owner=os.getuid(), approval=state.approval,
                              boot_id=BOOT, now=START, boottime_ns=2,
                              clock_trusted=True)
    finally:
        os.close(fd)


@pytest.mark.real_process
@pytest.mark.parametrize("phase", ["initial", "advance"])
def test_abrupt_worker_exit_leaves_refusing_store(tmp_path, phase):
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("ordinary-file fork crash test requires a POSIX fork context")
    key = SigningKey.generate()
    digest = "sha256:" + "a" * 64
    policy = BootstrapApprovalPolicy(frozenset({"operator-a"}), 300)
    context = BootstrapContext(BOOT, digest, BOOT, 1, digest, digest, digest,
                               digest, policy.digest(), 0, digest)
    payload = bootstrap_payload(context=context, operator="operator-a",
                                granted_at=START, expires_at="2026-10-13T00:05:00Z")
    approval = verify_bootstrap_approval(
        trust=OperatorTrust({"operator-a": bytes(key.verify_key)}), expected=context,
        policy=policy, operator="operator-a", payload=payload,
        signature=key.sign(approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)).signature,
        now=START,
    )
    state = begin_deadline(approval, boot_id=BOOT, now=START, boottime_ns=1, clock_trusted=True)
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if phase == "advance":
            store._retain_initial_at(fd, state, owner=os.getuid())
        worker = multiprocessing.get_context("fork").Process(
            target=_crash_after_sync, args=(directory, state, phase),
        )
        worker.start()
        worker.join(timeout=5)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        assert worker.exitcode == 73
        assert (directory / "transaction.pending").is_file()
        with pytest.raises(ApprovalRefused, match="unfinished"):
            store._advance_at(fd, owner=os.getuid(), approval=approval, boot_id=BOOT,
                              now=START, boottime_ns=3, clock_trusted=True)
        with pytest.raises(ApprovalRefused, match="unfinished"):
            store._retain_initial_at(fd, state, owner=os.getuid())
    finally:
        os.close(fd)
