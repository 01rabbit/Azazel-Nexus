"""Gate B: withdrawal of a never-published grant with the production manager.

Real BootstrapNarrowingManager, BootstrapClosedOverlayFiles,
BootstrapWithdrawalFiles, OverlayJournalStore, transaction guard and
GrantTransaction over a temporary tree mirroring the host (empty overlay,
persistent masks ``<unit> -> /dev/null``, no overlay journal). Only the system
bus (and the cgroup root tree) is synthetic.
"""

from hashlib import sha256
import json
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction, advance_transaction
from azazel_nexus.bootstrap_overlay_journal import new_overlay_journal
from azazel_nexus_runtime.bootstrap_close_files import BootstrapClosedOverlayFiles
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_withdrawal import BootstrapWithdrawalFiles
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap import Harness, evidence as bootstrap_evidence
from test_runtime_bootstrap_manager_stopped import (
    Session,
    StoppedManagerFakeBus,
    _cgroup_root,
)
from test_runtime_bootstrap_overlay_files import PAIR, _intent
from test_runtime_bootstrap_overlay_withdraw import _withdraw_environment

DIGEST = "sha256:" + "a" * 64


class _UnpublishedSession(Session):
    """Session whose unit-file calls (DbusUnitManager) report the masked baseline."""

    def __call__(self, method, unit):
        if method == "MaskUnitFiles":
            return None
        if method == "GetUnitFileState":
            return "masked"
        if method == "GetInactiveState":
            return True
        raise AssertionError("unexpected unit-file call " + method)


def _baseline_fragments(env):
    def mutate(_number, name, properties):
        path = env["overlay_path"] / name
        fragment = str(path) if path.exists() else str(env["masks_path"] / name)
        properties["FragmentPath"] = SimpleNamespace(signature="s", value=fragment)
        properties["ActiveState"] = SimpleNamespace(signature="s", value="inactive")
        return properties

    return mutate


def _closed_files(env):
    return BootstrapClosedOverlayFiles(
        overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"], overlay_path=env["overlay_path"],
        masks_path=env["masks_path"], higher_priority_path=env["higher_path"],
        journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
    )


def _withdrawal_files(env):
    return BootstrapWithdrawalFiles(
        overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"], transient_fd=env["transient_fd"],
        generator_early_fd=env["generator_early_fd"],
        overlay_path=env["overlay_path"], masks_path=env["masks_path"],
        higher_priority_path=env["higher_path"], transient_path=env["transient_path"],
        generator_early_path=env["generator_early_path"],
        journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
    )


def _real_manager(env, root_fd, buses):
    def factory():
        bus = StoppedManagerFakeBus(mutate=_baseline_fragments(env))
        buses.append(bus)
        return _UnpublishedSession(bus)

    return BootstrapNarrowingManager(
        job_timeout_seconds=0.5, session_factory=factory,
        closed_overlay_files=_closed_files(env),
        withdrawal_files=_withdrawal_files(env),
        cgroup_root_fd=root_fd, cgroup_owner_uid=os.getuid(),
    )


def _transaction(phase="pair_grant_intent"):
    txn = GrantTransaction(
        boot_id="11111111-1111-1111-1111-111111111111",
        context_digest=DIGEST, approval_digest=DIGEST, generation=1,
        generation_digest=DIGEST, grant_id="0123456789abcdef0123456789abcdef",
        unit_payload_digests=(
            ("azazel-auditd.service", "a" * 64),
            ("azazel-commissiond.service", "b" * 64),
        ),
    )
    assert txn.phase == "prepared"
    if phase == "prepared":
        return txn
    txn = advance_transaction(txn, "pair_grant_intent")
    if phase == "pair_grant_intent":
        return txn
    if phase == "closing":
        return advance_transaction(txn, "closing", evidence_digest=DIGEST)
    txn = advance_transaction(txn, "pair_grant_opened")
    assert txn.phase == phase
    return txn


@pytest.fixture
def host(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _root, root_fd = _cgroup_root(tmp_path)
        buses = []
        try:
            yield env, _real_manager(env, root_fd, buses), buses, root_fd
        finally:
            os.close(root_fd)


def _assert_baseline_untouched(env):
    assert env["store"].load_optional() is None
    assert list(env["overlay_path"].iterdir()) == []
    assert list(env["journal_path"].iterdir()) == []


@pytest.mark.parametrize("phase", ["prepared", "pair_grant_intent", "closing"])
def test_unpublished_pair_withdrawal_returns_none_then_confirms_empty(host, phase):
    env, manager, buses, _fd = host
    manager.close_starts()
    assert manager.withdraw_pair(_transaction(phase)) is None
    assert manager.withdrawal_kind == "unpublished-baseline"
    assert manager.confirm_empty_pair() is None
    _assert_baseline_untouched(env)
    members = [call.member for bus in buses for call in bus.calls]
    assert not {"StartUnit", "UnmaskUnitFiles", "EnableUnitFiles"} & set(members)


@pytest.mark.parametrize("phase", ["pair_grant_opened", "auditd_start_intent"])
def test_opened_or_later_phase_refuses_withdrawal_of_unpublished_pair(host, phase):
    env, manager, _buses, _fd = host
    manager.close_starts()
    txn = _transaction("pair_grant_opened")
    if phase != txn.phase:
        txn = advance_transaction(txn, phase)
    with pytest.raises(UnitOperationFailed):
        manager.withdraw_pair(txn)
    _assert_baseline_untouched(env)


def test_journal_appearing_after_close_starts_refuses_withdrawal(host):
    env, manager, _buses, _fd = host
    manager.close_starts()
    env["store"].create(new_overlay_journal(_intent()))
    with pytest.raises(UnitOperationFailed):
        manager.withdraw_pair(_transaction())
    assert env["store"].load_optional() is not None  # not removed or altered


def test_pair_unit_appearing_in_overlay_after_close_starts_refuses_withdrawal(host):
    env, manager, _buses, _fd = host
    manager.close_starts()
    candidate = env["overlay_path"] / PAIR[0]
    candidate.write_bytes(b"unowned")
    with pytest.raises(UnitOperationFailed):
        manager.withdraw_pair(_transaction())
    assert manager.withdrawal_kind is None
    with pytest.raises(UnitOperationFailed):  # no success cache survives refusal
        manager.confirm_empty_pair()
    assert candidate.read_bytes() == b"unowned"  # never adopted or removed
    assert env["store"].load_optional() is None


def test_refusal_after_confirmed_withdrawal_clears_label_and_cache(host):
    env, manager, _buses, _fd = host
    manager.close_starts()
    assert manager.withdraw_pair(_transaction()) is None
    assert manager.withdrawal_kind == "unpublished-baseline"
    candidate = env["overlay_path"] / PAIR[0]
    candidate.write_bytes(b"unowned")
    with pytest.raises(UnitOperationFailed):
        manager.withdraw_pair(_transaction())
    assert manager.withdrawal_kind is None
    with pytest.raises(UnitOperationFailed):
        manager.confirm_empty_pair()
    assert candidate.read_bytes() == b"unowned"


def test_withdrawal_without_close_starts_refuses(host):
    env, manager, buses, _fd = host
    with pytest.raises(UnitOperationFailed):
        manager.withdraw_pair(_transaction())
    _assert_baseline_untouched(env)
    assert not buses  # no bus session was opened


@pytest.fixture
def evidence():
    # Reuse the canonical synthetic approval fixture from its owning module.
    return bootstrap_evidence.__wrapped__(None)


def test_supervisor_refused_widening_is_contained_and_grant_closed(evidence, host):
    env, manager, _buses, _fd = host
    h = Harness(evidence, manager=manager)
    # Production factory: open_pair refuses before any overlay publication.
    with pytest.raises(UnitOperationFailed, match="widening refused"):
        h.supervisor.run()
    _assert_baseline_untouched(env)
    assert h.grant_journal is not None and h.grant_journal.phase == "closed"
    assert h.grant_journal.phase != "recovery_required"
    assert h.deadline_guard.releases >= 1
    assert not h.narrowed  # no emergency narrowing: containment was confirmed
    assert [call.member for bus in _buses for call in bus.calls
            if call.member == "StartUnit"] == []
    containment_evidence = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-containment-evidence/v2",
            "start_fence": "confirmed",
            "stopped": ["auditd", "commissiond"],
            "inactive": ["auditd", "commissiond"],
            "cgroup_empty_pair": ["auditd", "commissiond"],
            "masked_operations": ["auditd", "commissiond"],
            "masked_observations": ["auditd", "commissiond"],
            "grant_withdrawal": "unpublished-baseline",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert h.grant_journal.close_evidence_digest == (
        "sha256:" + sha256(containment_evidence).hexdigest()
    )
