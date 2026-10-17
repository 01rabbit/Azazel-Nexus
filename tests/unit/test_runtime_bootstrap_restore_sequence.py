"""Fail-closed tests for post-unlink bootstrap restoration."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_restore import BootstrapRestoreSequence
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_manager_stopped import (
    OWNER,
    StoppedManagerFakeBus,
    _cgroup_root,
    _report_overlay_fragments,
)
from test_runtime_bootstrap_masked import Message, PAIR
from test_runtime_bootstrap_overlay_withdraw import _close, _withdraw, _withdraw_environment
from test_runtime_bootstrap_restore_files import _restored


EXPECTED_FRAGMENTS = tuple(
    (unit, "/etc/systemd/system/" + UNIT_NAMES[unit]) for unit in PAIR
)


class RestoreFiles:
    def __init__(self, bus, *, fragments=EXPECTED_FRAGMENTS,
                 finalize_error=False, repopulate=None):
        self.bus = bus
        self.fragments = fragments
        self.finalize_error = finalize_error
        self.repopulate = repopulate
        self.events = bus.events
        self.calls = []

    def check(self):
        self.calls.append("check")
        self.events.append("file-check")
        return self.fragments

    def finalize(self, evidence):
        self.calls.append(("finalize", evidence))
        self.events.append("finalize")
        if self.repopulate is not None:
            self.repopulate.write_text("populated 1\n", encoding="ascii")
        if self.finalize_error:
            raise OSError("injected finalization refusal")
        return None


def _sequence(bus, files, root_fd, *, timeout_seconds=0.5, check_mount=None):
    return BootstrapRestoreSequence(
        bus=bus,
        message_factory=Message,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1, SIGNAL=4),
        timeout_seconds=timeout_seconds,
        files=files,
        expected_owner=OWNER,
        cgroup_root_fd=root_fd,
        owner_uid=os.getuid(),
        check_mount=check_mount,
    )


def _run(awaitable):
    return asyncio.run(awaitable)


def _bus(**kwargs):
    return StoppedManagerFakeBus(mutate=_report_overlay_fragments({
        "overlay_path": Path("/etc/systemd/system"),
    }), **kwargs)


def test_restore_reloads_stops_reverse_finalizes_then_rechecks_cgroups(tmp_path):
    bus = _bus()
    files = RestoreFiles(bus)
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        result = _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)

    assert result.owner == OWNER
    assert all(row[2][0] == "empty" for row in result.cgroups)
    members = [call.member for call in bus.calls]
    stops = [call.body[0] for call in bus.calls if call.member == "StopUnit"]
    assert members.count("Reload") == 1
    assert stops == [UNIT_NAMES[UnitKey.COMMISSIOND], UNIT_NAMES[UnitKey.AUDITD]]
    assert members.index("Reload") < members.index("StopUnit")
    assert files.calls[-1] == "check"
    finalize_index = bus.events.index("finalize")
    service_reads_after_finalize = [
        i for i, event in enumerate(bus.events)
        if i > finalize_index and event == "GetAll"
    ]
    assert service_reads_after_finalize
    assert not bus.handlers


def test_restore_refuses_stale_owner_before_reload(tmp_path):
    bus = _bus(owner_changes=True)
    files = RestoreFiles(bus)
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)
    assert not any(call.member == "Reload" for call in bus.calls)
    assert not any(call.member == "StopUnit" for call in bus.calls)
    assert not any(call[0] == "finalize" for call in files.calls)


def test_restore_refuses_wrong_fragment(tmp_path):
    bus = _bus()
    wrong = tuple((unit, "/wrong/" + UNIT_NAMES[unit]) for unit in PAIR)
    files = RestoreFiles(bus, fragments=wrong)
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)
    assert not any(call[0] == "finalize" for call in files.calls)


def test_restore_refuses_populated_cgroup(tmp_path):
    _root, root_fd = _cgroup_root(
        tmp_path, populated_unit=UNIT_NAMES[UnitKey.COMMISSIOND]
    )
    bus = _bus()
    files = RestoreFiles(bus)
    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)
    assert not any(call[0] == "finalize" for call in files.calls)


def test_restore_refuses_reload_failure(tmp_path):
    bus = _bus(reload_error=True)
    files = RestoreFiles(bus)
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)
    assert not any(call.member == "StopUnit" for call in bus.calls)
    assert not any(call[0] == "finalize" for call in files.calls)


def test_restore_refuses_finalization_failure(tmp_path):
    bus = _bus()
    files = RestoreFiles(bus, finalize_error=True)
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)
    assert any(call[0] == "finalize" for call in files.calls if isinstance(call, tuple))


def test_restore_refuses_cgroup_repopulation_during_finalization(tmp_path):
    _root, root_fd = _cgroup_root(tmp_path)
    populated_file = (
        _root / "system.slice" / UNIT_NAMES[UnitKey.COMMISSIOND] / "cgroup.events"
    )
    bus = _bus()
    files = RestoreFiles(bus, repopulate=populated_file)
    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd).restore())
    finally:
        os.close(root_fd)
    assert any(call[0] == "finalize" for call in files.calls if isinstance(call, tuple))


def test_restore_is_single_use_after_success(tmp_path):
    bus = _bus()
    files = RestoreFiles(bus)
    _root, root_fd = _cgroup_root(tmp_path)
    sequence = _sequence(bus, files, root_fd)
    try:
        _run(sequence.restore())
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            _run(sequence.restore())
    finally:
        os.close(root_fd)
    assert len(bus.calls) == call_count


@pytest.mark.parametrize("failure_at", [1, 2, 5])
def test_restore_mount_guard_refuses_before_finalization(tmp_path, failure_at):
    bus = _bus()
    files = RestoreFiles(bus)
    _root, root_fd = _cgroup_root(tmp_path)
    calls = []

    def changed_mount():
        calls.append(None)
        if len(calls) == failure_at:
            raise UnitOperationFailed("synthetic mount changed")

    try:
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd, check_mount=changed_mount).restore())
    finally:
        os.close(root_fd)
    assert len(calls) == failure_at
    assert not any(isinstance(call, tuple) and call[0] == "finalize" for call in files.calls)
    if failure_at == 1:
        assert not bus.calls


def test_restore_refuses_mount_change_during_final_bus_reply(tmp_path):
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        baseline = _bus()
        _run(_sequence(baseline, RestoreFiles(baseline), root_fd).restore())
        final_reply = len(baseline.calls)
        bus = _bus()
        files = RestoreFiles(bus)
        original_call = bus.call
        changed = False

        async def change_on_last_reply(message):
            nonlocal changed
            result = await original_call(message)
            if len(bus.calls) == final_reply:
                changed = True
            return result

        def mount_guard():
            if changed:
                raise UnitOperationFailed("mount changed at final reply")

        bus.call = change_on_last_reply
        with pytest.raises(UnitOperationFailed):
            _run(_sequence(bus, files, root_fd, check_mount=mount_guard).restore())
        assert changed
        assert any(isinstance(call, tuple) and call[0] == "finalize" for call in files.calls)
    finally:
        os.close(root_fd)


def test_restore_finalizes_real_withdrawn_overlay_journal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        assert _withdraw(env).phase == "withdrawing"

        def persistent_mask_fragments(_call_number, name, properties):
            properties["FragmentPath"] = SimpleNamespace(
                signature="s", value=str(env["masks_path"] / name),
            )
            properties["ActiveState"] = SimpleNamespace(
                signature="s", value="inactive",
            )
            return properties

        bus = StoppedManagerFakeBus(mutate=persistent_mask_fragments)
        actual_files = _restored(env)

        class RecordingFiles:
            evidence = None

            def check(self):
                return actual_files.check()

            def finalize(self, evidence):
                self.evidence = evidence
                return actual_files.finalize(evidence)

        files = RecordingFiles()
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            result = _run(_sequence(bus, files, root_fd).restore())
        finally:
            os.close(root_fd)

        evidence = files.evidence
        expected_names = (
            UNIT_NAMES[UnitKey.AUDITD], UNIT_NAMES[UnitKey.COMMISSIOND]
        )
        assert result.owner == OWNER
        assert evidence.stopped_pair == expected_names
        assert evidence.inactive_pair == expected_names
        assert evidence.withdrawn_pair == expected_names
        assert evidence.start_fence_closed is True
        assert evidence.persistent_masks_restored is True
        assert evidence.loaded_masks_confirmed is True
        closed = env["store"].load()
        assert closed.phase == "closed"
        assert closed.owned_files == ()
